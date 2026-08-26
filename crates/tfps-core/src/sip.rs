//! Parse de SIP suficiente para o TFPS — e nada além disso.
//!
//! Este módulo **não é uma pilha SIP**. Ele extrai de um datagrama os campos que o
//! sistema precisa para decidir e para forjar uma resposta, e ignora todo o resto.
//! A fronteira está no `SPEC.md` §1: *não fala SIP além de forjar respostas*.
//!
//! O parse empresta do buffer de entrada (zero-cópia). O caminho de decisão roda por
//! INVITE internacional, então nada aqui aloca.

/// Método SIP. Só os que o sistema observa; o resto é `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Invite,
    Register,
    Bye,
    Cancel,
    Ack,
    Options,
    Other,
}

impl Method {
    fn from_token(tok: &str) -> Self {
        // Métodos SIP são case-sensitive e maiúsculos (RFC 3261 §7.1).
        match tok {
            "INVITE" => Self::Invite,
            "REGISTER" => Self::Register,
            "BYE" => Self::Bye,
            "CANCEL" => Self::Cancel,
            "ACK" => Self::Ack,
            "OPTIONS" => Self::Options,
            _ => Self::Other,
        }
    }
}

/// Uma requisição SIP, emprestando do buffer original.
///
/// Os campos `via`, `from`, `to`, `call_id` e `cseq` são retidos **crus** porque a forja
/// de resposta os reusa literalmente (RFC 3261 §17.1.3, e `SPEC.md` §8). Não normalizar
/// aqui é deliberado: reescrever o que se vai copiar de volta só cria oportunidade de erro.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub method: Method,
    /// Request-URI crua, como veio na linha de requisição.
    pub request_uri: &'a str,
    /// Parte de usuário da Request-URI — o número discado, ainda **não canônico**.
    pub request_user: Option<&'a str>,
    pub via: Option<&'a str>,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub call_id: Option<&'a str>,
    pub cseq: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub p_asserted_identity: Option<&'a str>,
    /// Credencial apresentada. Sua **presença** é o sinal de força bruta: um `REGISTER`
    /// com `Authorization` é uma tentativa de senha, enquanto o `401` que o antecede é
    /// só o desafio normal.
    pub authorization: Option<&'a str>,
    /// Houve continuação de linha (header dobrado). Raro e legal; sinalizado porque
    /// este parser não a junta, e um valor dobrado sai truncado.
    pub folded: bool,
}

impl<'a> Request<'a> {
    /// Parte de usuário do `From` — o A-number, **asserção não verificada** do remetente
    /// (ver `CONTEXT.md`, verbete A-number).
    pub fn from_user(&self) -> Option<&'a str> {
        self.from.and_then(uri_user)
    }

    /// Tag do `From`, necessária para casar a resposta forjada.
    pub fn from_tag(&self) -> Option<&'a str> {
        self.from.and_then(|v| param(v, "tag"))
    }

    /// `branch` do topo do `Via` — o casador de transação da RFC 3261 §17.1.3.
    pub fn via_branch(&self) -> Option<&'a str> {
        self.via.and_then(|v| param(v, "branch"))
    }
}

/// Extrai a parte de usuário de uma URI SIP embutida num valor de header.
///
/// Aceita as formas que aparecem na prática: `sip:user@host`, `<sip:user@host>`,
/// `"Nome" <sip:user@host>;tag=x`, e `tel:+55...`.
fn uri_user(value: &str) -> Option<&str> {
    let start = value
        .find("sip:")
        .or_else(|| value.find("sips:"))
        .or_else(|| value.find("tel:"))?;
    let after_scheme = &value[start..];
    let colon = after_scheme.find(':')? + 1;
    let rest = &after_scheme[colon..];

    // A parte de usuário termina no `@`; sem `@` (caso `tel:`), termina no delimitador.
    let end = rest.find('@').unwrap_or_else(|| {
        rest.find(|c: char| c == '>' || c == ';' || c == '?' || c.is_whitespace())
            .unwrap_or(rest.len())
    });
    let user = &rest[..end];
    if user.is_empty() {
        None
    } else {
        Some(user)
    }
}

/// Extrai um parâmetro `;nome=valor` de um valor de header.
fn param<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    for part in value.split(';').skip(1) {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        if k.trim().eq_ignore_ascii_case(name) {
            let v = v.trim();
            let end = v
                .find(|c: char| c == ',' || c == '>' || c.is_whitespace())
                .unwrap_or(v.len());
            return Some(&v[..end]);
        }
    }
    None
}

/// Casa nome de header, aceitando a forma compacta da RFC 3261 §20.
fn header_is(name: &str, long: &str, compact: Option<&str>) -> bool {
    name.eq_ignore_ascii_case(long) || compact.is_some_and(|c| name.eq_ignore_ascii_case(c))
}

/// Uma resposta SIP. O caminho de decisão não a usa; o de **aprendizado** sim — é o
/// `200 OK` que diz se a chamada foi atendida, e a duração vem do `BYE` correspondente.
#[derive(Debug, Clone, Copy)]
pub struct Response<'a> {
    pub status: u16,
    pub call_id: Option<&'a str>,
}

/// Uma mensagem SIP é requisição ou resposta. Distinguir importa para observabilidade:
/// contar resposta como "não é SIP" faria o operador concluir que está capturando a
/// interface errada — e o projeto inteiro se define por não falhar em silêncio.
#[derive(Debug, Clone)]
pub enum Message<'a> {
    Request(Box<Request<'a>>),
    Response(Response<'a>),
    /// Keepalive CRLF da RFC 5626 §4.4.1 — o cliente atrás de NAT manda `\r\n\r\n` e o
    /// servidor devolve `\r\n`, só para manter o buraco do NAT aberto.
    ///
    /// Categoria própria por honestidade de relatório: numa porta 5060 com clientes
    /// residenciais **isto é a maioria dos pacotes**, e contá-lo como "não é SIP" faria
    /// o operador concluir que está capturando a interface errada.
    Keepalive,
}

/// Faz o parse de um datagrama SIP, requisição ou resposta.
pub fn parse(buf: &[u8]) -> Option<Message<'_>> {
    // Keepalive antes de tudo: é o caso mais frequente e o mais barato de reconhecer.
    if buf.len() <= 4 && !buf.is_empty() && buf.iter().all(|b| matches!(b, b'\r' | b'\n')) {
        return Some(Message::Keepalive);
    }
    let text = core::str::from_utf8(buf).ok()?;
    if text.starts_with("SIP/") {
        return parse_response(text).map(Message::Response);
    }
    parse_request(buf).map(|r| Message::Request(Box::new(r)))
}

fn parse_response(text: &str) -> Option<Response<'_>> {
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let status_line = lines.next()?;
    let mut parts = status_line.split(' ');
    let _version = parts.next()?;
    let status: u16 = parts.next()?.parse().ok()?;

    let mut call_id = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if header_is(name.trim(), "Call-ID", Some("i")) {
                call_id = Some(value.trim());
                break;
            }
        }
    }
    Some(Response { status, call_id })
}

/// Faz o parse de um datagrama SIP.
///
/// Devolve `None` quando o buffer não é UTF-8 ou não começa com uma linha de requisição
/// plausível. **Isso não é erro do sistema e nunca é motivo de bloqueio** — `SPEC.md` §4:
/// o que não se consegue interpretar sai de escopo e passa.
pub fn parse_request(buf: &[u8]) -> Option<Request<'_>> {
    // Headers SIP são ASCII na prática. Payload não-UTF-8 é lixo ou não é SIP;
    // nos dois casos o tratamento é o mesmo: não é assunto do sistema.
    let text = core::str::from_utf8(buf).ok()?;

    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let request_line = lines.next()?;

    let mut parts = request_line.split(' ');
    let method = Method::from_token(parts.next()?);
    let request_uri = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("SIP/") {
        return None;
    }

    let mut req = Request {
        method,
        request_uri,
        request_user: uri_user(request_uri),
        via: None,
        from: None,
        to: None,
        call_id: None,
        cseq: None,
        user_agent: None,
        p_asserted_identity: None,
        authorization: None,
        folded: false,
    };

    for line in lines {
        if line.is_empty() {
            break; // fim dos headers; o corpo (SDP) não interessa
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            req.folded = true;
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();

        // Só o topo do Via importa: é o que a resposta reusa.
        if req.via.is_none() && header_is(name, "Via", Some("v")) {
            req.via = Some(value);
        } else if header_is(name, "From", Some("f")) {
            req.from = Some(value);
        } else if header_is(name, "To", Some("t")) {
            req.to = Some(value);
        } else if header_is(name, "Call-ID", Some("i")) {
            req.call_id = Some(value);
        } else if header_is(name, "CSeq", None) {
            req.cseq = Some(value);
        } else if header_is(name, "User-Agent", None) {
            req.user_agent = Some(value);
        } else if header_is(name, "P-Asserted-Identity", None) {
            req.p_asserted_identity = Some(value);
        } else if header_is(name, "Authorization", None)
            || header_is(name, "Proxy-Authorization", None)
        {
            req.authorization = Some(value);
        }
    }

    Some(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &str = concat!(
        "INVITE sip:9011252612345678@pbx.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK776asdhds;rport\r\n",
        "Max-Forwards: 70\r\n",
        "From: \"Ramal 200\" <sip:200@pbx.example.com>;tag=1928301774\r\n",
        "To: <sip:9011252612345678@pbx.example.com>\r\n",
        "Call-ID: a84b4c76e66710@pc33.example.com\r\n",
        "CSeq: 314159 INVITE\r\n",
        "User-Agent: Grandstream GXP2140 1.0.9.14\r\n",
        "Content-Type: application/sdp\r\n",
        "Content-Length: 131\r\n",
        "\r\n",
        "v=0\r\no=- 53655765 2353687637 IN IP4 10.0.0.5\r\n",
    );

    #[test]
    fn extrai_os_campos_de_um_invite() {
        let r = parse_request(INVITE.as_bytes()).expect("deve parsear");
        assert_eq!(r.method, Method::Invite);
        assert_eq!(r.request_user, Some("9011252612345678"));
        assert_eq!(r.from_user(), Some("200"));
        assert_eq!(r.from_tag(), Some("1928301774"));
        assert_eq!(r.via_branch(), Some("z9hG4bK776asdhds"));
        assert_eq!(r.call_id, Some("a84b4c76e66710@pc33.example.com"));
        assert_eq!(r.cseq, Some("314159 INVITE"));
        assert_eq!(r.user_agent, Some("Grandstream GXP2140 1.0.9.14"));
        assert!(!r.folded);
    }

    #[test]
    fn distingue_register_com_e_sem_credencial() {
        // Sem `Authorization`: é o primeiro REGISTER, que só provoca o desafio.
        let sem = "REGISTER sip:pbx SIP/2.0\r\nFrom: <sip:1@pbx>\r\n\r\n";
        assert!(parse_request(sem.as_bytes())
            .unwrap()
            .authorization
            .is_none());
        // Com `Authorization`: é uma tentativa de senha — o que se conta.
        let com = "REGISTER sip:pbx SIP/2.0\r\n\
                   From: <sip:1@pbx>\r\n\
                   Authorization: Digest username=\"1001\", response=\"abc\"\r\n\r\n";
        let r = parse_request(com.as_bytes()).unwrap();
        assert!(r.authorization.is_some());
        assert_eq!(r.method, Method::Register);
    }

    #[test]
    fn aceita_forma_compacta_e_lf_puro() {
        let msg = "INVITE sip:5511999998888@example.com SIP/2.0\n\
                   v: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bKabc\n\
                   f: <sip:1000@example.com>;tag=xyz\n\
                   t: <sip:5511999998888@example.com>\n\
                   i: call-123\n\
                   CSeq: 1 INVITE\n\
                   \n";
        let r = parse_request(msg.as_bytes()).expect("deve parsear");
        assert_eq!(r.from_user(), Some("1000"));
        assert_eq!(r.via_branch(), Some("z9hG4bKabc"));
        assert_eq!(r.call_id, Some("call-123"));
    }

    #[test]
    fn so_o_topo_do_via_e_retido() {
        let msg = "INVITE sip:1@e.com SIP/2.0\r\n\
                   Via: SIP/2.0/UDP topo;branch=PRIMEIRO\r\n\
                   Via: SIP/2.0/UDP baixo;branch=SEGUNDO\r\n\
                   \r\n";
        let r = parse_request(msg.as_bytes()).unwrap();
        assert_eq!(r.via_branch(), Some("PRIMEIRO"));
    }

    #[test]
    fn header_dobrado_e_sinalizado() {
        let msg = "INVITE sip:1@e.com SIP/2.0\r\n\
                   From: <sip:200@e.com>\r\n\
                   \t;tag=continuacao\r\n\
                   \r\n";
        let r = parse_request(msg.as_bytes()).unwrap();
        assert!(r.folded, "continuação de linha precisa ser sinalizada");
    }

    #[test]
    fn tel_uri_sem_arroba() {
        let msg = "INVITE tel:+5511999998888 SIP/2.0\r\n\r\n";
        let r = parse_request(msg.as_bytes()).unwrap();
        assert_eq!(r.request_user, Some("+5511999998888"));
    }

    #[test]
    fn resposta_nao_e_confundida_com_lixo() {
        // O caso que apareceu no primeiro teste em tráfego real: 8 de 10 pacotes na
        // porta 5060 eram respostas, e o contador dizia "não é SIP".
        let msg = "SIP/2.0 200 OK\r\n\
                   Via: SIP/2.0/UDP 1.2.3.4;branch=z9hG4bK1\r\n\
                   Call-ID: abc-123\r\n\
                   CSeq: 1 INVITE\r\n\r\n";
        match parse(msg.as_bytes()).expect("deve parsear") {
            Message::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.call_id, Some("abc-123"));
            }
            other => panic!("esperava resposta, veio {other:?}"),
        }
        // E requisição continua sendo requisição.
        assert!(matches!(
            parse(INVITE.as_bytes()),
            Some(Message::Request(_))
        ));
        // Lixo continua sendo lixo.
        assert!(parse(b"nao sou sip").is_none());
    }

    #[test]
    fn keepalive_de_nat_nao_e_lixo() {
        // Apareceu na primeira implantação: 6 de 8 pacotes numa 5060 real eram
        // payloads de 2 bytes. São softphones atrás de NAT mantendo o pinhole.
        for ka in [&b"\r\n"[..], &b"\r\n\r\n"[..], &b"\n"[..]] {
            assert!(
                matches!(parse(ka), Some(Message::Keepalive)),
                "deveria reconhecer keepalive de {ka:?}"
            );
        }
        // Payload vazio não é keepalive; é pacote sem conteúdo.
        assert!(parse(b"").is_none());
        // E algo de 4 bytes que não seja CRLF continua sendo lixo.
        assert!(parse(b"abcd").is_none());
    }

    #[test]
    fn resposta_de_erro_tambem_e_reconhecida() {
        for (raw, code) in [
            ("SIP/2.0 403 Forbidden\r\n\r\n", 403u16),
            ("SIP/2.0 486 Busy Here\r\n\r\n", 486),
        ] {
            match parse(raw.as_bytes()).unwrap() {
                Message::Response(r) => assert_eq!(r.status, code),
                _ => panic!("esperava resposta"),
            }
        }
    }

    #[test]
    fn nao_sip_e_recusado_sem_panico() {
        assert!(parse_request(b"lixo binario \xff\xfe").is_none());
        assert!(parse_request(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse_request(b"").is_none());
        assert!(parse_request(b"INVITE\r\n").is_none());
    }

    #[test]
    fn metodo_desconhecido_nao_e_invite() {
        let msg = "SUBSCRIBE sip:1@e.com SIP/2.0\r\n\r\n";
        assert_eq!(parse_request(msg.as_bytes()).unwrap().method, Method::Other);
    }
}
