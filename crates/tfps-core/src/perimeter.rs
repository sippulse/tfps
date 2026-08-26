//! Perímetro — remoção de ruído por assinatura de user-agent.
//!
//! **Não existe para pegar fraude.** Existe para impedir que lixo contamine a linha de
//! base comportamental: se varredura alimenta o baseline de um par, o modelo aprende que
//! rajada para destino estranho é normal ali, e a defesa se envenena sozinha (`SPEC.md` §7).
//!
//! É também o **gancho de retenção do produto**: pacote removido aqui, quando a imposição
//! entrar, morre no `XDP_DROP` e portanto **não aparece no sngrep** — o operador instala,
//! abre a captura, e o lixo sumiu.
//!
//! Expectativa calibrada, e ela é modesta: na geração Java do TFPS a regra de user-agent
//! disparou 260 vezes em 19 meses, com a lista congelada em 16 assinaturas por uma década.
//! Como *detecção* isso é quase inútil — atacante competente usa UA normal. Como **filtro
//! de volume** é adequado, porque os scanners preguiçosos com UA padrão são a maioria
//! absoluta dos pacotes.

/// Assinaturas de ferramenta conhecida.
///
/// Herdadas da tabela `dialplan` (dpid 99997) do TFPS 2023, convertidas de regex para
/// casamento simples — todas eram âncora de início ou string literal, e um casador de
/// prefixo dispensa a dependência de regex no caminho quente.
static SIGNATURES: &[(&str, Match)] = &[
    ("sipcli", Match::Prefix),
    ("friendly", Match::Prefix),
    ("VaxUserAgent", Match::Prefix),
    ("VaxSIPUserAgent", Match::Prefix),
    ("sivus", Match::Prefix),
    ("Nsauditor", Match::Prefix),
    ("SipReg", Match::Prefix),
    ("Custom SIP", Match::Prefix),
    ("Nmap NSE", Match::Prefix),
    ("sipscan", Match::Prefix),
    ("sipsorcery", Match::Prefix),
    ("pplsip", Match::Prefix),
    ("SipClient", Match::Prefix),
    ("sipvicious", Match::Prefix),
    ("smap", Match::Exact),
    ("PBX", Match::Exact),
    ("Trixbox", Match::Exact),
    ("opensip", Match::Exact),
];

/// Padrões de injeção que aparecem em URI de ataque.
///
/// Herdados da regra **R12** do `tfps.m4` de 2023, que fazia sete verificações sobre
/// `$au`, `$ru`, `$rU`, `$fU`, `$fu` e o `Contact`. Diferente do user-agent, isto **não
/// tem explicação inocente**: nenhum telefone põe aspa simples ou `--` no `From`. Por
/// isso é sinal de confiança mais alta que a lista de ferramentas.
static INJECTION: &[&str] = &[
    "'",   // aspa simples — o clássico
    "%27", // aspa simples percent-encoded
    "--",  // comentário SQL
    "\\",  // escape
    "%24", // `$`
    "%60", // crase
    "==", "?=?",   // visto em campo pelo dev
    "union", // `UNION SELECT`
    "select", ";", // separador de comando fora de parâmetro
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    /// Começa com a assinatura. Cobre `^sipcli`, `^friendly`, etc.
    Prefix,
    /// É exatamente a assinatura. Cobre `^PBX$`, `^Trixbox$`, `^opensip$` — âncoras nas
    /// duas pontas, porque `PBX` como prefixo casaria user-agent legítimo de PBX real.
    Exact,
}

/// Filtro de ruído, com contagem por assinatura.
///
/// A contagem não é enfeite: o `SPEC.md` §12 exige reportar padrão que casa zero vezes.
/// Assinatura que não dispara em três meses está podre, e o operador precisa saber —
/// foi exatamente o que o `fail2ban` nunca fez.
#[derive(Debug, Clone)]
pub struct NoiseFilter {
    hits: Vec<u64>,
    /// Assinaturas acrescentadas por arquivo, com suas próprias contagens.
    extra: Vec<(String, Match, u64)>,
    /// Padrões de injeção acrescentados por arquivo.
    extra_injection: Vec<String>,
    injections: u64,
}

impl Default for NoiseFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl NoiseFilter {
    pub fn new() -> Self {
        Self {
            hits: vec![0; SIGNATURES.len()],
            extra: Vec::new(),
            extra_injection: Vec::new(),
            injections: 0,
        }
    }

    /// O user-agent casa alguma assinatura conhecida de ferramenta de varredura?
    ///
    /// Comparação sem diferenciar maiúsculas: o TFPS 2023 tinha `^[sS][iI][vV][uU][sS]`
    /// escrito à mão justamente por causa disso.
    pub fn is_noise(&mut self, user_agent: Option<&str>) -> Option<&'static str> {
        let ua = user_agent?.trim();
        if ua.is_empty() {
            // User-agent ausente é comum em tráfego legítimo (o TFPS Java viu 6.843
            // INVITEs sem UA). Ausência **não** é ruído.
            return None;
        }
        for (i, (sig, kind)) in SIGNATURES.iter().enumerate() {
            if matches_sig(ua, sig, *kind) {
                self.hits[i] += 1;
                return Some(sig);
            }
        }
        // As do arquivo vêm depois: as embutidas têm a contagem estável do relatório.
        for (sig, kind, n) in &mut self.extra {
            if matches_sig(ua, sig, *kind) {
                *n += 1;
                return Some("<arquivo>");
            }
        }
        None
    }

    /// Assinaturas e quantas vezes cada uma casou, para o relatório.
    pub fn hits(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        SIGNATURES
            .iter()
            .zip(&self.hits)
            .map(|((sig, _), n)| (*sig, *n))
    }

    /// Acrescenta uma assinatura de user-agent vinda de arquivo.
    ///
    /// **Acrescenta, nunca substitui.** Um arquivo que substituísse faria o operador que
    /// escreve três linhas perder as 18 embutidas sem perceber — downgrade silencioso,
    /// que é precisamente a falha que este projeto condena no `fail2ban`.
    ///
    /// Sintaxe: `texto` casa por prefixo; `=texto` casa exato (o equivalente a `^…$`).
    pub fn add_signature(&mut self, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with('#') {
            return;
        }
        let (kind, sig) = match raw.strip_prefix('=') {
            Some(rest) => (Match::Exact, rest.trim()),
            None => (Match::Prefix, raw),
        };
        if !sig.is_empty() {
            self.extra.push((sig.to_string(), kind, 0));
        }
    }

    /// Acrescenta um padrão de injeção vindo de arquivo.
    pub fn add_injection(&mut self, raw: &str) {
        let raw = raw.trim();
        if !raw.is_empty() && !raw.starts_with('#') {
            self.extra_injection.push(raw.to_ascii_lowercase());
        }
    }

    /// Quantas assinaturas o filtro conhece ao todo — embutidas mais as do arquivo.
    pub fn signature_count(&self) -> (usize, usize) {
        (SIGNATURES.len(), self.extra.len())
    }

    pub fn injection_count(&self) -> (usize, usize) {
        (INJECTION.len(), self.extra_injection.len())
    }

    /// A URI carrega padrão de injeção?
    ///
    /// Recebe as URIs cruas (Request-URI e `From`) porque o ataque costuma vir na parte
    /// de usuário ou no host, e normalizar antes esconderia o que se procura.
    ///
    /// **Não** é aplicado à mensagem inteira: `Via`, `User-Agent` e corpo SDP contêm
    /// caracteres legítimos que casariam por acidente.
    pub fn injection_in_uri(&mut self, uris: &[Option<&str>]) -> Option<&'static str> {
        for uri in uris.iter().flatten() {
            let lower = uri.to_ascii_lowercase();
            for pat in INJECTION {
                // `;` é legítimo como separador de parâmetro em URI SIP (`;tag=`,
                // `;transport=`), então só conta quando aparece na **parte de usuário**.
                if *pat == ";" {
                    if user_part(&lower).is_some_and(|u| u.contains(';')) {
                        self.injections += 1;
                        return Some(pat);
                    }
                    continue;
                }
                if lower.contains(pat) {
                    self.injections += 1;
                    return Some(pat);
                }
            }
            for pat in &self.extra_injection {
                if lower.contains(pat.as_str()) {
                    self.injections += 1;
                    return Some("<arquivo>");
                }
            }
        }
        None
    }

    pub fn injections(&self) -> u64 {
        self.injections
    }

    /// Assinaturas que nunca casaram — as candidatas a estarem podres.
    pub fn cold_signatures(&self) -> Vec<&'static str> {
        self.hits()
            .filter(|(_, n)| *n == 0)
            .map(|(s, _)| s)
            .collect()
    }
}

/// Quantas tentativas autenticadas numa janela caracterizam força bruta.
///
/// **Não se conta `401` cru**, e isso é a diferença entre funcionar e derrubar todos os
/// clientes: o desafio digest é o fluxo normal — todo `REGISTER` legítimo recebe um `401`
/// com nonce antes de reenviar com `Authorization`. Contar desafios bloquearia todo mundo.
///
/// O que se conta é **`REGISTER` carregando `Authorization`**: um telefone legítimo manda
/// um por ciclo de registro (tipicamente a cada 300 s), enquanto quem testa credencial
/// manda muitos por segundo. Nenhuma correlação de resposta é necessária, e nenhum estado
/// de diálogo.
pub const AUTH_ATTEMPTS_TO_BLOCK: u32 = 20;

/// Janela do contador acima, em segundos.
///
/// Medido no servidor de referência: **2 desafios em 45 s** de tráfego legítimo, ou seja
/// ~2,7/min. Vinte por minuto dá ~7× de folga. **Ressalva honesta**: NAT grande agrega
/// muitos telefones num IP e pode encostar no limiar — é a mesma limitação do `fail2ban`,
/// e o bloqueio é temporário justamente por isso.
pub const AUTH_WINDOW_SECS: u32 = 60;

/// Contador de tentativas autenticadas por origem, em janela deslizante.
#[derive(Debug, Clone, Default)]
pub struct AuthAbuse {
    /// Carimbos das últimas tentativas. Anel do tamanho exato do limiar: se a mais antiga
    /// ainda está na janela, o limiar foi atingido.
    stamps: [u32; AUTH_ATTEMPTS_TO_BLOCK as usize],
    len: u8,
    next: u8,
}

impl AuthAbuse {
    /// Registra uma tentativa autenticada e diz se o limiar foi atingido.
    pub fn attempt(&mut self, now: u32) -> (u32, bool) {
        self.stamps[self.next as usize] = now;
        self.next = (self.next + 1) % AUTH_ATTEMPTS_TO_BLOCK as u8;
        if (self.len as u32) < AUTH_ATTEMPTS_TO_BLOCK {
            self.len += 1;
        }
        let n = self.stamps[..self.len as usize]
            .iter()
            .filter(|s| now.saturating_sub(**s) < AUTH_WINDOW_SECS)
            .count() as u32;
        (n, n >= AUTH_ATTEMPTS_TO_BLOCK)
    }
}

fn matches_sig(ua: &str, sig: &str, kind: Match) -> bool {
    match kind {
        Match::Prefix => ua.len() >= sig.len() && ua[..sig.len()].eq_ignore_ascii_case(sig),
        Match::Exact => ua.eq_ignore_ascii_case(sig),
    }
}

/// Parte de usuário de uma URI SIP em minúsculas, para a checagem de `;`.
fn user_part(uri: &str) -> Option<&str> {
    let start = uri
        .find("sip:")
        .map(|i| i + 4)
        .or_else(|| uri.find("sips:").map(|i| i + 5))?;
    let rest = &uri[start..];
    let end = rest.find('@')?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pega_os_scanners_classicos() {
        let mut f = NoiseFilter::new();
        for ua in [
            "friendly-scanner",
            "sipcli/v1.8",
            "pplsip",
            "sipvicious 0.3.3",
            "Nmap NSE",
            "VaxSIPUserAgent/3.0",
        ] {
            assert!(f.is_noise(Some(ua)).is_some(), "deveria pegar {ua}");
        }
    }

    #[test]
    fn nao_pega_user_agent_legitimo() {
        let mut f = NoiseFilter::new();
        for ua in [
            "Grandstream GXP2140 1.0.9.14",
            "Asterisk PBX 18.9.0",
            "Z 5.5.5 rv2.10.16.6",
            "OpenSIPS (3.2.0 (x86_64/linux))",
            "Cisco-SIPGateway/IOS-12.x",
            "FPBX-2.8.1(1.8.20.0)",
        ] {
            assert!(f.is_noise(Some(ua)).is_none(), "falso positivo em {ua}");
        }
    }

    #[test]
    fn ancora_dupla_evita_falso_positivo_em_pbx_real() {
        let mut f = NoiseFilter::new();
        // `^PBX$` do TFPS 2023: só o UA que é exatamente "PBX" é scanner.
        assert!(f.is_noise(Some("PBX")).is_some());
        assert!(f.is_noise(Some("PBX Asterisk 18")).is_none());
        assert!(f.is_noise(Some("opensip")).is_some());
        assert!(f.is_noise(Some("OpenSIPS (3.2.0)")).is_none());
    }

    #[test]
    fn ausencia_de_user_agent_nao_e_ruido() {
        // O TFPS Java viu 6.843 INVITEs legítimos sem user-agent. Tratar ausência
        // como ruído descartaria tráfego bom — e envenenaria a medição de volume.
        let mut f = NoiseFilter::new();
        assert!(f.is_noise(None).is_none());
        assert!(f.is_noise(Some("")).is_none());
        assert!(f.is_noise(Some("   ")).is_none());
    }

    #[test]
    fn maiusculas_nao_importam() {
        let mut f = NoiseFilter::new();
        assert!(f.is_noise(Some("SIPVICIOUS")).is_some());
        assert!(f.is_noise(Some("SiVuS")).is_some());
    }

    #[test]
    fn pega_injecao_em_uri() {
        let mut f = NoiseFilter::new();
        for uri in [
            "sip:1001'@pbx.com",
            "sip:admin--@pbx.com",
            "sip:x%27or%271%27=%271@pbx.com",
            "sip:?=?@pbx.com",
            "sip:1 union select@pbx.com",
            "sip:a;drop@pbx.com",
        ] {
            assert!(
                f.injection_in_uri(&[Some(uri)]).is_some(),
                "deveria pegar injeção em {uri}"
            );
        }
        assert_eq!(f.injections(), 6);
    }

    #[test]
    fn nao_pega_uri_legitima() {
        let mut f = NoiseFilter::new();
        for uri in [
            "sip:1001@pbx.example.com",
            "<sip:5511999998888@gw.example.com>;tag=abc123",
            "sip:200@10.0.0.5:5060;transport=udp",
            "\"Ramal 200\" <sip:200@pbx.com>;tag=x",
            "sip:+5511999998888@carrier.net;user=phone",
        ] {
            assert!(
                f.injection_in_uri(&[Some(uri)]).is_none(),
                "falso positivo em {uri}"
            );
        }
    }

    #[test]
    fn ponto_e_virgula_de_parametro_nao_e_injecao() {
        // `;tag=`, `;transport=` e `;user=phone` são legítimos e frequentes. Só conta
        // quando o `;` está na parte de usuário, antes do `@`.
        let mut f = NoiseFilter::new();
        assert!(f
            .injection_in_uri(&[Some("sip:200@pbx.com;transport=tcp")])
            .is_none());
        assert!(f.injection_in_uri(&[Some("sip:20;0@pbx.com")]).is_some());
    }

    #[test]
    fn arquivo_acrescenta_e_nunca_substitui() {
        let mut f = NoiseFilter::new();
        f.add_signature("MeuScannerLocal");
        f.add_signature("=ExatoAssim");
        f.add_signature("# comentário ignorado");
        f.add_signature("   ");

        // A nova funciona…
        assert!(f.is_noise(Some("MeuScannerLocal/2.0")).is_some());
        assert!(f.is_noise(Some("ExatoAssim")).is_some());
        assert!(
            f.is_noise(Some("ExatoAssim e mais")).is_none(),
            "= é âncora dupla"
        );
        // …e as embutidas continuam valendo. É o ponto: acrescenta, não substitui.
        assert!(f.is_noise(Some("friendly-scanner")).is_some());
        assert_eq!(
            f.signature_count(),
            (18, 2),
            "comentário e vazio não entram"
        );
    }

    #[test]
    fn injecao_do_arquivo_tambem_acrescenta() {
        let mut f = NoiseFilter::new();
        f.add_injection("xp_cmdshell");
        assert!(f
            .injection_in_uri(&[Some("sip:a xp_cmdshell b@x")])
            .is_some());
        assert!(
            f.injection_in_uri(&[Some("sip:1001'@x")]).is_some(),
            "embutido segue"
        );
        assert_eq!(f.injection_count(), (11, 1));
    }

    #[test]
    fn o_desafio_digest_legitimo_nao_dispara() {
        // Um telefone registra a cada 300 s. Mesmo em uma hora inteira, não chega perto.
        let mut a = AuthAbuse::default();
        for ciclo in 0..12u32 {
            let (_, bloqueia) = a.attempt(ciclo * 300);
            assert!(!bloqueia, "registro periódico legítimo nunca pode bloquear");
        }
    }

    #[test]
    fn forca_bruta_dispara() {
        let mut a = AuthAbuse::default();
        let mut bloqueou = false;
        for i in 0..AUTH_ATTEMPTS_TO_BLOCK {
            let (_, b) = a.attempt(1000 + i); // uma por segundo
            bloqueou = b;
        }
        assert!(bloqueou, "20 tentativas em 20 s tem de bloquear");
    }

    #[test]
    fn a_janela_desliza_em_vez_de_zerar() {
        let mut a = AuthAbuse::default();
        // 19 tentativas, insuficiente.
        for i in 0..(AUTH_ATTEMPTS_TO_BLOCK - 1) {
            assert!(!a.attempt(1000 + i).1);
        }
        // Muito depois, uma tentativa isolada não pode somar com as antigas.
        let (n, bloqueia) = a.attempt(1000 + AUTH_WINDOW_SECS * 3);
        assert_eq!(n, 1);
        assert!(!bloqueia);
    }

    #[test]
    fn conta_por_assinatura_e_denuncia_as_frias() {
        let mut f = NoiseFilter::new();
        f.is_noise(Some("friendly-scanner"));
        f.is_noise(Some("friendly-scanner"));
        f.is_noise(Some("sipcli/v1.8"));

        let quentes: Vec<_> = f.hits().filter(|(_, n)| *n > 0).collect();
        assert_eq!(quentes.len(), 2);
        assert!(quentes.contains(&("friendly", 2)));
        assert!(quentes.contains(&("sipcli", 1)));

        // As demais nunca casaram — é isto que o relatório precisa dizer.
        assert!(f.cold_signatures().contains(&"pplsip"));
        assert!(!f.cold_signatures().contains(&"friendly"));
    }
}
