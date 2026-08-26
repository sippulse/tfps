//! Integração opcional com o [APIBAN](https://apiban.org) — lista colaborativa de IPs
//! de atacantes SIP, alimentada por honeypots.
//!
//! **Em segundo plano, nunca no caminho do pacote.** Foi exatamente aqui que o TFPS de
//! 2023 morreu: um `rest_get()` **síncrono por INVITE**, sem cache, com 4 workers — teto
//! de ~26 INVITEs/s, e qualquer indisponibilidade do apiban.org congelava a decisão de
//! todas as chamadas. Aqui a busca roda numa thread separada e entrega por canal; se a
//! rede cair, o sistema segue com a lista que já tem.
//!
//! O produto é **completo sem isto**. É integração opcional, e o único campo de
//! configuração que a habilita é a chave.

use std::net::Ipv4Addr;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// Intervalo entre buscas. O APIBAN é incremental por ID, então cada busca traz só o que
/// apareceu desde a anterior.
const POLL_SECS: u64 = 300;

/// Teto de endereços por resposta, para que um feed anômalo não encha o mapa de uma vez.
const MAX_PER_FETCH: usize = 5_000;

/// Um lote de endereços a condenar, com o ID para continuar de onde parou.
pub struct Batch {
    pub ips: Vec<Ipv4Addr>,
    pub next_id: Option<String>,
}

/// Inicia a busca periódica numa thread. O chamador drena o canal quando lhe convém.
///
/// `start_id` vem do que foi persistido: retomar do último ID evita rebaixar a lista
/// inteira a cada reinício.
pub fn spawn(key: String, start_id: Option<String>) -> Receiver<Batch> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut id = start_id.unwrap_or_else(|| "100".to_string());
        loop {
            match fetch(&key, &id) {
                Ok(b) => {
                    if let Some(next) = b.next_id.clone() {
                        id = next;
                    }
                    let vazio = b.ips.is_empty();
                    if tx.send(b).is_err() {
                        return; // o processo principal saiu
                    }
                    if vazio {
                        std::thread::sleep(Duration::from_secs(POLL_SECS));
                    }
                    // Com lote cheio, busca de novo já: o feed é paginado por ID.
                }
                Err(e) => {
                    // Falha de rede não é fatal e não pode ser silenciosa.
                    eprintln!("AVISO: APIBAN indisponível ({e}); seguindo com a lista atual");
                    std::thread::sleep(Duration::from_secs(POLL_SECS));
                }
            }
        }
    });
    rx
}

fn fetch(key: &str, id: &str) -> Result<Batch, String> {
    let url = format!("https://apiban.org/api/{key}/banned/{id}");
    let body = ureq::get(&url)
        .config()
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .call()
        .map_err(|e| format!("{e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("lendo resposta: {e}"))?;
    Ok(parse(&body))
}

/// Extrai endereços e o próximo ID da resposta do APIBAN.
///
/// Feito à mão em vez de com um desserializador porque o formato é raso e estável, e
/// porque tolerar campo desconhecido sem falhar é mais importante aqui do que rigor: uma
/// mudança no feed não pode derrubar a defesa.
fn parse(body: &str) -> Batch {
    let mut ips = Vec::new();
    let mut next_id = None;

    if let Some(rest) = body.split("\"ID\"").nth(1) {
        if let Some(v) = between(rest, '"', '"') {
            if !v.is_empty() && v != "none" {
                next_id = Some(v.to_string());
            }
        }
    }
    if let Some(arr) = body.split("\"ipaddress\"").nth(1) {
        let arr = arr.split(']').next().unwrap_or("");
        for tok in arr.split(',') {
            if let Some(v) = between(tok, '"', '"') {
                if let Ok(ip) = v.trim().parse::<Ipv4Addr>() {
                    ips.push(ip);
                    if ips.len() >= MAX_PER_FETCH {
                        break;
                    }
                }
            }
        }
    }
    Batch { ips, next_id }
}

fn between(s: &str, open: char, close: char) -> Option<&str> {
    let start = s.find(open)? + open.len_utf8();
    let rest = &s[start..];
    let end = rest.find(close)?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extrai_enderecos_e_o_proximo_id() {
        let body = r#"{"ID":"1698425647","ipaddress":["45.134.144.130","185.243.5.75"]}"#;
        let b = parse(body);
        assert_eq!(b.next_id.as_deref(), Some("1698425647"));
        assert_eq!(
            b.ips,
            vec![
                Ipv4Addr::new(45, 134, 144, 130),
                Ipv4Addr::new(185, 243, 5, 75)
            ]
        );
    }

    #[test]
    fn resposta_sem_novidade_nao_quebra() {
        let b = parse(r#"{"ID":"none","ipaddress":["no new bans"]}"#);
        assert!(b.next_id.is_none(), "`none` não é um ID para continuar");
        assert!(b.ips.is_empty(), "texto que não é IP é descartado");
    }

    #[test]
    fn lixo_no_feed_nao_derruba_a_defesa() {
        // Uma mudança de formato não pode virar pânico: o pior aceitável é não
        // acrescentar nada nesta rodada.
        for body in ["", "{}", "não é json", r#"{"ipaddress":[123]}"#] {
            let b = parse(body);
            assert!(b.ips.is_empty());
        }
    }

    #[test]
    fn respeita_o_teto_por_lote() {
        let muitos: Vec<String> = (0..MAX_PER_FETCH + 100)
            .map(|i| format!("\"10.{}.{}.1\"", i / 256, i % 256))
            .collect();
        let body = format!("{{\"ID\":\"5\",\"ipaddress\":[{}]}}", muitos.join(","));
        assert_eq!(parse(&body).ips.len(), MAX_PER_FETCH);
    }
}
