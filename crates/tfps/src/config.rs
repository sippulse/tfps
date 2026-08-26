//! Arquivo de configuração — `/etc/tfps/config.json`.
//!
//! **Todo campo é opcional e o sistema funciona sem o arquivo.** Isso não é conveniência:
//! é a restrição 1 do projeto. O que existe aqui é configuração de **instalação** (onde
//! olhar, como ler os números) e integração opcional — nunca configuração de **política**,
//! que diria o que é fraude. Os catorze botões do `defines.m4` do TFPS 2023 não têm
//! equivalente.
//!
//! Precedência: **linha de comando vence o arquivo, que vence o padrão embutido.**
//!
//! ```json
//! {
//!   "ports": [5060, 5061],
//!   "intl_prefixes": ["+", "00", "011", "9011"],
//!   "peers": { "10.0.0.5": { "intl_prefixes": ["9011"], "bare_e164": false } },
//!   "signatures": ["MeuScannerLocal", "=sipsak"],
//!   "injection": ["xp_cmdshell"],
//!   "apiban_key": "...",
//!   "learn_days": 30,
//!   "block_ttl": 3600
//! }
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const DEFAULT_PATH: &str = "/etc/tfps/config.json";

/// Plano de discagem de uma central.
///
/// Declarar bate aprender porque vale já na **primeira** chamada daquele peer, em vez de
/// esperar convergência — e 20,3% dos destinos não resolvem a país sem despelamento
/// correto. O aprendizado continua rodando em paralelo, e discordância vira alarme.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// Prefixos de discagem internacional daquela central, ex.: `["9011", "011"]`.
    #[serde(default)]
    pub intl_prefixes: Vec<String>,
    /// A central envia E.164 puro, sem prefixo. Comum em wholesale.
    ///
    /// Sinalizador explícito e não um prefixo vazio, porque a semântica é perigosa: com
    /// ele ligado, `2125551234` é Marrocos; sem ele, é um número nacional dos EUA.
    #[serde(default)]
    pub bare_e164: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub ports: Option<Vec<u16>>,
    /// Prefixos padrão, usados para peer sem plano declarado.
    pub intl_prefixes: Option<Vec<String>>,
    /// Plano por central, indexado pelo IP de origem.
    #[serde(default)]
    pub peers: BTreeMap<String, PeerConfig>,
    /// Assinaturas de user-agent que **acrescentam** às embutidas.
    ///
    /// Prefixo por padrão; `=texto` casa exato. Nunca substituem: um arquivo que
    /// substituísse faria quem escreve três linhas perder as 18 de fábrica sem perceber.
    #[serde(default)]
    pub signatures: Vec<String>,
    /// Padrões de injeção em URI que acrescentam aos embutidos.
    #[serde(default)]
    pub injection: Vec<String>,
    pub apiban_key: Option<String>,
    pub learn_days: Option<u32>,
    pub block_ttl: Option<u64>,
    pub stats_every: Option<u64>,
    pub checkpoint_every: Option<u64>,
    pub iface: Option<String>,
    pub db: Option<PathBuf>,
    pub xdp_obj: Option<PathBuf>,
    pub drop_map: Option<PathBuf>,
}

/// Resultado da leitura, para que a origem da configuração apareça no relatório de
/// arranque. O operador precisa saber se o arquivo foi lido, ignorado, ou está quebrado.
pub enum Loaded {
    /// Arquivo lido.
    File(Box<Config>, PathBuf),
    /// Não existe — comportamento normal e esperado.
    Absent,
    /// Existe mas não pôde ser lido. **Nunca silencioso**: configuração quebrada que é
    /// ignorada em silêncio faz o operador achar que declarou algo que não vale.
    Broken(String),
}

pub fn load(path: &Path) -> Loaded {
    if !path.exists() {
        return Loaded::Absent;
    }
    match std::fs::read_to_string(path) {
        Err(e) => Loaded::Broken(format!("lendo {}: {e}", path.display())),
        Ok(txt) => match serde_json::from_str::<Config>(&txt) {
            Ok(c) => Loaded::File(Box::new(c), path.to_path_buf()),
            Err(e) => Loaded::Broken(format!("{}: {e}", path.display())),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Config, String> {
        serde_json::from_str(s).map_err(|e| e.to_string())
    }

    #[test]
    fn arquivo_vazio_e_valido() {
        // A promessa central: nada é obrigatório.
        let c = parse("{}").expect("objeto vazio tem de valer");
        assert!(c.ports.is_none());
        assert!(c.signatures.is_empty());
        assert!(c.peers.is_empty());
    }

    #[test]
    fn le_o_exemplo_do_readme() {
        let c = parse(
            r#"{
              "ports": [5060, 5061],
              "intl_prefixes": ["+", "00"],
              "peers": { "10.0.0.5": { "intl_prefixes": ["9011"], "bare_e164": false } },
              "signatures": ["MeuScannerLocal", "=sipsak"],
              "injection": ["xp_cmdshell"],
              "apiban_key": "abc",
              "learn_days": 30,
              "block_ttl": 3600
            }"#,
        )
        .expect("o exemplo documentado tem de parsear");
        assert_eq!(c.ports.as_deref(), Some(&[5060u16, 5061][..]));
        assert_eq!(c.peers["10.0.0.5"].intl_prefixes, ["9011"]);
        assert_eq!(c.signatures.len(), 2);
        assert_eq!(c.apiban_key.as_deref(), Some("abc"));
    }

    #[test]
    fn campo_desconhecido_e_erro_e_nao_silencio() {
        // Um typo que fosse ignorado faria o operador acreditar que ligou o APIBAN
        // quando não ligou. `deny_unknown_fields` recusa e nomeia o campo errado.
        let e = parse(r#"{"apiban_kei": "x"}"#).unwrap_err();
        assert!(
            e.contains("apiban_kei"),
            "o erro precisa nomear o campo errado: {e}"
        );
        // E o campo certo continua valendo, obviamente.
        assert_eq!(
            parse(r#"{"apiban_key": "x"}"#).unwrap().apiban_key.as_deref(),
            Some("x")
        );
    }

    #[test]
    fn json_quebrado_vira_erro_legivel_e_nao_panico() {
        assert!(parse("{").is_err());
        assert!(parse("").is_err());
        assert!(parse(r#"{"ports": "não é lista"}"#).is_err());
    }

    #[test]
    fn ausencia_de_arquivo_nao_e_erro() {
        let p = std::path::Path::new("/caminho/que/nao/existe/config.json");
        assert!(matches!(load(p), Loaded::Absent));
    }
}
