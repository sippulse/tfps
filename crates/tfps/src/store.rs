//! Armazenamento durável em SQLite.
//!
//! **Um arquivo. Sem servidor, sem daemon, sem credencial, sem porta.** É zero
//! configuração de verdade — o TFPS de 2023 tinha senha de MySQL em texto claro em seis
//! pontos do `.cfg` gerado.
//!
//! E o operador **consegue abrir e ver o que o sistema aprendeu**:
//!
//! ```sh
//! sqlite3 /var/lib/tfps/tfps.db "select * from block_log order by ts desc limit 20"
//! ```
//!
//! Num produto silencioso por desenho, poder auditar o estado é o que separa "confio
//! nisso" de "não sei se está funcionando".
//!
//! **É armazenamento durável, não caminho quente** (`SPEC.md` §10). O conjunto de
//! trabalho vive em memória; aqui só acontecem a carga do boot e o checkpoint periódico.
//! Consultar SQL por INVITE seria gargalo de escrita no alvo wholesale.
//!
//! A divisão de estado importa: o de **perímetro** morre com o processo e se reconstrói
//! em minutos do próprio tráfego — coerente com o fail-open por não fixar o programa
//! eBPF. O **comportamental**, de 45 a 90 dias, é o que precisa sobreviver.

use std::net::Ipv4Addr;
use std::path::Path;

use rusqlite::{params, Connection};
use tfps_core::engine::{Engine, PairRecord, PeerCountryRecord};

pub const DEFAULT_PATH: &str = "/var/lib/tfps/tfps.db";

/// Versão do esquema. Mudança incompatível recria as tabelas em vez de corromper —
/// perder linha de base é recuperável em dias; ler bitmap com semântica errada não é.
const SCHEMA: i64 = 1;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("criando {}: {e}", dir.display()))?;
        }
        let conn =
            Connection::open(path).map_err(|e| format!("abrindo {}: {e}", path.display()))?;

        // WAL: leitura concorrente enquanto o checkpoint escreve, e menos fsync.
        // `synchronous=NORMAL` é o par usual de WAL — perder os últimos segundos num
        // corte de energia custa segundos de aprendizado, não a base.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("WAL: {e}"))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| format!("synchronous: {e}"))?;

        let me = Self { conn };
        me.migrate()?;
        Ok(me)
    }

    fn migrate(&self) -> Result<(), String> {
        let found: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);
        if found != 0 && found != SCHEMA {
            // Esquema incompatível: recomeça. Ver a nota em `SCHEMA`.
            for t in ["pair", "peer_country", "meta", "block_log"] {
                let _ = self.conn.execute(&format!("DROP TABLE IF EXISTS {t}"), []);
            }
        }
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS meta (
                     k TEXT PRIMARY KEY,
                     v TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS pair (
                     peer      TEXT    NOT NULL,
                     a_number  TEXT    NOT NULL,
                     cur       BLOB    NOT NULL,
                     prev      BLOB    NOT NULL,
                     period    INTEGER NOT NULL,
                     last_seen INTEGER NOT NULL,
                     PRIMARY KEY (peer, a_number)
                 );
                 CREATE TABLE IF NOT EXISTS peer_country (
                     peer    TEXT    NOT NULL,
                     country INTEGER NOT NULL,
                     calls   INTEGER NOT NULL,
                     PRIMARY KEY (peer, country)
                 );
                 -- Auditoria: todo bloqueio registra o porquê, legível por humano.
                 -- `SPEC.md` §12 exige que o operador possa reconstruir a decisão.
                 CREATE TABLE IF NOT EXISTS block_log (
                     ts     INTEGER NOT NULL,
                     ip     TEXT    NOT NULL,
                     reason TEXT    NOT NULL,
                     detail TEXT    NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS block_log_ts ON block_log (ts);",
            )
            .map_err(|e| format!("criando esquema: {e}"))?;
        self.conn
            .pragma_update(None, "user_version", SCHEMA)
            .map_err(|e| format!("user_version: {e}"))
    }

    /// Instante em que o aprendizado começou, gravado na primeira execução.
    ///
    /// **É o que dá sentido ao modo de aprendizado.** Sem persistir isto, cada restart
    /// reiniciaria os 30 dias e a contagem regressiva prometeria algo que um
    /// `systemctl restart` apagaria.
    pub fn learning_started(&self, default_now: u32) -> u32 {
        if let Ok(v) =
            self.conn
                .query_row("SELECT v FROM meta WHERE k = 'learning_started'", [], |r| {
                    r.get::<_, String>(0)
                })
        {
            if let Ok(t) = v.parse() {
                return t;
            }
        }
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO meta (k, v) VALUES ('learning_started', ?1)",
            params![default_now.to_string()],
        );
        default_now
    }

    pub fn log_block(&self, ts: u32, ip: Ipv4Addr, reason: &str, detail: &str) {
        let _ = self.conn.execute(
            "INSERT INTO block_log (ts, ip, reason, detail) VALUES (?1, ?2, ?3, ?4)",
            params![ts, ip.to_string(), reason, detail],
        );
    }

    /// Apaga auditoria antiga. Sem isto o arquivo cresce para sempre — foi o que
    /// produziu o `/var/log/opensips.log` de 477 MB que o `fail2ban` varre linha a linha.
    pub fn prune_log(&self, older_than: u32) -> usize {
        self.conn
            .execute("DELETE FROM block_log WHERE ts < ?1", params![older_than])
            .unwrap_or(0)
    }

    /// Grava o estado de aprendizado. Chamado no checkpoint, nunca por pacote.
    pub fn checkpoint(&mut self, engine: &Engine) -> Result<(usize, usize), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("transação: {e}"))?;
        let mut pairs = 0usize;
        let mut countries = 0usize;
        {
            let mut ins = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO pair
                     (peer, a_number, cur, prev, period, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|e| format!("preparando pair: {e}"))?;
            for r in engine.export_pairs() {
                ins.execute(params![
                    r.peer.to_string(),
                    r.a_number,
                    words_to_blob(&r.cur),
                    words_to_blob(&r.prev),
                    r.period,
                    r.last_seen
                ])
                .map_err(|e| format!("gravando par: {e}"))?;
                pairs += 1;
            }
            let mut insc = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO peer_country (peer, country, calls)
                     VALUES (?1, ?2, ?3)",
                )
                .map_err(|e| format!("preparando peer_country: {e}"))?;
            for r in engine.export_peer_countries() {
                insc.execute(params![r.peer.to_string(), r.country, r.calls])
                    .map_err(|e| format!("gravando país: {e}"))?;
                countries += 1;
            }
        }
        tx.commit().map_err(|e| format!("commit: {e}"))?;
        Ok((pairs, countries))
    }

    /// Carrega o estado no boot. Erro aqui **não é fatal** — o sistema recomeça o
    /// aprendizado, o que é ruim mas recuperável; não subir seria pior.
    pub fn load_into(&self, engine: &mut Engine) -> Result<(usize, usize), String> {
        let mut pairs = 0usize;
        let mut st = self
            .conn
            .prepare("SELECT peer, a_number, cur, prev, period, last_seen FROM pair")
            .map_err(|e| format!("lendo pair: {e}"))?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, u32>(4)?,
                    r.get::<_, u32>(5)?,
                ))
            })
            .map_err(|e| format!("iterando pair: {e}"))?;
        for row in rows.flatten() {
            let (peer, a_number, cur, prev, period, last_seen) = row;
            let (Ok(peer), Some(cur), Some(prev)) = (
                peer.parse::<Ipv4Addr>(),
                blob_to_words(&cur),
                blob_to_words(&prev),
            ) else {
                continue; // linha corrompida: ignora uma, não perde a base inteira
            };
            engine.import_pair(PairRecord {
                peer,
                a_number,
                cur,
                prev,
                period,
                last_seen,
            });
            pairs += 1;
        }

        let mut countries = 0usize;
        let mut st = self
            .conn
            .prepare("SELECT peer, country, calls FROM peer_country")
            .map_err(|e| format!("lendo peer_country: {e}"))?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u16>(1)?,
                    r.get::<_, u32>(2)?,
                ))
            })
            .map_err(|e| format!("iterando peer_country: {e}"))?;
        for (peer, country, calls) in rows.flatten() {
            if let Ok(peer) = peer.parse::<Ipv4Addr>() {
                engine.import_peer_country(PeerCountryRecord {
                    peer,
                    country,
                    calls,
                });
                countries += 1;
            }
        }
        Ok((pairs, countries))
    }
}

/// Bitmap como 32 bytes little-endian. Formato explícito para que o arquivo seja legível
/// por outra ferramenta, e não dependa da ordem de bytes da máquina que gravou.
fn words_to_blob(w: &[u64; 4]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn blob_to_words(b: &[u8]) -> Option<[u64; 4]> {
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u64; 4];
    for (i, chunk) in b.as_chunks::<8>().0.iter().enumerate() {
        out[i] = u64::from_le_bytes(*chunk);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfps_core::dialplan::DialPlan;
    use tfps_core::engine::Mode;
    use tfps_core::novelty::Timestamp;

    fn tmp() -> std::path::PathBuf {
        let n: u32 = std::process::id();
        std::env::temp_dir().join(format!(
            "tfps-test-{n}-{:?}.db",
            std::thread::current().id()
        ))
    }

    fn invite(from: &str, dialed: &str) -> Vec<u8> {
        format!("INVITE sip:{dialed}@pbx SIP/2.0\r\nFrom: <sip:{from}@pbx>;tag=t\r\n\r\n")
            .into_bytes()
    }

    #[test]
    fn o_bitmap_sobrevive_a_um_restart() {
        // A propriedade que dá sentido ao modo de aprendizado: sem isto, um
        // `systemctl restart` apagaria 30 dias de linha de base em silêncio.
        let path = tmp();
        let _ = std::fs::remove_file(&path);
        let peer = Ipv4Addr::new(10, 0, 0, 5);
        let t = Timestamp(1_800_000_000);

        let mut e1 = Engine::new(DialPlan::new(["00"]), Mode::Active);
        e1.observe(peer, &invite("200", "00551199998888"), t);
        e1.observe(peer, &invite("200", "00351912345678"), t);

        let mut s = Store::open(&path).unwrap();
        let (p, c) = s.checkpoint(&e1).unwrap();
        assert_eq!(p, 1, "um par");
        assert!(c >= 2, "dois países");

        // Processo novo, memória zerada.
        let mut e2 = Engine::new(DialPlan::new(["00"]), Mode::Active);
        let s2 = Store::open(&path).unwrap();
        s2.load_into(&mut e2).unwrap();

        // O que já era conhecido continua conhecido — não vira novidade de novo.
        let dec = e2.observe(peer, &invite("200", "00551199998888"), t);
        assert_eq!(
            dec,
            tfps_core::engine::Decision::Pass {
                country: "BR",
                novel: false
            },
            "Brasil já era conhecido antes do restart"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn o_inicio_do_aprendizado_nao_reinicia_a_cada_boot() {
        let path = tmp().with_extension("learn.db");
        let _ = std::fs::remove_file(&path);
        let s = Store::open(&path).unwrap();
        let primeiro = s.learning_started(1000);
        assert_eq!(primeiro, 1000);
        // Um "restart" depois, com relógio bem mais adiante.
        let s2 = Store::open(&path).unwrap();
        assert_eq!(
            s2.learning_started(9_999_999),
            1000,
            "reiniciar não pode empurrar o fim do aprendizado para frente"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn auditoria_grava_e_poda() {
        let path = tmp().with_extension("log.db");
        let _ = std::fs::remove_file(&path);
        let s = Store::open(&path).unwrap();
        s.log_block(100, Ipv4Addr::new(1, 2, 3, 4), "user-agent", "pplsip");
        s.log_block(200, Ipv4Addr::new(5, 6, 7, 8), "injeção", "'");
        assert_eq!(s.prune_log(150), 1, "só o mais antigo sai");
        let restantes: i64 = s
            .conn
            .query_row("SELECT count(*) FROM block_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(restantes, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn blob_corrompido_nao_derruba_a_carga() {
        assert!(blob_to_words(&[0u8; 31]).is_none());
        assert!(blob_to_words(&[]).is_none());
        assert!(blob_to_words(&[0u8; 32]).is_some());
        // Ida e volta preserva.
        let w = [1u64, 2, 3, 4];
        assert_eq!(blob_to_words(&words_to_blob(&w)), Some(w));
    }
}
