//! Durable storage in SQLite.
//!
//! **One file. No server, no daemon, no credentials, no port.** That is genuine zero
//! configuration — the 2023 TFPS had a plaintext MySQL password in six places of its
//! generated `.cfg`.
//!
//! And the operator **can open it and see what the system learned**:
//!
//! ```sh
//! sqlite3 /var/lib/tfps/tfps.db "select * from block_log order by ts desc limit 20"
//! ```
//!
//! In a product that is silent by design, being able to audit the state is what separates
//! "I trust this" from "I have no idea whether it works".
//!
//! **This is durable storage, not the hot path** (`SPEC.md` §10). The working set lives in
//! memory; only the boot load and the periodic checkpoint happen here. Querying SQL per
//! INVITE would be a write bottleneck at the wholesale target.
//!
//! The split of state matters: **perimeter** state dies with the process and rebuilds in
//! minutes from traffic — consistent with fail-open by not pinning the eBPF program. The
//! **behavioural** state, 45 to 90 days of it, is what has to survive.

use std::net::Ipv4Addr;
use std::path::Path;

use rusqlite::{params, Connection};
use tfps_core::engine::{Engine, PairRecord, PeerCountryRecord};

pub const DEFAULT_PATH: &str = "/var/lib/tfps/tfps.db";

/// Schema version. An incompatible change recreates the tables rather than corrupting —
/// losing a baseline is recoverable in days; reading a bitmap with the wrong semantics is
/// not.
const SCHEMA: i64 = 1;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        }
        let conn =
            Connection::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;

        // WAL: concurrent reads while the checkpoint writes, and fewer fsyncs.
        // `synchronous=NORMAL` is WAL's usual companion — losing the last few seconds to a
        // power cut costs seconds of learning, not the database.
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
            // Incompatible schema: start over. See the note on `SCHEMA`.
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
                 -- Audit: every block records why, in human-readable form.
                 -- `SPEC.md` §12 requires the operator to be able to reconstruct it.
                 CREATE TABLE IF NOT EXISTS block_log (
                     ts     INTEGER NOT NULL,
                     ip     TEXT    NOT NULL,
                     reason TEXT    NOT NULL,
                     detail TEXT    NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS block_log_ts ON block_log (ts);",
            )
            .map_err(|e| format!("creating schema: {e}"))?;
        self.conn
            .pragma_update(None, "user_version", SCHEMA)
            .map_err(|e| format!("user_version: {e}"))
    }

    /// The instant learning began, written on the first run.
    ///
    /// **This is what makes learning mode mean anything.** Without persisting it, every
    /// restart would reset the 30 days and the countdown would promise something a
    /// `systemctl restart` erases.
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

    /// Deletes old audit rows. Without this the file grows forever — which is what
    /// produced the 477 MB `/var/log/opensips.log` that `fail2ban` scans line by line.
    pub fn prune_log(&self, older_than: u32) -> usize {
        self.conn
            .execute("DELETE FROM block_log WHERE ts < ?1", params![older_than])
            .unwrap_or(0)
    }

    /// Writes the learning state. Called at checkpoint time, never per packet.
    pub fn checkpoint(&mut self, engine: &Engine) -> Result<(usize, usize), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("transaction: {e}"))?;
        let mut pairs = 0usize;
        let mut countries = 0usize;
        {
            let mut ins = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO pair
                     (peer, a_number, cur, prev, period, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|e| format!("preparing pair: {e}"))?;
            for r in engine.export_pairs() {
                ins.execute(params![
                    r.peer.to_string(),
                    r.a_number,
                    words_to_blob(&r.cur),
                    words_to_blob(&r.prev),
                    r.period,
                    r.last_seen
                ])
                .map_err(|e| format!("writing pair: {e}"))?;
                pairs += 1;
            }
            let mut insc = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO peer_country (peer, country, calls)
                     VALUES (?1, ?2, ?3)",
                )
                .map_err(|e| format!("preparing peer_country: {e}"))?;
            for r in engine.export_peer_countries() {
                insc.execute(params![r.peer.to_string(), r.country, r.calls])
                    .map_err(|e| format!("writing country: {e}"))?;
                countries += 1;
            }
        }
        tx.commit().map_err(|e| format!("commit: {e}"))?;
        Ok((pairs, countries))
    }

    /// Loads the state at boot. An error here is **not fatal** — the system restarts
    /// learning, which is bad but recoverable; refusing to start would be worse.
    pub fn load_into(&self, engine: &mut Engine) -> Result<(usize, usize), String> {
        let mut pairs = 0usize;
        let mut st = self
            .conn
            .prepare("SELECT peer, a_number, cur, prev, period, last_seen FROM pair")
            .map_err(|e| format!("reading pair: {e}"))?;
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
            .map_err(|e| format!("iterating pair: {e}"))?;
        for row in rows.flatten() {
            let (peer, a_number, cur, prev, period, last_seen) = row;
            let (Ok(peer), Some(cur), Some(prev)) = (
                peer.parse::<Ipv4Addr>(),
                blob_to_words(&cur),
                blob_to_words(&prev),
            ) else {
                continue; // corrupt row: skip one, do not lose the whole database
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
            .map_err(|e| format!("reading peer_country: {e}"))?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u16>(1)?,
                    r.get::<_, u32>(2)?,
                ))
            })
            .map_err(|e| format!("iterating peer_country: {e}"))?;
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

/// The bitmap as 32 little-endian bytes. An explicit format so the file is readable by
/// other tools and does not depend on the byte order of the machine that wrote it.
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
    fn the_bitmap_survives_a_restart() {
        // The property that makes learning mode meaningful: without it a
        // `systemctl restart` would silently erase 30 days of baseline.
        let path = tmp();
        let _ = std::fs::remove_file(&path);
        let peer = Ipv4Addr::new(10, 0, 0, 5);
        let t = Timestamp(1_800_000_000);

        let mut e1 = Engine::new(DialPlan::new(["00"]), Mode::Active);
        e1.observe(peer, &invite("200", "00551199998888"), t);
        e1.observe(peer, &invite("200", "00351912345678"), t);

        let mut s = Store::open(&path).unwrap();
        let (p, c) = s.checkpoint(&e1).unwrap();
        assert_eq!(p, 1, "one pair");
        assert!(c >= 2, "two countries");

        // A fresh process, memory wiped.
        let mut e2 = Engine::new(DialPlan::new(["00"]), Mode::Active);
        let s2 = Store::open(&path).unwrap();
        s2.load_into(&mut e2).unwrap();

        // What was already known stays known — it does not become novel again.
        let dec = e2.observe(peer, &invite("200", "00551199998888"), t);
        assert_eq!(
            dec,
            tfps_core::engine::Decision::Pass {
                country: "BR",
                novel: false
            },
            "Brazil was already known before the restart"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_learning_start_does_not_reset_on_every_boot() {
        let path = tmp().with_extension("learn.db");
        let _ = std::fs::remove_file(&path);
        let s = Store::open(&path).unwrap();
        let first = s.learning_started(1000);
        assert_eq!(first, 1000);
        // A "restart" later, with the clock much further along.
        let s2 = Store::open(&path).unwrap();
        assert_eq!(
            s2.learning_started(9_999_999),
            1000,
            "restarting must not push the end of learning further out"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_audit_log_writes_and_prunes() {
        let path = tmp().with_extension("log.db");
        let _ = std::fs::remove_file(&path);
        let s = Store::open(&path).unwrap();
        s.log_block(100, Ipv4Addr::new(1, 2, 3, 4), "user-agent", "pplsip");
        s.log_block(200, Ipv4Addr::new(5, 6, 7, 8), "injection", "'");
        assert_eq!(s.prune_log(150), 1, "only the oldest one goes");
        let remaining: i64 = s
            .conn
            .query_row("SELECT count(*) FROM block_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_corrupt_blob_does_not_break_loading() {
        assert!(blob_to_words(&[0u8; 31]).is_none());
        assert!(blob_to_words(&[]).is_none());
        assert!(blob_to_words(&[0u8; 32]).is_some());
        // Round-trip preserves the value.
        let w = [1u64, 2, 3, 4];
        assert_eq!(blob_to_words(&words_to_blob(&w)), Some(w));
    }
}
