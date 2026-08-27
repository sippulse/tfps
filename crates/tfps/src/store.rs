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
use tfps_core::country;
use tfps_core::engine::{Engine, PeerAnomalyRecord};

pub const DEFAULT_PATH: &str = "/var/lib/tfps/tfps.db";

/// Schema version. An incompatible change recreates the tables rather than corrupting —
/// losing a baseline is recoverable in days; reading a bitmap with the wrong semantics is
/// not.
const SCHEMA: i64 = 1;

/// A source's learned state, as stored — for the control tool.
pub struct SourceRow {
    pub peer: String,
    pub seen: Vec<u8>,
    pub n_countries: u32,
    pub rate_a: f64,
    pub last_seen: u32,
}

impl SourceRow {
    /// The countries this source has been seen to call, as labels.
    pub fn countries(&self) -> Vec<&'static str> {
        match blob_to_words(&self.seen) {
            Some(bits) => country::decode_bitmap(bits, [0; 4]),
            None => Vec::new(),
        }
    }
}

/// One audit row.
pub struct BlockRow {
    pub ts: u32,
    pub ip: String,
    pub reason: String,
    pub detail: String,
}

/// How an operator narrows a source search.
pub struct SourceFilter<'a> {
    pub peer: Option<&'a str>,
    /// Only sources that have called this country (ISO label, case-insensitive).
    pub country: Option<&'a str>,
    pub limit: usize,
}

impl Default for SourceFilter<'_> {
    fn default() -> Self {
        Self {
            peer: None,
            country: None,
            limit: 50,
        }
    }
}

impl SourceFilter<'_> {
    fn matches(&self, r: &SourceRow) -> bool {
        if self.peer.is_some_and(|p| r.peer != p) {
            return false;
        }
        if let Some(c) = self.country {
            if !r.countries().iter().any(|x| x.eq_ignore_ascii_case(c)) {
                return false;
            }
        }
        true
    }
}

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
            for t in [
                "peer_anomaly",
                "known_peer",
                "pair",
                "peer_country",
                "meta",
                "block_log",
            ] {
                let _ = self.conn.execute(&format!("DROP TABLE IF EXISTS {t}"), []);
            }
        }
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS meta (
                     k TEXT PRIMARY KEY,
                     v TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS peer_anomaly (
                     peer        TEXT    PRIMARY KEY,
                     seen        BLOB    NOT NULL,   -- 32 bytes: the 256-bit country set
                     n_countries INTEGER NOT NULL,
                     rate_a      REAL    NOT NULL,
                     rate_b      REAL    NOT NULL,
                     last_seen   INTEGER NOT NULL DEFAULT 0
                 );
                 -- Audit: every block records why, in human-readable form.
                 -- `SPEC.md` §12 requires the operator to be able to reconstruct it.
                 CREATE TABLE IF NOT EXISTS block_log (
                     ts     INTEGER NOT NULL,
                     ip     TEXT    NOT NULL,
                     reason TEXT    NOT NULL,
                     detail TEXT    NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS block_log_ts ON block_log (ts);
                 -- The APIBAN feed, kept because it cannot rebuild itself from traffic.
                 -- Perimeter state normally dies with the process and is relearned in
                 -- minutes (`SPEC.md` 10); this is the exception, since the feed is
                 -- consumed through a forward-only cursor. Losing it would mean the
                 -- integration silently protects nothing after a restart.
                 -- Registered peers that authenticated — known-good, never banned even by
                 -- the APIBAN feed re-applied at boot. This is what protects a customer on a
                 -- dynamic IP; it must persist so a restart does not knock them off.
                 CREATE TABLE IF NOT EXISTS known_peer (
                     ip        TEXT    PRIMARY KEY,
                     last_auth INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS apiban_ip (
                     ip TEXT PRIMARY KEY,
                     ts INTEGER NOT NULL
                 );",
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

    /// Records addresses from the feed, so they can be re-applied after a restart.
    pub fn apiban_add(&mut self, ips: &[Ipv4Addr], ts: u32) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("transaction: {e}"))?;
        {
            let mut ins = tx
                .prepare_cached("INSERT OR REPLACE INTO apiban_ip (ip, ts) VALUES (?1, ?2)")
                .map_err(|e| format!("preparing apiban_ip: {e}"))?;
            for ip in ips {
                ins.execute(params![ip.to_string(), ts])
                    .map_err(|e| format!("writing apiban_ip: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("commit: {e}"))
    }

    /// The feed addresses still worth applying. `since` bounds how stale an entry may be —
    /// APIBAN is a rolling list of hotspots, not a permanent verdict on an address.
    pub fn apiban_since(&self, since: u32) -> Result<Vec<Ipv4Addr>, String> {
        let mut st = self
            .conn
            .prepare("SELECT ip FROM apiban_ip WHERE ts >= ?1")
            .map_err(|e| format!("reading apiban_ip: {e}"))?;
        let rows = st
            .query_map(params![since], |r| r.get::<_, String>(0))
            .map_err(|e| format!("iterating apiban_ip: {e}"))?;
        Ok(rows.flatten().filter_map(|s| s.parse().ok()).collect())
    }

    /// Persists the known-good registered peers.
    pub fn save_known_peers(
        &mut self,
        peers: impl Iterator<Item = (std::net::Ipv4Addr, u32)>,
    ) -> Result<(), String> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("transaction: {e}"))?;
        {
            let mut ins = tx
                .prepare_cached("INSERT OR REPLACE INTO known_peer (ip, last_auth) VALUES (?1, ?2)")
                .map_err(|e| format!("preparing known_peer: {e}"))?;
            for (ip, ts) in peers {
                ins.execute(params![ip.to_string(), ts])
                    .map_err(|e| format!("writing known_peer: {e}"))?;
            }
        }
        tx.commit().map_err(|e| format!("commit: {e}"))
    }

    /// Loads the known-good peers newer than `since`, as (ip, last_auth).
    pub fn known_peers_since(&self, since: u32) -> Result<Vec<(std::net::Ipv4Addr, u32)>, String> {
        let mut st = self
            .conn
            .prepare("SELECT ip, last_auth FROM known_peer WHERE last_auth >= ?1")
            .map_err(|e| format!("reading known_peer: {e}"))?;
        let rows = st
            .query_map(params![since], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?))
            })
            .map_err(|e| format!("iterating known_peer: {e}"))?;
        Ok(rows
            .flatten()
            .filter_map(|(ip, ts)| ip.parse().ok().map(|ip| (ip, ts)))
            .collect())
    }

    /// Drops known peers that have not authenticated within the retention window.
    pub fn known_peers_prune(&self, older_than: u32) -> usize {
        self.conn
            .execute(
                "DELETE FROM known_peer WHERE last_auth < ?1",
                params![older_than],
            )
            .unwrap_or(0)
    }

    /// Every address currently on the APIBAN feed, for attributing a block to it.
    pub fn apiban_all(&self) -> Result<std::collections::HashSet<String>, String> {
        let mut st = self
            .conn
            .prepare("SELECT ip FROM apiban_ip")
            .map_err(|e| format!("reading apiban_ip: {e}"))?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| format!("iterating apiban_ip: {e}"))?;
        Ok(rows.flatten().collect())
    }

    /// Drops feed entries older than the retention window.
    pub fn apiban_prune(&self, older_than: u32) -> usize {
        self.conn
            .execute("DELETE FROM apiban_ip WHERE ts < ?1", params![older_than])
            .unwrap_or(0)
    }

    /// Reads a small named value. Used for anything that has to survive a restart but is
    /// not learning state — the APIBAN resume point, for instance.
    pub fn meta_get(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT v FROM meta WHERE k = ?1", params![key], |r| {
                r.get(0)
            })
            .ok()
    }

    /// Writes one. Failure is not fatal: the worst case is refetching a feed from the
    /// start, which costs bandwidth, not correctness.
    pub fn meta_set(&self, key: &str, value: &str) {
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO meta (k, v) VALUES (?1, ?2)",
            params![key, value],
        );
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

    /// Opens the database **read-only**, for the control tool.
    ///
    /// Read-only on purpose: `tfps_ctl` inspecting state must not be able to corrupt what
    /// the daemon is writing, and WAL lets it read while a checkpoint is in flight.
    pub fn open_readonly(path: &Path) -> Result<Self, String> {
        use rusqlite::OpenFlags;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| format!("opening {} read-only: {e}", path.display()))?;
        Ok(Self { conn })
    }

    /// Learned pairs, filtered the way an operator searches: by peer, by A-number
    /// substring, or by a country the pair has called.
    pub fn find_sources(&self, f: &SourceFilter<'_>) -> Result<Vec<SourceRow>, String> {
        let mut st = self
            .conn
            .prepare(
                "SELECT peer, seen, n_countries, rate_a, last_seen FROM peer_anomaly
                 ORDER BY last_seen DESC",
            )
            .map_err(|e| format!("reading peer_anomaly: {e}"))?;
        let rows = st
            .query_map([], |r| {
                Ok(SourceRow {
                    peer: r.get(0)?,
                    seen: r.get::<_, Vec<u8>>(1)?,
                    n_countries: r.get(2)?,
                    rate_a: r.get(3)?,
                    last_seen: r.get(4)?,
                })
            })
            .map_err(|e| format!("iterating peer_anomaly: {e}"))?;
        Ok(rows
            .flatten()
            .filter(|r| f.matches(r))
            .take(f.limit)
            .collect())
    }

    /// Sources by distinct-country breadth, and when last heard from.
    pub fn peers(&self) -> Result<Vec<(String, u32, u32)>, String> {
        let mut st = self
            .conn
            .prepare(
                "SELECT peer, n_countries, last_seen FROM peer_anomaly
                 ORDER BY n_countries DESC",
            )
            .map_err(|e| format!("reading peers: {e}"))?;
        let rows = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| format!("iterating peers: {e}"))?;
        Ok(rows.flatten().collect())
    }

    /// The countries a source has been seen to call. The new model tracks membership, not
    /// per-country counts, so this lists the set rather than frequencies.
    pub fn peer_countries(&self, peer: &str) -> Result<Vec<&'static str>, String> {
        let row = self
            .conn
            .query_row(
                "SELECT seen FROM peer_anomaly WHERE peer = ?1",
                params![peer],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map_err(|e| format!("reading peer_anomaly: {e}"))?;
        Ok(match blob_to_words(&row) {
            Some(bits) => country::decode_bitmap(bits, [0; 4]),
            None => Vec::new(),
        })
    }

    /// The block audit log, newest first.
    pub fn blocks(&self, limit: usize, ip: Option<&str>) -> Result<Vec<BlockRow>, String> {
        let (sql, args): (&str, Vec<String>) = match ip {
            Some(v) => (
                "SELECT ts, ip, reason, detail FROM block_log WHERE ip = ?1
                 ORDER BY ts DESC LIMIT ?2",
                vec![v.to_string(), limit.to_string()],
            ),
            None => (
                "SELECT ts, ip, reason, detail FROM block_log ORDER BY ts DESC LIMIT ?1",
                vec![limit.to_string()],
            ),
        };
        let mut st = self
            .conn
            .prepare(sql)
            .map_err(|e| format!("reading block_log: {e}"))?;
        let rows = st
            .query_map(rusqlite::params_from_iter(args), |r| {
                Ok(BlockRow {
                    ts: r.get(0)?,
                    ip: r.get(1)?,
                    reason: r.get(2)?,
                    detail: r.get(3)?,
                })
            })
            .map_err(|e| format!("iterating block_log: {e}"))?;
        Ok(rows.flatten().collect())
    }

    /// How many blocks happened since `ts`, grouped by reason. The shape of what the
    /// perimeter is actually catching, which one line of the periodic report cannot show.
    pub fn blocks_by_reason(&self, since: u32) -> Result<Vec<(String, u32)>, String> {
        let mut st = self
            .conn
            .prepare(
                "SELECT reason, COUNT(*) FROM block_log WHERE ts >= ?1
                 GROUP BY reason ORDER BY COUNT(*) DESC",
            )
            .map_err(|e| format!("reading block_log: {e}"))?;
        let rows = st
            .query_map(params![since], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| format!("iterating block_log: {e}"))?;
        Ok(rows.flatten().collect())
    }

    /// Breadth of the baseline: the widest single-source country count, and the total
    /// across sources. (The per-country call frequencies of the old model are gone.)
    pub fn country_spread(&self) -> Result<(u32, u32), String> {
        self.conn
            .query_row(
                "SELECT COALESCE(MAX(n_countries), 0), COALESCE(SUM(n_countries), 0) \
                 FROM peer_anomaly",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| format!("reading peer_anomaly: {e}"))
    }

    /// Totals for the status line: pairs, peers, and the newest thing the file knows about
    /// — which is how stale the snapshot is.
    pub fn totals(&self) -> Result<(u32, u32, u32), String> {
        self.conn
            .query_row(
                "SELECT COUNT(*), COUNT(*), COALESCE(MAX(last_seen), 0) FROM peer_anomaly",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| format!("reading totals: {e}"))
    }

    /// Forgets learned state for a peer, or for one pair of it.
    ///
    /// **Only meaningful with the daemon stopped.** A running process holds the working set
    /// in memory and would write it straight back at the next checkpoint, so the caller has
    /// to establish that before offering this.
    pub fn forget(&self, peer: &str, _a_number: Option<&str>) -> Result<usize, String> {
        self.conn
            .execute("DELETE FROM peer_anomaly WHERE peer = ?1", params![peer])
            .map_err(|e| format!("deleting: {e}"))
    }

    /// Writes the learning state. Called at checkpoint time, never per packet.
    pub fn checkpoint(&mut self, engine: &Engine) -> Result<(usize, usize), String> {
        let now = self.now_stamp();
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("transaction: {e}"))?;
        let mut sources = 0usize;
        {
            let mut ins = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO peer_anomaly
                     (peer, seen, n_countries, rate_a, rate_b, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|e| format!("preparing peer_anomaly: {e}"))?;
            for r in engine.export_anomaly() {
                ins.execute(params![
                    r.peer.to_string(),
                    words_to_blob(&r.seen_countries),
                    r.n_countries,
                    r.rate_a,
                    r.rate_b,
                    now
                ])
                .map_err(|e| format!("writing peer_anomaly: {e}"))?;
                sources += 1;
            }
        }
        tx.commit().map_err(|e| format!("commit: {e}"))?;
        Ok((sources, 0))
    }

    /// A wall-clock stamp for `last_seen`. The core is clockless, so reading the clock here
    /// at checkpoint time (never on the packet path) is harmless.
    fn now_stamp(&self) -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }

    /// Loads the state at boot. An error here is **not fatal** — the system restarts
    /// learning, which is bad but recoverable; refusing to start would be worse.
    pub fn load_into(&self, engine: &mut Engine) -> Result<(usize, usize), String> {
        let mut sources = 0usize;
        let mut st = self
            .conn
            .prepare("SELECT peer, seen, n_countries, rate_a, rate_b FROM peer_anomaly")
            .map_err(|e| format!("reading peer_anomaly: {e}"))?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, u32>(2)?,
                    r.get::<_, f64>(3)?,
                    r.get::<_, f64>(4)?,
                ))
            })
            .map_err(|e| format!("iterating peer_anomaly: {e}"))?;
        for row in rows.flatten() {
            let (peer, seen, n_countries, rate_a, rate_b) = row;
            let (Ok(peer), Some(seen_countries)) = (peer.parse::<Ipv4Addr>(), blob_to_words(&seen))
            else {
                continue; // corrupt row: skip one, do not lose the whole database
            };
            engine.import_anomaly(PeerAnomalyRecord {
                peer,
                seen_countries,
                n_countries,
                rate_a,
                rate_b,
            });
            sources += 1;
        }
        Ok((sources, 0))
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
    fn the_apiban_list_survives_a_restart_and_ages_out() {
        // The feed is consumed through a forward-only cursor, so what it already gave us
        // cannot be fetched again. Losing it on restart would leave the integration
        // looking healthy while protecting nothing.
        let dir = std::env::temp_dir().join(format!("tfps-apiban-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("t.db");
        let day = 86_400u32;
        let now = 100 * day;
        {
            let mut s = Store::open(&path).unwrap();
            s.apiban_add(&[Ipv4Addr::new(45, 134, 144, 130)], now - 2 * day)
                .unwrap();
            s.apiban_add(&[Ipv4Addr::new(185, 243, 5, 75)], now - 30 * day)
                .unwrap();
        }
        let s = Store::open(&path).unwrap();
        let fresh = s.apiban_since(now - 7 * day).unwrap();
        assert_eq!(
            fresh,
            vec![Ipv4Addr::new(45, 134, 144, 130)],
            "stale entries stay out"
        );
        assert_eq!(
            s.apiban_since(0).unwrap().len(),
            2,
            "but they are still on file"
        );
        assert_eq!(s.apiban_prune(now - 7 * day), 1);
        assert_eq!(
            s.apiban_since(0).unwrap().len(),
            1,
            "pruning removed the old one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn meta_survives_a_reopen() {
        // The APIBAN resume point lives here. Losing it means refetching the whole feed on
        // every restart, which is what this replaced.
        let dir = std::env::temp_dir().join(format!("tfps-meta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("t.db");
        {
            let s = Store::open(&path).unwrap();
            assert_eq!(s.meta_get("apiban_id"), None, "absent before it is written");
            s.meta_set("apiban_id", "1698425647");
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.meta_get("apiban_id").as_deref(), Some("1698425647"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_learned_state_survives_a_restart() {
        // The property that makes learning mode meaningful: without it a
        // `systemctl restart` would silently erase 30 days of baseline.
        let path = tmp();
        let _ = std::fs::remove_file(&path);
        let peer = Ipv4Addr::new(10, 0, 0, 5);
        let t = Timestamp(1_800_000_000);

        let mut e1 = Engine::new(DialPlan::new(["00"]), Mode::Active).with_behavioural();
        e1.observe(peer, &invite("200", "00551199998888"), t);
        e1.observe(peer, &invite("200", "00351912345678"), t);

        let mut s = Store::open(&path).unwrap();
        let (sources, _) = s.checkpoint(&e1).unwrap();
        assert_eq!(sources, 1, "one source persisted");

        // A fresh process, memory wiped.
        let mut e2 = Engine::new(DialPlan::new(["00"]), Mode::Active).with_behavioural();
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
