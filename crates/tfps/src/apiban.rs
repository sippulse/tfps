//! Optional [APIBAN](https://apiban.org) integration — a collaborative list of SIP
//! attacker IPs, fed by honeypots.
//!
//! **In the background, never on the packet path.** This is exactly where the 2023 TFPS
//! died: a **synchronous `rest_get()` per INVITE**, with no cache and 4 workers — a ceiling
//! of ~26 INVITEs/s, and any apiban.org outage froze the decision for every call. Here the
//! fetch runs on its own thread and delivers over a channel; if the network drops, the
//! system carries on with the list it already has.
//!
//! The product is **complete without this**. It is optional, and the only configuration
//! field that enables it is the key.

use std::net::Ipv4Addr;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// Interval between fetches. APIBAN is incremental by ID, so each fetch brings only what
/// appeared since the previous one.
const POLL_SECS: u64 = 300;

/// Ceiling of addresses per response, so an anomalous feed cannot fill the map at once.
const MAX_PER_FETCH: usize = 5_000;

/// A batch of addresses to condemn, plus the ID to resume from.
pub struct Batch {
    pub ips: Vec<Ipv4Addr>,
    pub next_id: Option<String>,
}

/// Starts periodic fetching on a thread. The caller drains the channel whenever it suits.
///
/// `start_id` comes from what was persisted: resuming from the last ID avoids re-downloading
/// the whole list on every restart.
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
                        return; // the main process is gone
                    }
                    if vazio {
                        std::thread::sleep(Duration::from_secs(POLL_SECS));
                    }
                    // On a full batch, fetch again immediately: the feed pages by ID.
                }
                Err(e) => {
                    // A network failure is not fatal and must not be silent.
                    eprintln!(
                        "WARNING: APIBAN unreachable ({e}); carrying on with the current list"
                    );
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
        .map_err(|e| format!("reading response: {e}"))?;
    Ok(parse(&body))
}

/// Extracts addresses and the next ID from an APIBAN response.
///
/// Hand-written rather than deserialised because the format is shallow and stable, and
/// because tolerating unknown fields without failing matters more here than strictness: a
/// change in the feed must not take the defence down.
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
    fn extracts_addresses_and_the_next_id() {
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
    fn a_response_with_nothing_new_does_not_break() {
        let b = parse(r#"{"ID":"none","ipaddress":["no new bans"]}"#);
        assert!(b.next_id.is_none(), "`none` is not an ID to resume from");
        assert!(b.ips.is_empty(), "text that is not an IP is discarded");
    }

    #[test]
    fn junk_in_the_feed_does_not_take_the_defence_down() {
        // A format change must not become a panic: the worst acceptable outcome is adding
        // nothing this round.
        for body in ["", "{}", "not json at all", r#"{"ipaddress":[123]}"#] {
            let b = parse(body);
            assert!(b.ips.is_empty());
        }
    }

    #[test]
    fn respects_the_per_batch_ceiling() {
        let many: Vec<String> = (0..MAX_PER_FETCH + 100)
            .map(|i| format!("\"10.{}.{}.1\"", i / 256, i % 256))
            .collect();
        let body = format!("{{\"ID\":\"5\",\"ipaddress\":[{}]}}", many.join(","));
        assert_eq!(parse(&body).ips.len(), MAX_PER_FETCH);
    }
}
