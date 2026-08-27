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
    // A dedicated agent whose DNS does not go through the C library. On a static musl
    // binary the system resolver cannot talk to the systemd-resolved stub (127.0.0.53) and
    // fails with EAI_AGAIN; and returning an IPv6 address on a host with no v6 route yields
    // EHOSTUNREACH. Our resolver skips the stub and returns only IPv4, sidestepping both.
    let agent = ureq::Agent::with_parts(
        ureq::config::Config::builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .build(),
        ureq::unversioned::transport::DefaultConnector::default(),
        MuslSafeResolver,
    );
    let body = agent
        .get(&url)
        .call()
        .map_err(|e| format!("{e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("reading response: {e}"))?;
    Ok(parse(&body))
}

/// A resolver that does its own DNS, independent of the C library's `getaddrinfo`.
#[derive(Debug)]
struct MuslSafeResolver;

impl ureq::unversioned::resolver::Resolver for MuslSafeResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        use std::net::{IpAddr, SocketAddr};
        let authority = uri.authority().ok_or(ureq::Error::HostNotFound)?;
        let host = authority.host();
        let port = authority.port_u16().unwrap_or_else(|| {
            if uri.scheme_str() == Some("http") {
                80
            } else {
                443
            }
        });

        let mut out = self.empty();
        // If it is already an IP, use it as-is.
        if let Ok(ip) = host.parse::<IpAddr>() {
            out.push(SocketAddr::new(ip, port));
            return Ok(out);
        }
        // A fixed lookup budget; ureq's own global timeout still bounds the whole call.
        let _ = timeout;
        match dns::resolve_a(host, Duration::from_secs(5)) {
            Some(ip) => {
                out.push(SocketAddr::new(IpAddr::V4(ip), port));
                Ok(out)
            }
            None => Err(ureq::Error::HostNotFound),
        }
    }
}

/// A minimal DNS A-record client, so resolution never touches `getaddrinfo`.
mod dns {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::Duration;

    /// Real nameservers, skipping the systemd-resolved stub the C library cannot use, with
    /// public fallbacks so a broken `resolv.conf` still resolves.
    fn nameservers() -> Vec<IpAddr> {
        let stub = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53));
        let mut out: Vec<IpAddr> = Vec::new();
        // The uplink file lists the real servers; the stub file lists 127.0.0.53.
        for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
            if let Ok(txt) = std::fs::read_to_string(path) {
                for line in txt.lines() {
                    if let Some(rest) = line.trim().strip_prefix("nameserver ") {
                        if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                            if ip != stub && !out.contains(&ip) {
                                out.push(ip);
                            }
                        }
                    }
                }
            }
            if !out.is_empty() {
                break;
            }
        }
        for ip in [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)] {
            let ip = IpAddr::V4(ip);
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        out
    }

    /// Looks up the first IPv4 for `host`, trying each nameserver until one answers.
    pub fn resolve_a(host: &str, timeout: Duration) -> Option<Ipv4Addr> {
        let mut q: Vec<u8> = Vec::with_capacity(64);
        q.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        for label in host.split('.').filter(|l| !l.is_empty()) {
            if label.len() > 63 {
                return None;
            }
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // end, type A, class IN

        for ns in nameservers() {
            let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
                continue;
            };
            let _ = sock.set_read_timeout(Some(timeout));
            if sock.send_to(&q, SocketAddr::new(ns, 53)).is_err() {
                continue;
            }
            let mut buf = [0u8; 512];
            let Ok(n) = sock.recv(&mut buf) else {
                continue;
            };
            if let Some(ip) = first_a(&buf[..n]) {
                return Some(ip);
            }
        }
        None
    }

    fn first_a(msg: &[u8]) -> Option<Ipv4Addr> {
        if msg.len() < 12 {
            return None;
        }
        let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
        let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
        let mut i = 12;
        for _ in 0..qd {
            i = skip_name(msg, i)?;
            i += 4;
        }
        for _ in 0..an {
            i = skip_name(msg, i)?;
            if i + 10 > msg.len() {
                return None;
            }
            let rtype = u16::from_be_bytes([msg[i], msg[i + 1]]);
            let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
            i += 10;
            if rtype == 1 && rdlen == 4 && i + 4 <= msg.len() {
                return Some(Ipv4Addr::new(msg[i], msg[i + 1], msg[i + 2], msg[i + 3]));
            }
            i += rdlen;
        }
        None
    }

    /// Steps past a DNS name (labels or a compression pointer).
    fn skip_name(msg: &[u8], mut i: usize) -> Option<usize> {
        loop {
            let len = *msg.get(i)?;
            if len & 0xc0 == 0xc0 {
                return Some(i + 2);
            }
            if len == 0 {
                return Some(i + 1);
            }
            i += 1 + len as usize;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_an_a_record_from_a_real_looking_response() {
            // A minimal response: 1 question, 1 answer A = 1.2.3.4.
            let msg = [
                0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, // header
                1, b'x', 0, 0, 1, 0, 1, // question x. A IN
                0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4, // answer
            ];
            assert_eq!(first_a(&msg), Some(Ipv4Addr::new(1, 2, 3, 4)));
        }

        #[test]
        fn a_truncated_message_does_not_panic() {
            for cut in 0..40 {
                let _ = first_a(&[0u8; 40][..cut]);
            }
        }

        #[test]
        fn nameservers_never_include_the_stub_and_always_offer_a_fallback() {
            let ns = nameservers();
            assert!(!ns.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))));
            assert!(!ns.is_empty());
        }
    }
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
