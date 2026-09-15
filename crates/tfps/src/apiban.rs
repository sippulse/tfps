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
#[derive(Debug, Default)]
pub struct Batch {
    pub ips: Vec<Ipv4Addr>,
    pub next_id: Option<String>,
}

/// What applying one batch actually did.
///
/// Four disjoint outcomes, and every address in the batch lands in exactly one.
/// `condemned` is a tally of writes the kernel accepted, not the batch size less
/// what we refused ourselves — counting the second and reporting it as the first
/// is what let the feed claim addresses it had never blocked.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// Addresses the kernel is now dropping.
    pub condemned: u64,
    /// Refused before the kernel: the operator's ignore list, and the rule that matched.
    pub ignored: Vec<(Ipv4Addr, String)>,
    /// Refused before the kernel: a registered peer that authenticated.
    pub known: Vec<Ipv4Addr>,
    /// Reached the kernel and was rejected, with the reason.
    pub failed: Vec<(Ipv4Addr, String)>,
}

/// Applies one feed batch, refusing locally first and writing what is left.
///
/// Every input is a closure so the whole decision is drivable from a test: the
/// real caller passes the ignore list, the engine's registered peers and the XDP
/// map, none of which a test can supply.
pub fn apply<E, K, B>(ips: &[Ipv4Addr], mut exempt: E, mut known_peer: K, mut block: B) -> Applied
where
    E: FnMut(Ipv4Addr) -> Option<String>,
    K: FnMut(Ipv4Addr) -> bool,
    B: FnMut(Ipv4Addr) -> Result<(), String>,
{
    let mut out = Applied::default();
    for &ip in ips {
        // A third-party feed listing your own range is exactly what the ignore
        // list is for: it is curated, but it is not yours.
        if let Some(rule) = exempt(ip) {
            out.ignored.push((ip, rule));
            continue;
        }
        if known_peer(ip) {
            // A registered customer's IP on the feed: it proved valid
            // credentials, so we do not knock it off.
            out.known.push(ip);
            continue;
        }
        // The kernel is the only party that can say the address is now blocked.
        // Its answer is the count.
        match block(ip) {
            Ok(()) => out.condemned += 1,
            Err(e) => out.failed.push((ip, e)),
        }
    }
    out
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
    //
    // A 4xx is returned, not raised: APIBAN answers "no new bans" with status 400, and
    // treating that as an error turned every quiet poll into a WARNING (one per five
    // minutes, two thousand a week on a real host). `received` decides what a status means.
    let agent = ureq::Agent::with_parts(
        ureq::config::Config::builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .build(),
        ureq::unversioned::transport::DefaultConnector::default(),
        MuslSafeResolver,
    );
    let mut response = agent.get(&url).call().map_err(|e| format!("{e}"))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("reading response: {e}"))?;
    received(status, &body)
}

/// What a reply means, decided from the status and the body together.
///
/// A 200 is a batch. A 4xx whose body is APIBAN's own "nothing new" reply is an empty
/// batch, because that is what it is — the feed is reachable, current, and quiet.
/// Anything else is reported with the status and the start of the body, so that the
/// next surprise from the API is diagnosable from the journal alone.
fn received(status: u16, body: &str) -> Result<Batch, String> {
    let nothing_new = body.contains("\"none\"") || body.contains("no new bans");
    match status {
        200..=299 => Ok(parse(body)),
        400..=499 if nothing_new => Ok(Batch::default()),
        _ => {
            let head: String = body.chars().take(80).collect();
            Err(format!("http status: {status}, body: {head:?}"))
        }
    }
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

    // THE DEFECT. APIBAN says "nothing new" with HTTP 400, and the client raised every
    // 4xx before the body was read, so the parser above -- which already understood the
    // reply -- never saw it. Every quiet poll became `WARNING: APIBAN unreachable`.
    #[test]
    fn nothing_new_with_a_400_status_is_an_empty_batch_not_an_outage() {
        let b = received(400, r#"{"ipaddress":["no new bans"],"ID":"none"}"#)
            .expect("a quiet feed is not an unreachable one");
        assert!(b.ips.is_empty());
        assert!(b.next_id.is_none(), "there is no ID to advance to");
    }

    // NEGATIVE CONTROLS. A 4xx that is not the quiet reply is still an error, and so is
    // anything 5xx even with a body that mentions bans -- and the message carries the
    // status and the body, so the journal says what the API actually said.
    #[test]
    fn other_failures_are_still_reported_with_what_the_api_said() {
        let e =
            received(403, r#"{"error":"invalid key"}"#).expect_err("a refused key is an outage");
        assert!(e.contains("403") && e.contains("invalid key"), "{e}");
        let e = received(500, "no new bans").expect_err("a server error is an outage");
        assert!(e.contains("500"), "{e}");
    }

    #[test]
    fn a_normal_batch_is_still_a_batch() {
        let b = received(200, r#"{"ipaddress":["195.96.139.178"],"ID":"1789480638"}"#).unwrap();
        assert_eq!(b.ips, vec![Ipv4Addr::new(195, 96, 139, 178)]);
        assert_eq!(b.next_id.as_deref(), Some("1789480638"));
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

#[cfg(test)]
mod apply_tests {
    use super::*;
    use std::cell::RefCell;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(45, 134, 144, last)
    }

    /// Records every address the kernel write was actually attempted on, so a
    /// test can assert what never reached it as well as what did.
    fn recorder() -> (RefCell<Vec<Ipv4Addr>>, ()) {
        (RefCell::new(Vec::new()), ())
    }

    // THE DEFECT. The kernel write's result was discarded, and the count was the
    // batch size less the addresses refused locally. So a map that is full, or
    // not writable, or not there, produced "N addresses condemned" having
    // blocked none of them -- while the perimeter's own block path, four hundred
    // lines away, alarms on exactly that failure. One rule, two behaviours, and
    // the silent one is on the path fed by a third party.
    #[test]
    fn a_refused_kernel_write_is_not_counted_as_condemned() {
        let batch = [ip(1), ip(2), ip(3)];
        let out = apply(
            &batch,
            |_| None,
            |_| false,
            |a| {
                if a == ip(2) {
                    Err("map is full".into())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(
            out.condemned, 2,
            "an address the kernel refused was never condemned"
        );
        assert_eq!(
            out.failed,
            vec![(ip(2), "map is full".to_string())],
            "and the refusal must be reportable, with its reason"
        );
    }

    // The whole feed refused is the case that matters most: the integration
    // looks healthy and protects nothing.
    #[test]
    fn a_feed_that_blocks_nothing_reports_nothing_condemned() {
        let batch = [ip(1), ip(2), ip(3)];
        let out = apply(&batch, |_| None, |_| false, |_| Err("no map".into()));
        assert_eq!(out.condemned, 0);
        assert_eq!(out.failed.len(), 3);
    }

    // NEGATIVE CONTROL. The happy path must be untouched: every address the
    // kernel accepted is still counted exactly once.
    #[test]
    fn every_accepted_address_is_still_counted_once() {
        let batch = [ip(1), ip(2), ip(3)];
        let out = apply(&batch, |_| None, |_| false, |_| Ok(()));
        assert_eq!(out.condemned, 3);
        assert!(out.failed.is_empty());
        assert!(out.ignored.is_empty());
        assert!(out.known.is_empty());
    }

    // NEGATIVE CONTROL. A local refusal is not a failure. Conflating the two
    // would turn every ignore-list hit into an alarm.
    #[test]
    fn a_local_refusal_is_not_a_kernel_failure() {
        let batch = [ip(1), ip(2)];
        let out = apply(
            &batch,
            |a| (a == ip(1)).then(|| "10.0.0.0/8".to_string()),
            |a| a == ip(2),
            |_| Ok(()),
        );
        assert_eq!(out.condemned, 0, "neither address reached the kernel");
        assert!(out.failed.is_empty(), "a refusal we made is not a failure");
        assert_eq!(out.ignored, vec![(ip(1), "10.0.0.0/8".to_string())]);
        assert_eq!(out.known, vec![ip(2)]);
    }

    // Precedence, and that a refused address touches nothing. The ignore list
    // outranks a learned registration, and neither reaches the map.
    #[test]
    fn a_refused_address_never_reaches_the_kernel() {
        let (seen, ()) = recorder();
        let batch = [ip(1), ip(2), ip(3)];
        let out = apply(
            &batch,
            |a| (a == ip(1)).then(|| "10.0.0.0/8".to_string()),
            |a| a == ip(1) || a == ip(2),
            |a| {
                seen.borrow_mut().push(a);
                Ok(())
            },
        );
        assert_eq!(
            *seen.borrow(),
            vec![ip(3)],
            "only the address nothing refused is written"
        );
        assert_eq!(
            out.ignored.len(),
            1,
            "the curated list outranks the learned registration"
        );
        assert!(out.known.iter().all(|a| *a != ip(1)));
        assert_eq!(out.condemned, 1);
    }

    // An empty batch says nothing at all -- there is no line to print, and the
    // caller must not be told a total that did not move.
    #[test]
    fn an_empty_batch_condemns_nothing() {
        let out = apply(&[], |_| None, |_| false, |_| Ok(()));
        assert_eq!(out, Applied::default());
        assert_eq!(out.condemned, 0);
    }

    // The counter and the report must agree. A count that is not the number of
    // accepted writes is the defect in another shape.
    #[test]
    fn the_count_always_equals_the_writes_the_kernel_accepted() {
        for failing in 0..=4usize {
            let batch: Vec<Ipv4Addr> = (1..=4).map(ip).collect();
            let out = apply(
                &batch,
                |_| None,
                |_| false,
                |a| {
                    if (a.octets()[3] as usize) <= failing {
                        Err("refused".into())
                    } else {
                        Ok(())
                    }
                },
            );
            assert_eq!(
                out.condemned as usize,
                4 - failing,
                "failing={failing}: condemned must equal the accepted writes"
            );
            assert_eq!(out.failed.len(), failing, "failing={failing}");
        }
    }
}
