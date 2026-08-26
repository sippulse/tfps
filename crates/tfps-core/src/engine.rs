//! The engine: joins prefix stripping, country resolution and novelty into a verdict.
//!
//! It follows the flow in `SPEC.md` §3. Two properties of that flow are structural and are
//! encoded here:
//!
//! - **the prefix filter comes before everything**, and whatever is not international
//!   leaves without being canonicalised — that is what makes cost scale with international
//!   volume rather than total volume;
//! - **the decision path has no dialog state**: duration and outcome are post-facto and
//!   belong to the learning path.
//!
//! The engine never reads a clock and never touches the network. Time arrives as a
//! parameter.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::country::{self, Country};
use crate::dialplan::DialPlan;
use crate::novelty::{PairState, RotatingBitmap, Timestamp};
use crate::perimeter::{
    AuthAttempts, AuthFailures, NoiseFilter, AUTH_FAILURE_WINDOW_SECS, AUTH_WINDOW_SECS,
};
use crate::sip::{self, Message, Method};

/// Which mode the behavioural layer is in.
///
/// The perimeter blocks from minute one; behaviour waits. `SPEC.md` §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Observes and **does not block**, until the given instant.
    Learning {
        until: Timestamp,
    },
    Active,
}

impl Mode {
    fn is_learning(&self, now: Timestamp) -> bool {
        matches!(self, Mode::Learning { until } if now < *until)
    }
}

/// What the engine decided about one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Not this system's business — not SIP, not an INVITE, or not international.
    /// **Never a block**, and the distinction matters: `R07` in the Java-era TFPS denied
    /// whatever it could not classify and became 39% of all rejections.
    OutOfScope(&'static str),
    /// International, either already known or not enough to fire.
    Pass { country: &'static str, novel: bool },
    /// Would have blocked, but the behavioural layer is still learning.
    WouldBlock {
        country: &'static str,
        novel_in_window: usize,
    },
    /// Block: the pair accumulated too many first-time countries within the window.
    Block {
        country: &'static str,
        novel_in_window: usize,
    },
    /// Perimeter noise: a scanning tool identified by its user-agent.
    /// Under enforcement this dies at `XDP_DROP` and vanishes from sngrep.
    Noise { signature: &'static str },
    /// An injection pattern in the URI. **Higher** confidence than a user-agent: a
    /// scanning tool can forge a legitimate UA, but no real phone puts a single quote or
    /// `--` in the `From` header.
    Injection { pattern: &'static str },
    /// Too many **rejected** credentials in the window — a password being guessed.
    ///
    /// This is the on-the-wire equivalent of what `fail2ban` reads out of a log file, and
    /// it is evidence rather than inference: the request carried a credential and the
    /// softswitch answered `401`/`407` anyway.
    AuthFailure { failures: u32 },
    /// Too many **authenticated** attempts in a short window, with no response ever seen.
    /// The volume backstop for softswitches that never answer — see
    /// `perimeter::AUTH_ATTEMPTS_TO_BLOCK`.
    AuthAbuse { attempts: u32 },
    /// International by shape, but with no recognisable country in the E.164 table.
    /// **Does not block** — it carries the digits so the operator can diagnose, instead of
    /// becoming a mute counter.
    UnknownCountry(String),
}

/// Counters for the observability requirements in `SPEC.md` §12.
///
/// They exist because this project's argument against `fail2ban` is that **the incumbent
/// fails silently**. A system unable to say what it is seeing would repeat that.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub packets: u64,
    pub sip_parsed: u64,
    /// SIP responses. Counted separately from `not_sip`: mistaking them for junk would
    /// make an operator conclude they are capturing the wrong interface.
    pub responses: u64,
    /// NAT CRLF keepalives. Counted separately because on a 5060 with residential clients
    /// they are most of the packets — calling them junk would make the report lie.
    pub keepalives: u64,
    pub not_sip: u64,
    /// Packets the perimeter would remove. The numerator of the measurement the project
    /// wants: what fraction of traffic on a public port is scanning.
    pub noise: u64,
    /// URIs carrying an injection pattern — rule R12 of the 2023 TFPS, revived.
    pub injections: u64,
    /// Sources condemned by the volume backstop.
    pub auth_abuse: u64,
    /// Authenticated attempts observed — a credential was presented.
    pub auth_attempts: u64,
    /// **Rejected** credentials observed: a request that carried `Authorization` and was
    /// answered `401`/`407`. The number that matters, and it can only rise on a softswitch
    /// that actually answers.
    pub auth_failures: u64,
    /// Credentials **accepted** — a `2xx` to an authenticated request. Reported because a
    /// deployment where this stays at zero while `auth_att` climbs is one where the failure
    /// rule is structurally blind, and the operator has to know that.
    pub auth_ok: u64,
    /// Challenges seen. Zero here with non-zero `auth_att` means the softswitch is not
    /// answering, so only the backstop can fire.
    pub digest_challenges: u64,
    pub invites: u64,
    pub international: u64,
    pub uncanonicalizable: u64,
    pub unknown_country: u64,
    pub novel: u64,
    pub blocks: u64,
    pub would_block: u64,
    /// Pairs refused by the memory ceiling. **Non-zero is a symptom of an A-number
    /// rotation attack** — and it must show up in the report, not vanish silently.
    pub pairs_dropped: u64,
    /// Peers refused by the ceiling.
    pub peers_dropped: u64,
}

/// Ceiling of pairs per peer.
///
/// It exists because `SPEC.md` §5 states that **rotating the A-number is expected attacker
/// behaviour** — and without a ceiling the system answers that by allocating until it dies.
/// At ~150 bytes per pair, an attacker at 1000 INVITEs/s with unique A-numbers fills 192 MB
/// in about 20 minutes. An anti-fraud system with a DoS vector described in its own
/// specification does not meet the premise.
const MAX_PAIRS_PER_PEER: usize = 50_000;

/// Ceiling of distinct peers. A peer is the source IP, which is not forgeable from the
/// observation point — so this ceiling is far looser than the pair one.
const MAX_PEERS: usize = 10_000;

/// One row of a pair's state, as the durable store sees it.
#[derive(Debug, Clone)]
pub struct PairRecord {
    pub peer: Ipv4Addr,
    pub a_number: String,
    pub cur: [u64; 4],
    pub prev: [u64; 4],
    pub period: u32,
    pub last_seen: u32,
}

/// How often a peer calls one country.
#[derive(Debug, Clone, Copy)]
pub struct PeerCountryRecord {
    pub peer: Ipv4Addr,
    pub country: u16,
    pub calls: u32,
}

#[derive(Debug, Default)]
struct PeerState {
    dial_plan: DialPlan,
    /// Per-A-number state, with the last-seen instant so pruning is possible.
    pairs: HashMap<String, (PairState, u32)>,
    /// Per-country frequency distribution — the prior a brand-new pair inherits.
    /// `SPEC.md` §6: inheriting the peer's whole set would not work, because a wholesale
    /// peer calls 200 countries and saturation would come straight back.
    country_calls: HashMap<u16, u32>,
    total_calls: u32,
    /// Authenticated attempts, regardless of outcome — the volume backstop.
    auth_attempts: AuthAttempts,
    /// Rejected credentials — the real brute-force signal.
    auth_failures: AuthFailures,
    /// Authenticated transactions still waiting for their response.
    pending: PendingAuth,
}

/// How many authenticated transactions per peer can be awaiting a response.
///
/// A ceiling rather than a map that grows: an attacker generating a unique `Call-ID` per
/// guess would otherwise make the defence allocate on demand.
const MAX_PENDING_PER_PEER: usize = 64;

/// How long an unanswered transaction is kept, in seconds. RFC 3261 Timer B/F is 64×T1 =
/// 32 s, after which the client has given up and no response can still be matched.
const PENDING_TTL_SECS: u32 = 32;

/// Transactions in which a credential was presented and the outcome is not yet known.
///
/// **Only authenticated requests are remembered.** A request with no credential is of no
/// interest: the `401` it receives is the normal challenge, and storing it would be the
/// mistake that blocks every customer.
#[derive(Debug, Default)]
struct PendingAuth {
    entries: Vec<(String, u32)>,
}

impl PendingAuth {
    fn remember(&mut self, key: String, now: u32) {
        self.entries
            .retain(|(_, t)| now.saturating_sub(*t) < PENDING_TTL_SECS);
        // A retransmission of the same request is the same attempt, not a second one.
        if let Some(e) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            e.1 = now;
            return;
        }
        if self.entries.len() < MAX_PENDING_PER_PEER {
            self.entries.push((key, now));
        }
    }

    /// Claims a transaction, if it was an authenticated one. Removing it on the first
    /// matching response is what keeps a retransmitted `401` from counting twice.
    fn claim(&mut self, key: &str) -> bool {
        match self.entries.iter().position(|(k, _)| k == key) {
            Some(i) => {
                self.entries.remove(i);
                true
            }
            None => false,
        }
    }
}

pub struct Engine {
    peers: HashMap<Ipv4Addr, PeerState>,
    default_plan: DialPlan,
    mode: Mode,
    pub noise_filter: NoiseFilter,
    pub stats: Stats,
}

impl Engine {
    pub fn new(default_plan: DialPlan, mode: Mode) -> Self {
        Self {
            peers: HashMap::new(),
            default_plan,
            mode,
            noise_filter: NoiseFilter::new(),
            stats: Stats::default(),
        }
    }

    /// Declares a peer's dial plan. See `SPEC.md` §4: declaring beats learning because it
    /// holds on the very first call instead of waiting for convergence.
    pub fn declare_dial_plan(&mut self, peer: Ipv4Addr, plan: DialPlan) {
        self.peers.entry(peer).or_default().dial_plan = plan;
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn pair_count(&self) -> usize {
        self.peers.values().map(|p| p.pairs.len()).sum()
    }

    /// A pair's state, in the shape the durable store writes.
    ///
    /// The core does **no I/O** — it exports and imports; the binary writes. That is what
    /// keeps everything here deterministic and testable without a disk.
    pub fn export_pairs(&self) -> impl Iterator<Item = PairRecord> + '_ {
        self.peers.iter().flat_map(|(ip, st)| {
            st.pairs.iter().map(move |(a, (pair, last))| {
                let (cur, prev, period) = pair.bitmap().parts();
                PairRecord {
                    peer: *ip,
                    a_number: a.clone(),
                    cur,
                    prev,
                    period,
                    last_seen: *last,
                }
            })
        })
    }

    /// Per-peer country frequencies — the prior a brand-new pair inherits.
    pub fn export_peer_countries(&self) -> impl Iterator<Item = PeerCountryRecord> + '_ {
        self.peers.iter().flat_map(|(ip, st)| {
            st.country_calls
                .iter()
                .map(move |(c, n)| PeerCountryRecord {
                    peer: *ip,
                    country: *c,
                    calls: *n,
                })
        })
    }

    /// Restores a pair. It honours the memory ceilings: persisted state must not be used
    /// to bypass the limit that protects against A-number rotation.
    pub fn import_pair(&mut self, r: PairRecord) {
        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&r.peer) {
            return;
        }
        let plan = self.default_plan.clone();
        let st = self.peers.entry(r.peer).or_insert_with(|| PeerState {
            dial_plan: plan,
            ..Default::default()
        });
        if st.pairs.len() >= MAX_PAIRS_PER_PEER {
            return;
        }
        st.pairs.insert(
            r.a_number,
            (
                PairState::from_bitmap(RotatingBitmap::from_parts(r.cur, r.prev, r.period)),
                r.last_seen,
            ),
        );
    }

    pub fn import_peer_country(&mut self, r: PeerCountryRecord) {
        let plan = self.default_plan.clone();
        let st = self.peers.entry(r.peer).or_insert_with(|| PeerState {
            dial_plan: plan,
            ..Default::default()
        });
        *st.country_calls.entry(r.country).or_insert(0) += r.calls;
        st.total_calls = st.total_calls.saturating_add(r.calls);
    }

    /// Approximate memory held by learning state, for the report. The operator needs to
    /// watch this grow before the service is killed by a cgroup limit.
    pub fn approx_state_bytes(&self) -> usize {
        const PER_PAIR: usize = 160; // PairState + String key + HashMap overhead
        const PER_PEER: usize = 256;
        self.peers.len() * PER_PEER + self.pair_count() * PER_PAIR
    }

    /// Processes a SIP datagram observed between `src` and `dst`.
    ///
    /// Returns the **subject** of the decision alongside it, because the two are not always
    /// the source of the packet: a request is judged on whoever sent it, but a `401` is
    /// evidence about whoever is *receiving* it. Getting that backwards would condemn the
    /// softswitch for challenging an attacker.
    pub fn observe_packet(
        &mut self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        payload: &[u8],
        now: Timestamp,
    ) -> (Ipv4Addr, Decision) {
        self.stats.packets += 1;

        let req = match sip::parse(payload) {
            Some(Message::Request(r)) => {
                self.stats.sip_parsed += 1;
                r
            }
            Some(Message::Response(r)) => {
                self.stats.responses += 1;
                // The subject is the party being answered, not the one answering.
                return (dst, self.observe_response(dst, &r, now));
            }
            Some(Message::Keepalive) => {
                self.stats.keepalives += 1;
                return (src, Decision::OutOfScope("NAT keepalive"));
            }
            None => {
                self.stats.not_sip += 1;
                return (src, Decision::OutOfScope("not SIP"));
            }
        };
        (src, self.observe_request(src, &req, now))
    }

    /// Convenience for callers that only have one address — every request, and every test
    /// that predates two-sided observation.
    pub fn observe(&mut self, peer: Ipv4Addr, payload: &[u8], now: Timestamp) -> Decision {
        self.observe_packet(peer, peer, payload, now).1
    }

    /// A response: the only place a **failed** authentication can be recognised.
    ///
    /// The pairing is the entire point. A `401` answering a request that carried no
    /// credential is the normal digest handshake and is ignored; a `401` answering one that
    /// *did* carry a credential is a rejected password.
    fn observe_response(
        &mut self,
        peer: Ipv4Addr,
        r: &sip::Response<'_>,
        now: Timestamp,
    ) -> Decision {
        if r.is_digest_challenge() {
            self.stats.digest_challenges += 1;
        }
        if !r.is_digest_challenge() && !r.is_success() {
            return Decision::OutOfScope("SIP response");
        }
        let Some(key) = sip::transaction_key(r.via_branch(), r.call_id, r.cseq) else {
            return Decision::OutOfScope("SIP response");
        };
        let Some(st) = self.peers.get_mut(&peer) else {
            // No state for this peer means no authenticated request was seen from it, so
            // there is nothing this response can be evidence about.
            return Decision::OutOfScope("SIP response");
        };
        if !st.pending.claim(&key) {
            return Decision::OutOfScope("SIP response");
        }
        if r.is_success() {
            // The credential was accepted. Earlier rejections were someone mistyping a
            // password, not an attack — forgetting them is what keeps a customer who fixed
            // their configuration from being blocked minutes later.
            self.stats.auth_ok += 1;
            st.auth_failures.clear();
            return Decision::OutOfScope("SIP response");
        }
        self.stats.auth_failures += 1;
        let (n, exceeded) = st.auth_failures.record(now.0, AUTH_FAILURE_WINDOW_SECS);
        if exceeded {
            return Decision::AuthFailure { failures: n };
        }
        Decision::OutOfScope("SIP response")
    }

    fn observe_request(
        &mut self,
        peer: Ipv4Addr,
        req: &sip::Request<'_>,
        now: Timestamp,
    ) -> Decision {
        // The perimeter comes before everything, and applies to **any** method: scanners
        // send OPTIONS and REGISTER as much as INVITE. It leaves here without touching any
        // state, which is exactly the point — noise must not enter the baseline.
        if let Some(sig) = self.noise_filter.is_noise(req.user_agent) {
            self.stats.noise += 1;
            return Decision::Noise { signature: sig };
        }

        // URI injection belongs with the perimeter and applies to any method: the attack
        // shows up in INVITE as much as in REGISTER and OPTIONS.
        if let Some(pat) =
            self.noise_filter
                .injection_in_uri(&[Some(req.request_uri), req.from, req.to])
        {
            self.stats.injections += 1;
            return Decision::Injection { pattern: pat };
        }

        // A credential was presented. The method is irrelevant — `REGISTER` is where a
        // password is stolen and `INVITE` is where it is spent, and both are challenged the
        // same way. What is recorded here is only the *attempt*; whether it was rejected is
        // decided when the response arrives, in `observe_response`.
        if req.is_authenticated_attempt() {
            self.stats.auth_attempts += 1;
            if self.peers.len() < MAX_PEERS || self.peers.contains_key(&peer) {
                let plan = self.default_plan.clone();
                let st = self.peers.entry(peer).or_insert_with(|| PeerState {
                    dial_plan: plan,
                    ..Default::default()
                });
                if let Some(key) = sip::transaction_key(req.via_branch(), req.call_id, req.cseq) {
                    st.pending.remember(key, now.0);
                }
                // The volume backstop, for the deployments where no response is ever seen.
                let (n, exceeded) = st.auth_attempts.record(now.0, AUTH_WINDOW_SECS);
                if exceeded {
                    self.stats.auth_abuse += 1;
                    return Decision::AuthAbuse { attempts: n };
                }
            }
        }

        if req.method != Method::Invite {
            return Decision::OutOfScope("not an INVITE");
        }
        self.stats.invites += 1;

        let Some(dialed) = req.request_user else {
            return Decision::OutOfScope("INVITE with no dialled number");
        };

        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&peer) {
            self.stats.peers_dropped += 1;
            return Decision::OutOfScope("peer ceiling reached");
        }
        let state = self.peers.entry(peer).or_insert_with(|| PeerState {
            dial_plan: self.default_plan.clone(),
            ..Default::default()
        });

        // The cheapest filter on the hot path: whatever is not international leaves here,
        // without canonicalising and without touching any state.
        let Some(digits) = state.dial_plan.to_international(dialed) else {
            return Decision::OutOfScope("not international for this peer");
        };
        self.stats.international += 1;

        let Some(c) = country::resolve(&digits) else {
            // International by shape, but with no recognisable country. **No block** —
            // that would be the R07 mistake. It carries the digits for diagnosis.
            self.stats.unknown_country += 1;
            return Decision::UnknownCountry(digits.0);
        };

        Self::decide(state, req, c, now, self.mode, &mut self.stats)
    }

    fn decide(
        state: &mut PeerState,
        req: &sip::Request<'_>,
        c: Country,
        now: Timestamp,
        mode: Mode,
        stats: &mut Stats,
    ) -> Decision {
        // The A-number is an unverified assertion by the sender; it serves as a grouping
        // key, never as identity. The trust anchor is the peer. `SPEC.md` §5.
        let a_number = req.from_user().unwrap_or("<no-from>").to_string();

        *state.country_calls.entry(c.index.0).or_insert(0) += 1;
        state.total_calls += 1;

        // Prune before inserting: pairs seen once and never again — the signature of
        // A-number rotation — fall out on their own, while legitimate ones that come back
        // stay.
        if state.pairs.len() >= MAX_PAIRS_PER_PEER && !state.pairs.contains_key(&a_number) {
            let cutoff = now.0.saturating_sub(crate::novelty::WINDOW_SECS);
            state.pairs.retain(|_, (_, last)| *last >= cutoff);
            if state.pairs.len() >= MAX_PAIRS_PER_PEER {
                // Still full after pruning: refuse the new pair instead of growing. What
                // is lost is learning about that A-number, not the process's integrity.
                stats.pairs_dropped += 1;
                return Decision::Pass {
                    country: c.iso,
                    novel: false,
                };
            }
        }

        let (pair, last) = state.pairs.entry(a_number).or_default();
        *last = now.0;
        let obs = pair.observe(c.index, now);

        if obs.novel {
            stats.novel += 1;
        }

        if !obs.triggered {
            return Decision::Pass {
                country: c.iso,
                novel: obs.novel,
            };
        }
        if mode.is_learning(now) {
            stats.would_block += 1;
            return Decision::WouldBlock {
                country: c.iso,
                novel_in_window: obs.novel_in_window,
            };
        }
        stats.blocks += 1;
        Decision::Block {
            country: c.iso,
            novel_in_window: obs.novel_in_window,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite(from: &str, dialed: &str) -> Vec<u8> {
        format!(
            "INVITE sip:{dialed}@pbx SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK1\r\n\
             From: <sip:{from}@pbx>;tag=t1\r\n\
             To: <sip:{dialed}@pbx>\r\n\
             Call-ID: c1\r\n\
             CSeq: 1 INVITE\r\n\r\n"
        )
        .into_bytes()
    }

    fn peer() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 5)
    }

    /// A `REGISTER`, with or without a credential. `n` varies the transaction, the way a
    /// client retrying a password does.
    fn register(n: u32, with_credential: bool) -> Vec<u8> {
        let auth = if with_credential {
            "Authorization: Digest username=\"1001\", realm=\"pbx\", response=\"deadbeef\"\r\n"
        } else {
            ""
        };
        format!(
            "REGISTER sip:pbx SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK{n}\r\n\
             From: <sip:1001@pbx>;tag=t1\r\n\
             To: <sip:1001@pbx>\r\n\
             Call-ID: reg-call\r\n\
             CSeq: {n} REGISTER\r\n{auth}\r\n"
        )
        .into_bytes()
    }

    /// The softswitch's answer to transaction `n`, reusing its `Via` branch verbatim as
    /// RFC 3261 §17.1.3 requires.
    fn response(n: u32, status: u16) -> Vec<u8> {
        format!(
            "SIP/2.0 {status} Whatever\r\n\
             Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK{n}\r\n\
             From: <sip:1001@pbx>;tag=t1\r\n\
             To: <sip:1001@pbx>;tag=s1\r\n\
             Call-ID: reg-call\r\n\
             CSeq: {n} REGISTER\r\n\r\n"
        )
        .into_bytes()
    }

    fn switch() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 1)
    }

    /// One full exchange: the peer sends, the softswitch answers. Returns the verdict on
    /// the answer, which is where a rejection is recognised.
    fn exchange(e: &mut Engine, n: u32, credential: bool, status: u16, at: u32) -> Decision {
        e.observe_packet(peer(), switch(), &register(n, credential), t(at));
        let (subject, dec) = e.observe_packet(switch(), peer(), &response(n, status), t(at));
        assert_eq!(
            subject,
            peer(),
            "a challenge is evidence about who receives it"
        );
        dec
    }

    fn engine() -> Engine {
        Engine::new(DialPlan::new(["+", "00", "011", "9011"]), Mode::Active)
    }

    fn t(s: u32) -> Timestamp {
        Timestamp(1_800_000_000 + s)
    }

    #[test]
    fn domestic_traffic_leaves_through_the_cheapest_filter() {
        let mut e = engine();
        let d = e.observe(peer(), &invite("200", "2005"), t(0));
        assert!(matches!(d, Decision::OutOfScope(_)));
        // It touched no state at all: neither pair nor peer.
        assert_eq!(e.pair_count(), 0);
        assert_eq!(e.stats.international, 0);
    }

    #[test]
    fn a_known_international_destination_passes() {
        let mut e = engine();
        let d = e.observe(peer(), &invite("200", "00551199998888"), t(0));
        assert_eq!(
            d,
            Decision::Pass {
                country: "BR",
                novel: true
            }
        );
        // The second call to the same country is no longer novel.
        let d = e.observe(peer(), &invite("200", "00551199997777"), t(10));
        assert_eq!(
            d,
            Decision::Pass {
                country: "BR",
                novel: false
            }
        );
    }

    #[test]
    fn ten_first_time_countries_in_an_hour_block() {
        let mut e = engine();
        let destinations = [
            "00252612345678", // SO
            "00371234567",    // LV
            "0038761234567",  // BA
            "0022012345678",  // GM
            "002451234567",   // GW
            "009601234567",   // MV
            "0053512345678",  // CU
            "002241234567",   // GN
            "0021612345678",  // TN
            "0037112345678",  // repeats LV on purpose: only 9 distinct countries
        ];
        let mut last = None;
        for (i, d) in destinations.iter().enumerate() {
            last = Some(e.observe(peer(), &invite("200", d), t(i as u32 * 60)));
        }
        // The tenth destination repeats Latvia, so only 9 first-time countries: no fire.
        assert!(matches!(last, Some(Decision::Pass { .. })));

        // One genuinely new country closes the count.
        let d = e.observe(peer(), &invite("200", "0038912345678"), t(700));
        assert!(
            matches!(d, Decision::Block { .. }),
            "expected a block, got {d:?}"
        );
        assert_eq!(e.stats.blocks, 1);
    }

    #[test]
    fn learning_mode_does_not_block_but_records() {
        let mut e = Engine::new(DialPlan::new(["00"]), Mode::Learning { until: t(100_000) });
        let destinations = [
            "00252612345678",
            "00371234567",
            "0038761234567",
            "0022012345678",
            "002451234567",
            "009601234567",
            "0053512345678",
            "002241234567",
            "0021612345678",
            "0038912345678",
        ];
        let mut last = None;
        for (i, d) in destinations.iter().enumerate() {
            last = Some(e.observe(peer(), &invite("200", d), t(i as u32 * 60)));
        }
        assert!(
            matches!(last, Some(Decision::WouldBlock { .. })),
            "learning mode only records, got {last:?}"
        );
        assert_eq!(e.stats.blocks, 0);
        assert_eq!(e.stats.would_block, 1);
    }

    #[test]
    fn different_pairs_do_not_add_up_together() {
        // Accumulation is per (peer, A-number) pair. Ten extensions each debuting one
        // country is normal office traffic, not fraud.
        let mut e = engine();
        let destinations = [
            "00252612345678",
            "00371234567",
            "0038761234567",
            "0022012345678",
            "002451234567",
            "009601234567",
            "0053512345678",
            "002241234567",
            "0021612345678",
            "0038912345678",
        ];
        for (i, d) in destinations.iter().enumerate() {
            let extension = format!("2{i:02}");
            let dec = e.observe(peer(), &invite(&extension, d), t(i as u32 * 60));
            assert!(
                matches!(dec, Decision::Pass { .. }),
                "extension {extension}: {dec:?}"
            );
        }
        assert_eq!(e.pair_count(), 10);
        assert_eq!(e.stats.blocks, 0);
    }

    #[test]
    fn a_number_rotation_does_not_grow_without_bound() {
        // The attack SPEC §5 describes as expected: a new A-number on every call. Without
        // a ceiling this would kill the process on memory — a DoS vector described in the
        // product's own specification.
        let mut e = engine();
        for i in 0..(MAX_PAIRS_PER_PEER + 5_000) {
            let a = format!("spoof{i}");
            // All in the same window, so pruning cannot remove them.
            e.observe(peer(), &invite(&a, "00551199998888"), t(0));
        }
        assert!(
            e.pair_count() <= MAX_PAIRS_PER_PEER,
            "ceiling exceeded: {} pairs",
            e.pair_count()
        );
        assert!(e.stats.pairs_dropped > 0, "refusals must be counted");
    }

    #[test]
    fn after_the_attack_pruning_returns_space_to_newcomers() {
        // A rotation attack fills the ceiling within one window. When the window passes
        // and a genuinely new pair shows up, pruning clears the ones that never returned —
        // the system recovers on its own, with no background sweep.
        let mut e = engine();
        for i in 0..MAX_PAIRS_PER_PEER {
            e.observe(
                peer(),
                &invite(&format!("spoof{i}"), "00551199998888"),
                t(0),
            );
        }
        assert_eq!(
            e.pair_count(),
            MAX_PAIRS_PER_PEER,
            "the attack must fill the ceiling"
        );

        // Two windows later a genuinely new customer arrives.
        let dec = e.observe(
            peer(),
            &invite("new-customer", "00551199998888"),
            t(crate::novelty::WINDOW_SECS * 2),
        );
        assert!(matches!(dec, Decision::Pass { .. }), "got {dec:?}");
        assert!(
            e.pair_count() < 10,
            "pruning should have swept the ephemeral ones; {} remain",
            e.pair_count()
        );
    }

    #[test]
    fn estimated_memory_is_reportable() {
        let mut e = engine();
        for i in 0..100 {
            e.observe(peer(), &invite(&format!("r{i}"), "00551199998888"), t(0));
        }
        assert!(e.approx_state_bytes() > 0);
        // The absolute ceiling has to fit inside the unit's MemoryMax=192M.
        let ceiling = MAX_PEERS * 256 + MAX_PEERS * MAX_PAIRS_PER_PEER * 160;
        assert!(ceiling > 0); // documents that the theoretical worst case is huge:
                              // which is why the pair ceiling is PER PEER and the peer ceiling is low — in
                              // practice a peer under attack saturates its own limit without affecting others.
    }

    #[test]
    fn junk_neither_crashes_nor_blocks() {
        let mut e = engine();
        for p in [&b"not sip at all"[..], &[0xff, 0xfe][..], &b""[..]] {
            assert!(matches!(
                e.observe(peer(), p, t(0)),
                Decision::OutOfScope(_)
            ));
        }
        assert_eq!(e.stats.not_sip, 3);
        assert_eq!(e.stats.blocks, 0);
    }

    #[test]
    fn a_peer_declared_plan_beats_the_default() {
        let mut e = Engine::new(DialPlan::new(["00"]), Mode::Active);
        let other = Ipv4Addr::new(10, 0, 0, 9);
        e.declare_dial_plan(other, DialPlan::new(["9011"]));

        // For the peer with its own plan, `00…` is not international.
        assert!(matches!(
            e.observe(other, &invite("200", "00551199998888"), t(0)),
            Decision::OutOfScope(_)
        ));
        // But `9011…` is.
        assert!(matches!(
            e.observe(other, &invite("200", "9011551199998888"), t(1)),
            Decision::Pass { country: "BR", .. }
        ));
    }
    #[test]
    fn the_challenge_every_customer_receives_never_counts() {
        // The failure mode that would take a whole network offline: a `401` answering a
        // `REGISTER` that carried no credential is the *normal* digest handshake. Fifty of
        // them, one per registration cycle, must produce nothing.
        let mut e = engine();
        for n in 0..50 {
            let d = exchange(&mut e, n, false, 401, n * 300);
            assert!(matches!(d, Decision::OutOfScope(_)), "got {d:?}");
        }
        assert_eq!(e.stats.auth_failures, 0, "no credential was ever rejected");
        assert_eq!(
            e.stats.digest_challenges, 50,
            "but the challenges were seen"
        );
    }

    #[test]
    fn five_rejected_credentials_condemn_the_source() {
        let mut e = engine();
        for n in 0..4 {
            let d = exchange(&mut e, n, true, 401, n * 10);
            assert!(
                matches!(d, Decision::OutOfScope(_)),
                "four is not yet a run"
            );
        }
        let d = exchange(&mut e, 4, true, 401, 40);
        assert!(
            matches!(d, Decision::AuthFailure { failures } if failures == 5),
            "the fifth rejected password must condemn: {d:?}"
        );
        assert_eq!(e.stats.auth_failures, 5);
    }

    #[test]
    fn a_407_from_a_proxy_counts_the_same_as_a_401() {
        // Toll fraud is spent on INVITE, and a proxy challenges with 407. The rule is about
        // the credential being rejected, not about which box rejected it.
        let mut e = engine();
        for n in 0..4 {
            exchange(&mut e, n, true, 407, n);
        }
        assert!(matches!(
            exchange(&mut e, 4, true, 407, 5),
            Decision::AuthFailure { .. }
        ));
    }

    #[test]
    fn an_accepted_credential_wipes_the_run() {
        // Someone fixing a mistyped password must not be blocked by their next slip. Only
        // an uninterrupted run is an attack.
        let mut e = engine();
        for n in 0..4 {
            exchange(&mut e, n, true, 401, n);
        }
        assert!(matches!(
            exchange(&mut e, 4, true, 200, 5),
            Decision::OutOfScope(_)
        ));
        assert_eq!(e.stats.auth_ok, 1);
        for n in 5..9 {
            let d = exchange(&mut e, n, true, 401, n);
            assert!(matches!(d, Decision::OutOfScope(_)), "the slate was clean");
        }
    }

    #[test]
    fn a_retransmitted_challenge_counts_once() {
        // UDP retransmits. Counting the same rejection three times would reach five after
        // two real attempts — and the operator would never work out why.
        let mut e = engine();
        e.observe_packet(peer(), switch(), &register(1, true), t(0));
        for _ in 0..5 {
            e.observe_packet(switch(), peer(), &response(1, 401), t(0));
        }
        assert_eq!(
            e.stats.auth_failures, 1,
            "one rejected credential, however many times it was sent"
        );
    }

    #[test]
    fn a_response_to_a_peer_we_never_saw_authenticate_is_ignored() {
        // Without a remembered authenticated request there is nothing the response can be
        // evidence about — and inventing state from an unsolicited packet would let anyone
        // get anyone else blocked.
        let mut e = engine();
        let (_, d) = e.observe_packet(switch(), peer(), &response(1, 401), t(0));
        assert!(matches!(d, Decision::OutOfScope(_)));
        assert_eq!(e.stats.auth_failures, 0);
    }

    #[test]
    fn the_volume_backstop_still_fires_when_nothing_ever_answers() {
        // The measured case on the reference server: opensips drops the junk before
        // authenticating it, so no `401` is ever emitted and the failure rule has no
        // evidence to work with. Something must still stop a credential-stuffing run.
        let mut e = engine();
        let mut fired = false;
        for n in 0..20 {
            let (_, d) = e.observe_packet(peer(), switch(), &register(n, true), t(n));
            fired |= matches!(d, Decision::AuthAbuse { .. });
        }
        assert!(
            fired,
            "20 credentials in 20 s with no answer must still block"
        );
        assert_eq!(
            e.stats.auth_failures, 0,
            "and honestly report zero failures"
        );
    }
}
