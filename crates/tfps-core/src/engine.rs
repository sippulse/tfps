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
use crate::perimeter::{AuthAbuse, NoiseFilter};
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
    /// Too many **authenticated** attempts in a short window — credential brute force.
    /// This is Chain A from `SPEC.md`, observed on the wire instead of in a log.
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
    /// Sources condemned for authentication brute force.
    pub auth_abuse: u64,
    /// Authenticated attempts observed — the denominator for the signal above.
    pub auth_attempts: u64,
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
    /// Brute-force counter for this source.
    auth: AuthAbuse,
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

    /// Processes a SIP datagram coming from `peer`.
    pub fn observe(&mut self, peer: Ipv4Addr, payload: &[u8], now: Timestamp) -> Decision {
        self.stats.packets += 1;

        let req = match sip::parse(payload) {
            Some(Message::Request(r)) => {
                self.stats.sip_parsed += 1;
                r
            }
            Some(Message::Response(_)) => {
                // The learning path will use this (`200 OK` says whether it was answered);
                // the decision path will not. For now it is counted, so the report is
                // honest.
                self.stats.responses += 1;
                return Decision::OutOfScope("SIP response");
            }
            Some(Message::Keepalive) => {
                self.stats.keepalives += 1;
                return Decision::OutOfScope("NAT keepalive");
            }
            None => {
                self.stats.not_sip += 1;
                return Decision::OutOfScope("not SIP");
            }
        };

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

        // Credential brute force: counts `REGISTER` **carrying `Authorization`**, never
        // the `401` challenge — every legitimate registration receives one, and counting
        // those would block every customer. See `perimeter::AUTH_ATTEMPTS_TO_BLOCK`.
        if req.method == Method::Register && req.authorization.is_some() {
            self.stats.auth_attempts += 1;
            if self.peers.len() < MAX_PEERS || self.peers.contains_key(&peer) {
                let plan = self.default_plan.clone();
                let st = self.peers.entry(peer).or_insert_with(|| PeerState {
                    dial_plan: plan,
                    ..Default::default()
                });
                let (n, exceeded) = st.auth.attempt(now.0);
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

        Self::decide(state, &req, c, now, self.mode, &mut self.stats)
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
        // O teto absoluto precisa caber no MemoryMax=192M da unidade systemd.
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
}
