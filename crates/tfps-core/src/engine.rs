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

use crate::anomaly::{AnomalySnapshot, Params, SourceAnomaly};
use crate::country::{self, Country};
use crate::dialplan::{DialPlan, InternationalDigits};
use crate::novelty::Timestamp;
use crate::perimeter::{
    AuthAttempts, AuthFailures, NoiseFilter, RegProbes, AUTH_FAILURE_WINDOW_SECS, AUTH_WINDOW_SECS,
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
        /// Fused evidence in nats.
        evidence_nats: u32,
        countries: u32,
    },
    /// The evidence crossed the bound, but the source has not been observed long enough
    /// for its own baseline. Reported, never blocked.
    Warming {
        country: &'static str,
        evidence_nats: u32,
        countries: u32,
    },
    /// Block: the source's fused evidence crossed the fire bound. `evidence_nats` is that
    /// evidence, `countries` the distinct destinations it has attempted — both go in the
    /// audit line.
    Block {
        country: &'static str,
        evidence_nats: u32,
        countries: u32,
    },
    /// Perimeter noise: a scanning tool identified by its user-agent.
    /// Under enforcement this dies at `XDP_DROP` and vanishes from sngrep.
    Noise { signature: &'static str },
    /// A scanner identified by its **identity** — a known scanner domain or tool name in the
    /// `From`/`To`/`Contact`/Request-URI (Censys, Shodan, friendly-scanner…), regardless of
    /// method. Also condemned to `XDP_DROP`.
    Scanner { id: &'static str },
    /// An injection pattern in the URI. **Higher** confidence than a user-agent: a
    /// scanning tool can forge a legitimate UA, but no real phone puts a single quote or
    /// `--` in the `From` header.
    Injection { pattern: &'static str },
    /// A singleton header appeared more than once (From, To, Call-ID, CSeq, User-Agent,
    /// P-Asserted-Identity, Authorization). The parser keeps the first and flags the
    /// duplicate; the message is condemned rather than guessed at, because the softswitch
    /// may use the other copy. This closes the duplicate-header smuggling evasion.
    Malformed { header: &'static str },
    /// Registration scanning: many REGISTER attempts, none succeeding — enumerating
    /// extensions without ever logging in. Carries the number of distinct extensions probed.
    /// Caught even with no credential presented, which the auth-failure rule cannot see.
    RegScan { extensions: u32 },
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
    /// Sources condemned by a known scanner identity (Censys, Shodan, friendly-scanner…).
    pub scanners: u64,
    /// Sources condemned for registration scanning (REGISTERs that never succeed).
    pub reg_scans: u64,
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
    /// International calls observed to complete (a `2xx`).
    pub intl_completed: u64,
    /// International calls observed to fail (a final `4xx`/`5xx`/`6xx`) — the scan signal.
    pub intl_failed: u64,
    /// First-time-dialling-prefix events, for the learned prefix benign rate.
    pub prefix_novel: u64,
    /// First-time-destination-range events, for the learned range benign rate.
    pub range_novel: u64,
    /// Calls to the operator's own country — national, excluded from the behavioural layer.
    pub domestic: u64,
    pub invites: u64,
    pub international: u64,
    pub uncanonicalizable: u64,
    pub unknown_country: u64,
    pub novel: u64,
    pub blocks: u64,
    pub would_block: u64,
    /// Firing verdicts suppressed because the source is still in its own warm-up.
    pub warming: u64,
    /// Successful registrations refused because the known-peer map was full.
    pub known_peers_dropped: u64,
    /// Pairs refused by the memory ceiling. **Non-zero is a symptom of an A-number
    /// rotation attack** — and it must show up in the report, not vanish silently.
    pub pairs_dropped: u64,
    /// Peers refused by the ceiling.
    pub peers_dropped: u64,
}

/// Ceiling of distinct peers. A peer is the source IP, which is not forgeable from the
/// observation point — so this ceiling is far looser than the pair one.
const MAX_PEERS: usize = 10_000;

/// REGISTER attempts from one source, with **no successful registration**, that mark it a
/// registration scanner — enumerating extensions without ever logging in. Counted as the
/// number of **distinct extensions** one source probes, so the rule is safe by construction:
/// a legitimate phone registers its own single AOR (a multi-line device its own few), which
/// never reaches this many; only a source spraying REGISTERs across many different extensions
/// does. Set well above any plausible legitimate device so no real endpoint is ever banned;
/// a real enumeration ("a few tries per extension, across the dial plan") sails past it.
/// Catches the no-credential probe the auth-failure rule (which needs a credential) misses.
pub const REG_SCAN_EXTENSIONS: usize = 10;

/// Per-source capacity for the distinct-extension tracker; ≥ `REG_SCAN_EXTENSIONS`.
const REG_PROBE_CAPACITY: usize = 16;

/// Window for the registration-scan counter.
pub const REG_SCAN_WINDOW_SECS: u32 = 600;

/// FNV-1a hash of an extension (AOR), so the distinct-extension tracker holds a `u64` rather
/// than borrowing the packet. Case-folded, since extensions are compared for identity only.
fn ext_id(aor: &str) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in aor.bytes() {
        h ^= b.to_ascii_lowercase() as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Ceiling on remembered known-good peers, to bound memory.
const MAX_KNOWN_PEERS: usize = 50_000;

/// How long a successful registration keeps a peer exempt from the third-party feed.
/// Longer than any registration interval, so a peer that is briefly offline is not
/// forgotten, but short enough that a reassigned dynamic IP does not inherit the trust for a
/// week. The perimeter's own evidence is never exempted.
pub const KNOWN_PEER_TTL_SECS: u32 = 24 * 3600;

/// A peer's durable detector state, as the store sees it.
#[derive(Debug, Clone)]
pub struct PeerAnomalyRecord {
    pub peer: Ipv4Addr,
    pub seen_countries: [u64; 4],
    pub n_countries: u32,
    pub rate_a: f64,
    pub rate_b: f64,
}

#[derive(Debug, Default)]
struct PeerState {
    dial_plan: DialPlan,
    /// The sequential IRSF detector for this source. One per peer — the A-number is gone as
    /// a key, which is what removes the rotation bypass. See `anomaly.rs`.
    anomaly: SourceAnomaly,
    /// Authenticated attempts, regardless of outcome — the volume backstop.
    auth_attempts: AuthAttempts,
    /// Rejected credentials — the real brute-force signal.
    auth_failures: AuthFailures,
    /// Authenticated transactions still waiting for their response.
    pending: PendingAuth,
    /// International INVITEs still waiting for a final response, so the completion arm can
    /// be fed when one arrives.
    pending_intl: PendingAuth,
    /// Distinct extensions this source has probed with REGISTER — the enumeration counter.
    reg_probes: RegProbes<REG_PROBE_CAPACITY>,
    /// The durable state changed since the last checkpoint. Checkpoints write only dirty
    /// sources, so a quiet installation does not rewrite every peer on every interval.
    dirty: bool,
}

/// How many authenticated transactions per peer can be awaiting a response.
///
/// A ceiling rather than a map that grows: an attacker generating a unique `Call-ID` per
/// guess would otherwise make the defence allocate on demand.
const MAX_PENDING_PER_PEER: usize = 32;

/// How long an unanswered transaction is kept, in seconds. RFC 3261 Timer B/F is 64×T1 =
/// 32 s, after which the client has given up and no response can still be matched.
const PENDING_TTL_SECS: u32 = 32;

/// Transactions in which a credential was presented and the outcome is not yet known.
///
/// **Only authenticated requests are remembered.** A request with no credential is of no
/// interest: the `401` it receives is the normal challenge, and storing it would be the
/// mistake that blocks every customer.
#[derive(Debug)]
struct PendingEntry {
    key: String,
    at: u32,
    /// None = unconfirmed legacy caller (`observe`, tests); Some = the request's destination.
    responder: Option<Ipv4Addr>,
    aor: Option<u64>,
    novel: bool,
}

#[derive(Debug, Default)]
struct PendingAuth {
    entries: Vec<PendingEntry>,
}

impl PendingAuth {
    fn remember(
        &mut self,
        key: String,
        now: u32,
        responder: Option<Ipv4Addr>,
        aor: Option<u64>,
        novel: bool,
    ) {
        self.entries
            .retain(|e| now.saturating_sub(e.at) < PENDING_TTL_SECS);
        // A retransmission of the same request is the same attempt, not a second one.
        if let Some(e) = self.entries.iter_mut().find(|e| e.key == key) {
            e.at = now;
            e.responder = responder;
            e.aor = aor;
            e.novel = novel;
            return;
        }
        if self.entries.len() < MAX_PENDING_PER_PEER {
            self.entries.push(PendingEntry {
                key,
                at: now,
                responder,
                aor,
                novel,
            });
        }
    }

    /// Claims a transaction, if it was an authenticated one **and the response came from the
    /// address the request was sent to**. Returning the recorded AOR lets a success clear
    /// only that AOR's failures. Removing the entry on the first matching response keeps a
    /// retransmitted `401` from counting twice.
    fn claim(&mut self, key: &str, src: Ipv4Addr) -> Option<(Option<u64>, bool)> {
        let i = self
            .entries
            .iter()
            .position(|e| e.key == key && e.responder.is_none_or(|expected| expected == src))?;
        let entry = self.entries.remove(i);
        Some((entry.aor, entry.novel))
    }
}

/// One international INVITE, as the decision function sees it: the dialling format, the
/// canonical destination, the request (for its transaction key) and the instant.
struct Observation<'a> {
    prefix: &'a str,
    digits: &'a InternationalDigits,
    request: &'a sip::Request<'a>,
    country: Country,
    now: Timestamp,
    responder: Option<Ipv4Addr>,
}

pub struct Engine {
    peers: HashMap<Ipv4Addr, PeerState>,
    /// The benign hypotheses and priors every source is judged against. Starts at the
    /// cold-start defaults and is refined from the deployment's own aggregate traffic
    /// during the learning window — see `recalibrate`.
    params: Params,
    default_plan: DialPlan,
    mode: Mode,
    /// The operator's own country/countries, by index. A destination resolving to one of
    /// these is **national, not international** — even when it arrived with a `+` or in
    /// E.164 — so it is out of scope for the behavioural layer. This is what keeps an
    /// inbound call to your own DID from being judged as an international destination.
    home_countries: std::collections::HashSet<u16>,
    /// IPs that have **successfully authenticated** — registered peers. They are known-good
    /// and must not be banned by the perimeter or the APIBAN feed: a customer on a dynamic
    /// IP proved it holds valid credentials. Value is the last-auth instant, so a peer that
    /// stops registering eventually ages out.
    known_peers: std::collections::HashMap<Ipv4Addr, u32>,
    /// Whether behavioural fraud detection runs at all.
    ///
    /// **Off by default.** The product is noise reduction — the perimeter and its clean
    /// sngrep — and that stands on its own. Behavioural detection (prefix and range novelty and the
    /// rest) is an opt-in extra: worth having, but most installs will never turn it on, and
    /// forcing its state, its learning window and its per-peer memory on everyone would be
    /// exactly the over-engineering this product is meant to avoid. When off, INVITEs are
    /// still seen and the perimeter still enforces; the fraud path simply does not run.
    behavioural: bool,
    pub noise_filter: NoiseFilter,
    pub stats: Stats,
}

impl Engine {
    /// A perimeter-only engine: noise reduction, no behavioural detection. The default.
    pub fn new(default_plan: DialPlan, mode: Mode) -> Self {
        Self {
            peers: HashMap::new(),
            default_plan,
            mode,
            params: Params::default(),
            home_countries: std::collections::HashSet::new(),
            known_peers: std::collections::HashMap::new(),
            behavioural: false,
            noise_filter: NoiseFilter::new(),
            stats: Stats::default(),
        }
    }

    /// Turns behavioural fraud detection on. Opt-in, per the product's shape.
    pub fn with_behavioural(mut self) -> Self {
        self.behavioural = true;
        self
    }

    pub fn behavioural_enabled(&self) -> bool {
        self.behavioural
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

    /// The calibrated parameters currently in force, for the report.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Mutable parameters, used by tests to disable the per-source warm-up.
    pub fn params_mut(&mut self) -> &mut Params {
        &mut self.params
    }

    /// Declares the operator's own country/countries by ISO label (`+1` is `NANP`).
    /// Returns the labels it could not resolve, so the binary can warn about a typo rather
    /// than silently leave a country international.
    pub fn set_home_countries<'a>(
        &mut self,
        isos: impl IntoIterator<Item = &'a str>,
    ) -> Vec<String> {
        let mut unknown = Vec::new();
        for iso in isos {
            match crate::country::index_for_iso(iso) {
                Some(idx) => {
                    self.home_countries.insert(idx.0);
                }
                None => unknown.push(iso.to_string()),
            }
        }
        unknown
    }

    pub fn home_country_count(&self) -> usize {
        self.home_countries.len()
    }

    /// Is this a registered peer that authenticated within `KNOWN_PEER_TTL_SECS`? Such a
    /// source is never banned — it proved it holds valid credentials.
    pub fn is_known_peer(&self, ip: Ipv4Addr, now: Timestamp) -> bool {
        self.known_peers
            .get(&ip)
            .is_some_and(|last| now.0.saturating_sub(*last) < KNOWN_PEER_TTL_SECS)
    }

    pub fn known_peer_count(&self) -> usize {
        self.known_peers.len()
    }

    /// Known-good peers, for persistence — they must survive a restart so the APIBAN feed,
    /// re-applied at boot, cannot knock a registered customer off before it re-registers.
    pub fn export_known_peers(&self) -> impl Iterator<Item = (Ipv4Addr, u32)> + '_ {
        self.known_peers.iter().map(|(ip, ts)| (*ip, *ts))
    }

    pub fn import_known_peer(&mut self, ip: Ipv4Addr, last_auth: u32) {
        if self.known_peers.len() < MAX_KNOWN_PEERS {
            self.known_peers.insert(ip, last_auth);
        }
    }

    /// Refits the benign hypotheses and the volume prior from the deployment's own
    /// aggregate traffic, then adopts them across every source. Meant to be called
    /// periodically (at checkpoint) during the learning window — it is the self-calibration
    /// the design calls for, so the operator tunes only the error rates, never the traffic
    /// constants. A parameter is only overridden once there is enough data to trust it;
    /// otherwise the cold-start default stands.
    pub fn recalibrate(&mut self) {
        let mut p = self.params.clone();
        // theta0_prefix: the population rate of first-time prefixes. Clamped so a
        // pathological sample cannot make the walk fire on everything or never.
        if self.stats.international >= 500 {
            let rp = self.stats.prefix_novel as f64 / self.stats.international as f64;
            p.theta0_prefix = rp.clamp(0.005, 0.3);
            let rr = self.stats.range_novel as f64 / self.stats.international as f64;
            p.theta0_range = rr.clamp(0.02, 0.4);
        }
        // theta0c: the population failure rate among observed final responses.
        let finals = self.stats.intl_completed + self.stats.intl_failed;
        if finals >= 200 {
            let rc = self.stats.intl_failed as f64 / finals as f64;
            p.theta0c = rc.clamp(0.05, 0.7);
        }
        // Volume prior: a method-of-moments Gamma fit to the current per-source rates.
        let rates: Vec<f64> = self
            .peers
            .values()
            .map(|s| s.anomaly.learned_rate())
            .collect();
        if rates.len() >= 20 {
            let n = rates.len() as f64;
            let mean = rates.iter().sum::<f64>() / n;
            let var = rates.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / n;
            if mean > 0.0 && var > 0.0 {
                p.prior_mean = mean;
                p.prior_strength = (mean / var).clamp(0.1, 50.0);
            }
        }
        self.params = p;
        // Adopt the refined hypotheses across every source, keeping their walks in place.
        for st in self.peers.values_mut() {
            st.anomaly.recalibrate(&self.params);
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Distinct sources under watch.
    pub fn source_count(&self) -> usize {
        self.peers.len()
    }

    /// Each **dirty** source's durable detector state, in the shape the store writes.
    ///
    /// Checkpoints are periodic and inline with capture, so rewriting every quiet peer
    /// every five minutes is wasted work and a needless stall. A peer becomes dirty when
    /// its walks or its rate posterior change.
    pub fn export_anomaly(&self) -> impl Iterator<Item = PeerAnomalyRecord> + '_ {
        self.peers
            .iter()
            .filter(|(_, st)| st.dirty)
            .map(|(ip, st)| {
                let snap = st.anomaly.snapshot();
                PeerAnomalyRecord {
                    peer: *ip,
                    seen_countries: snap.seen_countries,
                    n_countries: snap.n_countries,
                    rate_a: snap.rate_a,
                    rate_b: snap.rate_b,
                }
            })
    }

    /// Marks every source clean after a successful checkpoint.
    pub fn clear_anomaly_dirty(&mut self) {
        for st in self.peers.values_mut() {
            st.dirty = false;
        }
    }

    /// Restores a source's detector state. Honours the peer ceiling.
    pub fn import_anomaly(&mut self, r: PeerAnomalyRecord) {
        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&r.peer) {
            return;
        }
        let plan = self.default_plan.clone();
        let params = self.params.clone();
        let st = self.peers.entry(r.peer).or_insert_with(|| PeerState {
            dial_plan: plan,
            anomaly: SourceAnomaly::new(&params),
            ..Default::default()
        });
        st.anomaly = SourceAnomaly::from_snapshot(
            &params,
            AnomalySnapshot {
                seen_countries: r.seen_countries,
                n_countries: r.n_countries,
                rate_a: r.rate_a,
                rate_b: r.rate_b,
            },
        );
        st.dirty = false;
    }

    /// Approximate memory held by detector state, for the report.
    pub fn approx_state_bytes(&self) -> usize {
        // A SourceAnomaly is a fixed handful of words: three walks, a rate posterior, a
        // 256-bit country set, and two 128-byte range filters. Call it ~600 bytes per peer
        // with map overhead.
        const PER_PEER: usize = 600;
        self.peers.len() * PER_PEER
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
                return (dst, self.observe_response(dst, src, &r, now));
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
        let responder = (!dst.is_unspecified()).then_some(dst);
        (src, self.observe_request(src, responder, &req, now))
    }

    /// Convenience for callers that only have one address — every request, and every test
    /// that predates two-sided observation.
    pub fn observe(&mut self, peer: Ipv4Addr, payload: &[u8], now: Timestamp) -> Decision {
        // One-address convenience: no expected responder, so a response is not pinned to it.
        self.observe_packet(peer, Ipv4Addr::UNSPECIFIED, payload, now)
            .1
    }

    /// A response: the only place a **failed** authentication can be recognised.
    ///
    /// The pairing is the entire point. A `401` answering a request that carried no
    /// credential is the normal digest handshake and is ignored; a `401` answering one that
    /// *did* carry a credential is a rejected password.
    fn observe_response(
        &mut self,
        peer: Ipv4Addr,
        src: Ipv4Addr,
        r: &sip::Response<'_>,
        now: Timestamp,
    ) -> Decision {
        let mode = self.mode;
        let behavioural = self.behavioural;
        if r.is_digest_challenge() {
            self.stats.digest_challenges += 1;
        }
        // Provisional responses (1xx) are not outcomes — the final one comes later.
        let provisional = (100..200).contains(&r.status);
        let Some(key) = sip::transaction_key(r.via_branch(), r.call_id, r.cseq) else {
            return Decision::OutOfScope("SIP response");
        };
        let Some(st) = self.peers.get_mut(&peer) else {
            // No state for this peer means nothing this response can be evidence about.
            return Decision::OutOfScope("SIP response");
        };

        // A response can answer two questions at once: it may be the outcome of an
        // authenticated request, and — when that request was an international INVITE — the
        // outcome of a call. Claim both, and never let the auth path consume the completion
        // path: an authenticated INVITE answered `200` or `404` used to be swallowed here,
        // leaving the completion arm blind to exactly the traffic it exists to watch.
        // Provisional responses are neither outcome; claiming one would lose the final.
        let auth = if provisional {
            None
        } else {
            st.pending.claim(&key, src)
        };
        let intl = if provisional {
            None
        } else {
            st.pending_intl.claim(&key, src)
        };
        let was_auth = auth.is_some();
        let was_intl = intl.is_some();
        if !was_auth && !was_intl {
            return Decision::OutOfScope("SIP response");
        }

        let aor = auth.and_then(|(aor, _)| aor);
        let novel = intl.is_some_and(|(_, novel)| novel);
        if was_auth {
            let is_register = r
                .cseq
                .is_some_and(|c| c.to_ascii_uppercase().contains("REGISTER"));
            if r.is_success() {
                self.stats.auth_ok += 1;
                // A success clears only the AOR that succeeded. Clearing every failure let
                // an attacker with one valid account reset the counter while guessing
                // another account.
                st.auth_failures.clear_aor(aor.unwrap_or(0));
                if is_register {
                    // Only a successful REGISTER proves a registered peer. A 2xx to an
                    // authenticated INVITE is a call, not a registration, and used to grant
                    // seven days of perimeter immunity.
                    if let Some(aor) = aor {
                        st.reg_probes.remove(aor);
                    }
                    if self.known_peers.len() < MAX_KNOWN_PEERS
                        || self.known_peers.contains_key(&peer)
                    {
                        self.known_peers.insert(peer, now.0);
                    } else {
                        // A silent cap would make new customers lose the APIBAN exemption
                        // without anyone seeing why. Count it for the report.
                        self.stats.known_peers_dropped =
                            self.stats.known_peers_dropped.saturating_add(1);
                    }
                }
            } else if r.is_digest_challenge() {
                self.stats.auth_failures += 1;
                let (n, exceeded) =
                    st.auth_failures
                        .record(aor.unwrap_or(0), now.0, AUTH_FAILURE_WINDOW_SECS);
                if exceeded {
                    return Decision::AuthFailure { failures: n };
                }
            }
        }

        // Completion path: the final response to an international INVITE we remembered.
        // Only a final response is an outcome, and silence is never fed — the same honesty
        // the auth rule keeps. A digest challenge is the normal handshake, not a routing
        // outcome, whether or not the INVITE carried a credential.
        if was_intl && !r.is_digest_challenge() {
            let completed = r.is_success();
            if completed {
                self.stats.intl_completed += 1;
            } else if r.status >= 400 {
                self.stats.intl_failed += 1;
            } else {
                // A 3xx redirect is neither a completion nor a failure; ignore it.
                return Decision::OutOfScope("SIP response");
            }
            if behavioural {
                let v = st.anomaly.observe_completion(completed, novel, now.0);
                st.dirty = true;
                let evidence_nats = v.evidence.round().max(0.0) as u32;
                if v.fired {
                    if mode.is_learning(now) {
                        self.stats.would_block += 1;
                        return Decision::WouldBlock {
                            country: "?",
                            evidence_nats,
                            countries: v.countries,
                        };
                    }
                    if v.warming {
                        self.stats.warming += 1;
                        return Decision::Warming {
                            country: "?",
                            evidence_nats,
                            countries: v.countries,
                        };
                    }
                    self.stats.blocks += 1;
                    return Decision::Block {
                        country: "?",
                        evidence_nats,
                        countries: v.countries,
                    };
                }
            }
        }
        Decision::OutOfScope("SIP response")
    }

    fn observe_request(
        &mut self,
        peer: Ipv4Addr,
        responder: Option<Ipv4Addr>,
        req: &sip::Request<'_>,
        now: Timestamp,
    ) -> Decision {
        // The perimeter comes before everything, and applies to **any** method: scanners
        // send OPTIONS and REGISTER as much as INVITE. It leaves here without touching any
        // state, which is exactly the point — noise must not enter the baseline.
        if let Some(sig) = self.noise_filter.is_noise(req.user_agent.as_deref()) {
            self.stats.noise += 1;
            return Decision::Noise { signature: sig };
        }

        // URI injection belongs with the perimeter and applies to any method: the attack
        // shows up in INVITE as much as in REGISTER and OPTIONS. Only the Request-URI is
        // scanned: From/To user parts can be legitimate SIP names (`o'brien@`, `select@`),
        // and condemning a whole source for a name is a false positive. The Request-URI is
        // what the softswitch routes and what the classic injection targets.
        if let Some(pat) = self.noise_filter.injection_in_uri(&[Some(req.request_uri)]) {
            self.stats.injections += 1;
            return Decision::Injection { pattern: pat };
        }

        // A known scanner identity in From/To/Contact/Request-URI — self-identifying research
        // scanners (Censys, Shodan) and tools whose tell is the domain, not the UA. Applies
        // to every method: friendly-scanner and Censys both probe with OPTIONS, and this runs
        // before the INVITE gate so those are caught.
        if let Some(id) = self.noise_filter.scanner_id(&[
            Some(req.request_uri),
            req.from.as_deref(),
            req.to.as_deref(),
            req.p_asserted_identity.as_deref(),
        ]) {
            self.stats.scanners += 1;
            return Decision::Scanner { id };
        }

        // Duplicate singleton headers are ambiguous: the softswitch may read a different
        // copy than this parser. Condemn the source instead of guessing which one is real.
        if let Some(header) = req.duplicate {
            return Decision::Malformed { header };
        }

        // A credential is stolen at `REGISTER` and spent at `INVITE`, and both are challenged
        // the same way, so the credential path below runs for **any** authenticated request;
        // the enumeration counter is REGISTER-only. What either records is the *attempt*;
        // whether it was rejected is decided when the response arrives, in `observe_response`.
        let is_register = req.method == Method::Register;
        let credentialed = req.is_authenticated_attempt();
        if (is_register || credentialed)
            && (self.peers.len() < MAX_PEERS || self.peers.contains_key(&peer))
        {
            // The dial plan is cloned only when the peer is new. Cloning it for every
            // credentialed request would allocate once per packet under a brute-force run.
            let params = self.params.clone();
            let st = self.peers.entry(peer).or_insert_with(|| PeerState {
                dial_plan: self.default_plan.clone(),
                anomaly: SourceAnomaly::new(&params),
                ..Default::default()
            });

            // Registration scanning: an enumerator sprays REGISTERs across many *different*
            // extensions and completes none. Counting distinct target extensions — not raw
            // attempts — is what keeps a legitimate endpoint safe: a phone registers its own
            // one (a device its few) AOR(s) however many times it retransmits, so it never
            // climbs, and a source that has logged in even once is exempt outright.
            let aor_text = req.to_user().or(req.request_user).unwrap_or("");
            let aor_hash = ext_id(aor_text);
            if is_register {
                let distinct = st.reg_probes.record(aor_hash, now.0, REG_SCAN_WINDOW_SECS);
                // A success for one AOR removes only that AOR (on the response path). It no
                // longer exempts the source from enumerating every other extension.
                if distinct as usize >= REG_SCAN_EXTENSIONS {
                    self.stats.reg_scans += 1;
                    return Decision::RegScan {
                        extensions: distinct,
                    };
                }
            }

            if credentialed {
                self.stats.auth_attempts += 1;
                if let Some(key) = sip::transaction_key(
                    req.via_branch(),
                    req.call_id.as_deref(),
                    req.cseq.as_deref(),
                ) {
                    st.pending.remember(
                        key,
                        now.0,
                        responder,
                        is_register.then_some(aor_hash),
                        false,
                    );
                }
                // The volume backstop, for deployments where no response is ever seen.
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

        // The perimeter has run and may have condemned the source. Behavioural detection is
        // opt-in; with it off, the INVITE is simply out of scope — the product is a noise
        // filter and nothing here pretends otherwise.
        if !self.behavioural {
            return Decision::OutOfScope("behavioural detection off");
        }

        let Some(dialed) = req.request_user else {
            return Decision::OutOfScope("INVITE with no dialled number");
        };

        if self.peers.len() >= MAX_PEERS && !self.peers.contains_key(&peer) {
            self.stats.peers_dropped += 1;
            return Decision::OutOfScope("peer ceiling reached");
        }
        let params = self.params.clone();
        let state = self.peers.entry(peer).or_insert_with(|| PeerState {
            dial_plan: self.default_plan.clone(),
            anomaly: SourceAnomaly::new(&params),
            ..Default::default()
        });

        // The cheapest filter on the hot path: whatever is not international leaves here,
        // without canonicalising and without touching any state.
        let Some((digits, prefix)) = state.dial_plan.to_international_with_prefix(dialed) else {
            return Decision::OutOfScope("not international for this peer");
        };
        self.stats.international += 1;

        let Some(c) = country::resolve(&digits) else {
            // International by shape, but with no recognisable country. **No block** —
            // that would be the R07 mistake. It carries the digits for diagnosis.
            self.stats.unknown_country += 1;
            return Decision::UnknownCountry(digits.0);
        };

        // The operator's own country is national traffic, not fraud — this is where an
        // inbound call to a home E.164 DID leaves, before the detector ever sees it.
        if self.home_countries.contains(&c.index.0) {
            self.stats.domestic += 1;
            return Decision::OutOfScope("home country");
        }

        Self::decide(
            Observation {
                prefix: &prefix,
                digits: &digits,
                request: req,
                country: c,
                now,
                responder,
            },
            state,
            self.mode,
            &mut self.stats,
        )
    }

    fn decide(
        obs: Observation<'_>,
        state: &mut PeerState,
        mode: Mode,
        stats: &mut Stats,
    ) -> Decision {
        let Observation {
            prefix,
            digits,
            request,
            country: c,
            now,
            responder,
        } = obs;
        // One observation feeds the source's sequential detector: the destination country,
        // the dialling prefix it discovered, and the destination range it probed, at this
        // instant. All the state — prefix variety, range novelty, volume — lives inside it.
        let v = state.anomaly.observe(c.index, prefix, &digits.0, now.0);
        state.dirty = true;
        // Remember the call so its final response can feed the completion arm.
        if let Some(key) = sip::transaction_key(
            request.via_branch(),
            request.call_id.as_deref(),
            request.cseq.as_deref(),
        ) {
            state
                .pending_intl
                .remember(key, now.0, responder, None, v.first_range);
        }
        // A first-time country registers as novelty for the report's thermometer.
        stats.novel += u64::from(v.first_time);
        stats.prefix_novel += u64::from(v.first_prefix);
        stats.range_novel += u64::from(v.first_range);
        let evidence_nats = v.evidence.round().max(0.0) as u32;

        if !v.fired {
            return Decision::Pass {
                country: c.iso,
                novel: v.first_time,
            };
        }
        if mode.is_learning(now) {
            stats.would_block += 1;
            return Decision::WouldBlock {
                country: c.iso,
                evidence_nats,
                countries: v.countries,
            };
        }
        if v.warming {
            stats.warming += 1;
            return Decision::Warming {
                country: c.iso,
                evidence_nats,
                countries: v.countries,
            };
        }
        stats.blocks += 1;
        Decision::Block {
            country: c.iso,
            evidence_nats,
            countries: v.countries,
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

    /// A REGISTER for a specific AOR, used by the NAT/enumeration tests.
    fn register_ext(n: u32, ext: &str, credential: bool) -> Vec<u8> {
        let auth = if credential {
            "Authorization: Digest username=\"1001\", realm=\"pbx\", response=\"deadbeef\"\r\n"
        } else {
            ""
        };
        format!(
            "REGISTER sip:pbx SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK{n}\r\n\
             From: <sip:1001@pbx>;tag=t1\r\n\
             To: <sip:{ext}@pbx>\r\n\
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
        // The tests here exercise the behavioural path, so they opt into it. The default
        // engine is perimeter-only — covered by `perimeter_runs_with_behavioural_off`.
        // Warm-up is a separate, explicitly tested gate; existing arm tests disable it.
        let mut e =
            Engine::new(DialPlan::new(["+", "00", "011", "9011"]), Mode::Active).with_behavioural();
        e.params_mut().warmup_secs = 0;
        e.params_mut().warmup_calls = 0;
        e
    }

    #[test]
    fn a_censys_options_probe_is_condemned_as_a_scanner() {
        // The exact case: an OPTIONS from a self-identifying scanner. Caught even with
        // behavioural off, and even though it is not an INVITE.
        let mut e = Engine::new(DialPlan::new(["00"]), Mode::Active);
        let probe = b"OPTIONS sip:test.echo@sip5060.net SIP/2.0\r\n\
                      Via: SIP/2.0/UDP h;branch=z\r\n\
                      From: \"censysinspect\" <sip:censysinspect@censys.io>;tag=t\r\n\
                      To: <sip:test.echo@sip5060.net>\r\n\
                      Call-ID: c\r\nCSeq: 1 OPTIONS\r\n\r\n";
        assert!(matches!(
            e.observe(peer(), probe, t(0)),
            Decision::Scanner { .. }
        ));
        assert_eq!(e.stats.scanners, 1);
    }

    #[test]
    fn perimeter_runs_with_behavioural_off_but_fraud_does_not() {
        // The default product: noise is still condemned, an international INVITE is not
        // judged for fraud.
        let mut e = Engine::new(DialPlan::new(["+", "00"]), Mode::Active);
        assert!(!e.behavioural_enabled());
        // A scanner is still caught by the perimeter.
        let scan = b"OPTIONS sip:x@pbx SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z\r\n\
                     From: <sip:x@pbx>;tag=t\r\nCall-ID: c\r\nCSeq: 1 OPTIONS\r\n\
                     User-Agent: friendly-scanner\r\n\r\n";
        assert!(matches!(
            e.observe(peer(), scan, t(0)),
            Decision::Noise { .. }
        ));
        // But an international INVITE is out of scope, and no pair state is created.
        assert!(matches!(
            e.observe(peer(), &invite("1001", "00442039967796"), t(1)),
            Decision::OutOfScope("behavioural detection off")
        ));
        assert_eq!(e.source_count(), 0, "no behavioural state when it is off");
    }

    fn t(s: u32) -> Timestamp {
        Timestamp(1_800_000_000 + s)
    }

    #[test]
    fn domestic_traffic_leaves_through_the_cheapest_filter() {
        let mut e = engine();
        let d = e.observe(peer(), &invite("200", "2005"), t(0));
        assert!(matches!(d, Decision::OutOfScope(_)));
        // The cheapest filter: it never reached the international path.
        assert_eq!(e.stats.international, 0);
    }

    #[test]
    fn a_call_to_the_home_country_is_national_not_international() {
        // An inbound call to your own E.164 DID resolves to your country — that is national
        // traffic and must leave before the detector sees it.
        let mut e = engine();
        assert!(e.set_home_countries(["BR"]).is_empty());
        let d = e.observe(peer(), &invite("200", "005511999998888"), t(0));
        assert!(
            matches!(d, Decision::OutOfScope("home country")),
            "a Brazilian destination is national for a BR operator: {d:?}"
        );
        assert_eq!(e.stats.domestic, 1);
        assert_eq!(
            e.stats.international, 1,
            "it was still counted as reaching the intl path"
        );
        // A different country is still international.
        assert!(matches!(
            e.observe(peer(), &invite("200", "00447700900123"), t(1)),
            Decision::Pass { country: "GB", .. }
        ));
    }

    #[test]
    fn an_unknown_home_country_label_is_reported() {
        let mut e = engine();
        assert_eq!(e.set_home_countries(["BR", "ZZ", "nanp"]), vec!["ZZ"]);
        assert_eq!(e.home_country_count(), 2);
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
    fn learning_mode_records_would_block_not_block() {
        // A completion scan under learning is recorded, never enforced.
        let mut e = Engine::new(DialPlan::new(["00"]), Mode::Learning { until: t(100_000) })
            .with_behavioural();
        let mut saw_would = false;
        for i in 0..25u32 {
            let dest = format!("00{}12345678", 30 + i);
            e.observe_packet(peer(), switch(), &invite_n(i, &dest), t(i * 30));
            let (_, d) =
                e.observe_packet(switch(), peer(), &invite_response(i, 404), t(i * 30 + 1));
            if matches!(d, Decision::WouldBlock { .. }) {
                saw_would = true;
            }
            assert!(
                !matches!(d, Decision::Block { .. }),
                "learning must not block"
            );
        }
        assert!(saw_would, "the scan should have produced a WouldBlock");
        assert_eq!(e.stats.blocks, 0);
    }

    /// An INVITE to `dest` with a distinct transaction `n`, and the softswitch's response.
    fn invite_n(n: u32, dest: &str) -> Vec<u8> {
        format!(
            "INVITE sip:{dest}@pbx SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK{n}\r\n\
             From: <sip:200@pbx>;tag=t1\r\nTo: <sip:{dest}@pbx>\r\n\
             Call-ID: call-{n}\r\nCSeq: {n} INVITE\r\n\r\n"
        )
        .into_bytes()
    }
    fn invite_response(n: u32, status: u16) -> Vec<u8> {
        format!(
            "SIP/2.0 {status} X\r\n\
             Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK{n}\r\n\
             From: <sip:200@pbx>;tag=t1\r\nTo: <sip:x@pbx>;tag=s\r\n\
             Call-ID: call-{n}\r\nCSeq: {n} INVITE\r\n\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn international_calls_that_never_complete_are_a_scan() {
        // The AT&T signature, end to end: a source dials many countries and every call is
        // rejected (404). The completion arm should fire.
        let mut e = engine();
        let mut fired = false;
        for i in 0..25u32 {
            let dest = format!("00{}12345678", 30 + i);
            e.observe_packet(peer(), switch(), &invite_n(i, &dest), t(i * 30));
            let (subject, d) =
                e.observe_packet(switch(), peer(), &invite_response(i, 404), t(i * 30 + 1));
            if matches!(d, Decision::Block { .. }) {
                assert_eq!(
                    subject,
                    peer(),
                    "the block lands on the caller, not the switch"
                );
                fired = true;
            }
        }
        assert!(
            fired,
            "many international attempts, none completing, must block"
        );
        assert!(e.stats.intl_failed > 0 && e.stats.intl_completed == 0);
    }

    #[test]
    fn international_calls_that_answer_are_not_a_scan() {
        let mut e = engine();
        let mut ever = false;
        for i in 0..40u32 {
            let dest = format!("00{}12345678", 30 + (i % 3)); // a few countries, all answer
            e.observe_packet(peer(), switch(), &invite_n(i, &dest), t(i * 60));
            ever |= matches!(
                e.observe_packet(switch(), peer(), &invite_response(i, 200), t(i * 60 + 1))
                    .1,
                Decision::Block { .. }
            );
        }
        assert!(!ever, "completing calls are not a scan");
        assert!(e.stats.intl_completed > 0);
    }

    /// An INVITE that carries a credential — the normal case for a registered PBX.
    fn invite_auth(n: u32, dest: &str) -> Vec<u8> {
        format!(
            "INVITE sip:{dest}@pbx SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK{n}\r\n\
             From: <sip:200@pbx>;tag=t1\r\nTo: <sip:{dest}@pbx>\r\n\
             Call-ID: call-{n}\r\nCSeq: {n} INVITE\r\n\
             Proxy-Authorization: Digest username=\"200\", realm=\"pbx\", response=\"x\"\r\n\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn authenticated_invites_still_feed_the_completion_arm() {
        // The auth path used to claim the transaction before the completion path, so every
        // authenticated INVITE was invisible to the arm that watches call outcomes. This is
        // the regression test for that.
        let mut e = engine();
        let mut fired = false;
        for i in 0..25u32 {
            let dest = format!("00{}12345678", 30 + i);
            e.observe_packet(peer(), switch(), &invite_auth(i, &dest), t(i * 30));
            fired |= matches!(
                e.observe_packet(switch(), peer(), &invite_response(i, 404), t(i * 30 + 1))
                    .1,
                Decision::Block { .. }
            );
        }
        assert_eq!(
            e.stats.intl_failed, 25,
            "every authenticated INVITE's 404 is a failed completion"
        );
        assert!(
            fired,
            "authenticated calls that never complete must still fire"
        );
    }

    #[test]
    fn a_digest_challenge_to_an_unauthenticated_invite_is_not_a_failure() {
        // The 401 is the normal proxy handshake, exactly as it is for REGISTER. Counting
        // it as a failed completion would make every authenticated PBX look like a scanner.
        let mut e = engine();
        e.observe_packet(peer(), switch(), &invite_n(1, "00442039967796"), t(0));
        e.observe_packet(switch(), peer(), &invite_response(1, 401), t(1));
        assert_eq!(e.stats.intl_failed, 0);
        assert_eq!(e.stats.intl_completed, 0);
    }

    #[test]
    fn a_rejected_credential_on_an_invite_is_an_auth_failure_not_a_completion() {
        let mut e = engine();
        e.observe_packet(peer(), switch(), &invite_auth(1, "00442039967796"), t(0));
        e.observe_packet(switch(), peer(), &invite_response(1, 401), t(1));
        assert_eq!(e.stats.auth_failures, 1);
        assert_eq!(e.stats.intl_failed, 0);
    }

    #[test]
    fn route_probing_within_one_country_is_caught() {
        // The premium-destination phase: one country, one dialling format, many ranges in
        // a burst. No completion needed — the range arm carries it.
        let mut e = Engine::new(DialPlan::new(["00"]), Mode::Active).with_behavioural();
        e.params_mut().warmup_secs = 0;
        e.params_mut().warmup_calls = 0;
        let mut fired = false;
        for i in 0..20u32 {
            let dest = format!("004420{:04}1234", i * 17);
            fired |= matches!(
                e.observe(peer(), &invite_n(i, &dest), t(i * 20)),
                Decision::Block { .. }
            );
        }
        assert!(fired, "a range-probing burst must fire");
        assert!(e.stats.range_novel > 0);
    }

    #[test]
    fn recalibration_refits_and_still_catches_a_scan() {
        // Feed settled, completing international traffic so the population failure rate is
        // low, then confirm a fresh completion scan still fires against the tighter baseline.
        let mut e = engine();
        for i in 0..600u32 {
            e.observe_packet(peer(), switch(), &invite_n(i, "00551199998888"), t(i * 10));
            e.observe_packet(switch(), peer(), &invite_response(i, 200), t(i * 10 + 1));
        }
        e.recalibrate();
        assert!(e.params().theta0c <= 0.7, "theta0c stays within its clamp");

        // A fresh scanner whose calls never complete is still caught.
        let scanner = Ipv4Addr::new(203, 0, 113, 9);
        let mut fired = false;
        for i in 0..25u32 {
            let dest = format!("00{}12345678", 30 + i);
            e.observe_packet(
                scanner,
                switch(),
                &invite_n(1000 + i, &dest),
                t(200_000 + i * 30),
            );
            fired |= matches!(
                e.observe_packet(
                    switch(),
                    scanner,
                    &invite_response(1000 + i, 404),
                    t(200_000 + i * 30 + 1)
                )
                .1,
                Decision::Block { .. }
            );
        }
        assert!(fired, "recalibration must not blind the detector to a scan");
    }

    #[test]
    fn a_legitimate_sip_username_is_not_injection() {
        let mut e = engine();
        let d = e.observe(peer(), &invite("o'brien", "00442039967796"), t(0));
        assert!(!matches!(d, Decision::Injection { .. }), "{d:?}");
        assert_eq!(e.stats.injections, 0);
    }

    #[test]
    fn an_injection_in_the_request_uri_is_still_caught() {
        let mut e = engine();
        let msg = b"INVITE sip:1001'@pbx SIP/2.0\r\n\
                    Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK1\r\n\
                    From: <sip:200@pbx>;tag=a\r\nTo: <sip:1001'@pbx>\r\n\
                    Call-ID: c1\r\nCSeq: 1 INVITE\r\n\r\n";
        assert!(matches!(
            e.observe(peer(), msg, t(0)),
            Decision::Injection { .. }
        ));
    }

    #[test]
    fn duplicate_singleton_headers_are_condemned() {
        // Two From (or Call-ID/CSeq/User-Agent) copies are ambiguous; the parser keeps the
        // first and the engine condemns the source instead of guessing which one the
        // softswitch will use.
        let msg = b"INVITE sip:00442039967796@pbx SIP/2.0\r\n\
                    Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK1\r\n\
                    From: <sip:200@pbx>;tag=a\r\n\
                    From: <sip:201@pbx>;tag=b\r\n\
                    To: <sip:00442039967796@pbx>\r\n\
                    Call-ID: c1\r\nCSeq: 1 INVITE\r\n\r\n";
        assert_eq!(
            eobserve(&mut engine(), msg),
            Decision::Malformed { header: "From" }
        );
    }

    fn eobserve(e: &mut Engine, msg: &[u8]) -> Decision {
        e.observe(peer(), msg, t(0))
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
    fn a_new_source_is_reported_but_not_blocked() {
        let mut e = Engine::new(DialPlan::new(["00"]), Mode::Active).with_behavioural();
        // Even after the floor is reached, a source younger than the per-source warm-up is
        // reported as WARMING, never as BLOCK.
        let mut saw = false;
        for i in 0..20u32 {
            let dest = format!("004420{:04}1234", i * 17);
            let d = e.observe(peer(), &invite_n(i, &dest), t(i * 20));
            saw |= matches!(d, Decision::Warming { .. });
            assert!(
                !matches!(d, Decision::Block { .. }),
                "warming must not block"
            );
        }
        assert!(saw, "the evidence should have crossed the bound");
        assert_eq!(e.stats.blocks, 0);
        assert!(e.stats.warming > 0);
    }

    #[test]
    fn a_warm_source_is_blocked() {
        let mut e = Engine::new(DialPlan::new(["00"]), Mode::Active).with_behavioural();
        e.params_mut().warmup_secs = 3600;
        e.params_mut().warmup_calls = 5;
        // Five benign international calls over the first 400 s.
        for i in 0..5u32 {
            e.observe_packet(peer(), switch(), &invite_n(i, "00442039967796"), t(i * 100));
            e.observe_packet(switch(), peer(), &invite_response(i, 200), t(i * 100 + 1));
        }
        // At t=4000 the source is older than the warm-up and has enough calls.
        let mut fired = false;
        for i in 5..25u32 {
            let dest = format!("004420{:04}1234", i * 17);
            let d = e.observe(peer(), &invite_n(i, &dest), t(4000 + i * 20));
            fired |= matches!(d, Decision::Block { .. });
        }
        assert!(fired, "a warm source crossing the bound is blocked");
    }

    #[test]
    fn a_peer_declared_plan_beats_the_default() {
        let mut e = Engine::new(DialPlan::new(["00"]), Mode::Active).with_behavioural();
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
    // A no-credential REGISTER probe against extension `ext` — the enumeration the
    // auth-failure rule (which needs a credential) cannot see.
    fn reg_probe(seq: u32, ext: &str) -> Vec<u8> {
        format!(
            "REGISTER sip:pbx SIP/2.0\r\nVia: SIP/2.0/UDP h;branch=z{seq}\r\n\
             From: <sip:{ext}@pbx>;tag=t\r\nTo: <sip:{ext}@pbx>\r\n\
             Call-ID: c{seq}\r\nCSeq: {seq} REGISTER\r\n\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn registration_scanning_across_extensions_is_caught() {
        // The user's case: an IP sprays a few REGISTERs per extension across the dial plan,
        // never authenticating. Counting distinct extensions, the scan is caught once it has
        // reached across enough of them, with no registration ever succeeding.
        let mut e = engine();
        let mut fired = false;
        let mut seq = 0u32;
        for ext in 1000..1014 {
            // a few tries per extension, as a real scanner paces it
            for _ in 0..4 {
                let reg = reg_probe(seq, &ext.to_string());
                fired |= matches!(
                    e.observe(peer(), &reg, t(seq * 5)),
                    Decision::RegScan { .. }
                );
                seq += 1;
            }
        }
        assert!(
            fired,
            "an IP probing many extensions without ever registering must be caught"
        );
        assert!(e.stats.reg_scans >= 1);
    }

    #[test]
    fn a_phone_retransmitting_its_one_registration_is_never_a_reg_scanner() {
        // The worst-case false positive: a legitimate phone on a lossy link retransmitting
        // its single REGISTER many times before it has ever succeeded, in a deployment where
        // no response is captured at all. One extension, so it must never be flagged.
        let mut e = engine();
        for seq in 0..30u32 {
            let reg = reg_probe(seq, "2001");
            assert!(
                !matches!(e.observe(peer(), &reg, t(seq)), Decision::RegScan { .. }),
                "a source touching only its own extension is not enumerating"
            );
        }
        assert_eq!(e.stats.reg_scans, 0);
    }

    #[test]
    fn a_multi_line_device_below_the_threshold_is_never_a_reg_scanner() {
        // A multi-line device (a few AORs) that has not yet succeeded — e.g. it registers all
        // its lines before any response returns — stays under the distinct-extension
        // threshold and is never flagged.
        let mut e = engine();
        let mut seq = 0u32;
        for round in 0..8 {
            for line in 0..(REG_SCAN_EXTENSIONS as u32 - 1) {
                let ext = format!("30{line:02}");
                assert!(
                    !matches!(
                        e.observe(peer(), &reg_probe(seq, &ext), t(round)),
                        Decision::RegScan { .. }
                    ),
                    "fewer than REG_SCAN_EXTENSIONS distinct AORs must never be flagged"
                );
                seq += 1;
            }
        }
        assert_eq!(e.stats.reg_scans, 0);
    }

    #[test]
    fn a_nat_whose_phones_register_successfully_is_not_a_reg_scanner() {
        // A NAT/gateway behind one IP: each phone succeeds. The successful AOR is removed
        // from the probe set, so a real NAT with captured responses is not an enumerator.
        let mut e = engine();
        let mut ever = false;
        for i in 0..10u32 {
            let ext = format!("30{i:02}");
            e.observe_packet(peer(), switch(), &register_ext(i, &ext, true), t(i));
            ever |= matches!(
                e.observe_packet(switch(), peer(), &response(i, 200), t(i + 1))
                    .1,
                Decision::RegScan { .. }
            );
        }
        assert!(
            !ever,
            "a NAT whose phones register successfully is not enumerating"
        );
        assert_eq!(e.stats.reg_scans, 0);
    }

    #[test]
    fn one_success_does_not_exempt_a_source_from_enumerating_other_aors() {
        // The security trade-off: a valid registration for one AOR no longer suppresses
        // RegScan for every other extension. An attacker with one valid account cannot
        // enumerate with impunity; a phone/NAT that has not yet completed the other lines
        // is still protected by the distinct-AOR threshold.
        let mut e = engine();
        e.observe_packet(peer(), switch(), &register(1, true), t(0));
        e.observe_packet(switch(), peer(), &response(1, 200), t(1));
        let mut fired = false;
        for i in 2..(2 + REG_SCAN_EXTENSIONS as u32) {
            let reg = reg_probe(i, &format!("40{i}"));
            fired |= matches!(e.observe(peer(), &reg, t(i * 5)), Decision::RegScan { .. });
        }
        assert!(fired, "one success must not exempt the other AORs");
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
    fn a_successful_auth_marks_a_known_good_registered_peer() {
        // pedro registers from a dynamic IP: REGISTER with credentials, 200 OK. That IP is
        // now a known-good peer and must be exempt from banning.
        let mut e = engine();
        assert!(!e.is_known_peer(peer(), t(0)));
        exchange(&mut e, 1, true, 200, 0); // authenticated REGISTER -> 200
        assert!(
            e.is_known_peer(peer(), t(1)),
            "an authenticated peer is known-good"
        );
        assert_eq!(e.known_peer_count(), 1);
        // It ages out after the TTL if it stops registering.
        assert!(!e.is_known_peer(peer(), Timestamp(t(0).0 + KNOWN_PEER_TTL_SECS + 1)));
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
    fn a_response_from_a_different_source_is_ignored() {
        // The responder is pinned when the request is recorded. A forged 200 from another
        // address must not mark the peer known-good or count as an authentication success.
        let mut e = engine();
        e.observe_packet(peer(), switch(), &register(1, true), t(0));
        let attacker = Ipv4Addr::new(198, 51, 100, 1);
        let (_, d) = e.observe_packet(attacker, peer(), &response(1, 200), t(1));
        assert!(matches!(d, Decision::OutOfScope(_)));
        assert_eq!(e.stats.auth_ok, 0);
        assert!(!e.is_known_peer(peer(), t(1)));

        // The real responder still matches.
        let (_, d) = e.observe_packet(switch(), peer(), &response(1, 200), t(2));
        assert!(matches!(d, Decision::OutOfScope(_)));
        assert_eq!(e.stats.auth_ok, 1);
        assert!(e.is_known_peer(peer(), t(2)));
    }

    #[test]
    fn an_authenticated_invite_success_does_not_mark_known_good() {
        // Only a successful REGISTER proves a registered peer. A 2xx to an authenticated
        // INVITE is a call, not a registration, and used to grant seven days of immunity.
        let mut e = engine();
        e.observe_packet(peer(), switch(), &invite_auth(1, "00442039967796"), t(0));
        e.observe_packet(switch(), peer(), &invite_response(1, 200), t(1));
        assert_eq!(e.stats.auth_ok, 1);
        assert!(!e.is_known_peer(peer(), t(1)));
    }

    #[test]
    fn one_success_does_not_clear_failures_for_another_aor() {
        // Four failures for 1001, a success for 2002, then one more failure for 1001. The
        // valid account must not wipe the other account's run.
        let mut e = engine();
        for n in 0..4u32 {
            e.observe_packet(peer(), switch(), &register_ext(n, "1001", true), t(n));
            e.observe_packet(switch(), peer(), &response(n, 401), t(n));
        }
        e.observe_packet(peer(), switch(), &register_ext(4, "2002", true), t(4));
        e.observe_packet(switch(), peer(), &response(4, 200), t(4));
        let (_, d) = {
            e.observe_packet(peer(), switch(), &register_ext(5, "1001", true), t(5));
            e.observe_packet(switch(), peer(), &response(5, 401), t(5))
        };
        assert!(
            matches!(d, Decision::AuthFailure { .. }),
            "a valid 2002 must not clear the 1001 run"
        );
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
    fn a_register_flood_with_no_success_is_stopped() {
        // Authenticated REGISTERs from one source that never complete — whether the
        // softswitch answers 401 or (as on the reference server) drops them silently. A flood
        // against a single extension is not enumeration, so the auth-volume backstop stops it;
        // a flood spread across extensions is caught by the registration-scan rule. Either
        // verdict is a stop, and neither needs a response to be seen.
        let mut e = engine();
        let mut caught = false;
        for n in 0..60 {
            let (_, d) = e.observe_packet(peer(), switch(), &register(n, true), t(n));
            caught |= matches!(d, Decision::RegScan { .. } | Decision::AuthAbuse { .. });
        }
        assert!(
            caught,
            "a flood of REGISTERs that never succeed must be stopped"
        );
    }
}
