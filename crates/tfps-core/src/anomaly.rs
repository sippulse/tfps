//! Sequential IRSF detection: the `--behavioural` layer.
//!
//! The design and its literature are in `docs/anomaly-detection.md`. In one paragraph: the
//! fraud has three phases — find a target, work out how to dial out internationally, then
//! find which premium destinations route. The first is SIP scanning and belongs to the
//! perimeter (REGISTER/OPTIONS probes, extension enumeration, rejected credentials). The
//! other two are **first-contact discovery** and are detected with a **Threshold Random
//! Walk** (Jung et al., IEEE S&P 2004) — a sequential probability ratio test over two
//! distinct alphabets: the **dialling prefix** (`00`, `011`, `9011`, `+`) and the
//! **destination range** (the B-number with its last four digits dropped). Exploitation is
//! a count-rate change and is detected with **hierarchical Gamma-Poisson surprise**. All
//! arms yield evidence in log-likelihood units, so they add, and enforcement fires when the
//! total crosses a bound set by the error rates (α, β) — not by a hand-picked threshold.
//!
//! Everything here is deterministic and allocation-light. Time and counts arrive as
//! parameters; the module reads no clock and does no I/O, so it is exhaustively testable.

use crate::country::CountryIndex;

/// A one-sided sequential probability ratio test — the engine of the scan arm.
///
/// Accumulates the log-likelihood ratio between a benign hypothesis (`theta0` = probability
/// a call is a "first contact") and a scanner hypothesis (`theta1`, larger). Each trial
/// moves the walk up (a first contact — evidence for scanning) or down (a repeat — evidence
/// against). It fires when the walk crosses the upper bound; it is clamped at a floor rather
/// than the classic lower bound, so a source that behaves for a long time does not build
/// unbounded credit that a later burst would have to erase.
#[derive(Debug, Clone)]
pub struct SeqTest {
    llr: f64,
    step_hit: f64,
    step_miss: f64,
    upper: f64,
    floor: f64,
}

impl SeqTest {
    /// Builds a test from the two hypotheses and the tolerated error rates.
    ///
    /// `theta0` < `theta1`, both in (0, 1); `alpha` is the false-alarm rate, `beta` the miss
    /// rate. The bound `ln((1−β)/α)` is Wald's, and it is where "how many is too many"
    /// stops being a guess.
    pub fn new(theta0: f64, theta1: f64, alpha: f64, beta: f64) -> Self {
        let upper = ((1.0 - beta) / alpha).ln();
        Self {
            llr: 0.0,
            step_hit: (theta1 / theta0).ln(),
            step_miss: ((1.0 - theta1) / (1.0 - theta0)).ln(),
            upper,
            // A bounded well: a benign source cannot bank more than one "clear" decision of
            // credit. `ln(β/(1−α))` is Wald's lower bound; the floor is set there.
            floor: (beta / (1.0 - alpha)).ln(),
        }
    }

    /// Records one trial. `first_contact` is the suspicious outcome (novel country/prefix).
    /// Returns the evidence, in nats, currently standing for this arm (never below zero for
    /// fusion — a benign arm contributes nothing, it does not subtract from the others).
    pub fn observe(&mut self, first_contact: bool) -> f64 {
        self.llr += if first_contact {
            self.step_hit
        } else {
            self.step_miss
        };
        self.llr = self.llr.clamp(self.floor, self.upper + 1.0);
        self.evidence()
    }

    /// Adopts new hypotheses and bounds, keeping the walk where it stands. Used when the
    /// population estimate of the benign rate improves.
    pub fn recalibrate(&mut self, theta0: f64, theta1: f64, alpha: f64, beta: f64) {
        self.step_hit = (theta1 / theta0).ln();
        self.step_miss = ((1.0 - theta1) / (1.0 - theta0)).ln();
        self.upper = ((1.0 - beta) / alpha).ln();
        self.floor = (beta / (1.0 - alpha)).ln();
        self.llr = self.llr.clamp(self.floor, self.upper + 1.0);
    }

    /// Leaks the walk toward zero. Applied by elapsed time before each trial, so novelty
    /// spread over hours never accumulates while a burst in minutes does — which is what
    /// separates a legitimate source discovering its few countries from a scanner.
    pub fn decay(&mut self, factor: f64) {
        self.llr *= factor;
    }

    /// The non-negative evidence this arm contributes to the fused total.
    pub fn evidence(&self) -> f64 {
        self.llr.max(0.0)
    }

    /// Would this arm fire on its own?
    pub fn fired(&self) -> bool {
        self.llr >= self.upper
    }

    pub fn bound(&self) -> f64 {
        self.upper
    }
}

/// The destination-range window. Route probing happens in a burst before the long calls
/// start; the walk's own half-life decides how much of it is evidence.
pub const RANGE_WINDOW_SECS: u32 = 900;

/// Per-arm hard floors. The SPRT decides when there is enough evidence; these keep a single
/// or two isolated events from being enough. They are the main false-positive control.
pub const PREFIX_MIN_NOVEL: u32 = 4;
pub const RANGE_MIN_NOVEL: u32 = 10;
pub const COMPLETION_MIN_NOVEL_FAILURES: u32 = 10;
pub const VOLUME_MIN_PERIODS: u32 = 6;

/// How many trailing digits are ignored when forming a destination range. Four groups
/// 10,000 numbers, which is the scale of an IPRN block and matches the durable unit
/// measured in the corpus.
pub const RANGE_DIGITS: usize = 4;

/// A small rotating Bloom filter of destination ranges seen in the current and previous
/// window. 1,024 bits with three hashes holds about 80 ranges at ~1% false positive (200 at
/// ~9%) — and a false positive only *misses* novelty, which is the safe direction.
const RANGE_BLOOM_WORDS: usize = 16;
const RANGE_BLOOM_BITS: usize = RANGE_BLOOM_WORDS * 64;
const RANGE_BLOOM_HASHES: usize = 3;

#[derive(Debug, Clone, Default)]
struct RangeBloom {
    bits: [u64; RANGE_BLOOM_WORDS],
}

impl RangeBloom {
    fn clear(&mut self) {
        self.bits = [0; RANGE_BLOOM_WORDS];
    }

    fn positions(h: u64) -> impl Iterator<Item = usize> {
        // Double hashing: h1 + i·h2, with h2 forced odd so it never collapses to zero.
        let h1 = h as usize;
        let h2 = ((h >> 32) as usize) | 1;
        (0..RANGE_BLOOM_HASHES).map(move |i| h1.wrapping_add(i.wrapping_mul(h2)) % RANGE_BLOOM_BITS)
    }

    fn contains(&self, h: u64) -> bool {
        Self::positions(h).all(|p| self.bits[p / 64] & (1u64 << (p % 64)) != 0)
    }

    fn insert(&mut self, h: u64) {
        for p in Self::positions(h) {
            self.bits[p / 64] |= 1u64 << (p % 64);
        }
    }
}

/// FNV-1a, so a range or prefix is one 64-bit identity without allocating.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 1469598103934665603;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

/// A source's international-call rate as a Gamma posterior, scored by Negative-Binomial
/// predictive surprise. The exploitation-phase arm.
///
/// `a`/`b` are the Gamma shape/rate. They start at the **population prior** so a source with
/// no history is judged against the population, not against zero — which is what keeps a
/// rare caller's first calls from looking anomalous.
#[derive(Debug, Clone)]
pub struct RateModel {
    a: f64,
    b: f64,
    decay: f64,
    /// Completed scoring periods. The volume arm contributes only after enough history.
    periods: u32,
}

impl RateModel {
    /// `prior_mean` is the population's typical count per scoring period; `prior_strength`
    /// is how many periods of pseudo-evidence it is worth (small = weak prior, adapts fast).
    /// `decay` in (0, 1] forgets old evidence so the baseline tracks legitimate growth.
    pub fn new(prior_mean: f64, prior_strength: f64, decay: f64) -> Self {
        Self {
            a: prior_mean * prior_strength,
            b: prior_strength,
            decay,
            periods: 0,
        }
    }

    /// Surprise of observing `count` this period, in bits, **before** folding it in — so a
    /// fraud spike is scored against the baseline it has not yet polluted.
    pub fn surprise_bits(&self, count: u32) -> f64 {
        if count == 0 {
            return 0.0;
        }
        // Predictive is NegBin(r=a, p=b/(b+1)); P(X ≥ count) = I_{1−p}(count, r), the
        // regularized incomplete beta. Its cost does not grow with the count: the old
        // lower-tail sum looped once per call in the window, on the capture thread.
        let r = self.a;
        let p = self.b / (self.b + 1.0);
        let sf = regularized_beta(count as f64, r, 1.0 - p)
            .clamp(0.0, 1.0)
            .max(1e-12);
        -sf.log2()
    }

    /// Folds a period's count into the posterior, with forgetting.
    pub fn update(&mut self, count: u32) {
        self.a = self.a * self.decay + count as f64;
        self.b = self.b * self.decay + 1.0;
        self.periods = self.periods.saturating_add(1);
    }

    /// The current mean-rate estimate, for reporting.
    pub fn rate(&self) -> f64 {
        self.a / self.b
    }
}

/// The parameters that define "how suspicious is suspicious", shared by every source.
///
/// Only the error rates and the two hypotheses live here — no per-source, per-install
/// numbers. The benign priors are meant to be learned from the deployment's own aggregate
/// traffic; these are the cold-start defaults.
#[derive(Debug, Clone)]
pub struct Params {
    pub theta1: f64,
    /// Dialling-prefix arm's benign first-contact rate. Most sources settle on one dialling
    /// format, so a novel prefix is rare — but a source *discovering* how to dial out
    /// (`00`, `011`, `9011`) produces exactly this, and that discovery is the signal.
    pub theta0_prefix: f64,
    /// Destination-range arm's benign first-contact rate. Higher than the prefix's: a
    /// legitimate source does discover new ranges (a new customer, a new office), just not
    /// dozens inside one burst.
    pub theta0_range: f64,
    /// Completion arm: probability a *final* international response is a failure. Benign
    /// traffic mostly completes; a scanner probing dead routes mostly does not.
    pub theta0c: f64,
    pub theta1c: f64,
    pub alpha: f64,
    pub beta: f64,
    pub prior_mean: f64,
    pub prior_strength: f64,
    pub decay: f64,
    /// Fused-evidence bound at which enforcement fires (nats). Derived from `alpha`/`beta`.
    pub fire_bits: f64,
    /// A new source is observed but not enforced for this long...
    pub warmup_secs: u32,
    /// ...and until it has this many international calls.
    pub warmup_calls: u32,
}

impl Default for Params {
    fn default() -> Self {
        // Novelty is not rare early in a source's life — a legitimate business discovers
        // its handful of destinations at the start — so theta0 allows for that. A low
        // alpha pushes the fire point to a burst of novel destinations, not a single debut.
        let (alpha, beta) = (1e-4, 1e-2);
        Self {
            theta1: 0.70,
            theta0_prefix: 0.05,
            theta0_range: 0.15,
            theta0c: 0.20,
            theta1c: 0.85,
            alpha,
            beta,
            prior_mean: 2.0,
            prior_strength: 1.0,
            decay: 0.98,
            fire_bits: ((1.0 - beta) / alpha).ln(),
            warmup_secs: 24 * 3600,
            warmup_calls: 20,
        }
    }
}

/// What observing one international call concluded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    /// Total fused evidence, in nats.
    pub evidence: f64,
    /// Contribution of the dialling-prefix arm.
    pub prefix_bits: f64,
    /// Contribution of the destination-range arm.
    pub range_bits: f64,
    /// Contribution of the volume arm.
    pub volume_bits: f64,
    /// Contribution of the completion arm.
    pub completion_bits: f64,
    /// Distinct countries this source has been seen to attempt.
    pub countries: u32,
    /// This country was a first for the source.
    pub first_time: bool,
    /// This dialling prefix was a first for the source.
    pub first_prefix: bool,
    /// This destination range was a first for the source in the window.
    pub first_range: bool,
    /// The fused evidence crossed the fire bound.
    pub fired: bool,
    /// The source has not yet been observed long enough to enforce against.
    pub warming: bool,
}

/// Per-source detector state.
#[derive(Debug, Clone)]
pub struct SourceAnomaly {
    /// Countries ever attempted, as a 256-bit set — no rotation, just membership.
    seen_countries: [u64; 4],
    n_countries: u32,
    /// Dialling-prefix identifiers ever used (hashed, capped), for the prefix-scan arm.
    seen_prefixes: u64,
    prefix_bits_set: u32,
    prefix_scan: SeqTest,
    /// Novel prefixes/ranges in the current hard-floor window.
    prefix_window: u32,
    prefix_novel_in_window: u32,
    range_novel_in_window: u32,
    /// Destination ranges seen in the current and previous window, and the walk over them.
    range_current: RangeBloom,
    range_previous: RangeBloom,
    range_window: u32,
    range_scan: SeqTest,
    /// Consecutive novel-range completion failures, and when the run started.
    completion_novel_failures: u32,
    completion_failure_window: u32,
    /// Completion arm: fed by observed international-call outcomes, not by the INVITE.
    completion_scan: SeqTest,
    rate: RateModel,
    /// International calls in the current volume window, and when it started.
    window_start: u32,
    window_count: u32,
    /// When the last INVITE was seen, for the scan arms' decay.
    last_scan: u32,
    /// When the last completion outcome was seen, for that arm's decay.
    last_completion: u32,
    /// Standing volume surprise (bits), decayed across windows.
    volume_evidence: f64,
    fire_bits: f64,
    /// Per-source warm-up: first international call and how many have been seen.
    first_seen: u32,
    calls_seen: u32,
    warmup_secs: u32,
    warmup_calls: u32,
}

/// The volume window: exploitation is scored per hour of international volume.
pub const VOLUME_WINDOW_SECS: u32 = 3600;

/// Half-life of the scan-arm walk. The burst that fires the scanner has to happen inside a
/// few multiples of this; novelty spread wider than that leaks away.
pub const SCAN_HALFLIFE_SECS: u32 = 600;

impl Default for SourceAnomaly {
    fn default() -> Self {
        Self::new(&Params::default())
    }
}

impl SourceAnomaly {
    pub fn new(p: &Params) -> Self {
        Self {
            seen_countries: [0; 4],
            n_countries: 0,
            seen_prefixes: 0,
            prefix_bits_set: 0,
            prefix_scan: SeqTest::new(p.theta0_prefix, p.theta1, p.alpha, p.beta),
            prefix_window: 0,
            prefix_novel_in_window: 0,
            range_novel_in_window: 0,
            range_current: RangeBloom::default(),
            range_previous: RangeBloom::default(),
            range_window: 0,
            range_scan: SeqTest::new(p.theta0_range, p.theta1, p.alpha, p.beta),
            completion_novel_failures: 0,
            completion_failure_window: 0,
            completion_scan: SeqTest::new(p.theta0c, p.theta1c, p.alpha, p.beta),
            rate: RateModel::new(p.prior_mean, p.prior_strength, p.decay),
            window_start: 0,
            window_count: 0,
            last_scan: 0,
            last_completion: 0,
            volume_evidence: 0.0,
            fire_bits: p.fire_bits,
            first_seen: 0,
            calls_seen: 0,
            warmup_secs: p.warmup_secs,
            warmup_calls: p.warmup_calls,
        }
    }

    fn country_seen(&self, c: CountryIndex) -> bool {
        let (w, b) = (c.0 as usize / 64, c.0 as usize % 64);
        self.seen_countries[w] & (1u64 << b) != 0
    }

    fn mark_country(&mut self, c: CountryIndex) -> bool {
        let (w, b) = (c.0 as usize / 64, c.0 as usize % 64);
        if self.seen_countries[w] & (1u64 << b) != 0 {
            return false;
        }
        self.seen_countries[w] |= 1u64 << b;
        self.n_countries += 1;
        true
    }

    /// A 6-bit slot for a prefix, so "have I seen this prefix" is one bitmask test. Distinct
    /// dial prefixes are few; a hash into 64 slots is plenty and cannot grow.
    fn prefix_first_contact(&mut self, prefix: &str) -> bool {
        let bit = 1u64 << (fnv1a(prefix.as_bytes()) % 64);
        if self.seen_prefixes & bit != 0 {
            return false;
        }
        self.seen_prefixes |= bit;
        self.prefix_bits_set += 1;
        true
    }

    fn rotate_prefix(&mut self, now: u32) {
        if self.prefix_window == 0 {
            self.prefix_window = now;
            return;
        }
        if now.saturating_sub(self.prefix_window) >= RANGE_WINDOW_SECS {
            self.prefix_window = now;
            self.prefix_novel_in_window = 0;
        }
    }

    /// Rotates the range window lazily, on a call rather than on a timer. One window of
    /// memory is kept so a probe that straddles a boundary is not counted twice.
    fn rotate_ranges(&mut self, now: u32) {
        if self.range_window == 0 {
            self.range_window = now;
            return;
        }
        let elapsed = now.saturating_sub(self.range_window);
        if elapsed < RANGE_WINDOW_SECS {
            return;
        }
        if elapsed >= 2 * RANGE_WINDOW_SECS {
            self.range_previous.clear();
            self.range_current.clear();
        } else {
            core::mem::swap(&mut self.range_previous, &mut self.range_current);
            self.range_current.clear();
        }
        self.range_novel_in_window = 0;
        self.range_window = now;
    }

    /// Has this source dialled this destination range in the current or previous window?
    fn range_first_contact(&mut self, digits: &str, now: u32) -> bool {
        self.rotate_ranges(now);
        let end = digits.len().saturating_sub(RANGE_DIGITS);
        let Some(range) = digits.get(..end) else {
            return false;
        };
        if range.is_empty() {
            return false;
        }
        let h = fnv1a(range.as_bytes());
        if self.range_current.contains(h) || self.range_previous.contains(h) {
            return false;
        }
        self.range_current.insert(h);
        true
    }

    /// Observes one international call from this source: to `country`, dialled with
    /// `prefix` (the outbound format: `00`, `011`, `9011`, `+`), to a destination whose
    /// canonical digits are `digits`, at `now`. Returns the fused verdict.
    pub fn observe(
        &mut self,
        country: CountryIndex,
        prefix: &str,
        digits: &str,
        now: u32,
    ) -> Verdict {
        if self.first_seen == 0 {
            self.first_seen = now;
        }
        self.calls_seen = self.calls_seen.saturating_add(1);

        // Roll the volume window; score the closed window before resetting.
        if self.window_start == 0 {
            self.window_start = now;
        } else if now.saturating_sub(self.window_start) >= VOLUME_WINDOW_SECS {
            let bits = self.rate.surprise_bits(self.window_count);
            self.rate.update(self.window_count);
            // Decay the standing volume evidence and add this window's, so a single quiet
            // window does not erase a spike but sustained calm does.
            self.volume_evidence = self.volume_evidence * 0.5 + bits;
            self.window_start = now;
            self.window_count = 0;
        }
        self.window_count += 1;

        // Leak both scan walks by the time since the last INVITE — a 10-minute half-life,
        // so a burst inside the 5-15 min window still counts while slow variety leaks away.
        if self.last_scan != 0 {
            let dt = now.saturating_sub(self.last_scan) as f64;
            self.prefix_scan
                .decay(0.5f64.powf(dt / SCAN_HALFLIFE_SECS as f64));
            self.range_scan
                .decay(0.5f64.powf(dt / SCAN_HALFLIFE_SECS as f64));
        }
        self.last_scan = now;

        // The seen-country set is still tracked, for the report and for `tfps_ctl`. It is
        // not a separate arm: every new country is a new range, so counting both would
        // double the same first-contact event.
        let first_time = !self.country_seen(country);
        self.mark_country(country);

        self.rotate_prefix(now);
        let novel_prefix = self.prefix_first_contact(prefix);
        if novel_prefix {
            self.prefix_novel_in_window = self.prefix_novel_in_window.saturating_add(1);
        }
        self.prefix_scan.observe(novel_prefix);

        let novel_range = self.range_first_contact(digits, now);
        if novel_range {
            self.range_novel_in_window = self.range_novel_in_window.saturating_add(1);
        }
        self.range_scan.observe(novel_range);

        let mut v = self.fused(first_time, now);
        v.first_prefix = novel_prefix;
        v.first_range = novel_range;
        v
    }

    /// Records an observed **outcome** of an international call from this source: whether it
    /// completed (a `2xx`) or failed (a final `4xx`/`5xx`/`6xx`). Provisional responses and
    /// unseen ones are never fed here — silence is not evidence, the same honesty the auth
    /// rule keeps. Returns the refreshed verdict, which may now fire.
    pub fn observe_completion(&mut self, completed: bool, novel: bool, now: u32) -> Verdict {
        if self.last_completion != 0 {
            let dt = now.saturating_sub(self.last_completion) as f64;
            self.completion_scan
                .decay(0.5f64.powf(dt / SCAN_HALFLIFE_SECS as f64));
        }
        // Completions run on their own clock, so an INVITE never dilutes this arm's decay.
        self.last_completion = now;
        if completed {
            // A completed call is benign evidence and ends a failure run.
            self.completion_novel_failures = 0;
            self.completion_failure_window = 0;
            self.completion_scan.observe(false);
        } else if novel {
            // Only a failure to a first-contact range is scan evidence. An outage against
            // destinations the source already calls is not a route probe.
            if self.completion_failure_window == 0 {
                self.completion_failure_window = now;
            } else if now.saturating_sub(self.completion_failure_window) >= VOLUME_WINDOW_SECS {
                self.completion_failure_window = now;
                self.completion_novel_failures = 0;
            }
            self.completion_novel_failures = self.completion_novel_failures.saturating_add(1);
            self.completion_scan.observe(true);
        }
        self.fused(false, now)
    }

    /// Fuses the arms into a verdict. Each arm contributes its non-negative evidence, so a
    /// well-behaved arm never masks another.
    fn fused(&self, first_time: bool, now: u32) -> Verdict {
        let warmed = self.first_seen != 0
            && self.calls_seen >= self.warmup_calls
            && now.saturating_sub(self.first_seen) >= self.warmup_secs;
        // Each arm contributes only after a hard floor. A single novel country/prefix/range
        // (or two) is not enough; the floors are the false-positive control, the SPRT is
        // still what decides once the burst is real.
        let prefix_bits = if self.prefix_novel_in_window >= PREFIX_MIN_NOVEL {
            self.prefix_scan.evidence()
        } else {
            0.0
        };
        let range_bits = if self.range_novel_in_window >= RANGE_MIN_NOVEL {
            self.range_scan.evidence()
        } else {
            0.0
        };
        let completion_bits = if self.completion_novel_failures >= COMPLETION_MIN_NOVEL_FAILURES {
            self.completion_scan.evidence()
        } else {
            0.0
        };
        // Volume evidence is in bits; convert to nats to share units with the walks. A new
        // source needs several completed periods before a spike is measured against its own
        // norm rather than the cold-start population prior.
        let volume_bits = if self.rate.periods >= VOLUME_MIN_PERIODS {
            self.volume_evidence * core::f64::consts::LN_2
        } else {
            0.0
        };
        let evidence = prefix_bits + range_bits + completion_bits + volume_bits;
        Verdict {
            evidence,
            prefix_bits,
            range_bits,
            volume_bits,
            completion_bits,
            countries: self.n_countries,
            first_time,
            first_prefix: false,
            first_range: false,
            fired: evidence >= self.fire_bits,
            warming: !warmed,
        }
    }

    /// Adopts calibrated hypotheses across the arms, keeping their walks.
    pub fn recalibrate(&mut self, p: &Params) {
        self.prefix_scan
            .recalibrate(p.theta0_prefix, p.theta1, p.alpha, p.beta);
        self.range_scan
            .recalibrate(p.theta0_range, p.theta1, p.alpha, p.beta);
        self.completion_scan
            .recalibrate(p.theta0c, p.theta1c, p.alpha, p.beta);
        self.fire_bits = p.fire_bits;
    }

    /// The source's learned international-call rate, for the population prior fit.
    pub fn learned_rate(&self) -> f64 {
        self.rate.rate()
    }

    pub fn distinct_countries(&self) -> u32 {
        self.n_countries
    }

    /// The slow-moving state worth persisting: which countries this source has been seen to
    /// call, and its learned rate posterior. The fast walk evidence is intra-burst and, like
    /// the old debut window, is not persisted — a restart loses at most a burst's worth.
    pub fn snapshot(&self) -> AnomalySnapshot {
        AnomalySnapshot {
            seen_countries: self.seen_countries,
            n_countries: self.n_countries,
            rate_a: self.rate.a,
            rate_b: self.rate.b,
        }
    }

    /// Rebuilds from a snapshot at boot.
    pub fn from_snapshot(p: &Params, snap: AnomalySnapshot) -> Self {
        let mut me = Self::new(p);
        me.seen_countries = snap.seen_countries;
        me.n_countries = snap.n_countries;
        me.rate.a = snap.rate_a;
        me.rate.b = snap.rate_b;
        // The per-source warm-up is deliberately NOT marked warm here. Persisting a peer
        // after a few minutes would otherwise let a restart convert a cold source into a
        // warm one; the safe direction is to restart the short warm-up. The country set and
        // rate posterior still survive, and the global learning window is untouched.
        me
    }
}

/// The durable part of a source's detector state.
#[derive(Debug, Clone)]
pub struct AnomalySnapshot {
    pub seen_countries: [u64; 4],
    pub n_countries: u32,
    pub rate_a: f64,
    pub rate_b: f64,
}

/// Continued fraction for the incomplete beta (Lentz's method, Numerical Recipes §6.4).
/// A few dozen iterations, independent of the count.
fn betacf(a: f64, b: f64, x: f64) -> f64 {
    const MAXIT: usize = 200;
    const EPS: f64 = 3.0e-14;
    const FPMIN: f64 = 1.0e-300;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < FPMIN {
        d = FPMIN;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=MAXIT {
        let mf = m as f64;
        let m2 = 2.0 * mf;
        let aa = mf * (b - mf) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        h *= d * c;
        let aa = -(a + mf) * (qab + mf) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < EPS {
            break;
        }
    }
    h
}

/// The regularized incomplete beta I_x(a,b), which is the Negative-Binomial survival
/// function the volume arm needs.
fn regularized_beta(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let ln_bt = ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * x.ln() + b * (1.0 - x).ln();
    // Below this the survival function is far under the 1e-12 floor the caller clamps at;
    // returning the floor without running the continued fraction keeps a huge window O(1).
    if ln_bt < -60.0 {
        return 0.0;
    }
    let bt = ln_bt.exp();
    if x < (a + 1.0) / (a + b + 2.0) {
        bt * betacf(a, b, x) / a
    } else {
        1.0 - bt * betacf(b, a, 1.0 - x) / b
    }
}

/// A minimal `ln Γ(x)` (Lanczos), so the module carries no numeric dependency. Accurate to
/// well past what a surprise-in-bits needs.
fn ln_gamma(x: f64) -> f64 {
    const G: f64 = 7.0;
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        // Reflection, so the small counts near zero are exact.
        (core::f64::consts::PI / (core::f64::consts::PI * x).sin()).ln() - ln_gamma(1.0 - x)
    } else {
        let x = x - 1.0;
        let mut a = C[0];
        let t = x + G + 0.5;
        for (i, &c) in C.iter().enumerate().skip(1) {
            a += c / (x + i as f64);
        }
        0.5 * (2.0 * core::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ci(i: u16) -> CountryIndex {
        CountryIndex(i)
    }

    #[test]
    fn ln_gamma_matches_known_factorials() {
        // Γ(n) = (n−1)!  — a cheap correctness anchor for the surprise maths.
        assert!((ln_gamma(5.0) - 24.0f64.ln()).abs() < 1e-9, "Γ(5)=4!");
        assert!((ln_gamma(1.0)).abs() < 1e-9, "Γ(1)=1");
        assert!(
            (ln_gamma(0.5) - core::f64::consts::PI.sqrt().ln()).abs() < 1e-9,
            "Γ(½)=√π"
        );
    }

    #[test]
    fn a_known_country_is_evidence_against_scanning() {
        let p = Params::default();
        let mut t = SeqTest::new(p.theta0_prefix, p.theta1, p.alpha, p.beta);
        let after_hit = t.observe(true);
        let after_miss = t.observe(false);
        assert!(
            after_miss < after_hit,
            "a repeat call reduces the standing evidence"
        );
    }

    #[test]
    fn cold_start_does_not_punish_the_rare_caller() {
        // The explicit worry: a source that almost never calls, making a couple of calls,
        // must not be flagged on volume.
        let p = Params::default();
        let m = RateModel::new(p.prior_mean, p.prior_strength, p.decay);
        assert!(
            m.surprise_bits(3) < 4.0,
            "3 calls against the population prior is mild"
        );
    }

    #[test]
    fn a_settled_source_spiking_is_many_bits() {
        let p = Params::default();
        let mut m = RateModel::new(p.prior_mean, p.prior_strength, p.decay);
        // 30 periods at ~2 calls each: the posterior learns "normal is 2".
        for _ in 0..30 {
            m.update(2);
        }
        assert!(m.surprise_bits(3) < 5.0, "a normal day is unremarkable");
        assert!(m.surprise_bits(40) > 20.0, "a 20x spike is a loud signal");
    }

    #[test]
    fn the_prefix_arm_treats_each_new_prefix_as_a_first_contact() {
        let p = Params::default();
        let mut s = SourceAnomaly::new(&p);
        // Same country throughout, so only the prefix arm can move.
        let v1 = s.observe(ci(1), "00", "442039967796", 0);
        let v2 = s.observe(ci(1), "011", "442039967796", 0);
        let v3 = s.observe(ci(1), "9011", "442039967796", 0);
        let v4 = s.observe(ci(1), "+", "442039967796", 0);
        let v5 = s.observe(ci(1), "00", "442039967796", 0); // a repeat prefix
        assert_eq!(v1.prefix_bits, 0.0, "below the floor");
        assert_eq!(v2.prefix_bits, 0.0, "below the floor");
        assert_eq!(v3.prefix_bits, 0.0, "below the floor");
        assert!(
            v4.prefix_bits > 0.0,
            "the arm contributes once the four-prefix floor is reached"
        );
        assert!(
            v5.prefix_bits < v4.prefix_bits,
            "reusing a prefix is evidence against"
        );
    }

    #[test]
    fn failed_completions_are_evidence_of_scanning() {
        // The AT&T signature: attempts that never complete. A source whose international
        // calls keep failing accumulates evidence; one whose calls answer does not.
        let p = Params::default();
        let mut s = SourceAnomaly::new(&p);
        // Seed some novel ranges so the source is plausibly mid-scan, then feed failures.
        for i in 0..4u16 {
            let digits = format!("{}0000000", 30 + i);
            s.observe(ci(i), "+", &digits, i as u32 * 60);
        }
        let mut fired = false;
        for k in 0..20 {
            fired |= s.observe_completion(false, true, 240 + k * 30).fired; // nothing answers
        }
        assert!(fired, "many novel ranges and nothing completing must fire");

        // A source whose calls complete does not accumulate completion evidence.
        let mut s = SourceAnomaly::new(&p);
        let mut ever = false;
        for k in 0..40 {
            ever |= s.observe_completion(true, true, k * 60).fired;
        }
        assert!(!ever, "calls that answer are not a scan");
    }

    #[test]
    fn evidence_never_goes_negative_so_one_arm_cannot_mask_another() {
        // Fusion adds non-negative arms: a very well-behaved volume history must not bank
        // credit that hides a country scan.
        let p = Params::default();
        let mut s = SourceAnomaly::new(&p);
        for i in 0..20u16 {
            let digits = format!("{}0000000", 30 + i);
            let v = s.observe(ci(i), "+", &digits, 0);
            assert!(
                v.prefix_bits >= 0.0
                    && v.range_bits >= 0.0
                    && v.completion_bits >= 0.0
                    && v.volume_bits >= 0.0
            );
        }
    }

    #[test]
    fn the_range_arm_fires_on_route_probing_within_one_country() {
        // The phase the old detector could not see: many distinct destination ranges
        // dialled quickly, all through one country and one dialling prefix. A premium-rate
        // route scan looks exactly like this.
        let p = Params::default();
        let mut s = SourceAnomaly::new(&p);
        let mut fired = false;
        for i in 0..20u32 {
            // Same country (GB), same dialling format, a different range each time.
            let digits = format!("4420{:04}1234", i * 17);
            let v = s.observe(ci(1), "00", &digits, i * 20);
            fired |= v.fired;
            assert!(v.first_range, "each range is a first contact");
        }
        assert!(fired, "probing many ranges in a burst must fire");
    }

    #[test]
    fn the_range_arm_requires_ten_novel_ranges() {
        let p = Params::default();
        let mut s = SourceAnomaly::new(&p);
        for i in 0..9u32 {
            let v = s.observe(ci(1), "00", &format!("4420{:04}1234", i * 17), i * 20);
            assert!(!v.fired, "nine novel ranges are below the floor");
        }
        let v = s.observe(ci(1), "00", "442099991234", 200);
        assert!(v.fired, "the tenth novel range reaches the floor");
    }

    #[test]
    fn the_completion_arm_requires_ten_novel_failures() {
        let p = Params::default();
        let mut s = SourceAnomaly::new(&p);
        for k in 0..9u32 {
            let v = s.observe_completion(false, true, k * 20);
            assert!(!v.fired, "nine failures are below the floor");
        }
        assert!(s.observe_completion(false, true, 200).fired);
    }

    #[test]
    fn failures_to_known_ranges_are_not_scan_evidence() {
        let p = Params::default();
        let mut s = SourceAnomaly::new(&p);
        for k in 0..30u32 {
            let v = s.observe_completion(false, false, k * 20);
            assert!(
                !v.fired,
                "an outage against known destinations is not a probe"
            );
        }
    }

    #[test]
    fn the_volume_arm_waits_for_six_periods() {
        let p = Params::default();
        let mut m = RateModel::new(p.prior_mean, p.prior_strength, p.decay);
        for _ in 0..5 {
            m.update(2);
        }
        assert_eq!(m.periods, 5);
        m.update(2);
        assert_eq!(m.periods, 6);
    }

    #[test]
    fn repeating_one_range_is_evidence_against_probing() {
        let p = Params::default();
        let mut s = SourceAnomaly::new(&p);
        // Reach the ten-range floor first, so the arm contributes evidence.
        for i in 0..10u32 {
            s.observe(ci(1), "00", &format!("4420{:04}1234", i * 17), i * 20);
        }
        let hit = s.observe(ci(1), "00", "442099991234", 200);
        let again = s.observe(ci(1), "00", "442099991234", 220);
        assert!(hit.first_range);
        assert!(!again.first_range, "the same range is not a new contact");
        assert!(
            again.range_bits < hit.range_bits,
            "a repeat is evidence against"
        );
    }

    #[test]
    fn surprise_matches_the_brute_force_tail() {
        // The incomplete-beta form must agree with the definition it replaced. Checked
        // only where the tail is still representable, since both clamp at 1e-12.
        for (mean, strength) in [(2.0, 1.0), (40.0, 5.0), (0.5, 2.0)] {
            let m = RateModel::new(mean, strength, 0.98);
            let r = m.a;
            let p = m.b / (m.b + 1.0);
            for count in 0..40u32 {
                let mut cdf = 0.0f64;
                for j in 0..count {
                    let jf = j as f64;
                    let logpmf = ln_gamma(jf + r) - ln_gamma(r) - ln_gamma(jf + 1.0)
                        + r * p.ln()
                        + jf * (1.0 - p).ln();
                    cdf += logpmf.exp();
                }
                let brute = -(1.0 - cdf).max(1e-12).log2();
                if brute < 39.0 {
                    let fast = m.surprise_bits(count);
                    assert!(
                        (fast - brute).abs() < 1e-3,
                        "mean={mean} strength={strength} count={count}: fast={fast} brute={brute}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_huge_window_is_scored_without_iterating_over_it() {
        // The old tail sum did one iteration per call. A million-call window now costs the
        // same as a hundred-call one, and both saturate at the same reported floor.
        let p = Params::default();
        let m = RateModel::new(p.prior_mean, p.prior_strength, p.decay);
        assert!((m.surprise_bits(1_000_000) - 39.9).abs() < 0.1);
    }
}
