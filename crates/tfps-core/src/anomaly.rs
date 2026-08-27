//! Sequential IRSF detection: the `--behavioural` layer.
//!
//! The design and its literature are in `docs/anomaly-detection.md`. In one paragraph: the
//! fraud has a **scanning** phase (many distinct countries and prefixes, fast, mostly not
//! completing) and an **exploitation** phase (high call volume to the one route found). The
//! first is a port scan and is detected with a **Threshold Random Walk** (Jung et al.,
//! IEEE S&P 2004) — a sequential probability ratio test; the second is a count-rate change
//! and is detected with **hierarchical Gamma-Poisson surprise**. Both yield evidence in
//! log-likelihood units, so they add, and enforcement fires when the total crosses a bound
//! set by the error rates (α, β) — not by a hand-picked threshold.
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
        }
    }

    /// Surprise of observing `count` this period, in bits, **before** folding it in — so a
    /// fraud spike is scored against the baseline it has not yet polluted.
    pub fn surprise_bits(&self, count: u32) -> f64 {
        // Predictive is NegBin(r=a, p=b/(b+1)); surprise = −log2 P(X ≥ count).
        let r = self.a;
        let p = self.b / (self.b + 1.0);
        let mut cdf_below = 0.0f64;
        for j in 0..count {
            let jf = j as f64;
            let logpmf = ln_gamma(jf + r) - ln_gamma(r) - ln_gamma(jf + 1.0)
                + r * p.ln()
                + jf * (1.0 - p).ln();
            cdf_below += logpmf.exp();
        }
        let sf = (1.0 - cdf_below).max(1e-12);
        -sf.log2()
    }

    /// Folds a period's count into the posterior, with forgetting.
    pub fn update(&mut self, count: u32) {
        self.a = self.a * self.decay + count as f64;
        self.b = self.b * self.decay + 1.0;
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
    pub theta0: f64,
    pub theta1: f64,
    pub alpha: f64,
    pub beta: f64,
    pub prior_mean: f64,
    pub prior_strength: f64,
    pub decay: f64,
    /// Fused-evidence bound at which enforcement fires (nats). Derived from `alpha`/`beta`.
    pub fire_bits: f64,
}

impl Default for Params {
    fn default() -> Self {
        // Novelty is not rare early in a source's life — a legitimate business discovers
        // its handful of countries at the start — so theta0 allows for that. A low alpha
        // pushes the fire point out to "many rapid novel countries", matching the field
        // description ("dozens"), not three.
        let (alpha, beta) = (1e-4, 1e-2);
        Self {
            theta0: 0.15,
            theta1: 0.70,
            alpha,
            beta,
            prior_mean: 2.0,
            prior_strength: 1.0,
            decay: 0.98,
            fire_bits: ((1.0 - beta) / alpha).ln(),
        }
    }
}

/// What observing one international call concluded.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    /// Total fused evidence, in nats.
    pub evidence: f64,
    /// Contribution of the country-scan arm.
    pub country_bits: f64,
    /// Contribution of the prefix-scan arm.
    pub prefix_bits: f64,
    /// Contribution of the volume arm.
    pub volume_bits: f64,
    /// Distinct countries this source has been seen to attempt.
    pub countries: u32,
    /// The fused evidence crossed the fire bound.
    pub fired: bool,
}

/// Per-source detector state.
#[derive(Debug, Clone)]
pub struct SourceAnomaly {
    /// Countries ever attempted, as a 256-bit set — no rotation, just membership.
    seen_countries: [u64; 4],
    n_countries: u32,
    country_scan: SeqTest,
    /// Prefix identifiers ever used (hashed, capped), for the prefix-scan arm.
    seen_prefixes: u64,
    prefix_bits_set: u32,
    prefix_scan: SeqTest,
    rate: RateModel,
    /// International calls in the current volume window, and when it started.
    window_start: u32,
    window_count: u32,
    /// When the last call from this source was seen, for the scan-arm decay.
    last_call: u32,
    /// Standing volume surprise (bits), decayed across windows.
    volume_evidence: f64,
    fire_bits: f64,
}

/// The volume window: exploitation is scored per hour of international volume.
pub const VOLUME_WINDOW_SECS: u32 = 3600;

/// Half-life of the scan-arm walk. The burst that fires the scanner has to happen inside a
/// few multiples of this; novelty spread wider than that leaks away.
pub const SCAN_HALFLIFE_SECS: u32 = 600;

impl SourceAnomaly {
    pub fn new(p: &Params) -> Self {
        Self {
            seen_countries: [0; 4],
            n_countries: 0,
            country_scan: SeqTest::new(p.theta0, p.theta1, p.alpha, p.beta),
            seen_prefixes: 0,
            prefix_bits_set: 0,
            prefix_scan: SeqTest::new(p.theta0, p.theta1, p.alpha, p.beta),
            rate: RateModel::new(p.prior_mean, p.prior_strength, p.decay),
            window_start: 0,
            window_count: 0,
            last_call: 0,
            volume_evidence: 0.0,
            fire_bits: p.fire_bits,
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
        let mut h: u64 = 1469598103934665603;
        for byte in prefix.bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(1099511628211);
        }
        let bit = 1u64 << (h % 64);
        if self.seen_prefixes & bit != 0 {
            return false;
        }
        self.seen_prefixes |= bit;
        self.prefix_bits_set += 1;
        true
    }

    /// Observes one international call from this source: to `country`, dialled with
    /// `prefix`, at `now`. Returns the fused verdict.
    pub fn observe(&mut self, country: CountryIndex, prefix: &str, now: u32) -> Verdict {
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

        // Leak the scan walks by the time since the last call — a 10-minute half-life, so
        // the burst window the field description calls out (5-15 min) is exactly the scale
        // over which novelty still counts as a burst.
        if self.last_call != 0 {
            let dt = now.saturating_sub(self.last_call) as f64;
            let factor = 0.5f64.powf(dt / SCAN_HALFLIFE_SECS as f64);
            self.country_scan.decay(factor);
            self.prefix_scan.decay(factor);
        }
        self.last_call = now;

        // Scan arms: novelty is the first-contact event.
        let novel_country = !self.country_seen(country);
        self.mark_country(country);
        let country_bits = self.country_scan.observe(novel_country);

        let novel_prefix = self.prefix_first_contact(prefix);
        let prefix_bits = self.prefix_scan.observe(novel_prefix);

        // Volume evidence is in bits; convert to nats to share units with the walks.
        let volume_bits = self.volume_evidence * core::f64::consts::LN_2;
        let evidence = country_bits + prefix_bits + volume_bits;

        Verdict {
            evidence,
            country_bits,
            prefix_bits,
            volume_bits,
            countries: self.n_countries,
            fired: evidence >= self.fire_bits,
        }
    }

    pub fn distinct_countries(&self) -> u32 {
        self.n_countries
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
    fn the_scan_arm_fires_fast_on_a_scanner_and_never_on_breadth() {
        let p = Params::default();
        // A scanner: a new country almost every call.
        let mut s = SourceAnomaly::new(&p);
        // A scanner: a new country roughly every minute — a burst.
        let mut fired_at = None;
        for i in 0..20u16 {
            let v = s.observe(ci(i), "+", i as u32 * 60);
            if v.fired && fired_at.is_none() {
                fired_at = Some(i);
            }
        }
        assert!(
            fired_at.is_some_and(|i| i < 15),
            "a rapid scanner is caught: {fired_at:?}"
        );

        // A legitimate call centre: 3 distinct countries, even a couple in quick
        // succession at the start, then endless repeats. Must never fire.
        let mut s = SourceAnomaly::new(&p);
        let mut ever = false;
        for i in 0..60u32 {
            let c = ci((i % 3) as u16);
            ever |= s.observe(c, "+", i * 60).fired;
        }
        assert!(!ever, "a settled 3-country source must never fire");

        // A fresh source that legitimately calls 5 countries, but spread over the day.
        let mut s = SourceAnomaly::new(&p);
        let mut ever = false;
        for i in 0..5u16 {
            ever |= s.observe(ci(i), "+", i as u32 * 3600).fired; // one per hour
        }
        assert!(!ever, "novelty spread over hours is not a burst");
    }

    #[test]
    fn a_known_country_is_evidence_against_scanning() {
        let p = Params::default();
        let mut t = SeqTest::new(p.theta0, p.theta1, p.alpha, p.beta);
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
        let v1 = s.observe(ci(1), "00", 0);
        let v2 = s.observe(ci(1), "011", 0);
        let v3 = s.observe(ci(1), "00", 0); // a repeat prefix
        assert!(
            v2.prefix_bits > v1.prefix_bits,
            "a second distinct prefix adds evidence"
        );
        assert!(
            v3.prefix_bits < v2.prefix_bits,
            "reusing a prefix is evidence against"
        );
    }

    #[test]
    fn evidence_never_goes_negative_so_one_arm_cannot_mask_another() {
        // Fusion adds non-negative arms: a very well-behaved volume history must not bank
        // credit that hides a country scan.
        let p = Params::default();
        let mut s = SourceAnomaly::new(&p);
        for i in 0..20u16 {
            let v = s.observe(ci(i), "+", 0);
            assert!(v.country_bits >= 0.0 && v.prefix_bits >= 0.0 && v.volume_bits >= 0.0);
        }
    }
}
