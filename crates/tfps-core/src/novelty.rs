//! Novelty detection — the system's only behavioural signal.
//!
//! There is no statistical model here, and that is a decision rather than an omission
//! (`SPEC.md` §6). The supervised half died with the "no corpus" ruling; the unsupervised
//! half does not pay for itself, because 45% detection at 2% false positives is unusable
//! under a binary verdict. What remains is set membership: **has this pair ever called
//! this country?**
//!
//! Two measurements hold up the design:
//!
//! - a country debut happens on **0.85%** of calls after warm-up, falling to 0.28% for a
//!   mature unit — meaning **a single first-time country must never fire**;
//! - the rule "ten first-time countries within an hour" fired **4 times across 2,829
//!   account-days**, and those four windows were the most atypical in the corpus.
//!
//! Hence the signal is **accumulation**, not a single event.

use crate::country::CountryIndex;

/// Seconds since the Unix epoch. The core never reads a clock — time arrives as a
/// parameter, which keeps everything deterministic and testable without waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub u32);

impl Timestamp {
    fn saturating_sub(self, other: Self) -> u32 {
        self.0.saturating_sub(other.0)
    }
}

/// Accumulation window for the blocking predicate. A **universal constant**, derived from
/// the physics of the fraud: seconds are the scale of a signalling flood, days dilute the
/// episode.
pub const WINDOW_SECS: u32 = 3600;

/// How many first-time countries within the window trigger a block. A **universal
/// constant**, identical for every customer — not the per-customer kind of number that
/// nobody ever tuned and that killed the 2023 TFPS (`DEFAULT_QUOTA`, `MAX_CONCURRENT`).
pub const NOVEL_COUNTRIES_TO_BLOCK: usize = 10;

/// Bitmap rotation period, in seconds: 45 days. It must be **longer than the 30-day
/// learning mode**, otherwise the baseline never stabilises.
pub const ROTATION_SECS: u32 = 45 * 24 * 3600;

/// Two 256-bit bitmaps: the current period and the previous one.
///
/// "Has seen this country" is the **union** of the two, giving effective memory between `T`
/// and `2T` — 45 to 90 days. Keeping a timestamp per country would cost 240 timestamps per
/// pair and is unworkable at millions of pairs; two bitmaps cost **64 bytes**.
///
/// The side effect is what solves poisoned bootstrap: if the PBX arrived already
/// compromised and learning absorbed the fraud, **the poisoned countries age out on their
/// own**.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotatingBitmap {
    current: [u64; 4],
    previous: [u64; 4],
    /// Which rotation period `current` represents. Rotation is lazy: it happens when the
    /// pair is touched, not by a background sweep.
    period: u32,
}

impl RotatingBitmap {
    /// Rebuilds from persisted state. Used only when loading at boot.
    pub fn from_parts(current: [u64; 4], previous: [u64; 4], period: u32) -> Self {
        Self {
            current,
            previous,
            period,
        }
    }

    /// Raw parts, for persistence. Exposed because SQLite is the durable store and the
    /// core does no I/O — the binary is what writes.
    pub fn parts(&self) -> ([u64; 4], [u64; 4], u32) {
        (self.current, self.previous, self.period)
    }

    /// Rotates if the period changed. Always called before reading or marking.
    fn rotate_to(&mut self, now: Timestamp) {
        let p = now.0 / ROTATION_SECS;
        if p == self.period {
            return;
        }
        if p == self.period + 1 {
            self.previous = self.current;
        } else {
            // Two periods or more untouched: everything that was there has expired.
            self.previous = [0; 4];
        }
        self.current = [0; 4];
        self.period = p;
    }

    fn contains(&self, c: CountryIndex) -> bool {
        let (w, b) = (c.0 as usize / 64, c.0 as usize % 64);
        (self.current[w] | self.previous[w]) & (1u64 << b) != 0
    }

    fn insert(&mut self, c: CountryIndex) {
        let (w, b) = (c.0 as usize / 64, c.0 as usize % 64);
        self.current[w] |= 1u64 << b;
    }

    /// How many distinct countries this unit knows. Used in reports and the day-31 summary.
    pub fn len(&self) -> u32 {
        (0..4)
            .map(|i| (self.current[i] | self.previous[i]).count_ones())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A ring of recent debut timestamps, sized exactly to the predicate.
///
/// Only the last `NOVEL_COUNTRIES_TO_BLOCK` debuts matter: if the oldest of them is still
/// inside the window, the predicate has fired. Debuts are rare (0.85% of calls), so this
/// ring stays empty for the overwhelming majority of pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NoveltyWindow {
    stamps: [u32; NOVEL_COUNTRIES_TO_BLOCK],
    len: u8,
    next: u8,
}

impl NoveltyWindow {
    fn push(&mut self, now: Timestamp) {
        self.stamps[self.next as usize] = now.0;
        self.next = (self.next + 1) % NOVEL_COUNTRIES_TO_BLOCK as u8;
        if (self.len as usize) < NOVEL_COUNTRIES_TO_BLOCK {
            self.len += 1;
        }
    }

    /// How many debuts fall inside the window ending at `now`.
    fn count_within(&self, now: Timestamp) -> usize {
        self.stamps[..self.len as usize]
            .iter()
            .filter(|s| now.saturating_sub(Timestamp(**s)) < WINDOW_SECS)
            .count()
    }
}

/// What observing one call produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// The country was a first for this pair.
    pub novel: bool,
    /// How many debuts this pair accumulated in the current window.
    pub novel_in_window: usize,
    /// The blocking predicate fired.
    pub triggered: bool,
}

/// Learning state for one `(peer, A-number)` pair.
///
/// The two bitmaps are 64 bytes; with the period marker and the debut ring, a pair's full
/// state lands around a hundred bytes — one million pairs in a few tens of megabytes. That
/// is what makes an A-number key viable for the wholesale target: the carrier has a broad
/// profile, but **each pair has a narrow one** (`SPEC.md` §5). The test
/// `pair_state_fits_the_memory_budget` pins that budget.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairState {
    seen: RotatingBitmap,
    window: NoveltyWindow,
}

impl PairState {
    /// Rebuilds a pair's state from what was persisted.
    ///
    /// The debut window is **not** restored: it covers one hour, and a restarting process
    /// loses at most one hour of accumulation. Persisting the ring would cost more than it
    /// is worth.
    pub fn from_bitmap(seen: RotatingBitmap) -> Self {
        Self {
            seen,
            window: NoveltyWindow::default(),
        }
    }

    pub fn bitmap(&self) -> &RotatingBitmap {
        &self.seen
    }

    /// Records an international call from this pair to `country`.
    ///
    /// Returns what happened; it **does not decide a verdict** — the caller does, since it
    /// also knows whether learning mode is active.
    pub fn observe(&mut self, country: CountryIndex, now: Timestamp) -> Observation {
        self.seen.rotate_to(now);
        let novel = !self.seen.contains(country);
        if novel {
            self.seen.insert(country);
            self.window.push(now);
        }
        let novel_in_window = self.window.count_within(now);
        Observation {
            novel,
            novel_in_window,
            triggered: novel_in_window >= NOVEL_COUNTRIES_TO_BLOCK,
        }
    }

    /// Countries this pair knows — input to the summary shown at the day-31 confirmation.
    pub fn known_countries(&self) -> u32 {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(i: u16) -> CountryIndex {
        CountryIndex(i)
    }

    /// A safe instant inside a rotation period, away from the edges.
    fn t(secs: u32) -> Timestamp {
        Timestamp(ROTATION_SECS * 100 + secs)
    }

    #[test]
    fn the_first_call_to_a_country_is_novel_and_the_second_is_not() {
        let mut p = PairState::default();
        assert!(p.observe(c(63), t(0)).novel, "Somalia is a first");
        assert!(!p.observe(c(63), t(10)).novel, "already seen");
        assert_eq!(p.known_countries(), 1);
    }

    #[test]
    fn a_single_first_time_country_never_fires() {
        // The measurement is explicit: debuts happen on 0.85% of calls. Blocking an
        // isolated debut would block 0.85% of all international traffic.
        let mut p = PairState::default();
        let o = p.observe(c(63), t(0));
        assert!(o.novel);
        assert!(!o.triggered);
    }

    #[test]
    fn ten_first_time_countries_in_an_hour_fire() {
        let mut p = PairState::default();
        for i in 0..NOVEL_COUNTRIES_TO_BLOCK as u16 {
            let o = p.observe(c(i), t(i as u32 * 60));
            assert_eq!(o.triggered, i as usize == NOVEL_COUNTRIES_TO_BLOCK - 1);
        }
    }

    #[test]
    fn ten_countries_spread_over_more_than_an_hour_do_not_fire() {
        // The signal is accumulation *within a window*; the same total spread across a day
        // is normal traffic from someone working through the world slowly.
        let mut p = PairState::default();
        for i in 0..NOVEL_COUNTRIES_TO_BLOCK as u16 {
            let o = p.observe(c(i), t(i as u32 * 600)); // 10 min apart
            assert!(!o.triggered, "should not fire at {i}");
        }
    }

    #[test]
    fn repeating_the_same_country_does_not_accumulate() {
        let mut p = PairState::default();
        for k in 0..50 {
            let o = p.observe(c(63), t(k * 10));
            assert!(!o.triggered, "repetition is not novelty");
        }
    }

    #[test]
    fn the_bitmap_forgets_after_two_periods() {
        let mut p = PairState::default();
        p.observe(c(63), Timestamp(0));
        assert_eq!(p.known_countries(), 1);

        // One period later: still remembered, via the previous bitmap.
        p.observe(c(1), Timestamp(ROTATION_SECS + 10));
        assert!(!p.observe(c(63), Timestamp(ROTATION_SECS + 20)).novel);

        // Two periods after the original marking: forgotten.
        let o = p.observe(c(63), Timestamp(3 * ROTATION_SECS + 10));
        assert!(o.novel, "an aged-out country becomes novel again");
    }

    #[test]
    fn forgetting_heals_a_pbx_that_arrived_compromised() {
        // Scenario: installed on an already-defrauded PBX. Learning absorbs Somalia as
        // routine. After two periods with no further calls there, the poisoning clears on
        // its own — the second defence in SPEC §6.
        let mut poisoned = PairState::default();
        poisoned.observe(c(63), Timestamp(0));
        let later = poisoned.observe(c(63), Timestamp(2 * ROTATION_SECS + 1));
        assert!(later.novel, "the system must heal on its own");
    }

    #[test]
    fn the_window_slides_instead_of_resetting() {
        let mut p = PairState::default();
        // Nine debuts at the start of the hour.
        for i in 0..9u16 {
            p.observe(c(i), t(i as u32));
        }
        // A little over an hour later the nine have left the window: the tenth does not fire.
        let o = p.observe(c(9), t(WINDOW_SECS + 100));
        assert!(!o.triggered);
        assert_eq!(o.novel_in_window, 1);
    }

    #[test]
    fn pair_state_fits_the_memory_budget() {
        // The arithmetic that makes an A-number key viable in wholesale (SPEC §5 and §6).
        // Pinned as a test because it is a requirement, not a detail: if someone adds a
        // fat field to pair state, millions of pairs stop fitting.
        let bitmap = core::mem::size_of::<RotatingBitmap>();
        let pair = core::mem::size_of::<PairState>();
        assert!(bitmap <= 72, "RotatingBitmap grew to {bitmap} bytes");
        assert!(pair <= 128, "PairState grew to {pair} bytes");
        // One million pairs within the declared budget.
        assert!(pair * 1_000_000 <= 128 * 1024 * 1024);
    }
}
