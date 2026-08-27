//! The shared clock type.
//!
//! This module once held the rotating-bitmap novelty engine. That behavioural core has been
//! replaced by the sequential detector in `anomaly.rs` (see `docs/anomaly-detection.md`).
//! What remains is the one thing every layer still shares: a Unix-seconds timestamp. The
//! core reads no clock — time always arrives as one of these — which is what keeps the whole
//! of `tfps-core` deterministic and testable without waiting.

/// Seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub u32);

impl Timestamp {
    pub fn saturating_sub(self, other: Self) -> u32 {
        self.0.saturating_sub(other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturating_sub_does_not_underflow() {
        assert_eq!(Timestamp(5).saturating_sub(Timestamp(9)), 0);
        assert_eq!(Timestamp(9).saturating_sub(Timestamp(5)), 4);
    }
}
