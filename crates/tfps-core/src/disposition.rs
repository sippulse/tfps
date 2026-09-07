// What the perimeter does with a condemnation, as a pure function.
//
// The rule this file exists for: a condemnation must never be computed and then
// silently dropped. `SPEC.md` §12 makes silence an alarm, and the shape that
// broke it was an `if / else if / else if` chain in `main.rs` with no `else` —
// the third arm guarded on an enforcer that is `None` under `--no-enforce`. The
// two exemption arms printed, the enforcement arm printed, and the fourth case,
// "condemned while observing", fell off the end of the chain saying nothing.
//
// A chain can silently lack an arm. A total match over an enum cannot: adding a
// state without handling it stops the build. That is the actual repair, and it
// is why this is an enum rather than a fourth `else if`.
//
// It is also the only way to get the behaviour under test. The chain lived
// inside a 660-line `fn main` with no tests of its own; every input that
// matters is an argument here, including the enforcement state, which in the
// caller comes from whether an XDP program could be attached.

use core::fmt;

/// What should happen to a source the perimeter has judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition<'a> {
    /// Nothing was tripped.
    Ignore,
    /// Tripped a rule, but the static ignore list covers it.
    ExemptIgnoreIp {
        kind: &'a str,
        detail: &'a str,
        rule: &'a str,
    },
    /// Tripped a rule, but this peer registered and authenticated.
    ExemptKnownPeer { kind: &'a str, detail: &'a str },
    /// Condemned, and enforcement is on: block it and record it.
    Block { kind: &'a str, detail: &'a str },
    /// Condemned while observing only. Nothing is blocked, and the judgement
    /// still has to be reported -- that report is the entire point of an
    /// observe-only run.
    WouldBlock { kind: &'a str, detail: &'a str },
}

impl Disposition<'_> {
    /// The rule that fired, for any disposition that has one.
    pub fn kind(&self) -> Option<&str> {
        match self {
            Disposition::Ignore => None,
            Disposition::ExemptIgnoreIp { kind, .. }
            | Disposition::ExemptKnownPeer { kind, .. }
            | Disposition::Block { kind, .. }
            | Disposition::WouldBlock { kind, .. } => Some(kind),
        }
    }
}

impl fmt::Display for Disposition<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Disposition::Ignore => write!(f, "ignore"),
            Disposition::ExemptIgnoreIp { .. } | Disposition::ExemptKnownPeer { .. } => {
                write!(f, "exempt")
            }
            Disposition::Block { .. } => write!(f, "blocked"),
            Disposition::WouldBlock { .. } => write!(f, "would-block"),
        }
    }
}

/// Decide what to do with a judged source.
///
/// Precedence is deliberate and matches the order an operator expects: a
/// curated ignore list outranks a learned registration, and both outrank the
/// verdict. Enforcement is consulted last, because whether we *act* must never
/// change whether we *judged*.
pub fn disposition<'a>(
    reason: Option<(&'a str, &'a str)>,
    ignore_rule: Option<&'a str>,
    known_peer: bool,
    enforcing: bool,
) -> Disposition<'a> {
    let Some((kind, detail)) = reason else {
        return Disposition::Ignore;
    };
    if let Some(rule) = ignore_rule {
        return Disposition::ExemptIgnoreIp { kind, detail, rule };
    }
    if known_peer {
        return Disposition::ExemptKnownPeer { kind, detail };
    }
    if enforcing {
        return Disposition::Block { kind, detail };
    }
    // Observing. The judgement stands and is reported; only the acting stops.
    Disposition::WouldBlock { kind, detail }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INJECTION: Option<(&str, &str)> = Some(("injection", "'"));

    // THE DEFECT. `--no-enforce` is documented as "observe only" and the banner
    // prints `enforcement: OFF`, but a condemnation under it produced no line at
    // all: the chain's third arm was guarded on an enforcer that is `None`, and
    // there was no fourth arm. The two exemption arms above it did print, so the
    // tool reported the peers it declined to ban and stayed silent about the ones
    // it would have banned — the wrong way round, and against `SPEC.md` §12,
    // which makes silence an alarm.
    #[test]
    fn a_condemnation_while_observing_is_still_judged_aloud() {
        assert_eq!(
            disposition(INJECTION, None, false, false),
            Disposition::WouldBlock {
                kind: "injection",
                detail: "'"
            },
            "a source condemned under --no-enforce must still be judged aloud"
        );
    }

    // The name an operator reads in the log line, and greps for afterwards.
    #[test]
    fn the_observed_verdict_has_a_name_of_its_own() {
        let d = disposition(INJECTION, None, false, false);
        assert_eq!(d.to_string(), "would-block");
        assert_eq!(
            d.kind(),
            Some("injection"),
            "an observed verdict names the rule that fired, like every other"
        );
    }

    // NEGATIVE CONTROL for the fix above. Widening the not-enforcing path is how
    // you silently change the enforcing one; this pins it.
    #[test]
    fn enforcing_still_blocks_and_is_unchanged() {
        assert_eq!(
            disposition(INJECTION, None, false, true),
            Disposition::Block {
                kind: "injection",
                detail: "'"
            }
        );
        assert_eq!(
            disposition(INJECTION, None, false, true).to_string(),
            "blocked"
        );
    }

    // NEGATIVE CONTROL: the fix must not invent a judgement where none was made.
    // An unjudged source stays silent whether or not we are enforcing.
    #[test]
    fn no_reason_is_silent_in_both_enforcement_states() {
        for enforcing in [true, false] {
            assert_eq!(
                disposition(None, None, false, enforcing),
                Disposition::Ignore,
                "enforcing={enforcing}"
            );
        }
    }

    // Exemption outranks the verdict, and says so. Silence here would hide a
    // compromised trusted peer, which is when it matters most.
    #[test]
    fn the_ignore_list_outranks_the_verdict_and_is_still_reported() {
        assert_eq!(
            disposition(INJECTION, Some("10.0.0.0/8"), false, true),
            Disposition::ExemptIgnoreIp {
                kind: "injection",
                detail: "'",
                rule: "10.0.0.0/8"
            }
        );
    }

    // A curated list outranks a learned registration: both exempt, and the
    // operator's own configuration wins the attribution.
    #[test]
    fn the_ignore_list_outranks_a_registered_peer() {
        assert_eq!(
            disposition(INJECTION, Some("10.0.0.0/8"), true, true),
            Disposition::ExemptIgnoreIp {
                kind: "injection",
                detail: "'",
                rule: "10.0.0.0/8"
            }
        );
    }

    // The exemptions must not depend on enforcement. Whether we *act* cannot
    // change whether we *judged* — that conflation is the original defect.
    #[test]
    fn exemptions_do_not_depend_on_enforcement() {
        for enforcing in [true, false] {
            assert_eq!(
                disposition(INJECTION, None, true, enforcing),
                Disposition::ExemptKnownPeer {
                    kind: "injection",
                    detail: "'"
                },
                "enforcing={enforcing}"
            );
        }
    }

    // `main.rs` unwraps the enforcer inside the `Block` arm. That unwrap is safe
    // only because `Block` cannot be returned while not enforcing, which is a
    // fact about this function — so it is pinned here rather than asserted there.
    #[test]
    fn block_is_returned_only_while_enforcing() {
        for reason in [INJECTION, Some(("scanner", "sipvicious")), None] {
            for rule in [None, Some("10.0.0.0/8")] {
                for known in [true, false] {
                    assert!(
                        !matches!(
                            disposition(reason, rule, known, false),
                            Disposition::Block { .. }
                        ),
                        "Block while not enforcing: reason={reason:?} rule={rule:?} known={known}"
                    );
                }
            }
        }
    }

    #[test]
    fn would_block_is_returned_only_while_not_enforcing() {
        for reason in [INJECTION, Some(("scanner", "sipvicious")), None] {
            for rule in [None, Some("10.0.0.0/8")] {
                for known in [true, false] {
                    assert!(
                        !matches!(
                            disposition(reason, rule, known, true),
                            Disposition::WouldBlock { .. }
                        ),
                        "WouldBlock while enforcing: reason={reason:?} rule={rule:?} known={known}"
                    );
                }
            }
        }
    }

    // The pair above is only meaningful if both states are actually reachable;
    // two vacuous truths would also pass. This is that positive control.
    #[test]
    fn both_enforcement_outcomes_are_reachable() {
        assert!(matches!(
            disposition(INJECTION, None, false, true),
            Disposition::Block { .. }
        ));
        assert!(matches!(
            disposition(INJECTION, None, false, false),
            Disposition::WouldBlock { .. }
        ));
    }

    // Enforcement changes only the verdict arm. If it ever alters an exemption or
    // a silence, "judging is independent of acting" is gone and what the operator
    // is told would depend on whether protection happened to be on.
    #[test]
    fn enforcement_changes_only_the_verdict_arm() {
        for reason in [INJECTION, None] {
            for rule in [None, Some("10.0.0.0/8")] {
                for known in [true, false] {
                    let on = disposition(reason, rule, known, true);
                    let off = disposition(reason, rule, known, false);
                    let verdict_arm = matches!(
                        on,
                        Disposition::Block { .. } | Disposition::WouldBlock { .. }
                    );
                    if !verdict_arm {
                        assert_eq!(
                            on, off,
                            "enforcement changed a non-verdict outcome: \
                             reason={reason:?} rule={rule:?} known={known}"
                        );
                    }
                }
            }
        }
    }
}
