//! Per-peer dial plan — how a given PBX presents its numbers.
//!
//! This is the load-bearing piece of the design, and the reason is measured: **20.3% of
//! destinations in the production corpus do not resolve to a country without prefix
//! stripping**, and country is the only behavioural feature that survived measurement
//! (`SPEC.md` §4). Getting this wrong does not degrade a secondary feature — it degrades
//! the only one there is.
//!
//! Prefix stripping is also the **first filter on the hot path**: whatever matches no
//! prefix is not international for that PBX, falls out of scope, and passes without being
//! canonicalised. On a mostly-domestic carrier this is where most calls leave — and it is
//! what makes cost scale with international volume rather than total volume.

/// Maximum length of an E.164 number, without the `+` (ITU-T E.164 §6.2.1).
const E164_MAX_DIGITS: usize = 15;

/// Smallest plausible length for an international number (country code + subscriber).
/// A cheap gate before real validation; it does not claim to be exact.
const E164_MIN_DIGITS: usize = 7;

/// How a PBX presents the numbers it sends.
///
/// Declared in the JSON and **learned in parallel** — disagreement between the two is an
/// alarm, not a detail (`SPEC.md` §4): an extra prefix is harmless, **a missing prefix is
/// serious and silent**, because the international call escapes the whole system and
/// nothing reports it.
#[derive(Debug, Clone, Default)]
pub struct DialPlan {
    /// International dialling prefixes, e.g. `["+", "011", "9011", "00"]`.
    /// Order is irrelevant: matching is always **longest first**.
    prefixes: Vec<String>,
    /// The PBX sends plain E.164 with no prefix at all — common in wholesale.
    ///
    /// An explicit flag rather than an empty entry in the list, because the semantics are
    /// dangerous: with it on, `2125551234` is Morocco; with it off, it is a domestic US
    /// number. Requiring an explicit declaration prevents turning it on by accident.
    bare_e164: bool,
}

/// What remains after stripping the international prefix: country code plus subscriber,
/// in digits, without `+`. **Not yet validated** against a numbering plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternationalDigits(pub String);

impl DialPlan {
    pub fn new(prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            prefixes: prefixes.into_iter().map(Into::into).collect(),
            bare_e164: false,
        }
    }

    /// Declares that this PBX sends plain E.164. See the `bare_e164` field.
    pub fn with_bare_e164(mut self) -> Self {
        self.bare_e164 = true;
        self
    }

    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }

    /// Decides whether the dialled string is international for this PBX, and returns the
    /// digits.
    ///
    /// `None` means **out of scope, pass** — it is not a failure and never a reason to
    /// block. Repeating `R07` from the Java-era TFPS, which denied everything it could not
    /// classify and became 39% of all rejections, is the mistake this function exists to
    /// avoid.
    pub fn to_international(&self, dialed: &str) -> Option<InternationalDigits> {
        let cleaned = strip_visual_separators(dialed);

        // Longest-match. This resolves the classic ambiguity on its own: a PBX using `0`
        // for the national trunk and `00` for international yields `0212…` as national and
        // `00212…` as international, with no extra rule.
        let best = self
            .prefixes
            .iter()
            .filter(|p| !p.is_empty() && cleaned.starts_with(p.as_str()))
            .max_by_key(|p| p.len());

        let rest = match best {
            Some(p) => &cleaned[p.len()..],
            None if self.bare_e164 => cleaned.as_str(),
            None => return None,
        };

        let digits: String = rest.chars().filter(char::is_ascii_digit).collect();
        if rest.chars().any(|c| !c.is_ascii_digit()) {
            // Something non-numeric survived the prefix: not a dialable number.
            return None;
        }
        if !(E164_MIN_DIGITS..=E164_MAX_DIGITS).contains(&digits.len()) {
            return None;
        }
        Some(InternationalDigits(digits))
    }

    /// Does the dialled string match any declared prefix? A cheap hot-path gate that
    /// allocates nothing — used to discard domestic traffic before doing any work.
    pub fn looks_international(&self, dialed: &str) -> bool {
        if self.bare_e164 {
            return true;
        }
        self.prefixes
            .iter()
            .any(|p| !p.is_empty() && dialed.starts_with(p.as_str()))
    }
}

/// Strips visual separators seen in real Request-URIs: `-`, `.`, space, parentheses.
/// `+` is preserved, because it is a prefix and not a separator.
fn strip_visual_separators(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '.' | ' ' | '(' | ')'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> DialPlan {
        DialPlan::new(["+", "00", "011", "9011"])
    }

    #[test]
    fn matches_the_longest_prefix() {
        let p = plan();
        // `9011` beats `011`, which would beat `0` if it existed.
        assert_eq!(
            p.to_international("9011252612345678").unwrap().0,
            "252612345678"
        );
        assert_eq!(
            p.to_international("011252612345678").unwrap().0,
            "252612345678"
        );
        assert_eq!(
            p.to_international("00252612345678").unwrap().0,
            "252612345678"
        );
        assert_eq!(
            p.to_international("+252612345678").unwrap().0,
            "252612345678"
        );
    }

    #[test]
    fn the_classic_leading_zero_ambiguity_resolves_itself() {
        // A PBX using `0` for the national trunk and `00` for international.
        let p = DialPlan::new(["0", "00"]);
        // National: `0` is the longest matching prefix, and the rest is too short to be
        // plausibly international — the behaviour is pinned here regardless.
        assert_eq!(
            p.to_international("00212555123456").unwrap().0,
            "212555123456"
        );
        // With just `0`, what remains is still accepted as digits; this is the "extra
        // prefix" case, which the SPEC classifies as harmless — it will not canonicalise
        // into a valid country later.
        assert!(p.to_international("0212555123456").is_some());
    }

    #[test]
    fn out_of_scope_returns_none_and_never_blocks() {
        let p = plan();
        assert!(p.to_international("2005").is_none(), "internal extension");
        assert!(p.to_international("911").is_none(), "service code");
        assert!(
            p.to_international("5511999998888").is_none(),
            "national without prefix"
        );
    }

    #[test]
    fn plain_e164_requires_an_explicit_declaration() {
        let without = DialPlan::new(Vec::<String>::new());
        assert!(without.to_international("252612345678").is_none());

        let with = DialPlan::new(Vec::<String>::new()).with_bare_e164();
        assert_eq!(
            with.to_international("252612345678").unwrap().0,
            "252612345678"
        );
    }

    #[test]
    fn visual_separators_are_stripped() {
        let p = plan();
        assert_eq!(
            p.to_international("+55 (11) 99999-8888").unwrap().0,
            "5511999998888"
        );
    }

    #[test]
    fn rejects_what_is_not_dialable() {
        let p = plan();
        assert!(
            p.to_international("+55abc999998888").is_none(),
            "letters in the middle"
        );
        assert!(p.to_international("+1234").is_none(), "too short");
        assert!(
            p.to_international("+1234567890123456789").is_none(),
            "longer than E.164"
        );
    }

    #[test]
    fn the_cheap_gate_agrees_with_the_stripper() {
        let p = plan();
        assert!(p.looks_international("9011252612345678"));
        assert!(!p.looks_international("2005"));
    }
}
