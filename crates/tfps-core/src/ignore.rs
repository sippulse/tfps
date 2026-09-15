//! `ignoreip` — sources that are judged and reported but never enforced against.
//!
//! Two kinds of entry, and the difference is what keeps this on the right side of
//! `SPEC.md` §11:
//!
//! - **Local addresses**, discovered from the machine itself. Not configuration at all:
//!   nobody declares them, and they exist because a defence that can condemn the host it
//!   defends will eventually do so. It happened here during development.
//! - **Declared networks**, the operator's trusted carriers and management ranges — the
//!   equivalent of `fail2ban`'s `ignoreip`.
//!
//! The second kind **is** configuration, and §11 admits only *installation* configuration,
//! never *policy*. It earns its place by being a statement about **enforcement scope**
//! ("never act against this peer"), not about what fraud is: an exempt source is still
//! evaluated, still counted, and still reported. What it never does is change a verdict.
//!
//! Two rules keep it honest, both from §12:
//!
//! - **`0.0.0.0/0` is refused.** One entry that exempts every source would silently turn
//!   the product off. `--no-enforce` does that explicitly and announces it every minute.
//! - **Every entry counts its hits**, so an exemption that has matched nothing in three
//!   months is visible. A rule that matches zero and says nothing is the `fail2ban`
//!   failure this project is built against.

use std::net::Ipv4Addr;

/// Where an entry came from. Declared entries are reported separately because only they
/// are somebody's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// An address configured on this host.
    Local,
    /// Named by the operator.
    Declared,
}

impl Origin {
    /// How a person reads it, in the startup report and in a refusal.
    pub fn describe(self) -> &'static str {
        match self {
            Origin::Local => "this host",
            Origin::Declared => "declared",
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    label: String,
    net: u32,
    mask: u32,
    origin: Origin,
    hits: u64,
}

/// Networks exempt from enforcement.
#[derive(Debug, Clone, Default)]
pub struct IgnoreList {
    entries: Vec<Entry>,
}

impl IgnoreList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an address belonging to this host. Always exempt, never declared.
    pub fn add_local(&mut self, ip: Ipv4Addr) {
        if self.entries.iter().any(|e| e.label == ip.to_string()) {
            return;
        }
        self.entries.push(Entry {
            label: ip.to_string(),
            net: u32::from(ip),
            mask: u32::MAX,
            origin: Origin::Local,
            hits: 0,
        });
    }

    /// Adds `a.b.c.d` or `a.b.c.d/len` named by the operator.
    ///
    /// Returns an error rather than skipping a malformed entry: an operator who mistypes a
    /// network must not be left believing a range is exempt when it is not.
    pub fn add(&mut self, entry: &str) -> Result<(), String> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err("empty entry".into());
        }
        let (addr, len) = match entry.split_once('/') {
            Some((a, l)) => (
                a,
                l.parse::<u8>()
                    .map_err(|e| format!("{entry}: bad prefix length: {e}"))?,
            ),
            None => (entry, 32),
        };
        if len > 32 {
            return Err(format!("{entry}: prefix length above 32"));
        }
        if len == 0 {
            // The one knob that would turn the product off without saying so.
            return Err(format!(
                "{entry}: a /0 would exempt every source and silently disable enforcement. \
                 Use --no-enforce, which observes and announces it in every report."
            ));
        }
        let ip: Ipv4Addr = addr
            .parse()
            .map_err(|e| format!("{entry}: not an IPv4 address: {e}"))?;
        let mask = u32::MAX << (32 - len);
        self.entries.push(Entry {
            label: entry.to_string(),
            net: u32::from(ip) & mask,
            mask,
            origin: Origin::Declared,
            hits: 0,
        });
        Ok(())
    }

    /// Is this source exempt? Returns the entry that matched, and counts the hit.
    ///
    /// Counting is the point: `SPEC.md` §12 requires a rule that never matches to be
    /// reportable, and an exemption is a rule.
    pub fn exempt(&mut self, ip: Ipv4Addr) -> Option<&str> {
        self.exempt_entry(ip).map(|(label, _)| label)
    }

    /// The same lookup, keeping where the entry came from.
    ///
    /// A caller that has to explain a refusal to a person needs the difference: "this is
    /// an address of the host" is a fact about the machine, and "you declared this range"
    /// is a fact about their own configuration. One rule, one place — `exempt` delegates
    /// here rather than matching a second time.
    pub fn exempt_entry(&mut self, ip: Ipv4Addr) -> Option<(&str, Origin)> {
        let v = u32::from(ip);
        let hit = self.entries.iter_mut().find(|e| v & e.mask == e.net)?;
        hit.hits += 1;
        Some((&hit.label, hit.origin))
    }

    /// Every entry, for the startup report: label, where it came from, how often it fired.
    pub fn report(&self) -> impl Iterator<Item = (&str, Origin, u64)> + '_ {
        self.entries
            .iter()
            .map(|e| (e.label.as_str(), e.origin, e.hits))
    }

    /// Declared entries that have never matched. Local ones are excluded: the host not
    /// attacking itself is the normal case, not a stale rule.
    pub fn cold(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|e| e.origin == Origin::Declared && e.hits == 0)
            .map(|e| e.label.as_str())
            .collect()
    }

    pub fn total_hits(&self) -> u64 {
        self.entries.iter().map(|e| e.hits).sum()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn declared(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.origin == Origin::Declared)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// `exempt` and `exempt_entry` are one rule, so they cannot disagree about
    /// what matched. Two copies agree today and drift silently.
    #[test]
    fn the_two_lookups_are_the_same_rule() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let peer = Ipv4Addr::new(203, 0, 113, 7);
        let mut a = IgnoreList::new();
        a.add_local(host);
        a.add("203.0.113.0/24").unwrap();
        let mut b = a.clone();
        for ip in [host, peer, Ipv4Addr::new(8, 8, 8, 8)] {
            assert_eq!(
                a.exempt(ip).map(str::to_string),
                b.exempt_entry(ip).map(|(l, _)| l.to_string()),
                "the two lookups disagreed about {ip}"
            );
        }
        let mut c = a.clone();
        assert_eq!(c.exempt_entry(host).map(|(_, o)| o), Some(Origin::Local));
        assert_eq!(c.exempt_entry(peer).map(|(_, o)| o), Some(Origin::Declared));
        assert_eq!(c.exempt_entry(Ipv4Addr::new(8, 8, 8, 8)), None);
    }

    #[test]
    fn a_bare_address_is_a_single_host() {
        let mut l = IgnoreList::new();
        l.add("209.38.75.252").unwrap();
        assert_eq!(l.exempt(ip("209.38.75.252")), Some("209.38.75.252"));
        assert_eq!(
            l.exempt(ip("209.38.75.253")),
            None,
            "the neighbour is not exempt"
        );
    }

    #[test]
    fn a_prefix_covers_its_range_and_stops_there() {
        let mut l = IgnoreList::new();
        l.add("10.0.0.0/8").unwrap();
        l.add("192.168.1.0/24").unwrap();
        assert!(l.exempt(ip("10.255.3.9")).is_some());
        assert!(l.exempt(ip("192.168.1.77")).is_some());
        assert!(
            l.exempt(ip("192.168.2.77")).is_none(),
            "/24 must not leak into the next"
        );
        assert!(l.exempt(ip("11.0.0.1")).is_none());
    }

    #[test]
    fn a_zero_prefix_is_refused_because_it_would_disable_the_product_quietly() {
        // The earlier version accepted this and called it the operator's choice. One line
        // in a config file that turns enforcement off without a word in the report is
        // exactly the silent failure this project exists to avoid.
        let mut l = IgnoreList::new();
        let e = l.add("0.0.0.0/0").unwrap_err();
        assert!(
            e.contains("--no-enforce"),
            "the error must name the honest alternative: {e}"
        );
        assert!(l.is_empty());
    }

    #[test]
    fn a_malformed_entry_is_an_error_not_a_silent_skip() {
        let mut l = IgnoreList::new();
        assert!(l.add("not-an-ip").is_err());
        assert!(l.add("10.0.0.0/33").is_err());
        assert!(l.add("10.0.0.0/x").is_err());
        assert!(l.add("").is_err());
        assert!(l.is_empty(), "nothing was added by the failures");
    }

    #[test]
    fn hits_are_counted_so_a_stale_exemption_is_visible() {
        let mut l = IgnoreList::new();
        l.add("10.0.0.0/8").unwrap();
        l.add("203.0.113.0/24").unwrap();
        l.add_local(ip("209.38.75.252"));
        assert_eq!(l.cold().len(), 2, "nothing has matched yet");

        l.exempt(ip("10.1.2.3"));
        l.exempt(ip("10.4.5.6"));
        assert_eq!(
            l.cold(),
            vec!["203.0.113.0/24"],
            "only the unused one is cold"
        );
        assert_eq!(l.total_hits(), 2);

        let counted: Vec<_> = l.report().filter(|(_, _, h)| *h > 0).collect();
        assert_eq!(counted, vec![("10.0.0.0/8", Origin::Declared, 2)]);
    }

    #[test]
    fn a_local_address_is_never_reported_as_a_stale_rule() {
        // The host not attacking itself is the normal case, not a rule gone rotten.
        let mut l = IgnoreList::new();
        l.add_local(ip("127.0.0.1"));
        assert!(l.cold().is_empty());
        assert_eq!(l.declared(), 0);
    }

    #[test]
    fn the_first_matching_entry_wins_and_only_it_counts() {
        // Overlapping ranges must not inflate the hit count of every entry that covers the
        // address, or the report would show exemptions that never actually applied.
        let mut l = IgnoreList::new();
        l.add("10.0.0.0/8").unwrap();
        l.add("10.1.0.0/16").unwrap();
        l.exempt(ip("10.1.2.3"));
        assert_eq!(l.total_hits(), 1);
        assert_eq!(l.cold(), vec!["10.1.0.0/16"]);
    }
}
