//! Addresses that must never be blocked, whatever the evidence says.
//!
//! This exists because of something that actually happened during development: a
//! brute-force verification sent deliberately wrong credentials from the softswitch host
//! itself, and TFPS condemned **the host's own address**. The damage was limited — inbound
//! packets carry the attacker's source, not ours — but the principle is not: a defence that
//! can shoot the machine it defends will eventually do so at three in the morning.
//!
//! `fail2ban` learned the same lesson and calls it `ignoreip`. Two rules here:
//!
//! - **the host's own addresses are always ignored**, with no configuration required;
//! - the operator can name further networks, for trusted carriers and management ranges.
//!
//! An ignored address is still **judged and reported** — it is only never enforced. Silently
//! skipping the evaluation would hide an internal compromise, which is precisely the case
//! where the operator most needs to be told.

use std::net::Ipv4Addr;

/// Networks exempt from enforcement.
#[derive(Debug, Clone, Default)]
pub struct IgnoreList {
    /// `(network, mask)`, both in host order.
    nets: Vec<(u32, u32)>,
    /// Kept for the startup report: an operator has to be able to see what is exempt.
    labels: Vec<String>,
}

impl IgnoreList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `a.b.c.d` or `a.b.c.d/len`. A bare address is a `/32`.
    ///
    /// Returns an error rather than ignoring a malformed entry: an operator who mistypes a
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
        let ip: Ipv4Addr = addr
            .parse()
            .map_err(|e| format!("{entry}: not an IPv4 address: {e}"))?;
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        self.nets.push((u32::from(ip) & mask, mask));
        self.labels.push(entry.to_string());
        Ok(())
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        self.nets.iter().any(|(net, mask)| v & mask == *net)
    }

    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    pub fn len(&self) -> usize {
        self.nets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn a_bare_address_is_a_single_host() {
        let mut l = IgnoreList::new();
        l.add("209.38.75.252").unwrap();
        assert!(l.contains(ip("209.38.75.252")));
        assert!(
            !l.contains(ip("209.38.75.253")),
            "the neighbour is not exempt"
        );
    }

    #[test]
    fn a_prefix_covers_its_range_and_stops_there() {
        let mut l = IgnoreList::new();
        l.add("10.0.0.0/8").unwrap();
        l.add("192.168.1.0/24").unwrap();
        assert!(l.contains(ip("10.255.3.9")));
        assert!(l.contains(ip("192.168.1.77")));
        assert!(
            !l.contains(ip("192.168.2.77")),
            "/24 must not leak into the next one"
        );
        assert!(!l.contains(ip("11.0.0.1")));
    }

    #[test]
    fn a_malformed_entry_is_an_error_not_a_silent_skip() {
        // An operator who mistypes a network must not believe it is exempt.
        let mut l = IgnoreList::new();
        assert!(l.add("not-an-ip").is_err());
        assert!(l.add("10.0.0.0/33").is_err());
        assert!(l.add("10.0.0.0/x").is_err());
        assert!(l.add("").is_err());
        assert!(l.is_empty(), "nothing was added by the failures");
    }

    #[test]
    fn a_zero_prefix_matches_everything_and_is_the_operators_choice() {
        // 0.0.0.0/0 disables enforcement entirely. It is a legitimate thing to ask for
        // while investigating, so it works — the startup report is what makes it visible.
        let mut l = IgnoreList::new();
        l.add("0.0.0.0/0").unwrap();
        assert!(l.contains(ip("1.2.3.4")));
    }
}
