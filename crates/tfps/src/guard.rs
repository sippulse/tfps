//! The exemption list, assembled the same way for everything that can block.
//!
//! The daemon builds it at startup and `tfps_ctl ban` builds it before a hand-placed
//! block. Two assemblies would drift -- they did, once -- so there is one, here, and the
//! callers differ only in what they do about a rejected entry: the daemon alarms and
//! carries on, the control tool refuses to run. That is policy, and it stays with them.

use std::net::Ipv4Addr;

use tfps_core::ignore::IgnoreList;

/// An assembled list, plus every declared entry it could not parse.
///
/// A refused entry is never dropped quietly: an operator who believes a range is exempt
/// when it is not would draw exactly the wrong conclusion from a block.
pub struct Guard {
    pub list: IgnoreList,
    /// One message per entry `IgnoreList::add` refused, in the order given.
    pub rejected: Vec<String>,
}

/// The host's own addresses first, then what the operator declared.
///
/// `local` comes from `xdp::local_addresses` in both callers. Never condemning the machine
/// we are defending is not configurable: the one time it happened during development it
/// was a test firing from the host itself, and no operator would have guessed to switch
/// it on beforehand.
pub fn assemble<'a>(local: &[Ipv4Addr], declared: impl IntoIterator<Item = &'a str>) -> Guard {
    let mut list = IgnoreList::new();
    for &ip in local {
        list.add_local(ip);
    }
    let mut rejected = Vec::new();
    for entry in declared {
        if let Err(e) = list.add(entry) {
            rejected.push(e);
        }
    }
    Guard { list, rejected }
}

/// The daemon's entries as it persists them at checkpoint: `label=hits`, space
/// separated, local and declared alike. The control tool reads this back so a hand ban
/// honours entries the daemon was given on its command line, which no file records.
pub fn labels_from_checkpoint(line: &str) -> impl Iterator<Item = &str> {
    line.split_whitespace()
        .map(|tok| tok.split_once('=').map_or(tok, |(label, _)| label))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_comes_first_and_a_bad_entry_is_kept_as_a_message() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = assemble(&[host], ["203.0.113.0/24", "203.0.113.0/33"]);
        assert!(g.list.exempt(host).is_some(), "the host is on the list");
        assert!(g.list.exempt(Ipv4Addr::new(203, 0, 113, 7)).is_some());
        assert_eq!(
            g.rejected.len(),
            1,
            "the malformed entry is reported, not dropped"
        );
        assert!(
            g.rejected[0].contains("203.0.113.0/33"),
            "{}",
            g.rejected[0]
        );
    }

    #[test]
    fn checkpoint_labels_come_back_without_their_counts() {
        let got: Vec<&str> = labels_from_checkpoint("10.0.0.0/8=3 127.0.0.1=0 bare").collect();
        assert_eq!(got, ["10.0.0.0/8", "127.0.0.1", "bare"]);
        assert_eq!(labels_from_checkpoint("").count(), 0);
    }
}
