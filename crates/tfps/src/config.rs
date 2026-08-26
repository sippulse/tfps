//! Configuration file — `/etc/tfps/config.json`.
//!
//! **Every field is optional and the system works without the file.** That is not a
//! convenience: it is constraint 1 of the project. What lives here is **installation**
//! configuration (where to look, how to read the numbers) plus optional integrations —
//! never **policy** configuration, which would say what fraud is. The fourteen knobs of the
//! 2023 `defines.m4` have no equivalent.
//!
//! Precedence: **command line beats the file, which beats the built-in default.**
//!
//! ```json
//! {
//!   "ports": [5060, 5061],
//!   "intl_prefixes": ["+", "00", "011", "9011"],
//!   "peers": { "10.0.0.5": { "intl_prefixes": ["9011"], "bare_e164": false } },
//!   "signatures": ["MyLocalScanner", "=sipsak"],
//!   "injection": ["xp_cmdshell"],
//!   "apiban_key": "...",
//!   "learn_days": 30,
//!   "block_ttl": 3600
//! }
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const DEFAULT_PATH: &str = "/etc/tfps/config.json";

/// A PBX's dial plan.
///
/// Declaring beats learning because it holds on that peer's **very first** call instead of
/// waiting for convergence — and 20.3% of destinations do not resolve to a country without
/// correct prefix stripping. Learning keeps running in parallel, and disagreement becomes
/// an alarm.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// That PBX's international dialling prefixes, e.g. `["9011", "011"]`.
    #[serde(default)]
    pub intl_prefixes: Vec<String>,
    /// The PBX sends plain E.164 with no prefix. Common in wholesale.
    ///
    /// An explicit flag rather than an empty prefix, because the semantics are dangerous:
    /// with it on, `2125551234` is Morocco; with it off, it is a domestic US number.
    #[serde(default)]
    pub bare_e164: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub ports: Option<Vec<u16>>,
    /// Default prefixes, used for peers with no declared plan.
    pub intl_prefixes: Option<Vec<String>>,
    /// Per-PBX plan, keyed by source IP.
    #[serde(default)]
    pub peers: BTreeMap<String, PeerConfig>,
    /// User-agent signatures that **add** to the built-in ones.
    ///
    /// Prefix by default; `=text` matches exactly. They never replace: a file that replaced
    /// would make someone who writes three lines silently lose the 18 shipped ones.
    #[serde(default)]
    pub signatures: Vec<String>,
    /// URI injection patterns that add to the built-in ones.
    #[serde(default)]
    pub injection: Vec<String>,
    pub apiban_key: Option<String>,
    pub learn_days: Option<u32>,
    pub block_ttl: Option<u64>,
    pub stats_every: Option<u64>,
    pub checkpoint_every: Option<u64>,
    pub iface: Option<String>,
    pub db: Option<PathBuf>,
    pub xdp_obj: Option<PathBuf>,
    pub drop_map: Option<PathBuf>,
}

/// The read result, so the configuration's origin shows up in the startup report. The
/// operator needs to know whether the file was read, absent, or broken.
pub enum Loaded {
    /// File read successfully.
    File(Box<Config>, PathBuf),
    /// Absent — normal and expected.
    Absent,
    /// Present but unreadable. **Never silent**: broken configuration ignored quietly
    /// makes the operator believe they declared something that does not apply.
    Broken(String),
}

pub fn load(path: &Path) -> Loaded {
    if !path.exists() {
        return Loaded::Absent;
    }
    match std::fs::read_to_string(path) {
        Err(e) => Loaded::Broken(format!("reading {}: {e}", path.display())),
        Ok(txt) => match serde_json::from_str::<Config>(&txt) {
            Ok(c) => Loaded::File(Box::new(c), path.to_path_buf()),
            Err(e) => Loaded::Broken(format!("{}: {e}", path.display())),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Config, String> {
        serde_json::from_str(s).map_err(|e| e.to_string())
    }

    #[test]
    fn an_empty_file_is_valid() {
        // The core promise: nothing is mandatory.
        let c = parse("{}").expect("an empty object must be accepted");
        assert!(c.ports.is_none());
        assert!(c.signatures.is_empty());
        assert!(c.peers.is_empty());
    }

    #[test]
    fn parses_the_readme_example() {
        let c = parse(
            r#"{
              "ports": [5060, 5061],
              "intl_prefixes": ["+", "00"],
              "peers": { "10.0.0.5": { "intl_prefixes": ["9011"], "bare_e164": false } },
              "signatures": ["MyLocalScanner", "=sipsak"],
              "injection": ["xp_cmdshell"],
              "apiban_key": "abc",
              "learn_days": 30,
              "block_ttl": 3600
            }"#,
        )
        .expect("the documented example must parse");
        assert_eq!(c.ports.as_deref(), Some(&[5060u16, 5061][..]));
        assert_eq!(c.peers["10.0.0.5"].intl_prefixes, ["9011"]);
        assert_eq!(c.signatures.len(), 2);
        assert_eq!(c.apiban_key.as_deref(), Some("abc"));
    }

    #[test]
    fn an_unknown_field_is_an_error_not_silence() {
        // A typo that got ignored would make the operator believe APIBAN was enabled when
        // it was not. `deny_unknown_fields` refuses and names the offending field.
        let e = parse(r#"{"apiban_kei": "x"}"#).unwrap_err();
        assert!(
            e.contains("apiban_kei"),
            "the error must name the offending field: {e}"
        );
        // And the correct field still works, obviously.
        assert_eq!(
            parse(r#"{"apiban_key": "x"}"#)
                .unwrap()
                .apiban_key
                .as_deref(),
            Some("x")
        );
    }

    #[test]
    fn broken_json_becomes_a_readable_error_not_a_panic() {
        assert!(parse("{").is_err());
        assert!(parse("").is_err());
        assert!(parse(r#"{"ports": "not a list"}"#).is_err());
    }

    #[test]
    fn an_absent_file_is_not_an_error() {
        let p = std::path::Path::new("/path/that/does/not/exist/config.json");
        assert!(matches!(load(p), Loaded::Absent));
    }
}
