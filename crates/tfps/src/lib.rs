//! TFPS host side: capture, persistence, enforcement and the control tool.
//!
//! The library target exists so that `tfps` and `tfps_ctl` share one implementation of the
//! things that must not diverge — above all **the eBPF map key encoding**, which differs
//! between our own map and a third party's pinned one. Two copies of that would eventually
//! disagree, and the symptom would be an unban that silently removes nothing.
//!
//! The decision logic is not here: it lives in `tfps-core`, which does no I/O.

pub mod apiban;
pub mod config;
pub mod guard;
pub mod store;
pub mod xdp;

/// Prints a line, treating a closed pipe as a normal end rather than a panic.
///
/// Rust ignores `SIGPIPE`, so a plain `println!` **panics** the moment somebody runs
/// `tfps_ctl pairs | head` — which is precisely how an operator uses a tool like this. The
/// alternative fix is restoring the default signal disposition, which needs `unsafe`; the
/// workspace forbids it, and a macro costs nothing.
#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if writeln!(std::io::stdout(), $($arg)*).is_err() {
            // The reader went away. Nothing left to say, and nothing went wrong.
            std::process::exit(0);
        }
    }};
}

/// Renders one value as a single-line JSON document.
///
/// The newline is deliberately **not** here. Every caller hands the result to
/// `say!`, which adds it and which already owns what happens when the reader
/// goes away — see the macro above. Keeping that decision in one place is the
/// whole point of this function existing rather than each command calling
/// `serde_json` for itself.
pub fn json_line<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| format!("serialising output: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct Doc {
        a: u8,
        b: Option<&'static str>,
    }

    /// Compact, and in declaration order — a consumer pinning bytes depends on
    /// both. serde_json::to_string gives us this; the test is here so a switch
    /// to to_string_pretty is caught rather than shipped.
    #[test]
    fn json_line_is_compact_and_in_declaration_order() {
        let s = json_line(&Doc { a: 1, b: None }).unwrap();
        assert_eq!(s, r#"{"a":1,"b":null}"#);
    }

    /// The newline belongs to say!, which also owns the broken-pipe decision.
    /// Two sources of newline would double-space every JSONL stream.
    #[test]
    fn json_line_carries_no_newline_of_its_own() {
        let s = json_line(&Doc { a: 1, b: Some("x") }).unwrap();
        assert!(!s.contains('\n'), "the newline is say!'s to add");
    }
}
