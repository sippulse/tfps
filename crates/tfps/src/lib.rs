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
