//! TFPS core — IRSF fraud prevention for SIP networks.
//!
//! This crate holds the domain and **no I/O**: no network, no disk, no kernel. The event
//! source (packet capture today, XDP later) lives outside, which keeps everything here
//! deterministic and testable without privileges or hardware.
//!
//! Architecture in `SPEC.md`, normative vocabulary in `CONTEXT.md`.

pub mod anomaly;
pub mod country;
pub mod dialplan;
pub mod engine;
pub mod ignore;
pub mod net;
pub mod novelty;
pub mod perimeter;
pub mod sip;
