//! Measures the decision path: parse, perimeter, dial plan, country, novelty, verdict.
//!
//! No network and no disk — this is the cost of deciding about one INVITE, which is the
//! number that bounds everything else. Run with:
//!
//! ```sh
//! cargo run --release -p tfps-core --example decision_throughput
//! ```
//!
//! Two workloads, because they exercise different costs: a settled customer reuses one
//! A-number and hits the fast path, whereas an attacker rotating A-numbers forces a new
//! pair per call — allocation, hashing, and eventually the pruning ceiling.

use std::net::Ipv4Addr;
use std::time::Instant;

use tfps_core::dialplan::DialPlan;
use tfps_core::engine::{Decision, Engine, Mode};
use tfps_core::novelty::Timestamp;

fn invite(from: &str, dialed: &str) -> Vec<u8> {
    format!(
        "INVITE sip:{dialed}@pbx.example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK776asdhds\r\n\
         Max-Forwards: 70\r\n\
         From: \"Desk\" <sip:{from}@pbx.example.com>;tag=1928301774\r\n\
         To: <sip:{dialed}@pbx.example.com>\r\n\
         Call-ID: a84b4c76e66710@pc33.example.com\r\n\
         CSeq: 314159 INVITE\r\n\
         Contact: <sip:{from}@10.0.0.5:5060>\r\n\
         User-Agent: Grandstream GXP2170 1.0.9.135\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

/// Distinct payloads held at once.
///
/// Bounded deliberately: an earlier version built one payload per iteration and was
/// OOM-killed on a 1 vCPU droplet, which is exactly the class of machine this is supposed
/// to run on. The pool still exceeds the 50,000 pairs-per-peer ceiling, so the rotation
/// workload reaches the pruning path it is meant to exercise.
const POOL: usize = 65_536;

fn run(label: &str, n: usize, rotate_a_number: bool) {
    let mut engine =
        Engine::new(DialPlan::new(["+", "00", "011", "9011"]), Mode::Active).with_behavioural();
    let peer = Ipv4Addr::new(10, 0, 0, 5);
    // Build the payloads first: this measures deciding, not formatting strings.
    let payloads: Vec<Vec<u8>> = (0..POOL.min(n))
        .map(|i| {
            let from = if rotate_a_number {
                format!("{}", 1000 + i)
            } else {
                "1001".to_string()
            };
            invite(&from, "00442039967796")
        })
        .collect();

    // Assert the workload before timing it. A payload that fails to parse would leave
    // every iteration on the reject path and still print a confident INVITEs/s figure —
    // which is exactly what an earlier version of this file did.
    match engine.observe(peer, &payloads[0], Timestamp(1_800_000_000)) {
        Decision::Pass { country, .. } => assert_eq!(country, "GB"),
        other => panic!("benchmark payload does not reach a verdict: {other:?}"),
    }

    let t0 = Instant::now();
    for i in 0..n {
        let p = &payloads[i % payloads.len()];
        engine.observe(peer, p, Timestamp(1_800_000_000 + (i / 100) as u32));
    }
    let dt = t0.elapsed();
    let per = dt.as_nanos() as f64 / n as f64;
    println!(
        "{label:<28} {n:>9} INVITEs in {:>7.3}s  {:>8.0} ns each  {:>10.0} INVITEs/s/core",
        dt.as_secs_f64(),
        per,
        1e9 / per
    );
}

fn main() {
    println!("decision path only — no capture, no disk, single core\n");
    run("settled source (one country)", 1_000_000, false);
    run("varied A-numbers (same source)", 1_000_000, true);
}
