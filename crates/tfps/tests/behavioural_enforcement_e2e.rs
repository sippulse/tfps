use std::net::Ipv4Addr;
use std::path::PathBuf;

use tfps::store::Store;
use tfps_core::dialplan::DialPlan;
use tfps_core::disposition::{disposition, Disposition};
use tfps_core::engine::{Decision, Engine, Mode};
use tfps_core::novelty::Timestamp;

const PEER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const SWITCH: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const BASE: u32 = 1_800_000_000;
const DAY: u32 = 24 * 3600;
const BLOCK_TTL: u64 = 3600;

fn t(offset: u32) -> Timestamp {
    Timestamp(BASE + offset)
}

fn invite(seq: u32, dest: &str) -> Vec<u8> {
    format!(
        "INVITE sip:{dest}@pbx SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK{seq}\r\n\
         From: <sip:200@pbx>;tag=t1\r\n\
         To: <sip:{dest}@pbx>\r\n\
         Call-ID: call-{seq}\r\n\
         CSeq: {seq} INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

fn db_path() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tfps-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("tfps.db")
}

#[test]
fn a_24_hour_old_source_is_blocked_enforced_and_audited() {
    let path = db_path();
    let mut store = Store::open(&path).expect("store");
    let mut engine = Engine::new(DialPlan::new(["00"]), Mode::Active).with_behavioural();

    assert_eq!(engine.params().warmup_secs, DAY);
    assert_eq!(engine.params().warmup_calls, 20);

    let mut blocked_before = false;
    for i in 0..20u32 {
        let (_, d) = engine.observe_packet(PEER, SWITCH, &invite(i + 1, "00442039967796"), t(i));
        blocked_before |= matches!(d, Decision::Block { .. });
    }
    assert!(
        !blocked_before,
        "the source is still inside its 24 h warm-up and must not block"
    );
    assert_eq!(store.checkpoint(&engine).expect("checkpoint").0, 1);

    let mut hit = None;
    for i in 0..30u32 {
        let dest = format!("004420{:04}1234", i * 17);
        let at = DAY + 1 + i * 20;
        let (_, d) = engine.observe_packet(PEER, SWITCH, &invite(100 + i, &dest), t(at));
        if let Decision::Block {
            country,
            evidence_nats,
            countries,
        } = d
        {
            hit = Some((at, country, evidence_nats, countries));
            break;
        }
    }
    let (at, country, evidence_nats, countries) =
        hit.expect("a source older than 24 h with 20 calls must block");

    let detail =
        format!("country={country} evidence={evidence_nats}nats distinct_countries={countries}");
    let reason = ("behavioural", detail.as_str());

    match disposition(Some(reason), None, false, true) {
        Disposition::Block { kind, detail } => {
            assert_eq!(kind, "behavioural");
            assert_eq!(detail, reason.1);
            store
                .log_block(BASE + at, PEER, kind, detail)
                .expect("audit block");
        }
        other => panic!("expected an enforced block, got {other:?}"),
    }

    let rows = store
        .blocks(5, Some(&PEER.to_string()))
        .expect("read audit");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reason, "behavioural");
    assert!(rows[0].detail.contains("evidence="));

    let exempt = disposition(Some(reason), Some("10.0.0.0/8"), false, true);
    assert!(matches!(exempt, Disposition::ExemptIgnoreIp { .. }));

    let report = disposition(Some(reason), None, false, false);
    assert!(matches!(report, Disposition::WouldBlock { .. }));

    let mut applied = Vec::new();
    if let Disposition::Block { kind, detail } = disposition(Some(reason), None, false, true) {
        applied.push((PEER, BLOCK_TTL, kind, detail.to_string()));
    }
    assert_eq!(
        applied,
        vec![(PEER, BLOCK_TTL, "behavioural", detail.clone())]
    );

    let _ = std::fs::remove_dir_all(path.parent().expect("db parent"));
}
