//! Hand-placed bans and unbans leave a record.
//!
//! Written before the behavior exists. `tfps_ctl ban` placed a block and wrote
//! nothing about it, so `banned` showed the address with no reason, and
//! `tfps_ctl unban` wrote nothing either.
//!
//! The record lives beside the database, not in it: `tfps_ctl` opens the
//! database read-only on purpose (the note on `Store::open_readonly`). It is
//! written in monthly files so retention deletes whole months and never
//! rewrites a file another `tfps_ctl` may be appending to.

use std::net::Ipv4Addr;
use std::path::Path;

use tfps::hand_log::{self, HandAction, HandVerb};

/// A directory of its own under the system temp dir, removed when dropped.
/// No `tempfile` dependency: this crate has none, and a test helper is not a
/// reason to add one.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tfps-hand-log-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).expect("create temp dir");
    TempDir(dir)
}

fn ban(ts: u32, ip: [u8; 4], source: &str, reason: Option<&str>) -> HandAction {
    HandAction {
        ts,
        verb: HandVerb::Ban,
        ip: Ipv4Addr::from(ip),
        source: source.to_string(),
        reason: reason.map(str::to_string),
        expires: Some(ts + 3600),
    }
}

fn unban(ts: u32, ip: [u8; 4], source: &str) -> HandAction {
    HandAction {
        ts,
        verb: HandVerb::Unban,
        ip: Ipv4Addr::from(ip),
        source: source.to_string(),
        reason: None,
        expires: None,
    }
}

/// 2026-09-28 00:00:00 UTC, and whole days after it.
const SEP_28: u32 = 1_790_553_600;
const DAY: u32 = 86_400;

fn files_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

// ── where it goes ────────────────────────────────────────────────────────

#[test]
fn the_record_sits_beside_the_database_in_a_file_per_month() {
    let db = Path::new("/var/lib/tfps/tfps.db");
    assert_eq!(
        hand_log::path_for(db, SEP_28),
        Path::new("/var/lib/tfps/hand_actions-202609.jsonl")
    );
    assert_eq!(
        hand_log::path_for(db, SEP_28 + 3 * DAY),
        Path::new("/var/lib/tfps/hand_actions-202610.jsonl"),
        "October's actions go to October's file"
    );
}

// ── writing and reading ──────────────────────────────────────────────────

#[test]
fn an_appended_action_reads_back_whole() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    let a = ban(
        SEP_28,
        [198, 51, 100, 20],
        "sipnab",
        Some("scanner seen by sipnab"),
    );
    hand_log::append(&db, std::slice::from_ref(&a)).expect("append");
    let (read, unreadable) = hand_log::read_all(&db);
    assert_eq!(read, vec![a]);
    assert_eq!(unreadable, 0);
}

#[test]
fn each_action_is_one_line() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    hand_log::append(
        &db,
        &[
            ban(SEP_28, [198, 51, 100, 20], "sipnab", Some("first")),
            unban(SEP_28 + 60, [198, 51, 100, 20], "operator"),
        ],
    )
    .expect("append");
    let text = std::fs::read_to_string(hand_log::path_for(&db, SEP_28)).expect("read");
    assert_eq!(text.lines().count(), 2, "{text}");
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("each line is JSON");
        assert!(v["source"].is_string(), "{line}");
    }
}

#[test]
fn concurrent_writers_never_interleave_lines() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    let reason = "x".repeat(200);
    std::thread::scope(|s| {
        for t in 0..8u8 {
            let db = &db;
            let reason = &reason;
            s.spawn(move || {
                for i in 0..50u8 {
                    hand_log::append(db, &[ban(SEP_28, [198, 51, t, i], "sipnab", Some(reason))])
                        .expect("append");
                }
            });
        }
    });
    let (read, unreadable) = hand_log::read_all(&db);
    assert_eq!(unreadable, 0, "a line was torn by a concurrent writer");
    assert_eq!(read.len(), 400);
}

#[test]
fn a_corrupt_line_is_counted_and_the_rest_still_read() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    let a = ban(SEP_28, [198, 51, 100, 20], "sipnab", None);
    hand_log::append(&db, std::slice::from_ref(&a)).expect("append");
    let path = hand_log::path_for(&db, SEP_28);
    let mut text = std::fs::read_to_string(&path).expect("read");
    text.push_str("{not json\n");
    std::fs::write(&path, text).expect("write");
    let (read, unreadable) = hand_log::read_all(&db);
    assert_eq!(read, vec![a]);
    assert_eq!(
        unreadable, 1,
        "a bad line is reported, not silently dropped"
    );
}

#[test]
fn nothing_written_means_nothing_read_and_no_error() {
    let dir = tempdir();
    let (read, unreadable) = hand_log::read_all(&dir.path().join("tfps.db"));
    assert!(read.is_empty());
    assert_eq!(unreadable, 0);
}

#[test]
fn a_new_file_takes_the_databases_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    std::fs::write(&db, b"").expect("db");
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    hand_log::append(&db, &[ban(SEP_28, [198, 51, 100, 20], "sipnab", None)]).expect("append");
    let mode = std::fs::metadata(hand_log::path_for(&db, SEP_28))
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o640,
        "whoever may read the database may read this, and no one else"
    );
}

#[test]
fn with_no_database_a_new_file_is_owner_and_group_readable_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    hand_log::append(&db, &[ban(SEP_28, [198, 51, 100, 20], "sipnab", None)]).expect("append");
    let mode = std::fs::metadata(hand_log::path_for(&db, SEP_28))
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o640);
}

// ── what it says about an address ────────────────────────────────────────

#[test]
fn the_latest_hand_action_per_address_is_what_counts() {
    let actions = vec![
        ban(SEP_28, [198, 51, 100, 20], "sipnab", Some("first")),
        unban(SEP_28 + 60, [198, 51, 100, 20], "operator"),
        ban(SEP_28 + 120, [198, 51, 100, 20], "operator", Some("again")),
        ban(SEP_28 + 10, [198, 51, 100, 21], "sipnab", None),
    ];
    let latest = hand_log::latest_by_ip(&actions);
    assert_eq!(latest.len(), 2);
    let a = &latest["198.51.100.20"];
    assert_eq!(a.verb, HandVerb::Ban);
    assert_eq!(a.source, "operator");
    assert_eq!(a.reason.as_deref(), Some("again"));
}

#[test]
fn the_latest_is_decided_by_time_not_by_file_order() {
    let actions = vec![
        ban(SEP_28 + 120, [198, 51, 100, 20], "later", None),
        ban(SEP_28, [198, 51, 100, 20], "earlier", None),
    ];
    assert_eq!(
        hand_log::latest_by_ip(&actions)["198.51.100.20"].source,
        "later"
    );
}

// ── what a caller may say ────────────────────────────────────────────────

#[test]
fn a_source_is_a_short_plain_name() {
    for good in ["sipnab", "operator", "ops-console.1", "a_b"] {
        hand_log::check_source(good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for bad in [
        "",
        "has space",
        "semi;colon",
        "new\nline",
        "émoji",
        &"x".repeat(65),
    ] {
        let e = hand_log::check_source(bad).expect_err(bad);
        assert!(e.contains("--source"), "{bad:?}: {e}");
    }
}

#[test]
fn a_reason_is_bounded_and_carries_no_control_characters() {
    hand_log::check_reason("scanner seen by sipnab: 400 REGISTERs in 60 s").expect("plain text");
    for bad in ["", "new\nline", "tab\there", "bell\u{7}", &"x".repeat(257)] {
        let e = hand_log::check_reason(bad).expect_err(bad);
        assert!(e.contains("--reason"), "{bad:?}: {e}");
    }
}

// ── retention ────────────────────────────────────────────────────────────

#[test]
fn pruning_deletes_whole_months_past_the_window_and_nothing_else() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    // One action in each of five months, May through September 2026.
    for months_back in 0..5u32 {
        hand_log::append(
            &db,
            &[ban(
                SEP_28 - months_back * 31 * DAY,
                [198, 51, 100, 20],
                "sipnab",
                None,
            )],
        )
        .expect("append");
    }
    std::fs::write(dir.path().join("unrelated.txt"), b"keep me").expect("write");
    assert_eq!(files_in(dir.path()).len(), 6);

    // A 90-day window from Sep 28 reaches back to Jun 30, so May's file is
    // entirely older than the window and goes; June's holds a day inside it.
    let removed = hand_log::prune(&db, SEP_28, 90 * DAY).expect("prune");
    assert_eq!(removed, 1);
    let left = files_in(dir.path());
    assert!(
        !left.contains(&"hand_actions-202605.jsonl".to_string()),
        "{left:?}"
    );
    assert!(
        left.contains(&"hand_actions-202606.jsonl".to_string()),
        "{left:?}"
    );
    assert!(left.contains(&"unrelated.txt".to_string()), "{left:?}");
}

#[test]
fn pruning_never_deletes_the_current_month() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    hand_log::append(&db, &[ban(SEP_28, [198, 51, 100, 20], "sipnab", None)]).expect("append");
    let removed = hand_log::prune(&db, SEP_28, 0).expect("prune with a zero window");
    assert_eq!(removed, 0);
    assert!(hand_log::path_for(&db, SEP_28).exists());
}

// ── what `banned` asks: the latest action for the addresses it lists ─────

fn wanted(ips: &[[u8; 4]]) -> std::collections::HashSet<Ipv4Addr> {
    ips.iter().map(|o| Ipv4Addr::from(*o)).collect()
}

#[test]
fn latest_for_answers_only_the_addresses_asked_about() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    hand_log::append(
        &db,
        &[
            ban(SEP_28, [198, 51, 100, 20], "sipnab", Some("a")),
            ban(SEP_28, [198, 51, 100, 21], "sipnab", Some("b")),
        ],
    )
    .expect("append");
    let found = hand_log::latest_for(&db, &wanted(&[[198, 51, 100, 20]]));
    assert_eq!(found.by_ip.len(), 1);
    assert_eq!(
        found.by_ip[&Ipv4Addr::new(198, 51, 100, 20)]
            .reason
            .as_deref(),
        Some("a")
    );
}

#[test]
fn latest_for_takes_the_newest_month_over_an_older_one() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    hand_log::append(
        &db,
        &[ban(SEP_28 - 40 * DAY, [198, 51, 100, 20], "old", None)],
    )
    .expect("append");
    hand_log::append(&db, &[ban(SEP_28, [198, 51, 100, 20], "new", None)]).expect("append");
    let found = hand_log::latest_for(&db, &wanted(&[[198, 51, 100, 20]]));
    assert_eq!(found.by_ip[&Ipv4Addr::new(198, 51, 100, 20)].source, "new");
}

#[test]
fn latest_for_still_searches_older_months_for_an_address_not_yet_found() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    hand_log::append(
        &db,
        &[ban(SEP_28 - 40 * DAY, [198, 51, 100, 21], "august", None)],
    )
    .expect("append");
    hand_log::append(&db, &[ban(SEP_28, [198, 51, 100, 20], "september", None)]).expect("append");
    let found = hand_log::latest_for(&db, &wanted(&[[198, 51, 100, 20], [198, 51, 100, 21]]));
    assert_eq!(found.by_ip.len(), 2);
    assert_eq!(
        found.by_ip[&Ipv4Addr::new(198, 51, 100, 21)].source,
        "august"
    );
}

#[test]
fn latest_for_goes_by_time_when_lines_landed_out_of_order() {
    // Two tfps_ctl runs: one takes its time first and writes second.
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    hand_log::append(
        &db,
        &[
            ban(SEP_28 + 120, [198, 51, 100, 20], "later", None),
            ban(SEP_28 + 60, [198, 51, 100, 20], "earlier", None),
        ],
    )
    .expect("append");
    let found = hand_log::latest_for(&db, &wanted(&[[198, 51, 100, 20]]));
    assert_eq!(
        found.by_ip[&Ipv4Addr::new(198, 51, 100, 20)].source,
        "later"
    );
}

#[test]
fn latest_for_agrees_with_reading_everything() {
    // The fast path must give the same answer as the plain one, on a mix of
    // months, verbs, sources and out-of-order lines.
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    let mut actions = Vec::new();
    for i in 0..300u32 {
        let ts = SEP_28 - (i % 70) * DAY + (i * 37) % 900;
        let verb = if i % 4 == 0 {
            HandVerb::Unban
        } else {
            HandVerb::Ban
        };
        let mut a = ban(
            ts,
            [198, 51, 100, (i % 25) as u8],
            &format!("s{}", i % 7),
            None,
        );
        a.verb = verb;
        actions.push(a);
    }
    hand_log::append(&db, &actions).expect("append");
    let all: Vec<[u8; 4]> = (0..30u8).map(|o| [198, 51, 100, o]).collect();
    let fast = hand_log::latest_for(&db, &wanted(&all));
    let (read, _) = hand_log::read_all(&db);
    let plain = hand_log::latest_by_ip(&read);
    assert_eq!(fast.by_ip.len(), plain.len());
    for (ip, a) in &fast.by_ip {
        assert_eq!(plain[&ip.to_string()].ts, a.ts, "{ip}");
    }
}

#[test]
fn latest_for_counts_a_corrupt_line_it_had_to_read() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    hand_log::append(&db, &[ban(SEP_28, [198, 51, 100, 20], "sipnab", None)]).expect("append");
    let path = hand_log::path_for(&db, SEP_28);
    let mut text = std::fs::read_to_string(&path).expect("read");
    text.push_str("{not json\n");
    std::fs::write(&path, text).expect("write");
    let found = hand_log::latest_for(&db, &wanted(&[[198, 51, 100, 20]]));
    assert_eq!(found.by_ip.len(), 1);
    assert_eq!(found.unreadable, 1);
}

#[test]
fn latest_for_asked_about_nothing_reads_nothing() {
    let dir = tempdir();
    let db = dir.path().join("tfps.db");
    hand_log::append(&db, &[ban(SEP_28, [198, 51, 100, 20], "sipnab", None)]).expect("append");
    let path = hand_log::path_for(&db, SEP_28);
    std::fs::write(&path, "{not json\n").expect("write");
    let found = hand_log::latest_for(&db, &std::collections::HashSet::new());
    assert!(found.by_ip.is_empty());
    assert_eq!(found.unreadable, 0, "an empty question opens no file");
}
