//! `tfps_ctl` — inspect what TFPS has learned, and lift or place blocks.
//!
//! The counterpart to `fail2ban-client`, and it exists for the same reason that tool does:
//! a defence nobody can inspect is a defence nobody trusts. `SPEC.md` §12 makes manual
//! unblocking the **precision proxy** — with no labelled data it is the only measure of how
//! often the system is wrong, so the act has to be one command, not a database session.
//!
//! Two sources of truth, and the difference matters to anyone reading the output:
//!
//! - **Blocks live in the kernel.** They are read and written straight into the eBPF map,
//!   so an unban takes effect on the next packet.
//! - **Learning lives in SQLite**, written at checkpoint (every 300 s by default). What is
//!   shown is therefore a snapshot, and `status` says how old it is rather than letting
//!   somebody draw conclusions from stale rows.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use tfps::say;
use tfps::store::{BlockRow, SourceFilter, Store};
use tfps::xdp::{monotonic_ns, Blocklist};
use tfps_core::disposition::{gate, Gate};
use tfps_core::ignore::{IgnoreList, Origin};

fn usage() -> String {
    format!(
        "tfps_ctl — inspect and control a running TFPS

USAGE: tfps_ctl <command> [options]

  status                       what is running, what is blocked, how fresh the state is
  stats                        every counter: kernel drops, traffic mix, what got blocked
  banned [--why]               list condemned sources, with time left
  unban <ip>... | --all        lift a block. The precision measure of this product
  ban <ip> [--ttl N]           condemn a source by hand (default ttl: 3600s, 0 = forever)
  sources [filters]            list learned sources and the countries they call
  source <peer>                everything known about one source
  peers                        sources by country breadth, when last heard
  countries <peer>             the countries a source has been seen to call
  log [--limit N] [--ip IP]    the block audit log, newest first
  forget <peer> [--a NUMBER]   erase learned state (requires tfps stopped)

SOURCE FILTERS:
  --peer IP                    exactly this peer
  --country ISO                sources that have called this country, e.g. --country GB
  --limit N                    stop after N rows (default 50)

GLOBAL:
  --db PATH                    database (default: {db})
  --map PATH                   an explicitly pinned block map
  --json                       machine-readable output, one JSON document per line
  --config PATH                configuration, for ignoreip (default: {cfg})
  -h, --help                   this help

Reading blocks needs CAP_BPF (run as root). Reading learned state only needs the database.
",
        db = tfps::store::DEFAULT_PATH,
        cfg = tfps::config::DEFAULT_PATH
    )
}

struct Args {
    command: String,
    positional: Vec<String>,
    db: PathBuf,
    map: Option<PathBuf>,
    peer: Option<String>,
    a_number: Option<String>,
    country: Option<String>,
    ip: Option<String>,
    limit: usize,
    ttl: u64,
    all: bool,
    why: bool,
    json: bool,
    config: PathBuf,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        command: String::new(),
        positional: Vec::new(),
        db: PathBuf::from(tfps::store::DEFAULT_PATH),
        map: None,
        peer: None,
        a_number: None,
        country: None,
        ip: None,
        limit: 50,
        ttl: 3600,
        all: false,
        why: false,
        json: false,
        config: PathBuf::from(tfps::config::DEFAULT_PATH),
    };
    let mut it = argv.iter();
    let value = |name: &str, it: &mut std::slice::Iter<'_, String>| -> Result<String, String> {
        it.next()
            .cloned()
            .ok_or_else(|| format!("{name} requires a value"))
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--db" => a.db = PathBuf::from(value("--db", &mut it)?),
            "--map" => a.map = Some(PathBuf::from(value("--map", &mut it)?)),
            "--config" => a.config = PathBuf::from(value("--config", &mut it)?),
            "--peer" => a.peer = Some(value("--peer", &mut it)?),
            "--a" => a.a_number = Some(value("--a", &mut it)?),
            "--country" => a.country = Some(value("--country", &mut it)?),
            "--ip" => a.ip = Some(value("--ip", &mut it)?),
            "--limit" => {
                a.limit = value("--limit", &mut it)?
                    .parse()
                    .map_err(|e| format!("invalid --limit: {e}"))?
            }
            "--ttl" => {
                a.ttl = value("--ttl", &mut it)?
                    .parse()
                    .map_err(|e| format!("invalid --ttl: {e}"))?
            }
            "--all" => a.all = true,
            "--why" => a.why = true,
            "--json" => a.json = true,
            "-h" | "--help" => return Err(String::new()),
            other if other.starts_with('-') => return Err(format!("unknown option: {other}")),
            other if a.command.is_empty() => a.command = other.to_string(),
            other => a.positional.push(other.to_string()),
        }
    }
    if a.command.is_empty() {
        return Err(String::new());
    }
    Ok(a)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(e) if e.is_empty() => {
            say!("{}", usage().trim_end());
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("error: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };

    let r = match args.command.as_str() {
        "status" => status(&args),
        "stats" => stats(&args),
        "banned" => banned(&args),
        "unban" => unban(&args),
        "ban" => ban(&args),
        "sources" => sources(&args),
        "source" => source(&args),
        "peers" => peers(&args),
        "countries" => countries(&args),
        "log" => log(&args),
        "forget" => forget(&args),
        other => Err(format!("unknown command: {other}")),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------- commands

/// What `status` tells a program.
///
/// This file's own module comment says `status` exists so that nobody "draws
/// conclusions from stale rows", which is why the learned-state totals and the
/// checkpoint time are here and not only in the human view: a `--json` consumer
/// without them has exactly the blindness the command was written to prevent.
///
/// `map` is `Blocklist::source` — which of the three planes was opened: an
/// explicit pin, a third party's shared pin, or the daemon's own map by name.
/// The human path prints it as `enforcement :`; a program needs it to tell the
/// daemon's own enforcement from somebody else's map, and it is free at the
/// call site.
///
/// `pairs`/`peers`/`last_checkpoint` are `null`, never zeroed, when the
/// database cannot be read — the same null-not-zero rule `stats --json`'s
/// `kernel` and `condemnation` blocks follow, and for the same reason. Zero
/// pairs is an idle box; an unreadable database is a broken one.
/// `last_checkpoint` is an epoch second, and `null` when nothing has been
/// checkpointed yet: `Store::totals` coalesces that case to 0, which as a time
/// would read as 1970.
///
/// `mode` and `interface` stay `None`, and the nullability is not a
/// placeholder: this tool opens the blocklist **map**, not the XDP
/// **program**, so the attach mode and interface are not visible to it. Only
/// the daemon knows them, at attach time. Recording them is a daemon change,
/// and this is an output-formatting change.
#[derive(Serialize)]
struct StatusDoc {
    enforcement: &'static str,
    mode: Option<String>,
    interface: Option<String>,
    map: Option<String>,
    blocked_now: usize,
    pairs: Option<u32>,
    peers: Option<u32>,
    last_checkpoint: Option<u32>,
    db: String,
    version: String,
}

/// Built from arguments so it is drivable from a test: the real caller opens a
/// BPF map, which needs `CAP_BPF`, and a database.
///
/// `blocked` carries the map's own name alongside its entry count because the
/// two come from the same successful open — binding them in one `Result` is
/// what stops `enforcement: "inactive"` from ever appearing beside a named
/// `map`. `totals` is `Store::totals`'s `(pairs, peers, newest)`, or `None`
/// when the database could not be read.
fn status_doc(
    blocked: Result<(usize, String), String>,
    totals: Option<(u32, u32, u32)>,
    db: &Path,
    version: &str,
) -> StatusDoc {
    let (enforcement, blocked_now, map) = match blocked {
        Ok((n, source)) => ("active", n, Some(source)),
        Err(_) => ("inactive", 0, None),
    };
    StatusDoc {
        enforcement,
        mode: None,
        interface: None,
        map,
        blocked_now,
        pairs: totals.map(|(pairs, _, _)| pairs),
        peers: totals.map(|(_, peers, _)| peers),
        last_checkpoint: totals.and_then(|(_, _, newest)| (newest > 0).then_some(newest)),
        db: db.display().to_string(),
        version: version.to_string(),
    }
}

fn status(args: &Args) -> Result<(), String> {
    if args.json {
        let blocked = Blocklist::open(args.map.as_deref()).map(|b| (b.entries().len(), b.source));
        let totals = Store::open_readonly(&args.db).and_then(|s| s.totals()).ok();
        say!(
            "{}",
            tfps::json_line(&status_doc(
                blocked,
                totals,
                &args.db,
                env!("CARGO_PKG_VERSION")
            ))?
        );
        return Ok(());
    }
    say!("database          : {}", args.db.display());
    match Store::open_readonly(&args.db).and_then(|s| s.totals()) {
        Ok((pairs, peers, newest)) => {
            say!("learned state     : {pairs} pairs across {peers} peers");
            if newest > 0 {
                say!(
                    "last checkpoint   : {} ago (state is a snapshot, not live)",
                    ago(now().saturating_sub(newest))
                );
            }
        }
        Err(e) => say!("learned state     : unavailable — {e}"),
    }
    match Blocklist::open(args.map.as_deref()) {
        Ok(b) => {
            let e = b.entries();
            let permanent = e.iter().filter(|(_, until)| *until == 0).count();
            say!("enforcement       : {}", b.source);
            say!(
                "blocked now       : {} ({permanent} without expiry)",
                e.len()
            );
        }
        Err(e) => {
            say!("enforcement       : unreachable — {e}");
            say!("                    (learned state above is still readable)");
        }
    }
    Ok(())
}

/// The live KERNEL block of `stats --json`, or absent entirely when the
/// counters cannot be read — see `StatsDoc`'s doc comment.
#[derive(Serialize)]
struct KernelDoc {
    seen: u64,
    dropped: u64,
    expired: u64,
}

/// The TRAFFIC block of `stats --json`: the last checkpoint's counters,
/// straight from the `stats` meta line the human TRAFFIC block already
/// parses, as a map instead of two print columns — a program has no use for
/// column alignment. `age_secs` is the raw interval, not `ago()`'s
/// formatted string: a consumer recomputes its own presentation, the same
/// reasoning that keeps `log_doc`'s times as epoch integers rather than
/// strings.
///
/// The counters are integers for the same reason. They are `u64` counts in the
/// daemon (`main.rs`'s `counter_line` writes `engine::Stats`, every field a
/// `u64`), and rendering them as strings put `"udp":"120"` in the same document
/// as `"seen":120` — the same kind of number, two types, so a consumer would
/// have to know which command produced a field before it could add it up.
///
/// A value that does not parse is `null`, not dropped and not zero: the key
/// still tells a consumer the daemon reported that counter, and dropping it
/// would leave "the daemon never wrote this" and "this line is corrupt"
/// indistinguishable.
#[derive(Serialize)]
struct TrafficDoc {
    age_secs: Option<u32>,
    counters: std::collections::BTreeMap<String, Option<u64>>,
}

/// The condemnation-summary block of `stats --json`: of everything
/// currently condemned in the kernel, how many trace back to the
/// perimeter/manual audit log versus appear only because they are also on
/// the APIBAN feed. Absent entirely when `Blocklist::open` fails — see
/// `StatsDoc`'s doc comment.
#[derive(Serialize)]
struct CondemnationDoc {
    condemned_now: usize,
    perimeter_manual: usize,
    apiban_feed_only: usize,
}

/// What `stats --json` says: the live KERNEL block, the condemnation
/// summary, and the checkpointed TRAFFIC block, as one document instead of
/// three.
///
/// That is three of what the human path below prints, not all of it. The human
/// path also prints IGNOREIP, CALIBRATION, LEARNED and BLOCKS BY REASON, plus a
/// `running for` line, and none of those is in this document. Adding them is a
/// wider change than this one; what matters here is that the omission is
/// stated, so nobody reads `stats --json` as the whole of `stats`.
///
/// All three are `null`, never zeroed, when their source cannot be read:
/// `kernel` when the counters are unreachable, `condemnation` when
/// `Blocklist::open` fails (a *different* kernel map from the one `kernel`
/// reads — see `xdp::Blocklist::open` vs `xdp::live_counters`, either can
/// fail independently of the other), `traffic` before the first checkpoint
/// exists. A tool that could not read a counter and a counter that
/// genuinely reads zero are different facts; conflating them would report
/// "nothing was dropped", or "nothing is blocked", about a box whose
/// enforcement has failed or whose map this tool simply could not open.
#[derive(Serialize)]
struct StatsDoc {
    kernel: Option<KernelDoc>,
    condemnation: Option<CondemnationDoc>,
    traffic: Option<TrafficDoc>,
}

/// Built from already-computed values, the same way `status_doc` is: no
/// transformation happens here beyond wrapping. The nontrivial pieces —
/// `condemnation_counts`'s perimeter/feed split and `traffic_doc`'s
/// checkpoint parsing — are computed and tested on their own below.
fn stats_doc(
    kernel: Option<(u64, u64, u64)>,
    condemnation: Option<(usize, usize, usize)>,
    traffic: Option<TrafficDoc>,
) -> StatsDoc {
    StatsDoc {
        kernel: kernel.map(|(seen, dropped, expired)| KernelDoc {
            seen,
            dropped,
            expired,
        }),
        condemnation: condemnation.map(|(condemned_now, perimeter_manual, apiban_feed_only)| {
            CondemnationDoc {
                condemned_now,
                perimeter_manual,
                apiban_feed_only,
            }
        }),
        traffic,
    }
}

/// The perimeter/feed split inside one already-open blocklist read: how many
/// of `entries` trace back to the perimeter/manual audit log versus appear
/// only because they are also on the APIBAN feed. Mirrors the
/// `perimeter`/`feed` split the human path computes inline below, pulled out
/// so it is drivable with concrete addresses instead of a live kernel map
/// and database. Whether the blocklist could be opened at all — the
/// `Option` `stats` wraps this in for `stats_doc` — is decided by the
/// caller, not here: this function only ever runs once a read has already
/// succeeded.
fn condemnation_counts(
    entries: &[(Ipv4Addr, u64)],
    audit: &std::collections::HashSet<String>,
    apiban: &std::collections::HashSet<String>,
) -> (usize, usize, usize) {
    let perimeter = entries
        .iter()
        .filter(|(ip, _)| audit.contains(&ip.to_string()))
        .count();
    let feed = entries
        .iter()
        .filter(|(ip, _)| !audit.contains(&ip.to_string()) && apiban.contains(&ip.to_string()))
        .count();
    (entries.len(), perimeter, feed)
}

/// Parses the checkpoint's `stats` meta line into `stats --json`'s TRAFFIC
/// block. `None` when there is no checkpoint yet — the human path's "no
/// checkpoint yet" case — not an empty map, because the daemon has produced
/// no numbers at all yet, a different fact from zero of them.
fn traffic_doc(line: Option<&str>, ts: Option<u32>, now: u32) -> Option<TrafficDoc> {
    let line = line?;
    let counters = line
        .split_whitespace()
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.parse::<u64>().ok()))
        .collect();
    Some(TrafficDoc {
        age_secs: ts.map(|t| now.saturating_sub(t)),
        counters,
    })
}

/// The whole picture, from the two places it lives.
///
/// **The kernel half is live; the userspace half is a snapshot.** They are printed apart,
/// with the snapshot's age stated, because presenting a five-minute-old packet count beside
/// a current drop count as if both were now would be the kind of quiet inaccuracy this
/// project exists to avoid.
fn stats(args: &Args) -> Result<(), String> {
    if args.json {
        // A self-contained pass, independent of the human path below (the
        // same pattern `banned --json` uses): its own kernel counter read,
        // its own store open, its own blocklist open. Kept separate so
        // every line below this block stays untouched.
        let kernel = tfps::xdp::live_counters()
            .ok()
            .map(|c| (c.seen, c.dropped, c.expired));
        let s = Store::open_readonly(&args.db)?;
        let apiban = s.apiban_all().unwrap_or_default();
        let audit: std::collections::HashSet<String> = s
            .blocks(1_000_000, None)
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.ip)
            .collect();
        // `null`, not `(0, 0, 0)`, when the blocklist map cannot be opened —
        // the same reason `kernel` above is `None` rather than zeroed: a
        // consumer reading `condemned_now: 0` off a box whose map could not
        // even be opened would conclude nothing is blocked, the exact wrong
        // reading this null is here to prevent.
        let condemnation = Blocklist::open(args.map.as_deref())
            .ok()
            .map(|b| condemnation_counts(&b.entries(), &audit, &apiban));
        let stats_line = s.meta_get("stats");
        let stats_ts = s.meta_get("stats_ts").and_then(|t| t.parse::<u32>().ok());
        let traffic = traffic_doc(stats_line.as_deref(), stats_ts, now());
        say!(
            "{}",
            tfps::json_line(&stats_doc(kernel, condemnation, traffic))?
        );
        return Ok(());
    }
    match tfps::xdp::live_counters() {
        Ok(c) => {
            let share = if c.seen > 0 {
                100.0 * c.dropped as f64 / c.seen as f64
            } else {
                0.0
            };
            say!("KERNEL  (live)");
            say!("  seen on SIP ports : {}", c.seen);
            say!(
                "  dropped by XDP    : {} ({share:.1}% — gone before sngrep)",
                c.dropped
            );
            say!("  blocks expired    : {}", c.expired);
        }
        Err(e) => say!("KERNEL  (live)\n  unavailable — {e}"),
    }
    let s = Store::open_readonly(&args.db)?;
    let apiban = s.apiban_all().unwrap_or_default();
    // A perimeter block often lands on an IP that is also on the feed; attribute it to the
    // reason we condemned it (the audit log), not to the feed it happens to appear on.
    let audit: std::collections::HashSet<String> = s
        .blocks(1_000_000, None)
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.ip)
        .collect();
    if let Ok(b) = Blocklist::open(args.map.as_deref()) {
        let e = b.entries();
        let perimeter = e
            .iter()
            .filter(|(ip, _)| audit.contains(&ip.to_string()))
            .count();
        let feed = e
            .iter()
            .filter(|(ip, _)| !audit.contains(&ip.to_string()) && apiban.contains(&ip.to_string()))
            .count();
        say!("  condemned now     : {}", e.len());
        say!("    perimeter/manual : {perimeter}");
        say!("    APIBAN feed only : {feed}");
    }

    let now = now();
    match (s.meta_get("stats"), s.meta_get("stats_ts")) {
        (Some(line), ts) => {
            let age = ts
                .and_then(|t| t.parse::<u32>().ok())
                .map(|t| ago(now.saturating_sub(t)))
                .unwrap_or_else(|| "unknown".into());
            say!("\nTRAFFIC  (as of the last checkpoint, {age} ago)");
            // Two columns, so twenty counters stay readable in a terminal.
            let pairs: Vec<(&str, &str)> = line
                .split_whitespace()
                .filter_map(|kv| kv.split_once('='))
                .collect();
            for row in pairs.chunks(2) {
                let cell = |(k, v): &(&str, &str)| format!("{k:<16} {v:>10}");
                say!(
                    "  {}   {}",
                    cell(&row[0]),
                    row.get(1).map(cell).unwrap_or_default()
                );
            }
        }
        _ => say!("\nTRAFFIC\n  no checkpoint yet — the daemon writes these every 5 minutes"),
    }
    if let Some(t) = s.meta_get("started_at").and_then(|v| v.parse::<u32>().ok()) {
        say!("  {:<16} {:>10}", "running for", ago(now.saturating_sub(t)));
    }

    if let Some(line) = s.meta_get("ignoreip").filter(|l| !l.is_empty()) {
        say!("\nIGNOREIP  (exempt from enforcement, still judged and reported)");
        for entry in line.split_whitespace() {
            if let Some((label, hits)) = entry.rsplit_once('=') {
                let note = if hits == "0" { "  never matched" } else { "" };
                say!("  {label:<22} {hits:>8}{note}");
            }
        }
    }

    if let Some(cal) = s.meta_get("calibration").filter(|c| !c.is_empty()) {
        say!("\nCALIBRATION  (benign hypotheses learned from this deployment)");
        for kv in cal.split_whitespace() {
            if let Some((k, v)) = kv.split_once('=') {
                say!("  {k:<16} {v:>10}");
            }
        }
    }

    let (pairs, peers, _) = s.totals()?;
    let (countries, calls) = s.country_spread()?;
    say!("\nLEARNED");
    say!("  {:<16} {:>10}", "pairs", pairs);
    say!("  {:<16} {:>10}", "peers", peers);
    say!("  {:<16} {:>10}", "countries", countries);
    say!("  {:<16} {:>10}", "intl calls", calls);

    say!("\nBLOCKS BY REASON  (perimeter/manual — the APIBAN feed is a separate list)");
    say!(
        "  {:<16} {:>10}  {}",
        "apiban (feed)",
        apiban.len(),
        "permanent, not audit-logged"
    );
    for (label, since) in [
        ("last hour", 3600u32),
        ("last day", 86400),
        ("last week", 604_800),
    ] {
        let rows = s.blocks_by_reason(now.saturating_sub(since))?;
        let total: u32 = rows.iter().map(|(_, n)| n).sum();
        let detail: Vec<String> = rows.iter().map(|(r, n)| format!("{r}:{n}")).collect();
        say!("  {label:<16} {total:>10}  {}", detail.join(" "));
    }
    Ok(())
}

/// What `banned --json` says about one currently-condemned source.
///
/// `first_seen`/`expires` are epoch seconds, the same as every other time in
/// this contract (`log_doc`, `expires_epoch`, `traffic_doc`'s `age_secs`, the
/// row documents' `last_seen`). A consumer recomputes its own presentation; a
/// document that rendered one command's times as integers and another's as
/// formatted strings would make it guess which it had been handed.
///
/// `first_seen` is read from the audit log via `Store::blocks(1_000_000, None)`,
/// which is `ORDER BY ts DESC LIMIT 1000000`: on a box with more than a million
/// audit rows the truncation drops the OLDEST rows, and those are precisely the
/// ones `first_seen` reads from, so it would report the oldest row still within
/// the limit rather than the oldest there is.
#[derive(Serialize)]
struct BannedDoc {
    ip: String,
    reason: Option<String>,
    detail: Option<String>,
    first_seen: Option<u32>,
    expires: Option<u32>,
    enforced: bool,
}

/// Built from arguments so it is drivable from a test: the real caller needs
/// `CAP_BPF` to open the kernel map and a database file to attribute a reason.
/// `enforced` is always `true` — every row this feeds comes from the kernel's
/// own blocklist (`Blocklist::entries`), which by construction lists only what
/// is presently enforced. `first_seen`/`expires` arrive already as epoch
/// seconds (or `None`) and are carried through unchanged.
fn banned_doc(
    ip: &str,
    why: Option<(&str, &str)>,
    first_seen: Option<u32>,
    expires: Option<u32>,
) -> BannedDoc {
    let (reason, detail) = match why {
        Some((reason, detail)) => (Some(reason.to_string()), Some(detail.to_string())),
        None => (None, None),
    };
    BannedDoc {
        ip: ip.to_string(),
        reason,
        detail,
        first_seen,
        expires,
        enforced: true,
    }
}

/// Attributes each ip to its most recent reason/detail and its earliest
/// first-seen time, from a newest-first list of audit rows.
///
/// `reason`/`detail` take the newest row per ip — the same "most recent reason
/// wins" precedence `--why` already uses in the human path below.
/// `first_seen` takes the OLDEST row instead: the plain meaning of the name
/// is "when we first saw this source", not "when we most recently
/// classified it". There is no equivalent "oldest wins" scan anywhere else
/// in this file; this is new logic and is pinned by its own test rather
/// than only being exercised indirectly through `banned_doc`.
///
/// Assumes `rows` is ordered newest-first, exactly what `Store::blocks`
/// returns: a running overwrite of `first_seen` on every subsequent
/// occurrence of an ip converges on the oldest row by the time the scan
/// ends, including across a duplicate timestamp.
fn attribute_by_ip(
    rows: Vec<BlockRow>,
) -> std::collections::HashMap<String, (String, String, u32)> {
    let mut audit: std::collections::HashMap<String, (String, String, u32)> =
        std::collections::HashMap::new();
    for r in rows {
        audit
            .entry(r.ip)
            .and_modify(|(_, _, first_seen)| *first_seen = r.ts)
            .or_insert((r.reason, r.detail, r.ts));
    }
    audit
}

/// Turns a kernel blocklist expiry into wall-clock epoch seconds, or `None`
/// for "never expires".
///
/// `until` is `CLOCK_MONOTONIC` nanoseconds (see `Blocklist::insert`), not
/// wall-clock time, so it is not an epoch second and cannot be reported as one.
/// Correlating it against a `(now_wall, now_mono)` pair read together turns the
/// monotonic delta into an absolute epoch second — the same trick the human
/// path uses on the same `until` value to produce a countdown instead of an
/// absolute time. `saturating_sub` means an entry whose monotonic deadline
/// has already passed (the kernel would normally have dropped it by the
/// time `entries()` is read) reports zero seconds left rather than
/// underflowing.
fn expires_epoch(until: u64, now_wall: u32, now_mono: u64) -> Option<u32> {
    if until == 0 {
        return None;
    }
    let secs_left = until.saturating_sub(now_mono) / 1_000_000_000;
    // `until` is a raw `u64` from a BPF map — ours, or a third party's under
    // `--map`. A delta past `u32::MAX` seconds wraps under `as u32` into a
    // plausible-looking near-future expiry, which is worse than an obviously
    // saturated one.
    Some(now_wall.saturating_add(u32::try_from(secs_left).unwrap_or(u32::MAX)))
}

/// The attribution `banned` applies to one condemned address, in the same
/// precedence its human path below already prints: the audit log's own reason
/// wins, then the APIBAN feed, then nothing.
///
/// A perimeter block often lands on an address the feed also carries, and the
/// reason we condemned it is the perimeter one — the same "block_log reason
/// wins" ordering `condemnation_counts` applies to the same two sets. The feed
/// case renders as `("apiban", "feed")`, the human line's own two words split
/// at the seam its `{reason} ({detail})` format already puts between them;
/// without it, "blocked by the feed" and "not in this audit log" reach a
/// consumer as the same two nulls.
///
/// `first_seen` comes from the audit row and only from it. The feed carries no
/// per-address time, and there is nothing to substitute: the kernel entry's
/// expiry is a different fact and would be a lie under this name.
fn banned_attribution<'a>(
    ip: &str,
    audit: &'a std::collections::HashMap<String, (String, String, u32)>,
    apiban: &std::collections::HashSet<String>,
) -> (Option<(&'a str, &'a str)>, Option<u32>) {
    match audit.get(ip) {
        Some((reason, detail, ts)) => (Some((reason.as_str(), detail.as_str())), Some(*ts)),
        None if apiban.contains(ip) => (Some(("apiban", "feed")), None),
        None => (None, None),
    }
}

fn banned(args: &Args) -> Result<(), String> {
    let b = Blocklist::open(args.map.as_deref())?;
    let entries = b.entries();
    if args.json {
        // A self-contained pass over the same `entries` the human path below
        // iterates, with its own audit and feed lookups — kept separate from the
        // human path's `store`/`audit`/`apiban` below rather than shared, so this
        // branch can sit at the top and leave every line below it untouched. Both
        // sets are loaded here for the same reason the human path loads both: an
        // address on the feed alone is attributable, and reading only the audit
        // log reports it as unattributed.
        let store = Store::open_readonly(&args.db).ok();
        let audit = match store.as_ref().and_then(|s| s.blocks(1_000_000, None).ok()) {
            Some(rows) => attribute_by_ip(rows),
            None => std::collections::HashMap::new(),
        };
        let apiban = store
            .as_ref()
            .and_then(|s| s.apiban_all().ok())
            .unwrap_or_default();
        let now_wall = now();
        let now_mono = monotonic_ns();
        for (ip, until) in &entries {
            let ip_s = ip.to_string();
            let (why, first_seen) = banned_attribution(&ip_s, &audit, &apiban);
            let expires = expires_epoch(*until, now_wall, now_mono);
            say!(
                "{}",
                tfps::json_line(&banned_doc(&ip_s, why, first_seen, expires))?
            );
        }
        return Ok(());
    }
    if entries.is_empty() {
        say!("nothing is blocked");
        return Ok(());
    }
    // Attribute each block once, block_log winning over the APIBAN feed — a scanner is
    // often on both (APIBAN's honeypots catch the same tools), and the *reason* we
    // condemned it is the perimeter one, not the feed. Load both sets once.
    let store = Store::open_readonly(&args.db).ok();
    let apiban = store
        .as_ref()
        .and_then(|s| s.apiban_all().ok())
        .unwrap_or_default();
    // ip -> (reason, detail), most recent block per ip (rows come newest-first).
    let mut audit: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    if let Some(s) = store.as_ref() {
        if let Ok(rows) = s.blocks(1_000_000, None) {
            for r in rows {
                audit.entry(r.ip).or_insert((r.reason, r.detail));
            }
        }
    }

    let now_ns = monotonic_ns();
    let (mut n_perimeter, mut n_apiban, mut n_unknown) = (0usize, 0usize, 0usize);
    say!("{:<16} {:>10}  REASON", "SOURCE", "EXPIRES IN");
    for (ip, until) in &entries {
        let left = if *until == 0 {
            "never".to_string()
        } else {
            ago(((*until).saturating_sub(now_ns) / 1_000_000_000) as u32)
        };
        let ip_s = ip.to_string();
        // block_log reason wins; then the feed; then unknown.
        let why = if let Some((reason, detail)) = audit.get(&ip_s) {
            n_perimeter += 1;
            format!("{reason} ({detail})")
        } else if apiban.contains(&ip_s) {
            n_apiban += 1;
            "apiban (feed)".to_string()
        } else {
            n_unknown += 1;
            "not in this audit log".to_string()
        };
        if args.why {
            say!("{ip_s:<16} {left:>10}  {why}");
        } else {
            say!("{ip_s:<16} {left:>10}");
        }
    }
    say!(
        "\n{} blocked — {n_perimeter} perimeter/manual, {n_apiban} APIBAN feed{}",
        entries.len(),
        if n_unknown > 0 {
            format!(", {n_unknown} unattributed")
        } else {
            String::new()
        }
    );
    Ok(())
}

fn unban(args: &Args) -> Result<(), String> {
    let mut b = Blocklist::open(args.map.as_deref())?;
    if args.all {
        let all = b.entries();
        // `remove` returns whether the address was actually there — captured per
        // address rather than discarded, so `--json` can report what really
        // happened instead of assuming every listed address came off cleanly (the
        // same reason the single-address loop below reads `removed` before acting
        // on it: a listing taken moments earlier is not a guarantee about now).
        let mut removed = Vec::with_capacity(all.len());
        for (ip, _) in &all {
            removed.push((*ip, b.remove(*ip)?));
        }
        if args.json {
            for (ip, was_removed) in &removed {
                let refused = if *was_removed {
                    None
                } else {
                    Some("not-blocked")
                };
                say!(
                    "{}",
                    tfps::json_line(&action_doc(Some(&ip.to_string()), "unban", refused, None))?
                );
            }
            return Ok(());
        }
        say!("unbanned {} sources", all.len());
        return Ok(());
    }
    if args.positional.is_empty() {
        return Err("give at least one address, or --all".into());
    }
    for raw in &args.positional {
        let ip: Ipv4Addr = raw.parse().map_err(|e| format!("{raw}: {e}"))?;
        // Saying "unbanned" for an address that was never there would be a small lie the
        // operator acts on: they would stop looking for the real block.
        let removed = b.remove(ip)?;
        if args.json {
            let refused = if removed { None } else { Some("not-blocked") };
            say!(
                "{}",
                tfps::json_line(&action_doc(Some(&ip.to_string()), "unban", refused, None))?
            );
        } else if removed {
            say!("unbanned {ip}");
        } else {
            say!("{ip} was not blocked");
        }
    }
    Ok(())
}

/// Which entry exempted a hand-placed block, and where that entry came from.
#[derive(Debug, PartialEq, Eq)]
struct Exemption {
    origin: Origin,
    rule: String,
}

/// What `place` did with a list of addresses. Every address lands in exactly one.
#[derive(Debug, Default, PartialEq, Eq)]
struct Placed {
    blocked: Vec<Ipv4Addr>,
    exempt: Vec<(Ipv4Addr, Exemption)>,
    failed: Vec<(Ipv4Addr, String)>,
}

/// Places blocks by hand, refusing what the daemon refuses.
///
/// The guard is consulted **before** the kernel, and a refused address touches
/// nothing at all. `xdp::local_addresses` says why in its own doc comment: it
/// exists "so the system cannot condemn the machine it is defending", and a
/// command placing a block from outside the daemon has exactly the same
/// obligation. One typo at a root prompt blackholes the box, and on a remote
/// host that is the last command anybody gets to run.
///
/// Every input is an argument so the whole decision is drivable from a test:
/// the kernel map needs `CAP_BPF` and a pinned path and cannot be opened by one.
fn place(
    ips: &[Ipv4Addr],
    guard: &mut IgnoreList,
    mut block: impl FnMut(Ipv4Addr) -> Result<(), String>,
) -> Placed {
    let mut out = Placed::default();
    for &ip in ips {
        // The same gate as the daemon (`tfps_core::disposition::gate`), with one
        // deliberate difference: a hand ban is the operator overriding the
        // registered-peer heuristic, so that test is answered `false` here and
        // both non-exempt arms lead to the write.
        let why = guard.exempt_entry(ip).map(|(rule, origin)| Exemption {
            origin,
            rule: rule.to_string(),
        });
        match gate(why, false) {
            Gate::Exempt(why) => out.exempt.push((ip, why)),
            Gate::KnownPeer | Gate::Enforce => match block(ip) {
                Ok(()) => out.blocked.push(ip),
                Err(e) => out.failed.push((ip, e)),
            },
        }
    }
    out
}

/// What `ban --json` and `unban --json` each say about one address.
///
/// `applied` is derived from `refused.is_none()` in `action_doc`, never set
/// independently, so the two facts cannot disagree — see
/// `applied_is_exactly_the_absence_of_a_refusal`. A policy refusal
/// (`"local"`, `"declared"`, `"not-blocked"`) and a kernel write failure
/// (`"kernel"`) are deliberately different strings: the first means the
/// system worked as designed, the second means enforcement itself is
/// broken, and one term for both would report "refused as configured" about
/// a box that is not blocking anything — see
/// `a_kernel_failure_is_reported_separately_from_a_policy_refusal`. `ip` is
/// never `null` in this build: both commands parse addresses with `?`
/// before any per-address work, so an unparseable address aborts the whole
/// command (not rendered as JSON at all) rather than ever reaching this
/// document.
#[derive(Serialize)]
struct ActionDoc {
    ip: Option<String>,
    action: String,
    applied: bool,
    refused: Option<String>,
    expires: Option<u32>,
    source: &'static str,
}

/// Built from arguments so it is drivable from a test without touching the
/// kernel map. `refused` is what `place`'s existing guard (or, for `unban`,
/// `Blocklist::remove`'s return value) already decided — this only renders
/// that decision, never re-derives it.
fn action_doc(
    ip: Option<&str>,
    action: &str,
    refused: Option<&str>,
    expires: Option<u32>,
) -> ActionDoc {
    ActionDoc {
        ip: ip.map(str::to_string),
        action: action.to_string(),
        applied: refused.is_none(),
        refused: refused.map(str::to_string),
        expires,
        source: "operator",
    }
}

/// A hand ban's expiry, as a wall-clock epoch second for `action_doc` to carry.
///
/// This is genuinely new arithmetic: the human path below only ever turns
/// `args.ttl` into a relative duration (`ago(args.ttl as u32)`), never an
/// absolute time. `Blocklist::insert` computes the kernel deadline as
/// `monotonic_ns() + ttl_secs * 1e9`; this computes the same instant
/// directly in wall-clock terms — `now_wall + ttl_secs` — without reading
/// anything back from the kernel, because the caller already knows both
/// inputs at the moment it asks for the write. `0` means "forever" (see
/// `Blocklist::insert`), which has no expiry to report.
fn ban_expires(now_wall: u32, ttl_secs: u64) -> Option<u32> {
    if ttl_secs == 0 {
        None
    } else {
        // `--ttl` parses into a `u64` with no upper bound, so a ttl past
        // `u32::MAX` gets here. `as u32` would wrap it first and leave
        // `saturating_add` nothing to save: `--ttl 4294967296` would report an
        // expiry of now. Clamp before the add, not after.
        Some(now_wall.saturating_add(u32::try_from(ttl_secs).unwrap_or(u32::MAX)))
    }
}

/// Maps one `Placed` outcome to the JSONL documents `ban --json` prints —
/// one per input address, in the same blocked/exempt/failed bucket order
/// the human path below already iterates.
///
/// This is the one place that DECIDES which refusal string an address
/// gets; `action_doc` only renders a string it is already handed. The two
/// policy strings are `CONTEXT.md`'s own words for the two kinds of ignoreip
/// entry — **local** (the host's own addresses, discovered) and **declared**
/// (the operator's) — which are also the `Origin` variants' names. Folding
/// `"kernel"` into `"local"`, or swapping the two `Origin` arms, would
/// compile cleanly and pass every `action_doc` test — see
/// `ban_action_docs_maps_each_placed_outcome_to_its_own_refusal`, which
/// drives this function through a real `Placed` instead.
fn ban_action_docs(out: &Placed, expires: Option<u32>) -> Vec<ActionDoc> {
    let mut docs = Vec::with_capacity(out.blocked.len() + out.exempt.len() + out.failed.len());
    for ip in &out.blocked {
        docs.push(action_doc(Some(&ip.to_string()), "ban", None, expires));
    }
    for (ip, why) in &out.exempt {
        let reason = match why.origin {
            Origin::Local => "local",
            Origin::Declared => "declared",
        };
        docs.push(action_doc(Some(&ip.to_string()), "ban", Some(reason), None));
    }
    for (ip, _e) in &out.failed {
        docs.push(action_doc(
            Some(&ip.to_string()),
            "ban",
            Some("kernel"),
            None,
        ));
    }
    docs
}

/// The per-address diagnostics for whatever `place` refused or failed to
/// write, on stderr, in both plain and `--json` mode.
///
/// stderr is not the JSON stream, so printing these here corrupts nothing on
/// stdout. `--json` mode needs them for a reason plain mode does not: per
/// `ActionDoc`'s doc comment, a kernel write failure is deliberately rendered
/// as the categorical label `"refused":"kernel"`, the same shape a policy
/// refusal gets — `ban_action_docs` never puts the underlying `Blocklist`
/// error string into the document, and `ActionDoc` gains no field here to
/// hold it. Without this function's stderr output, a `--json` caller learns
/// THAT a write failed but never WHY; the specific reason (map missing,
/// permission, ...) exists only in `e` below, and this is the only place it
/// is still rendered.
fn report_ban_diagnostics(out: &Placed) {
    for (ip, why) in &out.exempt {
        match why.origin {
            Origin::Local => {
                eprintln!("error: refusing to block {ip}: it is an address of this host")
            }
            Origin::Declared => eprintln!(
                "error: refusing to block {ip}: ignoreip={} says never enforce against it",
                why.rule
            ),
        }
    }
    for (ip, e) in &out.failed {
        eprintln!("error: could not block {ip}: {e}");
    }
}

fn ban(args: &Args) -> Result<(), String> {
    if args.positional.is_empty() {
        return Err("give at least one address".into());
    }
    let mut ips = Vec::with_capacity(args.positional.len());
    for raw in &args.positional {
        ips.push(raw.parse::<Ipv4Addr>().map_err(|e| format!("{raw}: {e}"))?);
    }
    // The daemon's own entries as of its last checkpoint, when there is a database to
    // read them from. This is how a hand ban honours `--ignoreip` given on the daemon's
    // command line, which no file records. Absent or unreadable is the `--no-db` case
    // and is not an error here; the file and the host still apply.
    let persisted = Store::open_readonly(&args.db)
        .ok()
        .and_then(|s| s.meta_get("ignoreip"));
    let mut guard = enforcement_guard(
        &tfps::xdp::local_addresses(),
        tfps::config::load(&args.config),
        persisted.as_deref(),
    )?;
    // The map is opened on the first address that survives the guard, not before.
    // Refusing to blackhole the host is a decision this tool can make on its own,
    // and making it conditional on CAP_BPF and a running daemon would mean the
    // answer to "would this have blocked my box?" depends on who is asking.
    let mut b: Option<Blocklist> = None;
    let out = place(&ips, &mut guard, |ip| {
        let bl = match b.as_mut() {
            Some(bl) => bl,
            None => b.insert(Blocklist::open(args.map.as_deref())?),
        };
        bl.insert(ip, args.ttl)
    });

    if args.json {
        // Render `out` exactly as computed above — the same guard decision
        // the human path below prints as prose. The final `Ok`/`Err` is
        // shared with the human path too (mirrored below), so `--json`
        // changes only the rendering, never the exit code. The per-address
        // stderr diagnostics are shared too, via `report_ban_diagnostics`:
        // `--json` renders a kernel failure as the flattened
        // `"refused":"kernel"` on stdout, so stderr is the only place the
        // specific reason is still available to a `--json` caller.
        let expires = ban_expires(now(), args.ttl);
        for doc in ban_action_docs(&out, expires) {
            say!("{}", tfps::json_line(&doc)?);
        }
        report_ban_diagnostics(&out);
        return if out.exempt.is_empty() && out.failed.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{} of {} addresses were not blocked",
                out.exempt.len() + out.failed.len(),
                ips.len()
            ))
        };
    }

    let how = if args.ttl == 0 {
        "with no expiry".to_string()
    } else {
        format!("for {}", ago(args.ttl as u32))
    };
    for ip in &out.blocked {
        say!("blocked {ip} {how}");
    }
    report_ban_diagnostics(&out);
    // NOT recorded in block_log, deliberately. A hand-placed block still leaves
    // no trace, so `banned --why` cannot explain it — that is a real gap, and
    // fixing it means opening the database read-write from this tool, which the
    // note on `Store::open_readonly` forbids on purpose and which would run a
    // migration from a binary that is not the daemon. That is a decision about
    // this tool's contract, not a bug fix, so it is left alone here.
    if out.exempt.is_empty() && out.failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} of {} addresses were not blocked",
            out.exempt.len() + out.failed.len(),
            ips.len()
        ))
    }
}

/// The exemptions the daemon applies, assembled by the daemon's own code.
///
/// `tfps::guard::assemble` is the one assembly; what differs here is the inputs
/// and the policy. The host's addresses come from the kernel as they do for the
/// daemon; the declared entries come from the configuration file and from the
/// list the daemon persisted at its last checkpoint, which also carries whatever
/// `--ignoreip` it was started with. Everything arrives as an argument so the
/// assembly is drivable from a test; `ban` is the only caller.
///
/// An empty host set is refused, not accepted. `local_addresses` returns nothing
/// when `/proc/net/fib_trie` cannot be read, and a real host is never empty --
/// loopback alone is a LOCAL route whenever `lo` is up. So empty means the read
/// failed, and a guard built without the host's addresses is exactly the guard
/// that lets a typo blackhole the box.
///
/// The policy on a bad input is the one place this tool differs from the daemon,
/// on purpose. The daemon alarms and carries on, with hours of traffic ahead and
/// a startup report to say it in; this command has one write to make, and the
/// alternative is making it while an exemption the operator believes in is
/// silently absent. So a malformed entry or a broken file aborts.
fn enforcement_guard(
    local: &[Ipv4Addr],
    loaded: tfps::config::Loaded,
    persisted: Option<&str>,
) -> Result<IgnoreList, String> {
    if local.is_empty() {
        return Err(
            "could not read this host's addresses from /proc/net/fib_trie; \
             refusing to place a block without the host guard"
                .into(),
        );
    }
    let from_file = match loaded {
        tfps::config::Loaded::File(c, _) => c.ignoreip.clone(),
        tfps::config::Loaded::Absent => Vec::new(),
        tfps::config::Loaded::Broken(e) => return Err(e),
    };
    let from_daemon: Vec<String> = persisted
        .map(|line| {
            tfps::guard::labels_from_checkpoint(line)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let guard = tfps::guard::assemble(
        local,
        from_file.iter().chain(&from_daemon).map(String::as_str),
    );
    if let Some(e) = guard.rejected.into_iter().next() {
        return Err(e);
    }
    Ok(guard.list)
}

/// What `sources --json` says about one learned pair: the same fields the
/// human COUNTRIES/RATE/LAST columns already print, per row.
///
/// `countries` is `SourceRow.n_countries`, the stored column — see `SourceDoc`
/// below for why that and not the decoded list's length.
#[derive(Serialize)]
struct SourceRowDoc {
    peer: String,
    countries: u32,
    /// `null` when the stored rate is not a finite number.
    ///
    /// `rate_a` is `REAL NOT NULL` and SQLite stores an infinity faithfully, so
    /// a non-finite value can reach here. JSON cannot spell one — `serde_json`
    /// renders it `null` whatever the field is declared as — so the type says so
    /// rather than promising a number it cannot always supply.
    rate: Option<f64>,
    last_seen: u32,
}

/// Built from a `SourceRow`'s already-loaded fields — no transformation,
/// just field selection, the same as `status_doc`.
fn source_row_doc(peer: &str, countries: u32, rate: f64, last_seen: u32) -> SourceRowDoc {
    SourceRowDoc {
        peer: peer.to_string(),
        countries,
        rate: finite(rate),
        last_seen,
    }
}

/// A rate a reader can use, or `None`. One rule in one place, so the two
/// documents carrying this field cannot disagree about a non-finite value.
fn finite(v: f64) -> Option<f64> {
    v.is_finite().then_some(v)
}

fn sources(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let f = SourceFilter {
        peer: args.peer.as_deref(),
        country: args.country.as_deref(),
        limit: args.limit,
    };
    let rows = s.find_sources(&f)?;
    if args.json {
        // Reuses the same `rows` the human path below iterates, already
        // limited by `SourceFilter.limit` inside `find_sources` — no
        // separate limiting logic to keep in sync.
        for r in &rows {
            say!(
                "{}",
                tfps::json_line(&source_row_doc(
                    &r.peer,
                    r.n_countries,
                    r.rate_a,
                    r.last_seen
                ))?
            );
        }
        return Ok(());
    }
    if rows.is_empty() {
        say!("no source matches");
        return Ok(());
    }
    say!("{:<16} {:>8} {:>9}  COUNTRIES", "PEER", "COUNTRIES", "LAST");
    let now = now();
    for r in &rows {
        let c = r.countries();
        let shown: Vec<&str> = c.iter().take(10).copied().collect();
        let tail = if c.len() > shown.len() {
            format!(" +{}", c.len() - shown.len())
        } else {
            String::new()
        };
        say!(
            "{:<16} {:>8} {:>9}  {}{}",
            r.peer,
            r.n_countries,
            ago(now.saturating_sub(r.last_seen)),
            shown.join(","),
            tail
        );
    }
    say!("\n{} sources", rows.len());
    Ok(())
}

/// What `source --json` says about one peer: the same fields `source`'s
/// human path already prints, plus the full country list it already
/// decodes to print the chunked lines below.
///
/// `countries` is `SourceRow.n_countries` — the SAME stored column
/// `SourceRowDoc`/`PeerRowDoc` use — not `c.len()`, the decoded list's
/// length, even though `c.len()` is what `source`'s own human "countries
/// known" line prints just below. The two counts are equal for any row
/// written under the current country table: `n_countries` is incremented
/// once per newly-set bit (`anomaly.rs`), and `decode_bitmap` decodes via
/// the literal inverse (`country.rs`). But they are not equal *by
/// invariant*: `decode_bitmap` silently drops a bit whose index has no
/// current `CODES` entry, while `n_countries` is a raw, unconditional
/// counter, so a row written under a past, since-renumbered-or-pruned
/// version of that table could show the two counts apart. Consistency
/// wins over the human path's own choice here: `countries` means
/// `n_countries` wherever it is a scalar in this contract, full stop, so
/// `sources --json` and `source --json` never disagree about the same
/// peer. A consumer wanting the decoded count takes
/// `countries_known.len()` instead.
#[derive(Serialize)]
struct SourceDoc {
    peer: String,
    countries: u32,
    /// `null` when the stored rate is not a finite number.
    ///
    /// `rate_a` is `REAL NOT NULL` and SQLite stores an infinity faithfully, so
    /// a non-finite value can reach here. JSON cannot spell one — `serde_json`
    /// renders it `null` whatever the field is declared as — so the type says so
    /// rather than promising a number it cannot always supply.
    rate: Option<f64>,
    last_seen: u32,
    countries_known: Vec<String>,
}

/// Built from a `SourceRow`'s already-loaded fields and its already-decoded
/// country list — no transformation, just field selection. `countries` is the
/// caller's `SourceRow.n_countries`, never recomputed from `countries_known`.
fn source_doc(
    peer: &str,
    countries: u32,
    rate: f64,
    last_seen: u32,
    countries_known: &[&str],
) -> SourceDoc {
    SourceDoc {
        peer: peer.to_string(),
        countries,
        rate: finite(rate),
        last_seen,
        countries_known: countries_known.iter().map(|c| c.to_string()).collect(),
    }
}

fn source(args: &Args) -> Result<(), String> {
    let [peer] = args.positional.as_slice() else {
        return Err("usage: tfps_ctl source <peer>".into());
    };
    let s = Store::open_readonly(&args.db)?;
    let rows = s.find_sources(&SourceFilter {
        peer: Some(peer),
        limit: usize::MAX,
        ..Default::default()
    })?;
    let Some(r) = rows.first() else {
        return Err(format!("no source {peer} in the database"));
    };
    let c = r.countries();
    if args.json {
        // `r.n_countries`, not `c.len()` — see `SourceDoc`'s doc comment.
        say!(
            "{}",
            tfps::json_line(&source_doc(
                &r.peer,
                r.n_countries,
                r.rate_a,
                r.last_seen,
                &c
            ))?
        );
        return Ok(());
    }
    say!("peer              : {}", r.peer);
    say!(
        "last seen         : {} ago",
        ago(now().saturating_sub(r.last_seen))
    );
    say!("learned rate      : {:.2} intl calls / window", r.rate_a);
    say!("countries known   : {}", c.len());
    for chunk in c.chunks(12) {
        say!("                    {}", chunk.join(" "));
    }
    say!(
        "\nThe detector fires when a source's evidence — a burst of novel countries, \
         several prefixes, or a volume spike against this baseline — crosses the bound."
    );
    Ok(())
}

/// What `peers --json` says about one peer: the same two columns `peers`'s
/// human path already prints, per row. `countries` is the stored count — see
/// `SourceDoc` above.
#[derive(Serialize)]
struct PeerRowDoc {
    peer: String,
    countries: u32,
    last_seen: u32,
}

/// Built from one already-loaded `s.peers()` row — no transformation, just
/// field selection.
fn peer_row_doc(peer: &str, countries: u32, last_seen: u32) -> PeerRowDoc {
    PeerRowDoc {
        peer: peer.to_string(),
        countries,
        last_seen,
    }
}

fn peers(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let rows = s.peers()?;
    if args.json {
        // `s.peers()` applies no limit itself (see store.rs); `.take` here
        // is the same limiting the human loop below applies to the same
        // `rows`.
        for (peer, ncoun, last) in rows.iter().take(args.limit) {
            say!("{}", tfps::json_line(&peer_row_doc(peer, *ncoun, *last))?);
        }
        return Ok(());
    }
    if rows.is_empty() {
        say!("no peer learned yet");
        return Ok(());
    }
    say!("{:<16} {:>9} {:>9}  COUNTRIES", "PEER", "COUNTRIES", "LAST");
    let now = now();
    for (peer, ncoun, last) in rows.iter().take(args.limit) {
        let seen: Vec<&str> = s.peer_countries(peer).unwrap_or_default();
        say!(
            "{:<16} {:>9} {:>9}  {}",
            peer,
            ncoun,
            ago(now.saturating_sub(*last)),
            seen.iter().take(6).copied().collect::<Vec<_>>().join(" ")
        );
    }
    say!("\n{} sources", rows.len());
    Ok(())
}

/// What `countries --json` says about one peer's learned country set.
///
/// The human view below chunks this list purely to wrap a terminal
/// (`chunks(16)`, joined with spaces); a program wants the list itself, so
/// this is a JSON array — never the joined, chunked string — and an empty
/// list renders `[]`, never `null`.
///
/// The field is `countries_known`, the name `SourceDoc` already gives the same
/// array, and not `countries`, which is a `u32` in `SourceRowDoc`, `SourceDoc`
/// and `PeerRowDoc`. One field name carrying a scalar in three documents and an
/// array in a fourth is the ambiguity `CONTEXT.md` exists to prevent.
#[derive(Serialize)]
struct CountriesDoc {
    peer: String,
    countries_known: Vec<String>,
}

/// Built from an already-decoded country list — no transformation, just
/// field selection and the `&str` -> owned `String` conversion `json_line`
/// needs.
fn countries_doc(peer: &str, countries: &[&str]) -> CountriesDoc {
    CountriesDoc {
        peer: peer.to_string(),
        countries_known: countries.iter().map(|c| c.to_string()).collect(),
    }
}

fn countries(args: &Args) -> Result<(), String> {
    let [peer] = args.positional.as_slice() else {
        return Err("usage: tfps_ctl countries <peer>".into());
    };
    let s = Store::open_readonly(&args.db)?;
    let names = s.peer_countries(peer)?;
    if names.is_empty() {
        return Err(format!("nothing learned for source {peer}"));
    }
    if args.json {
        say!("{}", tfps::json_line(&countries_doc(peer, &names))?);
        return Ok(());
    }
    say!("{peer} has been seen to call {} countries:", names.len());
    for chunk in names.chunks(16) {
        say!("  {}", chunk.join(" "));
    }
    Ok(())
}

/// What `log --json` says about one row of the block audit log.
///
/// `first_seen`/`expires`/`unbanned_at` are epoch integers, as every time in
/// this contract is — `banned_doc` above carries the same two field names the
/// same way. See `log_doc_carries_epoch_integers_not_strings`.
#[derive(Serialize)]
struct LogDoc {
    ip: String,
    reason: String,
    detail: String,
    first_seen: u32,
    expires: Option<u32>,
    unbanned_at: Option<u32>,
    enforced: bool,
    disposition: String,
}

/// Built from one audit row — which already carries `ip`/`reason`/`detail`/
/// `ts` as one unit — plus whatever else only the caller knows. No database
/// needed to drive it from a test. `reason` is `BlockRow.reason`, the store
/// column of that name, and the human path's `REASON` header — one term for
/// one thing, per `CONTEXT.md`.
///
/// `disposition` is `CONTEXT.md`'s word for what the perimeter does with a
/// source it has judged, and its value is one of that entry's four: **ignore**,
/// **exempt**, **would-block** or **block**. The glossary grounds those in
/// `tfps_core::disposition`, whose variants are `Ignore`, `ExemptIgnoreIp`,
/// `ExemptKnownPeer` and `Block` — so `"blocked"`, the past tense this field
/// used to carry, names none of them. A **verdict** is a different statement
/// again (pass, challenge or block, about an attempt) and is not what this
/// field holds.
fn log_doc(
    row: &BlockRow,
    expires: Option<u32>,
    unbanned_at: Option<u32>,
    enforced: bool,
    disposition: &str,
) -> LogDoc {
    LogDoc {
        ip: row.ip.clone(),
        reason: row.reason.clone(),
        detail: row.detail.clone(),
        first_seen: row.ts,
        expires,
        unbanned_at,
        enforced,
        disposition: disposition.to_string(),
    }
}

fn log(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let rows: Vec<BlockRow> = s.blocks(args.limit, args.ip.as_deref())?;
    if args.json {
        // Every row in block_log got there through `log_block`, which
        // main.rs calls only from the `Disposition::Block` arm (see
        // main.rs) — so every row here is an enforced block: `enforced` and
        // `disposition` are constant, the latter `CONTEXT.md`'s `block`. `expires`/`unbanned_at` are not columns
        // block_log has yet (see its schema in store.rs); they are `null`
        // until a future store change adds them, which needs no change to
        // this document's shape.
        for r in &rows {
            say!(
                "{}",
                tfps::json_line(&log_doc(r, None, None, true, "block"))?
            );
        }
        return Ok(());
    }
    if rows.is_empty() {
        say!("the audit log is empty");
        return Ok(());
    }
    say!("{:<9} {:<16} {:<14} DETAIL", "AGE", "SOURCE", "REASON");
    let now = now();
    for r in &rows {
        say!(
            "{:<9} {:<16} {:<14} {}",
            ago(now.saturating_sub(r.ts)),
            r.ip,
            r.reason,
            r.detail
        );
    }
    Ok(())
}

/// What `forget --json` says about one erase.
#[derive(Serialize)]
struct ForgetDoc {
    peer: String,
    forgotten: usize,
}

/// Built from arguments so it is drivable from a test without a database.
fn forget_doc(peer: &str, forgotten: usize) -> ForgetDoc {
    ForgetDoc {
        peer: peer.to_string(),
        forgotten,
    }
}

fn forget(args: &Args) -> Result<(), String> {
    let Some(peer) = args.positional.first() else {
        return Err("usage: tfps_ctl forget <peer> [--a NUMBER]".into());
    };
    // A running daemon holds the working set in memory and would write it straight back at
    // the next checkpoint. Deleting rows underneath it would look like it worked and then
    // quietly undo itself — the exact class of silent failure this project exists to avoid.
    if Blocklist::open(args.map.as_deref()).is_ok() {
        return Err(
            "tfps appears to be running: its in-memory state would be written back at the \
             next checkpoint, undoing this. Stop the service first (systemctl stop tfps)."
                .into(),
        );
    }
    let s = Store::open(Path::new(&args.db))?;
    let n = s.forget(peer, args.a_number.as_deref())?;
    if args.json {
        say!("{}", tfps::json_line(&forget_doc(peer, n))?);
        return Ok(());
    }
    say!("forgot {n} pairs for {peer}");
    Ok(())
}

// ---------------------------------------------------------------- helpers

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// A compact duration. Operators read these in a column, so the widest case has to stay
/// short: `3d4h` rather than `3 days, 4 hours`.
fn ago(secs: u32) -> String {
    match secs {
        0 => "now".to_string(),
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h{}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{}h", s / 86400, (s % 86400) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Result<Args, String> {
        parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    /// One top-level handler's body: everything between the `{` that opens
    /// `fn <name>(args: &Args)` and the `}` that closes it.
    ///
    /// The end is the first `"\n}\n"` after the opening brace. rustfmt puts a
    /// top-level function's closing brace alone at column 0, and nothing inside
    /// the function is ever at column 0, so this is exact rather than a
    /// heuristic — `cargo fmt --all --check` is one of this repository's gates,
    /// which is what makes that layout something a test may rely on.
    ///
    /// Scanning instead for the next `"\nfn "`/`"\nstruct "` — what the two
    /// tests below used to do, each with its own copy of the marker list —
    /// overshoots EVERY handler in this file, by between 2 and 23 lines, because
    /// the doc comment and `#[derive(...)]` attribute of the following item sit
    /// between the closing brace and that item's own keyword. A check meant to
    /// read one handler then reads its neighbour's preamble too, and a doc
    /// comment mentioning `args.json` is enough to make the check below pass
    /// for a handler that has no such branch at all.
    fn handler_body<'a>(src: &'a str, name: &str) -> &'a str {
        let sig = format!("\nfn {name}(args: &Args)");
        let start = src.find(&sig).unwrap_or_else(|| {
            panic!("no handler `fn {name}(args: &Args)` found for advertised command `{name}`")
        });
        let body_start = start
            + src[start..]
                .find('{')
                .unwrap_or_else(|| panic!("handler `{name}` has no opening brace"))
            + 1;
        let body_end = body_start
            + src[body_start..]
                .find("\n}\n")
                .unwrap_or_else(|| panic!("handler `{name}` has no closing brace at column 0"));
        &src[body_start..body_end]
    }

    /// The guard the daemon builds: this host's addresses, plus what the
    /// operator declared.
    fn guard(local: &[Ipv4Addr], declared: &[&str]) -> IgnoreList {
        let mut g = IgnoreList::new();
        for a in local {
            g.add_local(*a);
        }
        for d in declared {
            g.add(d).expect("fixture: the declared entry must parse");
        }
        g
    }

    // THE DEFECT, half one. `xdp::local_addresses` exists, in its own words, "so
    // the system cannot condemn the machine it is defending" — and `ban` never
    // asked. One typo at a root prompt blackholes the box, and on a remote host
    // that is the last command you get to run.
    #[test]
    fn the_host_is_never_condemned_by_hand() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = guard(&[host], &[]);
        let mut written = Vec::new();
        let out = place(&[host], &mut g, |a| {
            written.push(a);
            Ok(())
        });
        assert!(
            written.is_empty(),
            "the host's own address must never reach the kernel map"
        );
        assert_eq!(out.blocked, Vec::<Ipv4Addr>::new());
        assert_eq!(out.exempt.len(), 1);
        assert_eq!(out.exempt[0].1.origin, Origin::Local);
    }

    // THE DEFECT, half two. The operator declared "never enforce against this
    // range". A hand-placed block went round it without a word.
    #[test]
    fn a_declared_ignoreip_range_is_refused_by_hand_too() {
        let mut g = guard(&[], &["203.0.113.0/24"]);
        let mut written = Vec::new();
        let out = place(&[ip(7)], &mut g, |a| {
            written.push(a);
            Ok(())
        });
        assert!(
            written.is_empty(),
            "a declared range must not be overridden silently"
        );
        assert_eq!(out.exempt.len(), 1);
        assert_eq!(out.exempt[0].1.origin, Origin::Declared);
        assert_eq!(
            out.exempt[0].1.rule, "203.0.113.0/24",
            "the refusal must name the entry, so the operator knows what to change"
        );
    }

    // NEGATIVE CONTROL. The command still has to work. An address nothing
    // exempts is blocked exactly once and reported as blocked.
    #[test]
    fn an_ordinary_address_is_still_blocked() {
        let mut g = guard(&[Ipv4Addr::new(10, 0, 0, 60)], &["192.168.0.0/16"]);
        let mut written = Vec::new();
        let out = place(&[ip(7)], &mut g, |a| {
            written.push(a);
            Ok(())
        });
        assert_eq!(written, vec![ip(7)]);
        assert_eq!(out.blocked, vec![ip(7)]);
        assert!(out.exempt.is_empty());
        assert!(out.failed.is_empty());
    }

    // A refusal must not take the rest of the batch down with it, and the
    // outcomes must stay disjoint: every address lands in exactly one bucket.
    #[test]
    fn one_refusal_does_not_stop_the_others() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = guard(&[host], &["192.168.0.0/16"]);
        let batch = [ip(1), host, Ipv4Addr::new(192, 168, 1, 5), ip(2)];
        let mut written = Vec::new();
        let out = place(&batch, &mut g, |a| {
            written.push(a);
            Ok(())
        });
        assert_eq!(written, vec![ip(1), ip(2)]);
        assert_eq!(out.blocked, vec![ip(1), ip(2)]);
        assert_eq!(out.exempt.len(), 2);
        assert_eq!(
            out.blocked.len() + out.exempt.len() + out.failed.len(),
            batch.len(),
            "every address must land in exactly one outcome"
        );
    }

    // NEGATIVE CONTROL. A kernel refusal is not an exemption. Conflating them
    // would tell the operator their own configuration stopped a write that the
    // map actually rejected.
    #[test]
    fn a_kernel_failure_is_not_an_exemption() {
        let mut g = guard(&[], &[]);
        let out = place(&[ip(7)], &mut g, |_| Err("map is full".into()));
        assert!(out.exempt.is_empty());
        assert_eq!(out.failed, vec![(ip(7), "map is full".to_string())]);
        assert!(out.blocked.is_empty());
    }

    // An empty guard refuses nothing: the fixture must be able to say "no" only
    // because something was put in it, not by construction.
    #[test]
    fn an_empty_guard_refuses_nothing() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = guard(&[], &[]);
        let out = place(&[host, ip(7)], &mut g, |_| Ok(()));
        assert_eq!(out.blocked, vec![host, ip(7)]);
        assert!(out.exempt.is_empty());
    }

    // The seam the tests above do not reach: `place` honours whatever guard it
    // is handed, so the guard has to be shown to contain the two real sources.
    // Dropping either loop in `enforcement_guard` would pass every test above.
    #[test]
    fn the_guard_is_built_from_the_host_and_the_file() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let cfg = tfps::config::Config {
            ignoreip: vec!["203.0.113.0/24".to_string()],
            ..Default::default()
        };
        let mut g = enforcement_guard(
            &[host],
            tfps::config::Loaded::File(Box::new(cfg), PathBuf::new()),
            None,
        )
        .expect("a readable host and a well-formed file build a guard");
        assert_eq!(
            g.exempt_entry(host).map(|(_, o)| o),
            Some(Origin::Local),
            "the host's own address comes from the kernel"
        );
        assert_eq!(
            g.exempt_entry(Ipv4Addr::new(203, 0, 113, 7))
                .map(|(_, o)| o),
            Some(Origin::Declared),
            "the declared range comes from the file"
        );
        assert!(
            g.exempt_entry(Ipv4Addr::new(8, 8, 8, 8)).is_none(),
            "nothing else is exempt"
        );
    }

    // What the daemon persisted at checkpoint is honoured too: that is where an
    // entry given as `--ignoreip` on its command line lives, and no file has it.
    #[test]
    fn the_daemons_own_entries_are_honoured_by_a_hand_ban() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = enforcement_guard(
            &[host],
            tfps::config::Loaded::Absent,
            Some("10.0.0.60=0 198.51.100.0/24=7"),
        )
        .expect("checkpoint labels are well-formed entries");
        assert_eq!(
            g.exempt_entry(Ipv4Addr::new(198, 51, 100, 9))
                .map(|(_, o)| o),
            Some(Origin::Declared)
        );
        assert_eq!(
            g.exempt_entry(host).map(|(_, o)| o),
            Some(Origin::Local),
            "the host stays local even when the checkpoint lists it too"
        );
    }

    // A fresh install has no file at all. That must not weaken the host guard.
    #[test]
    fn an_absent_file_still_guards_the_host() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let mut g = enforcement_guard(&[host], tfps::config::Loaded::Absent, None)
            .expect("no file is the normal case");
        assert!(g.exempt_entry(host).is_some());
        assert!(g.exempt_entry(ip(8)).is_none(), "nothing was declared");
    }

    // `local_addresses` returns nothing only when /proc/net/fib_trie could not be
    // read: loopback alone is a LOCAL route on any host with `lo` up. A guard
    // built without the host is the guard that lets a typo blackhole the box, so
    // the command refuses to run rather than run unguarded.
    #[test]
    fn an_unreadable_host_set_refuses_to_place_anything() {
        let err = enforcement_guard(&[], tfps::config::Loaded::Absent, None)
            .expect_err("no host addresses must not become no host guard");
        assert!(
            err.contains("fib_trie"),
            "the operator is told what failed: {err}"
        );
    }

    // A broken file and a malformed entry both abort, where the daemon alarms
    // and continues. This tool has one write to make and the alternative is
    // making it while an exemption the operator believes in is silently absent.
    #[test]
    fn a_broken_file_or_entry_aborts_rather_than_weakening_the_guard() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        assert!(enforcement_guard(
            &[host],
            tfps::config::Loaded::Broken("EOF while parsing".into()),
            None
        )
        .is_err());
        let cfg = tfps::config::Config {
            ignoreip: vec!["203.0.113.0/33".to_string()],
            ..Default::default()
        };
        assert!(enforcement_guard(
            &[host],
            tfps::config::Loaded::File(Box::new(cfg), PathBuf::new()),
            None,
        )
        .is_err());
    }

    #[test]
    fn the_command_comes_first_and_addresses_follow() {
        let a = args(&["unban", "1.2.3.4", "5.6.7.8"]).unwrap();
        assert_eq!(a.command, "unban");
        assert_eq!(a.positional, ["1.2.3.4", "5.6.7.8"]);
    }

    #[test]
    fn filters_parse() {
        let a = args(&[
            "pairs",
            "--peer",
            "10.0.0.5",
            "--country",
            "gb",
            "--limit",
            "5",
        ])
        .unwrap();
        assert_eq!(a.peer.as_deref(), Some("10.0.0.5"));
        assert_eq!(a.country.as_deref(), Some("gb"));
        assert_eq!(a.limit, 5);
    }

    #[test]
    fn an_option_with_no_value_is_an_error_not_a_default() {
        // Silently defaulting would make `--limit` at the end of a line mean something the
        // operator did not ask for.
        assert!(args(&["sources", "--limit"]).is_err());
        assert!(args(&["banned", "--bogus"]).is_err());
    }

    /// The consumer builds argv as [subcommand, "--json", ...], so the flag has to
    /// parse in that slot. The flat loop means every position works; this pins it.
    #[test]
    fn json_flag_defaults_off_and_parses_in_any_position() {
        assert!(!args(&["status"]).unwrap().json, "default must be off");
        assert!(args(&["status", "--json"]).unwrap().json);
        assert!(args(&["log", "--json", "--limit", "10"]).unwrap().json);
        assert!(args(&["log", "--limit", "10", "--json"]).unwrap().json);
    }

    /// --json must not swallow the next word the way --db does.
    #[test]
    fn json_flag_takes_no_value() {
        let a = args(&["log", "--json", "--limit", "7"]).unwrap();
        assert_eq!(a.limit, 7, "--json must not consume --limit");
    }

    #[test]
    fn durations_stay_narrow_enough_for_a_column() {
        assert_eq!(ago(0), "now");
        assert_eq!(ago(45), "45s");
        assert_eq!(ago(600), "10m");
        assert_eq!(ago(3700), "1h1m");
        assert_eq!(ago(200_000), "2d7h");
        assert!(ago(u32::MAX).len() <= 9);
    }

    #[test]
    fn status_doc_reports_an_open_map_as_active() {
        let d = status_doc(
            Ok((3, "own map id 7".to_string())),
            Some((120, 4, 1_756_800_000)),
            Path::new("/var/lib/tfps/tfps.db"),
            "0.1.0",
        );
        assert_eq!(d.enforcement, "active");
        assert_eq!(d.blocked_now, 3);
        assert_eq!(d.mode, None, "the control tool cannot see the attach mode");
        assert_eq!(d.interface, None);
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"enforcement":"active","mode":null,"interface":null,"map":"own map id 7","blocked_now":3,"pairs":120,"peers":4,"last_checkpoint":1756800000,"db":"/var/lib/tfps/tfps.db","version":"0.1.0"}"#
        );
    }

    #[test]
    fn status_doc_reports_an_unopenable_map_as_inactive_with_nothing_blocked() {
        let d = status_doc(
            Err("no such map".to_string()),
            Some((120, 4, 1_756_800_000)),
            Path::new("/x"),
            "0.1.0",
        );
        assert_eq!(d.enforcement, "inactive");
        assert_eq!(d.blocked_now, 0, "inactive means we are blocking nothing");
        assert_eq!(
            d.map, None,
            "there is no map to name when the map could not be opened"
        );
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"enforcement":"inactive","mode":null,"interface":null,"map":null,"blocked_now":0,"pairs":120,"peers":4,"last_checkpoint":1756800000,"db":"/x","version":"0.1.0"}"#
        );
    }

    /// `Blocklist::open` prefers an explicit pin, then a third party's shared
    /// pin, then our own map by name, and records which in `b.source` "for the
    /// operator to see which plane they are editing" (its own words). The human
    /// path prints that string; without it in the document, a program cannot
    /// tell the daemon's own map from a third party's pinned one, which is the
    /// difference between editing enforcement and editing somebody else's.
    #[test]
    fn status_doc_names_the_map_it_read() {
        for source in [
            "own map id 7",
            "pinned map /sys/fs/bpf/tfps/blocked",
            "shared map /sys/fs/bpf/sipvault/drop",
        ] {
            let d = status_doc(Ok((0, source.to_string())), None, Path::new("/x"), "0.1.0");
            assert_eq!(
                d.map.as_deref(),
                Some(source),
                "the three planes must stay distinguishable"
            );
        }
    }

    /// The learned-state totals get the null-not-zero treatment `kernel` and
    /// `condemnation` already get in `stats --json`: a database this tool could
    /// not open and a database with nothing learned in it are different facts,
    /// and `"pairs":0` for the first would report an idle box instead of an
    /// unreadable one.
    #[test]
    fn status_doc_nulls_the_learned_totals_when_the_store_is_unreadable() {
        let d = status_doc(
            Ok((3, "own map id 7".to_string())),
            None,
            Path::new("/x"),
            "0.1.0",
        );
        assert_eq!(d.pairs, None);
        assert_eq!(d.peers, None);
        assert_eq!(d.last_checkpoint, None);
        let line = tfps::json_line(&d).unwrap();
        assert!(line.contains(r#""pairs":null"#), "{line}");
        assert!(
            line.contains(r#""blocked_now":3"#),
            "the kernel half is independent: {line}"
        );
    }

    /// `totals()` returns `COALESCE(MAX(last_seen), 0)`, so a database that
    /// exists but has never been checkpointed reports 0 — which as an epoch
    /// second is 1970-01-01, an answer a consumer would age to fifty-odd years.
    /// The human path prints the line only when it is non-zero; this nulls it
    /// for the same reason.
    #[test]
    fn status_doc_nulls_an_unwritten_checkpoint_rather_than_reporting_epoch_zero() {
        let d = status_doc(
            Ok((0, "own map id 7".to_string())),
            Some((0, 0, 0)),
            Path::new("/x"),
            "0.1.0",
        );
        assert_eq!(d.last_checkpoint, None, "never checkpointed is not 1970");
        assert_eq!(
            d.pairs,
            Some(0),
            "an empty database really did read zero pairs"
        );
    }

    // A DELIBERATE CONTRACT CHANGE, not a test relaxed to fit the code:
    // `first_seen`/`expires` were RFC3339 strings here and epoch integers in
    // `log_doc`, `expires_epoch`, `traffic_doc`'s `age_secs` and the three row
    // documents' `last_seen` — two sites against six, for the same kind of
    // value. The rule this contract states about itself (see `TrafficDoc`:
    // "a consumer recomputes its own presentation") settles it in favour of the
    // six. These expectations are the new contract; the old string literals were
    // removed, not loosened.
    #[test]
    fn banned_doc_carries_epoch_times_and_nulls_an_unattributed_source() {
        let attributed = banned_doc(
            "198.51.100.10",
            Some(("user-agent", "pplsip")),
            Some(1756917600),
            Some(1756921200),
        );
        assert_eq!(attributed.ip, "198.51.100.10");
        assert_eq!(attributed.reason.as_deref(), Some("user-agent"));
        assert_eq!(attributed.detail.as_deref(), Some("pplsip"));
        assert_eq!(
            attributed.first_seen,
            Some(1756917600),
            "an epoch integer, not an RFC3339 string"
        );
        assert_eq!(attributed.expires, Some(1756921200));
        assert!(attributed.enforced);
        assert_eq!(
            tfps::json_line(&attributed).unwrap(),
            r#"{"ip":"198.51.100.10","reason":"user-agent","detail":"pplsip","first_seen":1756917600,"expires":1756921200,"enforced":true}"#
        );
        let bare = banned_doc("198.51.100.12", None, None, None);
        assert_eq!(bare.ip, "198.51.100.12");
        assert_eq!(bare.reason, None);
        assert_eq!(bare.detail, None);
        assert_eq!(bare.first_seen, None);
        assert_eq!(bare.expires, None);
        assert!(bare.enforced, "a listed source is enforced by definition");
        assert_eq!(
            tfps::json_line(&bare).unwrap(),
            r#"{"ip":"198.51.100.12","reason":null,"detail":null,"first_seen":null,"expires":null,"enforced":true}"#
        );
    }

    // The merge `banned --json` uses to turn a newest-first audit scan into a
    // per-ip (rule, detail, first_seen): `rule`/`detail` take the newest row
    // per ip; `first_seen` takes the OLDEST row instead. This is genuinely
    // new logic (no equivalent "oldest wins" scan exists in the human path),
    // so it is pinned directly rather than only through `banned_doc`, which
    // never sees more than one row at a time.
    #[test]
    fn attribute_by_ip_takes_the_newest_reason_and_the_oldest_first_seen() {
        let rows = vec![
            // ip A: three rows for one source, arriving newest-first — the
            // order `Store::blocks` actually returns.
            BlockRow {
                ts: 300,
                ip: "198.51.100.10".to_string(),
                reason: "scanner".to_string(),
                detail: "d3".to_string(),
            },
            BlockRow {
                ts: 200,
                ip: "198.51.100.10".to_string(),
                reason: "user-agent".to_string(),
                detail: "d2".to_string(),
            },
            BlockRow {
                ts: 100,
                ip: "198.51.100.10".to_string(),
                reason: "injection".to_string(),
                detail: "d1".to_string(),
            },
            // ip B: a single row — its one row is both the newest and the
            // oldest at once.
            BlockRow {
                ts: 500,
                ip: "198.51.100.11".to_string(),
                reason: "auth-failed".to_string(),
                detail: "db".to_string(),
            },
            // ip C: two rows sharing one timestamp — a duplicate the merge
            // must not choke on.
            BlockRow {
                ts: 400,
                ip: "198.51.100.12".to_string(),
                reason: "reg-scan".to_string(),
                detail: "first".to_string(),
            },
            BlockRow {
                ts: 400,
                ip: "198.51.100.12".to_string(),
                reason: "reg-scan".to_string(),
                detail: "second".to_string(),
            },
        ];
        let audit = attribute_by_ip(rows);

        let a = audit.get("198.51.100.10").expect("ip A is present");
        assert_eq!(a.0, "scanner", "rule takes the newest row");
        assert_eq!(a.1, "d3", "detail takes the newest row");
        assert_eq!(a.2, 100, "first_seen takes the OLDEST row, not the newest");

        let b = audit.get("198.51.100.11").expect("ip B is present");
        assert_eq!(
            b,
            &("auth-failed".to_string(), "db".to_string(), 500),
            "a single row is both its own newest and its own oldest"
        );

        let c = audit.get("198.51.100.12").expect("ip C is present");
        assert_eq!(
            c.1, "first",
            "a duplicate timestamp keeps the first row seen"
        );
        assert_eq!(c.2, 400, "first_seen still resolves across the duplicate");

        assert!(
            attribute_by_ip(Vec::new()).is_empty(),
            "no audit rows means no attribution, not a panic"
        );
    }

    /// `banned`'s human path puts every condemned address in one of three
    /// classes, in this order: the audit log's own reason, then the APIBAN feed
    /// ("apiban (feed)"), then "not in this audit log". `--json` read the audit
    /// log and nothing else, so the second and third collapsed into the same
    /// two nulls — a consumer told "we do not know why this is blocked" about an
    /// address the box can account for exactly. `stats --json` already gets this
    /// split right, through `condemnation_counts`.
    ///
    /// The feed case renders as `("apiban", "feed")`: the human path's own two
    /// words, split at the seam its own `{reason} ({detail})` format already
    /// puts between them.
    #[test]
    fn banned_attribution_mirrors_the_human_paths_three_classes() {
        let mut audit = std::collections::HashMap::new();
        audit.insert(
            "198.51.100.10".to_string(),
            ("scanner".to_string(), "sipvicious".to_string(), 1756800000),
        );
        // Also on the feed: the audit reason still wins, the same precedence the
        // human path and `condemnation_counts` both apply.
        audit.insert(
            "198.51.100.11".to_string(),
            ("user-agent".to_string(), "pplsip".to_string(), 1756800100),
        );
        let apiban: std::collections::HashSet<String> =
            ["198.51.100.11".to_string(), "198.51.100.20".to_string()]
                .into_iter()
                .collect();

        assert_eq!(
            banned_attribution("198.51.100.10", &audit, &apiban),
            (Some(("scanner", "sipvicious")), Some(1756800000)),
            "an audited address reports its own reason"
        );
        assert_eq!(
            banned_attribution("198.51.100.11", &audit, &apiban),
            (Some(("user-agent", "pplsip")), Some(1756800100)),
            "on both, the audit reason wins — we condemned it for the perimeter reason"
        );
        assert_eq!(
            banned_attribution("198.51.100.20", &audit, &apiban),
            (Some(("apiban", "feed")), None),
            "on the feed only: attributed to the feed, not collapsed into unattributed"
        );
        assert_eq!(
            banned_attribution("198.51.100.30", &audit, &apiban),
            (None, None),
            "on neither: a hand ban with no audit row and no feed entry"
        );
    }

    // The reconstruction `banned --json` uses to turn a kernel expiry
    // (CLOCK_MONOTONIC nanoseconds) into wall-clock epoch seconds. This is
    // genuinely new arithmetic — the human path only ever produces a
    // relative countdown from the same `until` value, never an absolute
    // time — so it is pinned directly.
    #[test]
    fn expires_epoch_reconstructs_wall_clock_from_a_monotonic_delta() {
        let now_mono: u64 = 10_000_000_000_000; // an arbitrary monotonic "now"
        let now_wall: u32 = 1_756_800_000;

        // A live entry: 3600s of monotonic time remain until expiry.
        let until = now_mono + 3600 * 1_000_000_000;
        assert_eq!(
            expires_epoch(until, now_wall, now_mono),
            Some(now_wall + 3600),
            "a live entry's expiry is now + the remaining monotonic delta"
        );

        // An already-expired entry. The kernel would normally have dropped
        // this by the time `entries()` is read, but the arithmetic must
        // not underflow (a plain subtraction would panic in debug builds)
        // or produce a time in the past relative to `until`.
        let expired_until = now_mono - 60 * 1_000_000_000;
        assert_eq!(
            expires_epoch(expired_until, now_wall, now_mono),
            Some(now_wall),
            "an already-elapsed delta saturates to zero seconds left, not underflow"
        );

        // `until == 0` means "never expires" (see `Blocklist::insert`).
        assert_eq!(
            expires_epoch(0, now_wall, now_mono),
            None,
            "a permanent block has no expiry to report"
        );
    }

    /// Every time this contract carries is an epoch integer, `log`'s included:
    /// a consumer recomputes its own presentation, and a document that mixed
    /// integers and formatted strings for the same kind of value would make a
    /// consumer guess which it had. This pins the type, not just the number.
    #[test]
    fn log_doc_carries_epoch_integers_not_strings() {
        let row = BlockRow {
            ts: 1756800000,
            ip: "198.51.100.10".to_string(),
            reason: "scanner".to_string(),
            detail: "sipvicious".to_string(),
        };
        let d = log_doc(&row, Some(1756803600), None, true, "block");
        assert_eq!(d.ip, "198.51.100.10");
        assert_eq!(d.reason, "scanner");
        assert_eq!(d.detail, "sipvicious");
        assert_eq!(d.first_seen, 1756800000, "an epoch integer, not a string");
        assert_eq!(d.expires, Some(1756803600));
        assert_eq!(d.unbanned_at, None);
        assert!(d.enforced);
        assert_eq!(
            d.disposition, "block",
            "the glossary's disposition (CONTEXT.md), not the past tense"
        );
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"ip":"198.51.100.10","reason":"scanner","detail":"sipvicious","first_seen":1756800000,"expires":1756803600,"unbanned_at":null,"enforced":true,"disposition":"block"}"#
        );
    }

    /// The arithmetic `ban --json` uses to turn `--ttl` into an absolute
    /// expiry: genuinely new logic — the human path only ever prints a
    /// relative duration (`ago(args.ttl as u32)`), never an absolute time —
    /// so it is pinned directly with concrete values rather than only
    /// indirectly through `action_doc`.
    #[test]
    fn ban_expires_turns_a_ttl_into_an_absolute_epoch_or_none() {
        assert_eq!(
            ban_expires(1_756_800_000, 3600),
            Some(1_756_803_600),
            "an absolute expiry is now_wall + the ttl"
        );
        assert_eq!(
            ban_expires(1_756_800_000, 0),
            None,
            "ttl 0 means forever (see Blocklist::insert), which has no expiry"
        );
        assert_eq!(
            ban_expires(0, 1),
            Some(1),
            "a fixture now_wall of zero is still real arithmetic, not a special case"
        );
    }

    /// `--ttl` parses into a `u64` with no upper bound, so a ttl above
    /// `u32::MAX` reaches this function. `ttl_secs as u32` wraps there, and
    /// `saturating_add` cannot help afterwards because the value it is handed
    /// has already wrapped: `--ttl 4294967296` would report an expiry of *now*,
    /// i.e. a block that has already elapsed, for a ban that in the kernel lasts
    /// essentially forever.
    /// A rate that is not a finite number must say so as `null`, and the field
    /// must be TYPED nullable so the contract and the wire agree.
    ///
    /// `rate_a` is a `REAL NOT NULL` column and SQLite stores an infinity
    /// faithfully, so a non-finite value is reachable from the database. JSON
    /// has no way to spell one: `serde_json` renders it `null` regardless of
    /// what the field is declared as. Left as a bare `f64`, the document would
    /// promise a number and hand back `null` — a consumer deserialising into
    /// `f64` gets a parse error rather than a value, with nothing on stderr and
    /// exit 0. Making it `Option<f64>` changes no wire byte; it stops the type
    /// from lying about what can arrive.
    #[test]
    fn a_non_finite_rate_is_null_and_the_field_admits_it() {
        for bad in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            let d = source_row_doc("203.0.113.9", 3, bad, 1756800000);
            assert_eq!(d.rate, None, "a non-finite rate is not a number: {bad}");
            assert_eq!(
                tfps::json_line(&d).unwrap(),
                r#"{"peer":"203.0.113.9","countries":3,"rate":null,"last_seen":1756800000}"#
            );
        }
        let ok = source_row_doc("203.0.113.9", 3, 1.5, 1756800000);
        assert_eq!(ok.rate, Some(1.5), "a finite rate is unchanged");
        assert_eq!(
            tfps::json_line(&ok).unwrap(),
            r#"{"peer":"203.0.113.9","countries":3,"rate":1.5,"last_seen":1756800000}"#,
            "the wire bytes for a finite rate must not move"
        );
        // `source` carries the same field and must answer the same way.
        let one = source_doc("203.0.113.9", 3, f64::INFINITY, 1756800000, &["GB"]);
        assert_eq!(one.rate, None);
        assert!(tfps::json_line(&one).unwrap().contains(r#""rate":null"#));
    }

    /// `detail` is a SIP `User-Agent`: an attacker writes it. The contract is
    /// one JSON document per line, so a raw newline in that field would end the
    /// line early and every following field would land in a record the consumer
    /// never sees as malformed — it would just parse as a shorter object.
    ///
    /// The human rendering genuinely is broken this way today (a newline splits
    /// the column layout across lines); this pins that the JSON one is not.
    #[test]
    fn a_hostile_detail_cannot_break_the_one_document_per_line_contract() {
        let row = BlockRow {
            ts: 1756800000,
            ip: "10.0.0.1".to_string(),
            reason: "scanner".to_string(),
            detail: "friendly\nscanner\r\n\"quoted\" \\slash\\ \u{1}ctrl\t{\"ip\":\"1.2.3.4\"}"
                .to_string(),
        };
        // Guard the fixture before trusting the assertions below: a `detail`
        // that did not actually contain the hostile bytes would make every
        // check here pass while proving nothing.
        assert!(row.detail.contains('\n') && row.detail.contains('\r'));
        assert!(row.detail.contains('"') && row.detail.contains('\\'));
        assert!(
            row.detail.contains('\u{1}'),
            "fixture must carry a control char"
        );

        let line = tfps::json_line(&log_doc(&row, None, None, true, "block")).unwrap();
        assert!(
            !line.contains('\n'),
            "a raw newline would split the record: {line}"
        );
        assert!(!line.contains('\r'), "a bare CR would too: {line}");
        assert!(
            !line.contains('\u{1}'),
            "a raw control character is not valid inside a JSON string: {line}"
        );
        // and the value must survive exactly, not merely be made safe
        let back: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            back["detail"].as_str().unwrap(),
            row.detail,
            "escaping must be lossless"
        );
        assert_eq!(back["ip"].as_str().unwrap(), "10.0.0.1");
    }

    #[test]
    fn ban_expires_saturates_a_ttl_too_large_for_the_field() {
        assert_eq!(
            ban_expires(1_000, u64::from(u32::MAX) + 1),
            Some(u32::MAX),
            "a ttl one second past the field's range is far future, not now"
        );
        assert_eq!(
            ban_expires(1_000, u64::MAX),
            Some(u32::MAX),
            "and the largest ttl there is saturates too"
        );
        assert_eq!(
            ban_expires(1_000, u64::from(u32::MAX)),
            Some(u32::MAX),
            "the last ttl that fits still saturates on the add, not wraps"
        );
    }

    /// The same class of cast on the way back out of the kernel. `until` is a
    /// raw `u64` read from a BPF map — our own daemon's or, with `--map`, a
    /// third party's — so a value whose remaining delta exceeds `u32::MAX`
    /// seconds is an input this function must survive rather than assume away.
    /// `secs_left as u32` wraps it into a plausible-looking near-future expiry,
    /// which is worse than an obviously saturated one.
    #[test]
    fn expires_epoch_saturates_a_delta_too_large_for_the_field() {
        assert_eq!(
            expires_epoch(u64::MAX, 1_000, 0),
            Some(u32::MAX),
            "an 18-billion-second delta saturates; wrapping it invents a nearby expiry"
        );
        let just_over = (u64::from(u32::MAX) + 1) * 1_000_000_000;
        assert_eq!(
            expires_epoch(just_over, 1_000, 0),
            Some(u32::MAX),
            "one second past the field's range is already past it"
        );
    }

    /// `action_doc`'s own tests are handed the refusal string already
    /// decided — they cannot catch a bug in the code that DECIDES it. This
    /// drives a real `Placed` through `place()` (the same way
    /// `a_kernel_failure_is_not_an_exemption` does, no live kernel needed)
    /// so the `Origin::Local => "local"` / `Origin::Declared => "declared"` /
    /// `failed => "kernel"` mapping in `ban_action_docs` is checked against
    /// concrete addresses. Swapping the two `Origin` arms, or folding
    /// `"kernel"` into `"local"`, must turn this red.
    #[test]
    fn ban_action_docs_maps_each_placed_outcome_to_its_own_refusal() {
        let host = Ipv4Addr::new(10, 0, 0, 60);
        let declared_ip = Ipv4Addr::new(203, 0, 113, 7);
        let blocked_ip = Ipv4Addr::new(198, 51, 100, 5);
        let failed_ip = Ipv4Addr::new(198, 51, 100, 6);
        let mut g = guard(&[host], &["203.0.113.0/24"]);
        let out = place(&[host, declared_ip, blocked_ip, failed_ip], &mut g, |ip| {
            if ip == failed_ip {
                Err("map is full".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(
            out.blocked,
            vec![blocked_ip],
            "fixture sanity: one address blocks"
        );
        assert_eq!(
            out.exempt.len(),
            2,
            "fixture sanity: two addresses are exempt"
        );
        assert_eq!(out.failed, vec![(failed_ip, "map is full".to_string())]);

        let docs = ban_action_docs(&out, Some(1756921210));
        assert_eq!(
            docs.len(),
            4,
            "every input address gets exactly one document"
        );

        let blocked = &docs[0];
        assert_eq!(blocked.ip.as_deref(), Some("198.51.100.5"));
        assert!(blocked.applied);
        assert_eq!(blocked.refused, None);
        assert_eq!(
            blocked.expires,
            Some(1756921210),
            "an epoch integer, not an RFC3339 string"
        );

        let local = &docs[1];
        assert_eq!(
            local.ip.as_deref(),
            Some("10.0.0.60"),
            "this host's own address is the Origin::Local case"
        );
        assert!(!local.applied);
        assert_eq!(
            local.refused.as_deref(),
            Some("local"),
            "Origin::Local must render as \"local\", not \"declared\""
        );
        assert_eq!(local.expires, None, "a refusal has no expiry");

        let declared = &docs[2];
        assert_eq!(
            declared.ip.as_deref(),
            Some("203.0.113.7"),
            "the declared ignoreip range is the Origin::Declared case"
        );
        assert!(!declared.applied);
        assert_eq!(
            declared.refused.as_deref(),
            Some("declared"),
            "Origin::Declared must render as \"declared\", not \"local\""
        );
        assert_eq!(declared.expires, None);

        let failed = &docs[3];
        assert_eq!(failed.ip.as_deref(), Some("198.51.100.6"));
        assert!(!failed.applied);
        assert_eq!(
            failed.refused.as_deref(),
            Some("kernel"),
            "a kernel write failure must not be folded into a policy refusal"
        );
        assert_eq!(failed.expires, None);
    }

    #[test]
    fn action_doc_renders_every_outcome_the_guard_can_produce() {
        let applied = action_doc(Some("198.51.100.20"), "ban", None, Some(1756921210));
        assert_eq!(
            tfps::json_line(&applied).unwrap(),
            r#"{"ip":"198.51.100.20","action":"ban","applied":true,"refused":null,"expires":1756921210,"source":"operator"}"#
        );
        for (ip, action, reason) in [
            ("192.0.2.1", "ban", "local"),
            ("192.0.2.77", "ban", "declared"),
            ("198.51.100.7", "ban", "kernel"),
            ("198.51.100.21", "unban", "not-blocked"),
        ] {
            let line = tfps::json_line(&action_doc(Some(ip), action, Some(reason), None)).unwrap();
            assert!(line.contains(&format!(r#""ip":"{ip}""#)), "{line}");
            assert!(line.contains(&format!(r#""refused":"{reason}""#)), "{line}");
            assert!(
                line.contains(r#""applied":false"#),
                "a refusal never applied: {line}"
            );
            assert!(
                line.contains(r#""expires":null"#),
                "a refusal has no expiry: {line}"
            );
        }
    }

    /// `applied` and `refused` are the same fact twice. They may never disagree.
    #[test]
    fn applied_is_exactly_the_absence_of_a_refusal() {
        assert!(action_doc(Some("1.2.3.4"), "unban", None, None).applied);
        assert!(!action_doc(Some("1.2.3.4"), "unban", Some("not-blocked"), None).applied);
    }

    /// A kernel write failure is not a policy refusal. Folding them together would
    /// report "refused as configured" about a box whose enforcement is broken.
    #[test]
    fn a_kernel_failure_is_reported_separately_from_a_policy_refusal() {
        let kernel = tfps::json_line(&action_doc(
            Some("198.51.100.7"),
            "ban",
            Some("kernel"),
            None,
        ))
        .unwrap();
        let policy =
            tfps::json_line(&action_doc(Some("192.0.2.1"), "ban", Some("local"), None)).unwrap();
        assert!(kernel.contains(r#""refused":"kernel""#));
        assert!(policy.contains(r#""refused":"local""#));
        assert_ne!(kernel, policy);
    }

    #[test]
    fn output_goes_through_the_pipe_safe_macro() {
        // `tfps_ctl pairs | head` closes the pipe early. Rust ignores SIGPIPE, so a plain
        // `println!` panics there — this file must not contain one.
        // The needle is assembled at runtime, otherwise this test's own source would
        // contain the very thing it forbids and fail against itself.
        let needle = concat!("print", "ln!(");
        let src = include_str!("tfps_ctl.rs");
        // `eprintln!` ends in the same characters and is fine: stderr is not the piped
        // stream, and a diagnostic that cannot be written is not worth surviving for.
        let hits = src
            .match_indices(needle)
            .filter(|(i, _)| !src[..*i].ends_with(char::is_alphabetic))
            .count();
        assert_eq!(
            hits, 0,
            "use say!() instead of {needle}) so a closed pipe ends the run instead of panicking"
        );
    }

    /// Unreachable kernel counters are null, not zero. A tool that cannot read a
    /// counter and a counter that reads zero are different answers, and a
    /// consumer that cannot tell them apart will report "nothing was dropped"
    /// about a box whose enforcement is broken.
    #[test]
    fn stats_doc_nulls_the_kernel_block_when_counters_are_unreachable() {
        let d = stats_doc(None, Some((7, 5, 2)), None);
        let line = tfps::json_line(&d).unwrap();
        assert!(line.contains(r#""kernel":null"#), "{line}");
        assert!(line.contains(r#""condemned_now":7"#), "{line}");
    }

    #[test]
    fn stats_doc_reports_live_counters_when_they_are_readable() {
        let d = stats_doc(Some((100, 40, 3)), Some((7, 5, 2)), None);
        let line = tfps::json_line(&d).unwrap();
        assert!(line.contains(r#""seen":100"#), "{line}");
        assert!(line.contains(r#""dropped":40"#), "{line}");
        assert!(line.contains(r#""expired":3"#), "{line}");
    }

    /// The condemnation summary gets the same null-not-zero treatment as the
    /// kernel block, and for the same reason: `Blocklist::open` failing is a
    /// different fact from a blocklist that is genuinely empty, and a
    /// consumer reading `condemned_now: 0` off a box whose map could not
    /// even be opened would draw exactly the wrong conclusion — "nothing is
    /// blocked" — about a box this tool simply could not check.
    #[test]
    fn stats_doc_nulls_the_condemnation_block_when_the_blocklist_is_unreachable() {
        let d = stats_doc(Some((100, 40, 3)), None, None);
        let line = tfps::json_line(&d).unwrap();
        assert!(line.contains(r#""condemnation":null"#), "{line}");
        assert!(
            line.contains(r#""seen":100"#),
            "the kernel block is independent and must still report: {line}"
        );
    }

    /// The perimeter/feed split `stats --json`'s condemnation summary uses,
    /// pinned directly with concrete addresses — the same reason
    /// `attribute_by_ip` and `expires_epoch` above are tested on their own
    /// rather than only indirectly through `stats_doc`, which never sees more
    /// than the three already-computed counts.
    #[test]
    fn condemnation_counts_splits_perimeter_from_feed_only() {
        let audit: std::collections::HashSet<String> =
            ["198.51.100.10".to_string()].into_iter().collect();
        let apiban: std::collections::HashSet<String> =
            ["198.51.100.10".to_string(), "198.51.100.20".to_string()]
                .into_iter()
                .collect();
        let entries = vec![
            // On both the audit log and the feed: attributed to the audit
            // log, the same "block_log reason wins" precedence the human
            // path already uses in `banned`.
            (Ipv4Addr::new(198, 51, 100, 10), 0u64),
            // On the feed only.
            (Ipv4Addr::new(198, 51, 100, 20), 0u64),
            // On neither — a hand ban with no audit row and no feed entry.
            (Ipv4Addr::new(198, 51, 100, 30), 0u64),
        ];
        let (condemned_now, perimeter_manual, apiban_feed_only) =
            condemnation_counts(&entries, &audit, &apiban);
        assert_eq!(
            condemned_now, 3,
            "every entry counts toward the total regardless of attribution"
        );
        assert_eq!(
            perimeter_manual, 1,
            "the audited-and-on-the-feed entry is attributed to the audit log, not the feed"
        );
        assert_eq!(
            apiban_feed_only, 1,
            "only the feed-only entry counts here; the unattributed entry counts toward neither"
        );
    }

    #[test]
    fn condemnation_counts_is_all_zero_for_an_empty_blocklist() {
        let audit = std::collections::HashSet::new();
        let apiban = std::collections::HashSet::new();
        assert_eq!(condemnation_counts(&[], &audit, &apiban), (0, 0, 0));
    }

    /// The checkpoint-line parsing and age arithmetic `stats --json`'s TRAFFIC
    /// block uses. `age_secs` is a raw interval, not `ago()`'s formatted
    /// string — a program recomputes its own presentation, the same
    /// reasoning that keeps `log_doc`'s times as epoch integers.
    #[test]
    fn traffic_doc_parses_the_checkpoint_line_and_ages_it_in_raw_seconds() {
        let d = traffic_doc(
            Some("udp=120 syn=40 auth_fail=3"),
            Some(1_756_800_000),
            1_756_800_600,
        )
        .expect("a checkpoint line is present");
        assert_eq!(
            d.age_secs,
            Some(600),
            "raw seconds, not a formatted duration string"
        );
        assert_eq!(
            d.counters.get("udp"),
            Some(&Some(120)),
            "an integer, not the string \"120\" — `kernel.seen` in the same document is one"
        );
        assert_eq!(d.counters.get("syn"), Some(&Some(40)));
        assert_eq!(d.counters.get("auth_fail"), Some(&Some(3)));
        assert_eq!(d.counters.len(), 3, "no extra or dropped counters");
    }

    #[test]
    fn traffic_doc_is_none_when_there_is_no_checkpoint_yet() {
        assert!(
            traffic_doc(None, None, 1_756_800_000).is_none(),
            "no checkpoint yet is a different fact from a checkpoint with zero counters"
        );
    }

    #[test]
    fn traffic_doc_ages_null_when_the_checkpoint_has_no_timestamp() {
        let d = traffic_doc(Some("udp=120"), None, 1_756_800_600)
            .expect("a counters line without a timestamp still parses");
        assert_eq!(d.age_secs, None);
        assert_eq!(d.counters.get("udp"), Some(&Some(120)));
    }

    /// A counter the daemon wrote and this tool cannot read as a number is
    /// `null` — the key survives, so "the daemon never reported this counter"
    /// stays distinguishable from "this checkpoint line is corrupt". Dropping
    /// the key would collapse the two, the same conflation `stats --json`'s
    /// null-not-zero blocks exist to prevent one level up.
    #[test]
    fn traffic_doc_nulls_a_counter_it_cannot_read_rather_than_dropping_it() {
        let d = traffic_doc(Some("udp=120 syn=? auth_fail=3"), None, 1_756_800_600)
            .expect("a checkpoint line is present");
        assert_eq!(d.counters.len(), 3, "the unreadable counter keeps its key");
        assert_eq!(d.counters.get("syn"), Some(&None));
        assert_eq!(d.counters.get("udp"), Some(&Some(120)));
    }

    #[test]
    fn forget_doc_names_the_peer_and_the_count() {
        assert_eq!(
            tfps::json_line(&forget_doc("203.0.113.9", 12)).unwrap(),
            r#"{"peer":"203.0.113.9","forgotten":12}"#
        );
    }

    #[test]
    fn a_source_row_is_one_object_per_line_with_no_count_line() {
        let d = source_row_doc("203.0.113.9", 12, 1.5, 1756800000);
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"peer":"203.0.113.9","countries":12,"rate":1.5,"last_seen":1756800000}"#
        );
    }

    /// `peers --json`'s row is the same shape minus `rate` — `peers`'s human
    /// path never prints a rate column, so there is none to carry.
    #[test]
    fn a_peer_row_has_no_rate_field() {
        let d = peer_row_doc("203.0.113.9", 7, 1756800000);
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"peer":"203.0.113.9","countries":7,"last_seen":1756800000}"#
        );
    }

    /// `source --json` answers about ONE peer with an object that also carries
    /// the full country list — the same list the human path already decodes
    /// to print its chunked lines, here as an array instead.
    #[test]
    fn a_source_doc_carries_the_full_country_list_as_an_array() {
        let d = source_doc("203.0.113.9", 3, 1.5, 1756800000, &["GB", "DE", "FR"]);
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"peer":"203.0.113.9","countries":3,"rate":1.5,"last_seen":1756800000,"countries_known":["GB","DE","FR"]}"#
        );
    }

    /// Pins that `SourceDoc.countries` is the caller's stored count, passed
    /// straight through, and never recomputed here as
    /// `countries_known.len()`. The two counts are equal by construction
    /// for a row written under the current country table (see `SourceDoc`'s
    /// doc comment for why they are not equal *by invariant*), so a test
    /// using equal values would pass whichever one `source_doc` actually
    /// used; deliberately mismatched values are what would catch a future
    /// edit that swapped `countries` for `countries_known.len()`.
    #[test]
    fn a_source_doc_countries_is_the_stored_count_not_the_decoded_length() {
        let d = source_doc("203.0.113.9", 5, 1.5, 1756800000, &["GB", "DE", "FR"]);
        assert_eq!(
            d.countries, 5,
            "must be the caller's stored count (5), not countries_known.len() (3)"
        );
    }

    /// The human view chunks countries to wrap a terminal. A program wants the
    /// list, so the array is the countries themselves and never a joined string.
    #[test]
    fn countries_are_an_array_not_the_wrapped_string() {
        let d = countries_doc("203.0.113.9", &["GB", "DE", "FR"]);
        assert_eq!(
            tfps::json_line(&d).unwrap(),
            r#"{"peer":"203.0.113.9","countries_known":["GB","DE","FR"]}"#
        );
    }

    #[test]
    fn a_peer_with_no_countries_is_an_empty_array_not_null() {
        let line = tfps::json_line(&countries_doc("203.0.113.9", &[])).unwrap();
        assert!(line.contains(r#""countries_known":[]"#), "{line}");
    }

    /// Every subcommand `usage()` advertises must accept --json AND its handler
    /// must actually branch on it. `parse()` sets `args.json` unconditionally for
    /// ANY command word — it never checks the word against `main()`'s dispatch
    /// table, so `assert!(a.json, ...)` on the parsed `Args` is true for a
    /// fictional command with no JSON rendering at all, just as it is for a real
    /// one. What the JSON contract actually requires is that the handler
    /// function honours the flag, so this reads each handler's own source (the
    /// same `include_str!` technique `output_goes_through_the_pipe_safe_macro`,
    /// above, already uses) and looks for an `args.json` branch there, instead
    /// of trusting the parser to have validated anything. `handler_body` is what
    /// makes "there" mean this handler and not the next one — see its own
    /// comment.
    #[test]
    fn every_advertised_subcommand_accepts_json() {
        let help = usage();
        let names: Vec<String> = help
            .lines()
            .skip_while(|l| !l.starts_with("USAGE:"))
            .take_while(|l| !l.starts_with("SOURCE FILTERS:"))
            .filter(|l| l.starts_with("  ") && !l.trim().is_empty())
            .filter_map(|l| l.split_whitespace().next().map(str::to_string))
            .filter(|w| w.chars().all(|c| c.is_ascii_lowercase()))
            .collect();
        assert_eq!(names.len(), 11, "expected 11 subcommands, got {names:?}");

        let src = include_str!("tfps_ctl.rs");
        for n in &names {
            assert!(
                handler_body(src, n).contains("args.json"),
                "`{n}`'s handler has no args.json branch — it accepts the flag but ignores it"
            );
        }
    }

    /// `report_ban_diagnostics` exists because `ban --json` once silently dropped
    /// the specific kernel-failure reason a caller needs to tell "map missing"
    /// from "permission denied" — collapsing both to the same
    /// `"refused":"kernel"` and printing nothing else. The fix was to call the
    /// same diagnostics function from both of `ban`'s branches; nothing but this
    /// test stops a future edit from quietly deleting one of those two calls and
    /// reintroducing exactly that regression, since `cargo test` would stay green
    /// either way otherwise.
    ///
    /// Two calls, one per branch, is the whole requirement, so counting them in
    /// `ban`'s own body says it directly. Which branch a surviving call sits in
    /// does not need finding: `ban` has exactly one `if args.json` block and one
    /// path past it, so a body holding two calls has one on each.
    #[test]
    fn ban_reports_diagnostics_in_both_json_and_plain_mode() {
        let src = include_str!("tfps_ctl.rs");
        let calls = handler_body(src, "ban")
            .matches("report_ban_diagnostics(")
            .count();
        assert_eq!(
            calls, 2,
            "`ban` must call report_ban_diagnostics from both its --json branch and its \
             plain path; {calls} call(s) found, so one mode is silently losing the \
             specific kernel-failure reason again"
        );
    }

    /// `log`'s handler is the only caller of `log_doc`, and the disposition it
    /// passes is a constant. `log_doc_carries_epoch_integers_not_strings` above
    /// hands the document its own value, so it proves only that whatever it is
    /// given comes back out — it cannot see the CALL SITE choosing a word
    /// outside the glossary, which is exactly what it was doing.
    ///
    /// `CONTEXT.md`'s Disposition entry enumerates **ignore**, **exempt**,
    /// **would-block** and **block**, and grounds them in
    /// `tfps_core::disposition`, whose variants are `Ignore`,
    /// `ExemptIgnoreIp`, `ExemptKnownPeer` and `Block`. `"blocked"` is none of
    /// them, and this is the one field a consumer is most likely to match
    /// against that enum's own vocabulary.
    #[test]
    fn log_passes_a_glossary_disposition_to_the_document() {
        let src = include_str!("tfps_ctl.rs");
        let body = handler_body(src, "log");
        assert!(
            body.contains(r#"log_doc(r, None, None, true, "block")"#),
            "log must pass CONTEXT.md's disposition `block`, not a past tense or \
             any other word outside the glossary"
        );
    }

    #[test]
    fn the_help_text_advertises_the_flag() {
        assert!(
            usage().contains("--json"),
            "an undocumented flag is an unusable one"
        );
    }

    /// `status` must report the binary's real version, never a literal. The
    /// `status_doc` tests pass a version in as an argument, so they prove the
    /// document serialises whatever it is given — they cannot catch the CALL SITE
    /// regressing to a typed-in string. This reads the file's own source, the same
    /// technique `output_goes_through_the_pipe_safe_macro` already uses above,
    /// scoped to `status`'s own body: searching the whole file would let the call
    /// site regress to a literal and still pass on any other occurrence of the
    /// macro, including one in this test.
    #[test]
    fn status_reports_the_crate_version_not_a_literal() {
        let src = include_str!("tfps_ctl.rs");
        assert!(
            handler_body(src, "status").contains("env!(\"CARGO_PKG_VERSION\")"),
            "status must pass the crate version to status_doc, never a literal"
        );
    }
}
