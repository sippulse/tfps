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

use tfps::say;
use tfps::store::{BlockRow, SourceFilter, Store};
use tfps::xdp::{monotonic_ns, Blocklist};

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
  -h, --help                   this help

Reading blocks needs CAP_BPF (run as root). Reading learned state only needs the database.
",
        db = tfps::store::DEFAULT_PATH
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

fn status(args: &Args) -> Result<(), String> {
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

/// The whole picture, from the two places it lives.
///
/// **The kernel half is live; the userspace half is a snapshot.** They are printed apart,
/// with the snapshot's age stated, because presenting a five-minute-old packet count beside
/// a current drop count as if both were now would be the kind of quiet inaccuracy this
/// project exists to avoid.
fn stats(args: &Args) -> Result<(), String> {
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
    if let Ok(b) = Blocklist::open(args.map.as_deref()) {
        let e = b.entries();
        say!(
            "  condemned now     : {} ({} permanent, e.g. the APIBAN feed)",
            e.len(),
            e.iter().filter(|(_, u)| *u == 0).count()
        );
    }

    let s = Store::open_readonly(&args.db)?;
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

    say!("\nBLOCKS BY REASON");
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

fn banned(args: &Args) -> Result<(), String> {
    let b = Blocklist::open(args.map.as_deref())?;
    let entries = b.entries();
    if entries.is_empty() {
        say!("nothing is blocked");
        return Ok(());
    }
    // The audit log says *why* for perimeter blocks; the APIBAN feed is a separate record,
    // since its thousands of addresses are not written to the audit log. Load both once.
    let store = Store::open_readonly(&args.db).ok();
    let apiban = store
        .as_ref()
        .and_then(|s| s.apiban_all().ok())
        .unwrap_or_default();
    let now_ns = monotonic_ns();
    let mut apiban_count = 0usize;
    say!("{:<16} {:>10}  REASON", "SOURCE", "EXPIRES IN");
    for (ip, until) in &entries {
        let left = if *until == 0 {
            "never".to_string()
        } else {
            ago(((*until).saturating_sub(now_ns) / 1_000_000_000) as u32)
        };
        let ip_s = ip.to_string();
        let from_apiban = apiban.contains(&ip_s);
        if from_apiban {
            apiban_count += 1;
        }
        let why = match (args.why, store.as_ref()) {
            (true, Some(s)) => s
                .blocks(1, Some(&ip_s))
                .ok()
                .and_then(|v| v.into_iter().next())
                .map(|r| format!("{} ({})", r.reason, r.detail))
                .or_else(|| from_apiban.then(|| "apiban (feed)".to_string()))
                .unwrap_or_else(|| "not in this audit log".to_string()),
            _ => String::new(),
        };
        say!("{ip_s:<16} {left:>10}  {why}");
    }
    say!(
        "\n{} blocked ({apiban_count} from the APIBAN feed, {} from the perimeter/manual)",
        entries.len(),
        entries.len() - apiban_count
    );
    Ok(())
}

fn unban(args: &Args) -> Result<(), String> {
    let mut b = Blocklist::open(args.map.as_deref())?;
    if args.all {
        let all = b.entries();
        for (ip, _) in &all {
            b.remove(*ip)?;
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
        if b.remove(ip)? {
            say!("unbanned {ip}");
        } else {
            say!("{ip} was not blocked");
        }
    }
    Ok(())
}

fn ban(args: &Args) -> Result<(), String> {
    let mut b = Blocklist::open(args.map.as_deref())?;
    if args.positional.is_empty() {
        return Err("give at least one address".into());
    }
    for raw in &args.positional {
        let ip: Ipv4Addr = raw.parse().map_err(|e| format!("{raw}: {e}"))?;
        b.insert(ip, args.ttl)?;
        let how = if args.ttl == 0 {
            "with no expiry".to_string()
        } else {
            format!("for {}", ago(args.ttl as u32))
        };
        say!("blocked {ip} {how}");
    }
    Ok(())
}

fn sources(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let f = SourceFilter {
        peer: args.peer.as_deref(),
        country: args.country.as_deref(),
        limit: args.limit,
    };
    let rows = s.find_sources(&f)?;
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

fn peers(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let rows = s.peers()?;
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

fn countries(args: &Args) -> Result<(), String> {
    let [peer] = args.positional.as_slice() else {
        return Err("usage: tfps_ctl countries <peer>".into());
    };
    let s = Store::open_readonly(&args.db)?;
    let names = s.peer_countries(peer)?;
    if names.is_empty() {
        return Err(format!("nothing learned for source {peer}"));
    }
    say!("{peer} has been seen to call {} countries:", names.len());
    for chunk in names.chunks(16) {
        say!("  {}", chunk.join(" "));
    }
    Ok(())
}

fn log(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let rows: Vec<BlockRow> = s.blocks(args.limit, args.ip.as_deref())?;
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
}
