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
use tfps::store::{BlockRow, PairFilter, Store};
use tfps::xdp::{monotonic_ns, Blocklist};
use tfps_core::country;

fn usage() -> String {
    format!(
        "tfps_ctl — inspect and control a running TFPS

USAGE: tfps_ctl <command> [options]

  status                       what is running, what is blocked, how fresh the state is
  banned [--why]               list condemned sources, with time left
  unban <ip>... | --all        lift a block. The precision measure of this product
  ban <ip> [--ttl N]           condemn a source by hand (default ttl: 3600s, 0 = forever)
  pairs [filters]              list learned (peer, A-number) pairs
  pair <peer> <a-number>       everything known about one pair
  peers                        peers, their pair counts and when last heard
  countries <peer>             where that peer actually calls, by volume
  log [--limit N] [--ip IP]    the block audit log, newest first
  forget <peer> [--a NUMBER]   erase learned state (requires tfps stopped)

PAIR FILTERS:
  --peer IP                    exactly this peer
  --a TEXT                     A-number containing TEXT
  --country ISO                pairs that have called this country, e.g. --country GB
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
        "banned" => banned(&args),
        "unban" => unban(&args),
        "ban" => ban(&args),
        "pairs" => pairs(&args),
        "pair" => pair(&args),
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

fn banned(args: &Args) -> Result<(), String> {
    let b = Blocklist::open(args.map.as_deref())?;
    let entries = b.entries();
    if entries.is_empty() {
        say!("nothing is blocked");
        return Ok(());
    }
    // The audit log says *why*, which the kernel map cannot know.
    let store = Store::open_readonly(&args.db).ok();
    let now_ns = monotonic_ns();
    say!("{:<16} {:>10}  REASON", "SOURCE", "EXPIRES IN");
    for (ip, until) in &entries {
        let left = if *until == 0 {
            "never".to_string()
        } else {
            ago(((*until).saturating_sub(now_ns) / 1_000_000_000) as u32)
        };
        let why = match (args.why, store.as_ref()) {
            (true, Some(s)) => s
                .blocks(1, Some(&ip.to_string()))
                .ok()
                .and_then(|v| v.into_iter().next())
                .map(|r| format!("{} ({})", r.reason, r.detail))
                .unwrap_or_else(|| "not in this audit log".to_string()),
            _ => String::new(),
        };
        say!("{ip:<16} {left:>10}  {why}");
    }
    say!("\n{} blocked", entries.len());
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

fn pairs(args: &Args) -> Result<(), String> {
    let s = Store::open_readonly(&args.db)?;
    let f = PairFilter {
        peer: args.peer.as_deref(),
        a_number: args.a_number.as_deref(),
        country: args.country.as_deref(),
        limit: args.limit,
    };
    let rows = s.find_pairs(&f)?;
    if rows.is_empty() {
        say!("no pair matches");
        return Ok(());
    }
    say!(
        "{:<16} {:<22} {:>6} {:>9}  COUNTRIES",
        "PEER",
        "A-NUMBER",
        "SEEN",
        "LAST"
    );
    let now = now();
    for r in &rows {
        let c = r.countries();
        let shown: Vec<&str> = c.iter().take(8).copied().collect();
        let tail = if c.len() > shown.len() {
            format!(" +{}", c.len() - shown.len())
        } else {
            String::new()
        };
        say!(
            "{:<16} {:<22} {:>6} {:>9}  {}{}",
            r.peer,
            truncate(&r.a_number, 22),
            c.len(),
            ago(now.saturating_sub(r.last_seen)),
            shown.join(","),
            tail
        );
    }
    say!("\n{} pairs", rows.len());
    Ok(())
}

fn pair(args: &Args) -> Result<(), String> {
    let [peer, a_number] = args.positional.as_slice() else {
        return Err("usage: tfps_ctl pair <peer> <a-number>".into());
    };
    let s = Store::open_readonly(&args.db)?;
    let rows = s.find_pairs(&PairFilter {
        peer: Some(peer),
        limit: usize::MAX,
        ..Default::default()
    })?;
    let Some(r) = rows.iter().find(|r| r.a_number == *a_number) else {
        return Err(format!("no pair {peer} / {a_number} in the database"));
    };
    let c = r.countries();
    say!("peer              : {}", r.peer);
    say!("a-number          : {}", r.a_number);
    say!(
        "last seen         : {} ago",
        ago(now().saturating_sub(r.last_seen))
    );
    say!("rotation period   : {}", r.period);
    say!("countries known   : {}", c.len());
    for chunk in c.chunks(12) {
        say!("                    {}", chunk.join(" "));
    }
    say!(
        "\nA first-time country here is one absent from that list. Ten of them within an\n\
         hour is what condemns the pair."
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
    say!("{:<16} {:>7} {:>9}  TOP COUNTRIES", "PEER", "PAIRS", "LAST");
    let now = now();
    for (peer, pairs, last) in rows.iter().take(args.limit) {
        let top: Vec<String> = s
            .peer_countries(peer)?
            .into_iter()
            .take(5)
            .filter_map(|(idx, calls)| country::iso_for_index(idx).map(|c| format!("{c}:{calls}")))
            .collect();
        say!(
            "{:<16} {:>7} {:>9}  {}",
            peer,
            pairs,
            ago(now.saturating_sub(*last)),
            top.join(" ")
        );
    }
    say!("\n{} peers", rows.len());
    Ok(())
}

fn countries(args: &Args) -> Result<(), String> {
    let [peer] = args.positional.as_slice() else {
        return Err("usage: tfps_ctl countries <peer>".into());
    };
    let s = Store::open_readonly(&args.db)?;
    let rows = s.peer_countries(peer)?;
    if rows.is_empty() {
        return Err(format!("nothing learned for peer {peer}"));
    }
    let total: u32 = rows.iter().map(|(_, n)| *n).sum();
    say!("{:<10} {:>8} {:>7}", "COUNTRY", "CALLS", "SHARE");
    for (idx, calls) in rows.iter().take(args.limit) {
        say!(
            "{:<10} {:>8} {:>6.1}%",
            country::iso_for_index(*idx).unwrap_or("?"),
            calls,
            100.0 * f64::from(*calls) / f64::from(total.max(1))
        );
    }
    say!(
        "\n{total} international calls across {} countries",
        rows.len()
    );
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

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    let keep: String = s.chars().take(width.saturating_sub(1)).collect();
    format!("{keep}…")
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
        assert!(args(&["pairs", "--limit"]).is_err());
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

    #[test]
    fn long_a_numbers_are_truncated_not_wrapped() {
        assert_eq!(truncate("1001", 8), "1001");
        assert_eq!(truncate("123456789012", 8), "1234567…");
    }
}
