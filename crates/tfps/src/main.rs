//! TFPS — watches SIP on the wire, learns each source's behaviour, and decides.
//!
//! Capture is `AF_PACKET`/`SOCK_DGRAM`, hooking at the netdev layer and **not opening a UDP
//! socket**: the softswitch keeps its own bind and never notices (`SPEC.md` §2).
//!
//! The perimeter already enforces: a source condemned by user-agent, URI injection or
//! credential brute force goes into a map the XDP program consults, and vanishes from
//! sngrep. The **fraud** verdict is not enforced yet — the forged `603` is still missing.
//!
//! Needs `CAP_NET_RAW` (capture), plus `CAP_BPF` and `CAP_NET_ADMIN` (XDP).

mod apiban;
mod config;
mod store;
mod xdp;

use std::collections::BTreeMap;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, Socket, Type};
use tfps_core::dialplan::DialPlan;
use tfps_core::engine::{Decision, Engine, Mode};
use tfps_core::net::{classify_other, parse_ipv4_udp, tcp_ports, NotUdp};
use tfps_core::novelty::Timestamp;

/// `AF_PACKET` on Linux. `socket2` exposes no constant for this family, so the value goes
/// in directly — it has been stable in the Linux ABI forever.
const AF_PACKET: i32 = 17;

/// `ETH_P_IP` in network order, as `AF_PACKET`'s `socket(2)` expects.
const ETH_P_IP_BE: i32 = 0x0008;

/// A generous MTU: SIP over UDP rarely exceeds this, and what does gets fragmented.
const BUF: usize = 65_536;

struct Args {
    ports: Vec<u16>,
    intl_prefixes: Vec<String>,
    learn_secs: u32,
    stats_every: u64,
    verbose: bool,
    debug_unparsed: bool,
    xdp_obj: PathBuf,
    shared_map: PathBuf,
    iface: Option<String>,
    block_ttl: u64,
    no_enforce: bool,
    db: PathBuf,
    checkpoint_every: u64,
    apiban_key: Option<String>,
    signatures: Option<PathBuf>,
    config: PathBuf,
    /// Per-peer dial plan from the file. Declaring beats learning because it holds on
    /// that peer's very first call.
    peer_plans: Vec<(Ipv4Addr, DialPlan)>,
    /// Which flags the operator actually passed — the file only fills in the rest.
    given: std::collections::HashSet<String>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            ports: vec![5060],
            // Covers the common shapes; `SPEC.md` §4 says to declare it per PBX.
            intl_prefixes: vec!["+".into(), "00".into(), "011".into(), "9011".into()],
            learn_secs: 30 * 24 * 3600,
            stats_every: 60,
            verbose: false,
            debug_unparsed: false,
            xdp_obj: PathBuf::from(xdp::DEFAULT_OBJ),
            shared_map: PathBuf::from(xdp::SIPVAULT_DROP_MAP),
            iface: None,
            // One hour. A perimeter block must undo itself, and a scanner that returns is
            // re-blocked on its first packet — the cost of being wrong is one hour.
            block_ttl: 3600,
            no_enforce: false,
            db: PathBuf::from(store::DEFAULT_PATH),
            // Five minutes. Losing that to a power cut costs five minutes of learning —
            // and checkpointing per packet would be a write bottleneck.
            checkpoint_every: 300,
            apiban_key: None,
            signatures: None,
            config: PathBuf::from(config::DEFAULT_PATH),
            peer_plans: Vec::new(),
            given: std::collections::HashSet::new(),
        }
    }
}

fn usage() -> &'static str {
    "\
tfps — IRSF fraud prevention for SIP networks

USAGE: tfps [options]

  --ports 5060,5080        SIP ports to watch             (default: 5060)
  --intl +,00,011,9011     international dialling prefixes
  --learn-days N           days in learning mode          (default: 30)
  --active                 skip learning (same as --learn-days 0)
  --stats-every N          seconds between reports        (default: 60)
  -v, --verbose            print every international attempt
      --debug-unparsed     show the start of payloads that failed to parse
      --iface eth0         XDP interface               (default: default route)
      --xdp-obj PATH       our BPF object              (default: /usr/local/lib/tfps/tfps_xdp.o)
      --drop-map PATH      a drop map already pinned by another product
      --block-ttl N        seconds a block lasts       (default: 3600, 0 = never expires)
      --no-enforce         observe only, do not load XDP
      --db PATH            SQLite database             (default: /var/lib/tfps/tfps.db)
      --no-db              do not persist (learning dies on restart)
      --checkpoint-every N seconds between writes      (default: 300)
      --apiban-key KEY     enable APIBAN (optional, in the background)
      --signatures PATH    file that ADDS signatures to the built-in ones
      --config PATH        configuration               (default: /etc/tfps/config.json)
  -h, --help               this help

Capture is AF_PACKET; it opens no UDP socket and does not clash with the softswitch.
Requires CAP_NET_RAW (run as root).
"
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        a.given.insert(arg.clone());
        let mut next = |name: &str| it.next().ok_or_else(|| format!("{name} requires a value"));
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{}", usage());
                std::process::exit(0);
            }
            "--ports" => {
                a.ports = next("--ports")?
                    .split(',')
                    .map(|p| {
                        p.trim()
                            .parse::<u16>()
                            .map_err(|e| format!("invalid port: {e}"))
                    })
                    .collect::<Result<_, _>>()?;
            }
            "--intl" => {
                a.intl_prefixes = next("--intl")?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
            }
            "--learn-days" => {
                let d: u32 = next("--learn-days")?.parse().map_err(|e| format!("{e}"))?;
                a.learn_secs = d * 24 * 3600;
            }
            "--active" => a.learn_secs = 0,
            "--stats-every" => {
                a.stats_every = next("--stats-every")?.parse().map_err(|e| format!("{e}"))?;
            }
            "-v" | "--verbose" => a.verbose = true,
            "--debug-unparsed" => a.debug_unparsed = true,
            "--xdp-obj" => a.xdp_obj = PathBuf::from(next("--xdp-obj")?),
            "--drop-map" => a.shared_map = PathBuf::from(next("--drop-map")?),
            "--iface" => a.iface = Some(next("--iface")?),
            "--block-ttl" => {
                a.block_ttl = next("--block-ttl")?.parse().map_err(|e| format!("{e}"))?;
            }
            "--no-enforce" => a.no_enforce = true,
            "--db" => a.db = PathBuf::from(next("--db")?),
            "--no-db" => a.db = PathBuf::new(),
            "--apiban-key" => a.apiban_key = Some(next("--apiban-key")?),
            "--signatures" => a.signatures = Some(PathBuf::from(next("--signatures")?)),
            "--config" => a.config = PathBuf::from(next("--config")?),
            "--checkpoint-every" => {
                a.checkpoint_every = next("--checkpoint-every")?
                    .parse()
                    .map_err(|e| format!("{e}"))?;
            }
            other => return Err(format!("unknown option: {other}")),
        }
    }
    if a.ports.is_empty() {
        return Err("no ports to watch".into());
    }
    Ok(a)
}

/// Applies the file on top of the defaults, **without overriding the command line**.
///
/// Precedence: command line > file > built-in default. It is the order that surprises
/// nobody, and the one that lets you debug in production without editing a file.
fn apply_config(a: &mut Args, c: &config::Config) {
    macro_rules! unless_given {
        ($flag:literal, $field:ident, $val:expr) => {
            if !a.given.contains($flag) {
                if let Some(v) = $val {
                    a.$field = v;
                }
            }
        };
    }
    unless_given!("--ports", ports, c.ports.clone());
    unless_given!("--intl", intl_prefixes, c.intl_prefixes.clone());
    unless_given!("--stats-every", stats_every, c.stats_every);
    unless_given!("--block-ttl", block_ttl, c.block_ttl);
    unless_given!("--checkpoint-every", checkpoint_every, c.checkpoint_every);
    unless_given!("--db", db, c.db.clone());
    unless_given!("--xdp-obj", xdp_obj, c.xdp_obj.clone());
    unless_given!("--drop-map", shared_map, c.drop_map.clone());

    if !a.given.contains("--iface") && c.iface.is_some() {
        a.iface = c.iface.clone();
    }
    if !a.given.contains("--apiban-key") && c.apiban_key.is_some() {
        a.apiban_key = c.apiban_key.clone();
    }
    if !a.given.contains("--learn-days") && !a.given.contains("--active") {
        if let Some(d) = c.learn_days {
            a.learn_secs = d.saturating_mul(24 * 3600);
        }
    }

    for (ip, pc) in &c.peers {
        match ip.parse::<Ipv4Addr>() {
            Ok(addr) => {
                let mut plan = DialPlan::new(pc.intl_prefixes.clone());
                if pc.bare_e164 {
                    plan = plan.with_bare_e164();
                }
                a.peer_plans.push((addr, plan));
            }
            // A peer with an invalid IP is a typo that would make the operator believe
            // they declared a plan that does not apply. Never silently.
            Err(e) => {
                eprintln!("WARNING: peer \"{ip}\" in the config is not a valid IPv4 address ({e})")
            }
        }
    }
}

fn now() -> Timestamp {
    Timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0),
    )
}

fn main() -> ExitCode {
    let mut extra_signatures: Vec<String> = Vec::new();
    let mut extra_injection: Vec<String> = Vec::new();
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };

    let mut args = args;
    match config::load(&args.config) {
        config::Loaded::File(c, path) => {
            apply_config(&mut args, &c);
            println!("  configuration     : {}", path.display());
            // File signatures are applied after the engine exists; kept here until then.
            extra_signatures = c.signatures.clone();
            extra_injection = c.injection.clone();
        }
        config::Loaded::Absent => {}
        config::Loaded::Broken(e) => {
            // Broken configuration ignored silently would make the operator believe they
            // declared something that does not apply.
            eprintln!("ALARM: invalid configuration, falling back to defaults — {e}");
        }
    }
    let args = args;

    let start = now();

    // The database opens before the engine because it decides **when learning started** —
    // without that, every restart would reset the 30 days and the countdown would lie.
    let db = if args.db.as_os_str().is_empty() {
        None
    } else {
        match store::Store::open(&args.db) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("ALARM: no persistence — {e}");
                eprintln!("       learning will be lost on the next restart.");
                None
            }
        }
    };

    let learn_from = db
        .as_ref()
        .map(|d| d.learning_started(start.0))
        .unwrap_or(start.0);

    let mode = if args.learn_secs == 0 {
        Mode::Active
    } else {
        Mode::Learning {
            until: Timestamp(learn_from.saturating_add(args.learn_secs)),
        }
    };

    let plan = DialPlan::new(args.intl_prefixes.clone());
    let mut engine = Engine::new(plan, mode);

    // Signatures **add** to the built-in ones; they never replace. Replacing would make
    // someone who writes three lines silently lose the 18 shipped ones.
    for sig in &extra_signatures {
        engine.noise_filter.add_signature(sig);
    }
    for pat in &extra_injection {
        engine.noise_filter.add_injection(pat);
    }
    for (ip, plan) in &args.peer_plans {
        engine.declare_dial_plan(*ip, plan.clone());
    }
    if !args.peer_plans.is_empty() {
        println!("  declared plans    : {} peers", args.peer_plans.len());
    }
    if let Some(path) = args.signatures.as_ref() {
        match std::fs::read_to_string(path) {
            Ok(txt) => {
                let mut ua = 0usize;
                let mut inj = 0usize;
                for line in txt.lines() {
                    match line.trim().split_once(char::is_whitespace) {
                        Some(("injection", rest)) => {
                            engine.noise_filter.add_injection(rest);
                            inj += 1;
                        }
                        _ => {
                            engine.noise_filter.add_signature(line);
                            ua += 1;
                        }
                    }
                }
                println!(
                    "  extra signatures  : {ua} user-agent, {inj} injection ({})",
                    path.display()
                );
            }
            Err(e) => eprintln!("WARNING: could not read {}: {e}", path.display()),
        }
    }
    let (ua_int, ua_ext) = engine.noise_filter.signature_count();
    let (inj_int, inj_ext) = engine.noise_filter.injection_count();

    if let Some(d) = db.as_ref() {
        match d.load_into(&mut engine) {
            Ok((p, c)) if p > 0 || c > 0 => {
                println!("  state restored    : {p} pairs, {c} peer-country rows");
            }
            Ok(_) => println!("  state restored    : empty database (first run)"),
            Err(e) => eprintln!("WARNING: could not restore state: {e}"),
        }
    }

    println!("tfps {} — starting", env!("CARGO_PKG_VERSION"));
    println!("  watched ports     : {:?}", args.ports);
    println!("  intl prefixes     : {:?}", args.intl_prefixes);
    match mode {
        // The mode is announced loudly and repeated in reports: this project's stated
        // difference from fail2ban is that the incumbent fails silently (`SPEC.md` §12).
        Mode::Active => println!("  mode              : ACTIVE — would block right away"),
        Mode::Learning { until } => println!(
            "  mode              : LEARNING for {} days (until {}), does NOT block",
            args.learn_secs / 86400,
            until.0
        ),
    }
    // Enforcement: load XDP, or say so loudly and carry on observing. Never pretend.
    let mut enforcer = if args.no_enforce {
        println!("  enforcement       : OFF via --no-enforce (observe only)");
        None
    } else {
        let iface = args
            .iface
            .clone()
            .or_else(xdp::default_interface)
            .unwrap_or_else(|| "eth0".to_string());
        match xdp::Enforcer::attach(&args.shared_map, &args.xdp_obj, &iface, &args.ports) {
            Ok(e) => {
                println!(
                    "  enforcement       : {} — garbage vanishes from sngrep",
                    e.mode
                );
                println!("  block expires in  : {}s", args.block_ttl);
                Some(e)
            }
            Err(err) => {
                // SPEC §12 requirement: an anti-fraud system that appears to protect
                // without protecting is exactly this project's criticism of the incumbent.
                eprintln!("ALARM: enforcement INACTIVE — {err}");
                eprintln!("       the system will OBSERVE but will NOT block anything.");
                println!("  enforcement       : INACTIVE (see the alarm above)");
                None
            }
        }
    };
    println!(
        "  perimeter         : {ua_int} user-agents (+{ua_ext} from file), \
         {inj_int} injection patterns (+{inj_ext})"
    );

    let sock = match Socket::new(
        Domain::from(AF_PACKET),
        Type::DGRAM,
        Some(Protocol::from(ETH_P_IP_BE)),
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: could not open the capture socket: {e}");
            eprintln!("       AF_PACKET requires CAP_NET_RAW — run as root.");
            return ExitCode::FAILURE;
        }
    };

    // A read timeout so the loop wakes even with no traffic. **Without this the silence
    // alarm can never fire**: it would sit inside a loop that only runs when a packet
    // arrives, and a system seeing nothing would stay mute — precisely the fail2ban failure
    // mode this project uses as its difference (`SPEC.md` §12).
    if let Err(e) = sock.set_read_timeout(Some(Duration::from_secs(1))) {
        eprintln!("warning: could not set a read timeout: {e}");
        eprintln!("         the silence alarm may not fire on a quiet link.");
    }

    // `socket2::Socket` implements `Read`, which allows a normal buffer and avoids
    // `MaybeUninit` — and therefore avoids `unsafe`, which the workspace forbids.
    let mut sock = sock;
    let mut buf = vec![0u8; BUF];
    let mut last_report = start.0;
    let mut seen_ports: BTreeMap<u16, u64> = BTreeMap::new();
    // APIBAN on its own thread: HTTP never touches the packet path. It was the synchronous
    // `rest_get()` per INVITE that capped the 2023 TFPS at ~26 calls/s.
    let apiban_rx = args.apiban_key.as_ref().map(|k| {
        println!("  APIBAN            : enabled, syncing in the background");
        apiban::spawn(k.clone(), None)
    });

    let mut nothing_seen_warned = false;
    let mut apiban_total = 0u64;
    let mut db = db;
    let mut last_checkpoint = start.0;
    // Blind spots: counted so they can become a warning. Ignoring them silently would
    // repeat the very failure this project uses as its difference from fail2ban.
    let (mut n_ipv6, mut n_tcp, mut n_frag) = (0u64, 0u64, 0u64);
    let mut blind_warned = false;
    let mut auth_blind_warned = false;

    loop {
        let n = match sock.read(&mut buf) {
            Ok(n) => n,
            // Timeout and interruption are not errors: they are the chance to report on a quiet link.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                0
            }
            Err(e) => {
                eprintln!("capture error: {e}");
                return ExitCode::FAILURE;
            }
        };

        let t = now();
        if n > 0 {
            if parse_ipv4_udp(&buf[..n]).is_none() {
                match classify_other(&buf[..n]) {
                    NotUdp::Ipv6 => n_ipv6 += 1,
                    // Only counts TCP **on the SIP ports**. Counting all TCP would include
                    // the administrator's own SSH session, turning the warning into noise.
                    NotUdp::Tcp => {
                        if let Some((sp, dp)) = tcp_ports(&buf[..n]) {
                            if args.ports.contains(&sp) || args.ports.contains(&dp) {
                                n_tcp += 1;
                            }
                        }
                    }
                    NotUdp::LaterFragment => n_frag += 1,
                    NotUdp::Other => {}
                }
            }
            if let Some(d) = parse_ipv4_udp(&buf[..n]) {
                let on_port = args.ports.contains(&d.dst_port) || args.ports.contains(&d.src_port);
                if on_port {
                    *seen_ports.entry(d.dst_port).or_insert(0) += 1;
                    // Both addresses go in: a request is judged on its sender, but a
                    // `401` is evidence about whoever is *receiving* it. The engine returns
                    // the subject so the block lands on the right party.
                    let (subject, dec) = engine.observe_packet(d.src, d.dst, d.payload, t);
                    // Perimeter noise condemns the source: its next packets die at XDP,
                    // before the libpcap tap, and vanish from sngrep.
                    let reason = match &dec {
                        Decision::Noise { signature } => Some(("user-agent", *signature)),
                        Decision::Injection { pattern } => Some(("injection", *pattern)),
                        Decision::AuthFailure { .. } => Some(("auth-failed", "rejected")),
                        Decision::AuthAbuse { .. } => Some(("auth-volume", "no-answer")),
                        _ => None,
                    };
                    if let (Some((kind, detail)), Some(e)) = (reason, enforcer.as_mut()) {
                        match e.block(subject, args.block_ttl) {
                            Ok(()) => {
                                println!(
                                    "BLOCKED peer={subject} reason={kind} detail={detail} ttl={}s",
                                    args.block_ttl
                                );
                                // Durable audit: the operator must be able to reconstruct
                                // the decision later, without relying on the journal.
                                if let Some(s) = db.as_ref() {
                                    s.log_block(t.0, subject, kind, detail);
                                }
                            }
                            Err(err) => eprintln!("ALARM: could not block {subject}: {err}"),
                        }
                    }
                    if args.debug_unparsed
                        && matches!(&dec, Decision::OutOfScope(r) if *r == "not SIP")
                    {
                        // Diagnostic requirement: "could not parse" has to be investigable,
                        // otherwise the counter is noise nobody knows how to read.
                        let n = d.payload.len().min(72);
                        let preview: String = d.payload[..n]
                            .iter()
                            .map(|b| {
                                if b.is_ascii_graphic() || *b == b' ' {
                                    *b as char
                                } else {
                                    '.'
                                }
                            })
                            .collect();
                        println!(
                            "NOT-SIP peer={} {}:{}->{} len={} [{preview}]",
                            d.src,
                            d.src,
                            d.src_port,
                            d.dst_port,
                            d.payload.len()
                        );
                    }
                    report(&dec, subject, args.verbose);
                }
            }
        }

        // APIBAN batches, if any. Non-blocking: it only drains what has already arrived.
        if let (Some(rx), Some(e)) = (apiban_rx.as_ref(), enforcer.as_mut()) {
            while let Ok(batch) = rx.try_recv() {
                let n = batch.ips.len();
                for ip in batch.ips {
                    // No expiry: the APIBAN list is curated, and re-applying it hourly
                    // would only generate pointless writes.
                    let _ = e.block(ip, 0);
                }
                if n > 0 {
                    apiban_total += n as u64;
                    println!("APIBAN: {n} addresses condemned (total {apiban_total})");
                }
            }
        }

        // Checkpoint: durable, never on the hot path (`SPEC.md` §10).
        if let Some(s) = db.as_mut() {
            if t.0.saturating_sub(last_checkpoint) >= args.checkpoint_every.max(30) as u32 {
                last_checkpoint = t.0;
                match s.checkpoint(&engine) {
                    Ok((p, _)) => {
                        // A 90-day audit window — more than twice the bitmap ageing
                        // window, and enough to investigate.
                        s.prune_log(t.0.saturating_sub(90 * 24 * 3600));
                        if args.verbose {
                            println!("    checkpoint: {p} pairs written");
                        }
                    }
                    Err(e) => eprintln!("ALARM: checkpoint failed — {e}"),
                }
            }
        }

        if t.0.saturating_sub(last_report) >= args.stats_every.max(1) as u32 {
            last_report = t.0;
            print_stats(&engine, &seen_ports, t, mode);
            if let Some(e) = enforcer.as_ref() {
                if e.has_own_counters() {
                    let c = e.counters();
                    println!(
                        "    XDP: dropped={} seen={} expired={} in_map={} blocked_by_us={}",
                        c.dropped,
                        c.seen,
                        c.expired,
                        e.blocked_count(),
                        e.blocked_by_us
                    );
                } else {
                    // A third-party map: the total is mostly theirs. Only what this
                    // process wrote can be claimed as ours.
                    println!(
                        "    XDP: in_map={} (shared) blocked_by_us={}",
                        e.blocked_count(),
                        e.blocked_by_us
                    );
                }
            }
            // Observability requirement: silence is an alarm, not normality.
            if engine.stats.packets == 0 && !nothing_seen_warned {
                eprintln!(
                    "ALARM: no packets seen on ports {:?} in {}s. \
                     Wrong interface, wrong port, or SIP over TLS?",
                    args.ports, args.stats_every
                );
                nothing_seen_warned = true;
            }
            // A signature that never matches is rotten and the operator needs to know —
            // exactly what fail2ban never did (`SPEC.md` §12).
            if n_ipv6 + n_tcp > 0 {
                println!("    blind spots: ipv6={n_ipv6} tcp={n_tcp} fragments={n_frag}");
                if !blind_warned {
                    eprintln!(
                        "WARNING: there is SIP this system does NOT analyse on ports {:?} — \
                         IPv6={n_ipv6}, TCP={n_tcp}. That traffic passes uninspected \
                         (SIP over TLS is structural blindness; see the README).",
                        args.ports
                    );
                    blind_warned = true;
                }
            }
            // The failure rule needs the softswitch's answer. Where none is ever seen it
            // cannot fire, and saying nothing about that would be the exact blindness this
            // project condemns in fail2ban — a rule that structurally cannot match.
            if engine.stats.auth_attempts > 0
                && engine.stats.digest_challenges == 0
                && !auth_blind_warned
            {
                eprintln!(
                    "WARNING: {} credentials presented and not one digest challenge seen on \
                     ports {:?}. \
                     Failed-authentication blocking cannot fire — only the volume backstop \
                     can. Either the softswitch answers on a path this capture does not see, \
                     or it drops these requests without challenging them.",
                    engine.stats.auth_attempts, args.ports
                );
                auth_blind_warned = true;
            }
            let total = engine.noise_filter.hits().count();
            if engine.noise_filter.cold_signatures().len() == total
                && engine.stats.sip_parsed > 1000
            {
                eprintln!(
                    "WARNING: none of the {total} user-agent signatures matched in {} \
                     SIP messages. The list may be out of date.",
                    engine.stats.sip_parsed
                );
            }
        }
    }
}

fn report(dec: &Decision, peer: Ipv4Addr, verbose: bool) {
    match dec {
        Decision::Block { country, novel_in_window } => println!(
            "BLOCK peer={peer} country={country} first_time_in_window={novel_in_window}"
        ),
        Decision::WouldBlock { country, novel_in_window } => println!(
            "WOULD BLOCK (learning) peer={peer} country={country} first_time_in_window={novel_in_window}"
        ),
        Decision::Noise { signature } if verbose => {
            println!("noise peer={peer} signature={signature}")
        }
        Decision::Injection { pattern } if verbose => {
            println!("injection peer={peer} pattern={pattern}")
        }
        Decision::AuthFailure { failures } => {
            // Always visible: a run of rejected credentials is the precursor of Chain A.
            println!("AUTH FAILURES peer={peer} rejected_credentials_in_window={failures}")
        }
        Decision::AuthAbuse { attempts } => {
            // The backstop fired, which also says the softswitch never answered.
            println!("AUTH VOLUME peer={peer} authenticated_attempts_unanswered={attempts}")
        }
        Decision::UnknownCountry(digits) => {
            // Always visible, even without -v: it is a symptom of a wrong dial plan, and a
            // wrong dial plan means international calls escaping the system entirely.
            println!("UNKNOWN COUNTRY peer={peer} digits={digits}")
        }
        Decision::Pass { country, novel } if verbose => {
            println!("pass peer={peer} country={country} first_time={novel}")
        }
        _ => {}
    }
}

fn print_stats(e: &Engine, ports: &BTreeMap<u16, u64>, t: Timestamp, mode: Mode) {
    let s = &e.stats;
    let mode_label = match mode {
        Mode::Active => "ACTIVE".to_string(),
        Mode::Learning { until } => {
            let left = until.0.saturating_sub(t.0);
            format!(
                "LEARNING ({}d {}h left)",
                left / 86400,
                (left % 86400) / 3600
            )
        }
    };
    println!(
        "--- mode={mode_label} packets={} sip={} responses={} keepalive={} not_sip={} noise={} ({}%) injection={} auth_att={} auth_fail={} auth_ok={} auth_chal={} auth_volume={} invites={} intl={} \
         unknown_country={} first_time={} blocks={} would_block={} peers={} pairs={} ports={:?}",
        s.packets,
        s.sip_parsed,
        s.responses,
        s.keepalives,
        s.not_sip,
        s.noise,
        s.noise
            .checked_mul(100)
            .and_then(|n| n.checked_div(s.sip_parsed))
            .unwrap_or(0),
        s.injections,
        s.auth_attempts,
        s.auth_failures,
        s.auth_ok,
        s.digest_challenges,
        s.auth_abuse,
        s.invites,
        s.international,
        s.unknown_country,
        s.novel,
        s.blocks,
        s.would_block,
        e.peer_count(),
        e.pair_count(),
        ports
    );
}
