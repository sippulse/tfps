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

use tfps::{apiban, config, say, store, xdp};

use std::collections::BTreeMap;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, Socket, Type};
use tfps_core::dialplan::DialPlan;
use tfps_core::engine::{Decision, Engine, Mode};
use tfps_core::ignore::IgnoreList;
use tfps_core::net::{classify_other, parse_ipv4_udp, tcp_ports, NotUdp};
use tfps_core::novelty::Timestamp;

/// Where the APIBAN resume point is kept between runs.
const APIBAN_ID_KEY: &str = "apiban_id";

/// How long a feed address stays applied. APIBAN is a rolling list of hotspots, not a
/// permanent verdict, and an address that left the feed a week ago has probably been
/// cleaned up or reassigned.
const APIBAN_RETENTION_SECS: u32 = 7 * 24 * 3600;

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
    behavioural: bool,
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
    ignoreip: Vec<String>,
    home_countries: Vec<String>,
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
            behavioural: false,
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
            ignoreip: Vec::new(),
            home_countries: Vec::new(),
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
      --ignoreip CIDR      never enforce against this address or network (repeatable)
      --home-country ISO   your own country, not treated as international (repeatable)
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
                say!("{}", usage().trim_end());
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
            "--behavioural" | "--fraud" => a.behavioural = true,
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
            "--ignoreip" => a.ignoreip.push(next("--ignoreip")?),
            "--home-country" => a.home_countries.push(next("--home-country")?),
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
    // The file adds to the command line here rather than replacing it: both are the
    // operator's own words, and dropping either would be a surprise.
    a.ignoreip.extend(c.ignoreip.iter().cloned());
    a.home_countries.extend(c.home_countries.iter().cloned());
    if !a.given.contains("--apiban-key") && c.apiban_key.is_some() {
        a.apiban_key = c.apiban_key.clone();
    }
    if !a.given.contains("--learn-days") && !a.given.contains("--active") {
        if let Some(d) = c.learn_days {
            a.learn_secs = d.saturating_mul(24 * 3600);
        }
        if c.behavioural {
            a.behavioural = true;
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
            say!("  configuration     : {}", path.display());
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
    if args.behavioural {
        engine = engine.with_behavioural();
    }
    let unknown_home = engine.set_home_countries(args.home_countries.iter().map(String::as_str));
    for iso in &unknown_home {
        eprintln!("WARNING: home country \"{iso}\" is not a known ISO label — ignored");
    }

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
        say!("  declared plans    : {} peers", args.peer_plans.len());
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
                say!(
                    "  extra signatures  : {ua} user-agent, {inj} injection ({})",
                    path.display()
                );
            }
            Err(e) => eprintln!("WARNING: could not read {}: {e}", path.display()),
        }
    }
    let (ua_int, ua_ext) = engine.noise_filter.signature_count();
    let (inj_int, inj_ext) = engine.noise_filter.injection_count();

    if engine.behavioural_enabled() {
        if let Some(d) = db.as_ref() {
            match d.load_into(&mut engine) {
                Ok((p, c)) if p > 0 || c > 0 => {
                    say!("  state restored    : {p} pairs, {c} peer-country rows");
                }
                Ok(_) => say!("  state restored    : empty database (first run)"),
                Err(e) => eprintln!("WARNING: could not restore state: {e}"),
            }
        }
    }

    say!("tfps {} — starting", env!("CARGO_PKG_VERSION"));
    say!("  watched ports     : {:?}", args.ports);
    say!("  intl prefixes     : {:?}", args.intl_prefixes);
    // The behavioural layer only reasons about *international* destinations, and the
    // international prefixes are how it tells one from an internal extension or an inbound
    // call to an E.164 DID. Wrong prefixes mean the wrong calls are judged — so with
    // behavioural on, make the operator confirm them rather than trust a default.
    if engine.behavioural_enabled() {
        say!(
            "  ATTENTION         : behavioural detection reasons only about INTERNATIONAL \
             calls. Configure `intl_prefixes` (globally and per peer) for THIS installation \
             — it is how extensions and inbound E.164 DIDs are told apart from real \
             outbound international destinations. Defaults are a starting point, not a fit."
        );
        if engine.home_country_count() == 0 {
            say!(
                "  RECOMMENDED       : set `home_countries` (e.g. [\"BR\"]) so calls to your \
                 own country are treated as national, not international."
            );
        } else {
            say!(
                "  home countries    : {} configured (national, not international)",
                engine.home_country_count()
            );
        }
        say!(
            "  RECOMMENDED       : add your INBOUND gateway IPs to `ignoreip` — they deliver \
             calls to your internal destinations and should never be judged or blocked."
        );
    }
    if !engine.behavioural_enabled() {
        say!("  mode              : NOISE REDUCTION (perimeter only; --behavioural adds fraud detection)");
    } else {
        match mode {
            // The mode is announced loudly and repeated: this project's difference from
            // fail2ban is that the incumbent fails silently (`SPEC.md` §12).
            Mode::Active => say!("  mode              : FRAUD DETECTION, ACTIVE — would block right away"),
            Mode::Learning { until } => say!(
                "  mode              : FRAUD DETECTION, LEARNING for {} days (until {}), does NOT block",
                args.learn_secs / 86400,
                until.0
            ),
        }
    }
    // Enforcement: load XDP, or say so loudly and carry on observing. Never pretend.
    let mut enforcer = if args.no_enforce {
        say!("  enforcement       : OFF via --no-enforce (observe only)");
        None
    } else {
        let iface = args
            .iface
            .clone()
            .or_else(xdp::default_interface)
            .unwrap_or_else(|| "eth0".to_string());
        match xdp::Enforcer::attach(&args.shared_map, &args.xdp_obj, &iface, &args.ports) {
            Ok(e) => {
                say!(
                    "  enforcement       : {} — garbage vanishes from sngrep",
                    e.mode
                );
                say!("  block expires in  : {}s", args.block_ttl);
                Some(e)
            }
            Err(err) => {
                // SPEC §12 requirement: an anti-fraud system that appears to protect
                // without protecting is exactly this project's criticism of the incumbent.
                eprintln!("ALARM: enforcement INACTIVE — {err}");
                eprintln!("       the system will OBSERVE but will NOT block anything.");
                say!("  enforcement       : INACTIVE (see the alarm above)");
                None
            }
        }
    };
    say!(
        "  perimeter         : {ua_int} user-agents (+{ua_ext} from file), \
         {inj_int} injection patterns (+{inj_ext})"
    );

    // Never condemn the machine we are defending. This is not configurable, because the
    // one time it happened during development it was a test firing from the host itself —
    // and no operator would have guessed to switch it on beforehand.
    let mut ignoreip = IgnoreList::new();
    let local = xdp::local_addresses();
    for ip in &local {
        ignoreip.add_local(*ip);
    }
    for entry in &args.ignoreip {
        // A refused entry is announced, never dropped quietly: an operator who believes a
        // range is exempt when it is not would draw exactly the wrong conclusion from a
        // block.
        if let Err(e) = ignoreip.add(entry) {
            eprintln!("ALARM: ignoreip entry rejected — {e}");
        }
    }
    // §12 requires the operator to see which rules exist, not just how many.
    say!(
        "  ignoreip          : {} local, {} declared",
        ignoreip.len() - ignoreip.declared(),
        ignoreip.declared()
    );
    for (label, origin, _) in ignoreip.report() {
        let kind = match origin {
            tfps_core::ignore::Origin::Local => "this host",
            tfps_core::ignore::Origin::Declared => "declared",
        };
        say!("                      {label} ({kind})");
    }

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
        // Resume where the last run stopped. Without this the whole feed is refetched on
        // every restart — the module documents the resume, so not wiring it up would have
        // been a promise kept only in a comment.
        let resume = db.as_ref().and_then(|s| s.meta_get(APIBAN_ID_KEY));
        match &resume {
            Some(id) => say!("  APIBAN            : enabled, resuming from id {id}"),
            None => say!("  APIBAN            : enabled, first sync (whole feed)"),
        }
        apiban::spawn(k.clone(), resume)
    });

    // Re-apply what the feed already gave us. The map died with the previous process and
    // the feed cursor only moves forward, so without this the integration would come back
    // up protecting nothing — and would look perfectly healthy while doing it.
    let mut apiban_total = 0u64;
    if args.apiban_key.is_some() {
        if let (Some(s), Some(e)) = (db.as_ref(), enforcer.as_mut()) {
            match s.apiban_since(start.0.saturating_sub(APIBAN_RETENTION_SECS)) {
                Ok(ips) => {
                    let (mut restored, mut failed) = (0u64, 0u64);
                    for ip in ips {
                        if ignoreip.exempt(ip).is_some() {
                            continue;
                        }
                        match e.block(ip, 0) {
                            Ok(()) => restored += 1,
                            // Announcing a restore that did not happen would leave the
                            // operator believing in protection that is not there.
                            Err(_) => failed += 1,
                        }
                    }
                    apiban_total = restored;
                    if restored > 0 {
                        say!("  APIBAN restored   : {restored} addresses from the last 7 days");
                    }
                    if failed > 0 {
                        eprintln!("ALARM: {failed} APIBAN addresses could not be restored");
                    }
                }
                Err(err) => eprintln!("WARNING: could not restore the APIBAN list: {err}"),
            }
        }
    }

    let mut nothing_seen_warned = false;
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
                    let exempt = reason.and_then(|_| ignoreip.exempt(subject).map(str::to_string));
                    if let (Some((kind, detail)), Some(rule)) = (reason, exempt) {
                        // Judged, reported, not enforced. Staying silent here would hide a
                        // compromised trusted peer, which is when it matters most.
                        say!("EXEMPT peer={subject} reason={kind} detail={detail} ignoreip={rule}");
                    } else if let (Some((kind, detail)), Some(e)) = (reason, enforcer.as_mut()) {
                        match e.block(subject, args.block_ttl) {
                            Ok(()) => {
                                say!(
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
                        say!(
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
                let mut n = batch.ips.len();
                // Persist the resume point before the addresses: refetching a batch is
                // harmless, whereas losing the id means starting the feed over.
                if let (Some(id), Some(s)) = (&batch.next_id, db.as_ref()) {
                    s.meta_set(APIBAN_ID_KEY, id);
                }
                if let Some(s) = db.as_mut() {
                    if let Err(err) = s.apiban_add(&batch.ips, t.0) {
                        eprintln!("WARNING: could not persist the APIBAN batch: {err}");
                    }
                }
                for ip in batch.ips {
                    // A third-party feed listing your own range is exactly what the ignore
                    // list is for: it is curated, but it is not yours.
                    if let Some(rule) = ignoreip.exempt(ip) {
                        say!("APIBAN: {ip} not blocked, ignoreip={rule}");
                        // Counted out as well as skipped: reporting it as condemned would
                        // overstate what the feed actually did.
                        n -= 1;
                        continue;
                    }
                    // No expiry: the APIBAN list is curated, and re-applying it hourly
                    // would only generate pointless writes.
                    let _ = e.block(ip, 0);
                }
                if n > 0 {
                    apiban_total += n as u64;
                    say!("APIBAN: {n} addresses condemned (total {apiban_total})");
                }
            }
        }

        // Checkpoint: durable, never on the hot path (`SPEC.md` §10).
        if let Some(s) = db.as_mut() {
            if t.0.saturating_sub(last_checkpoint) >= args.checkpoint_every.max(30) as u32 {
                last_checkpoint = t.0;
                // The control tool runs in another process and cannot read these
                // counters from memory. Writing them at checkpoint is what lets
                // `tfps_ctl stats` show the whole picture instead of only the kernel half.
                s.meta_set("stats", &counter_line(&engine.stats));
                s.meta_set("stats_ts", &t.0.to_string());
                s.meta_set("started_at", &start.0.to_string());
                s.meta_set(
                    "ignoreip",
                    &ignoreip
                        .report()
                        .map(|(label, _, hits)| format!("{label}={hits}"))
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                // A 90-day audit window for the block log, and the APIBAN retention prune;
                // both apply whether or not behavioural detection is on.
                s.prune_log(t.0.saturating_sub(90 * 24 * 3600));
                s.apiban_prune(t.0.saturating_sub(APIBAN_RETENTION_SECS));
                // Only the behavioural layer has learned state worth persisting.
                if engine.behavioural_enabled() {
                    // Refit the benign hypotheses and the volume prior from the traffic seen
                    // so far, then persist. This is the self-calibration: the operator tunes
                    // error rates, never the traffic constants.
                    engine.recalibrate();
                    let p = engine.params();
                    s.meta_set(
                        "calibration",
                        &format!(
                            "theta0_prefix={:.3} theta0c={:.3} prior_mean={:.2}",
                            p.theta0_prefix, p.theta0c, p.prior_mean
                        ),
                    );
                    match s.checkpoint(&engine) {
                        Ok((n, _)) if args.verbose => say!("    checkpoint: {n} sources written"),
                        Ok(_) => {}
                        Err(e) => eprintln!("ALARM: checkpoint failed — {e}"),
                    }
                }
            }
        }

        if t.0.saturating_sub(last_report) >= args.stats_every.max(1) as u32 {
            last_report = t.0;
            print_stats(&engine, &seen_ports, t, mode);
            if let Some(e) = enforcer.as_ref() {
                if e.has_own_counters() {
                    let c = e.counters();
                    say!(
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
                    say!(
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
                say!("    blind spots: ipv6={n_ipv6} tcp={n_tcp} fragments={n_frag}");
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
            // §12.4: a rule that matches zero must be reportable. An exemption is a rule,
            // and a stale one is worse than a stale signature — it is a hole somebody
            // opened deliberately and then forgot.
            let cold = ignoreip.cold();
            if ignoreip.total_hits() > 0 || !cold.is_empty() {
                say!(
                    "    ignoreip: {} exemption(s) applied{}",
                    ignoreip.total_hits(),
                    if cold.is_empty() {
                        String::new()
                    } else {
                        format!(", never matched: {}", cold.join(" "))
                    }
                );
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
        Decision::Block { country, bits, countries } => say!(
            "BLOCK peer={peer} country={country} evidence={bits}bits distinct_countries={countries}"
        ),
        Decision::WouldBlock { country, bits, countries } => say!(
            "WOULD BLOCK (learning) peer={peer} country={country} evidence={bits}bits distinct_countries={countries}"
        ),
        Decision::Noise { signature } if verbose => {
            say!("noise peer={peer} signature={signature}")
        }
        Decision::Injection { pattern } if verbose => {
            say!("injection peer={peer} pattern={pattern}")
        }
        Decision::AuthFailure { failures } => {
            // Always visible: a run of rejected credentials is the precursor of Chain A.
            say!("AUTH FAILURES peer={peer} rejected_credentials_in_window={failures}")
        }
        Decision::AuthAbuse { attempts } => {
            // The backstop fired, which also says the softswitch never answered.
            say!("AUTH VOLUME peer={peer} authenticated_attempts_unanswered={attempts}")
        }
        Decision::UnknownCountry(digits) => {
            // Always visible, even without -v: it is a symptom of a wrong dial plan, and a
            // wrong dial plan means international calls escaping the system entirely.
            say!("UNKNOWN COUNTRY peer={peer} digits={digits}")
        }
        Decision::Pass { country, novel } if verbose => {
            say!("pass peer={peer} country={country} first_time={novel}")
        }
        _ => {}
    }
}

/// The userspace counters as `key=value` pairs, for the database.
///
/// Hand-rolled rather than serialised: the reader is one function in `tfps_ctl`, the format
/// is greppable by eye in `sqlite3`, and a new counter costs one line here.
fn counter_line(s: &tfps_core::engine::Stats) -> String {
    [
        ("packets", s.packets),
        ("sip", s.sip_parsed),
        ("responses", s.responses),
        ("keepalive", s.keepalives),
        ("not_sip", s.not_sip),
        ("noise", s.noise),
        ("injection", s.injections),
        ("auth_att", s.auth_attempts),
        ("auth_fail", s.auth_failures),
        ("auth_ok", s.auth_ok),
        ("auth_chal", s.digest_challenges),
        ("intl_ok", s.intl_completed),
        ("intl_fail", s.intl_failed),
        ("auth_volume", s.auth_abuse),
        ("invites", s.invites),
        ("intl", s.international),
        ("unknown_country", s.unknown_country),
        ("first_time", s.novel),
        ("blocks", s.blocks),
        ("would_block", s.would_block),
        ("pairs_dropped", s.pairs_dropped),
        ("peers_dropped", s.peers_dropped),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={v}"))
    .collect::<Vec<_>>()
    .join(" ")
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
    say!(
        "--- mode={mode_label} packets={} sip={} responses={} keepalive={} not_sip={} noise={} ({}%) injection={} auth_att={} auth_fail={} auth_ok={} auth_chal={} auth_volume={} intl_ok={} intl_fail={} invites={} intl={} \
         unknown_country={} first_time={} blocks={} would_block={} sources={} ports={:?}",
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
        s.intl_completed,
        s.intl_failed,
        s.invites,
        s.international,
        s.unknown_country,
        s.novel,
        s.blocks,
        s.would_block,
        e.source_count(),
        ports
    );
}
