//! Synthetic scenarios for the behavioural layer — no capture, no disk decisions, no
//! enforcement.
//!
//! Each scenario feeds SIP datagrams to a real `Engine`, prints the first verdict that would
//! block with the fused evidence and the counters that produced it, and writes an Ethernet
//! pcap you can open in sngrep, tcpdump or Wireshark.
//!
//! ```sh
//! cargo run --release -p tfps-core --example behaviour_scenarios
//! ```
//!
//! `blocks` is the number of `Block` **verdicts** the engine emitted. This example does not
//! enforce: production drops the source only with `--enforce-behavioural`. The pcaps are
//! written to `sim/pcaps/` at the repository root.

use std::fs::File;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use tfps_core::dialplan::DialPlan;
use tfps_core::engine::{Decision, Engine, Mode};
use tfps_core::novelty::Timestamp;

const PEER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const SWITCH: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// A real deployment timestamp, not zero: the engine uses zero as "window unset".
const BASE: u32 = 1_800_000_000;

fn t(offset: u32) -> Timestamp {
    Timestamp(BASE + offset)
}

fn invite(seq: u32, from: &str, dest: &str, auth: bool) -> Vec<u8> {
    let credential = if auth {
        "Proxy-Authorization: Digest username=\"200\", realm=\"pbx\", response=\"deadbeef\"\r\n"
    } else {
        ""
    };
    format!(
        "INVITE sip:{dest}@pbx SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK{seq}\r\n\
         From: <sip:{from}@pbx>;tag=t1\r\n\
         To: <sip:{dest}@pbx>\r\n\
         Call-ID: call-{seq}\r\n\
         CSeq: {seq} INVITE\r\n\
         {credential}\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

fn response(seq: u32, status: u16) -> Vec<u8> {
    format!(
        "SIP/2.0 {status} Whatever\r\n\
         Via: SIP/2.0/UDP 10.0.0.5;branch=z9hG4bK{seq}\r\n\
         From: <sip:200@pbx>;tag=t1\r\n\
         To: <sip:200@pbx>;tag=s1\r\n\
         Call-ID: call-{seq}\r\n\
         CSeq: {seq} INVITE\r\n\r\n"
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------------------
// pcap writer — Ethernet / IPv4 / UDP, ports 5060 -> 5060.
// ---------------------------------------------------------------------------------------

fn pcap_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sim/pcaps")
}

struct Pcap {
    file: File,
    id: u16,
}

impl Pcap {
    fn create(path: &Path) -> io::Result<Self> {
        let mut file = File::create(path)?;
        // pcap global header, little-endian, LINKTYPE_ETHERNET = 1.
        file.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
        file.write_all(&2u16.to_le_bytes())?;
        file.write_all(&4u16.to_le_bytes())?;
        file.write_all(&0i32.to_le_bytes())?;
        file.write_all(&0u32.to_le_bytes())?;
        file.write_all(&65_535u32.to_le_bytes())?;
        file.write_all(&1u32.to_le_bytes())?;
        Ok(Self { file, id: 0 })
    }

    fn write(&mut self, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8], at: u32) -> io::Result<()> {
        let frame = frame(src, dst, payload, self.id);
        self.id = self.id.wrapping_add(1);

        let mut record = Vec::with_capacity(16);
        record.extend_from_slice(&at.to_le_bytes());
        record.extend_from_slice(&0u32.to_le_bytes()); // microseconds
        record.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        record.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        self.file.write_all(&record)?;
        self.file.write_all(&frame)
    }
}

fn frame(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8], id: u16) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut f = Vec::with_capacity(14 + ip_len);

    f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // dst MAC
    f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // src MAC
    f.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    let ip_start = f.len();
    f.push(0x45); // v4, IHL 5
    f.push(0); // DSCP/ECN
    f.extend_from_slice(&(ip_len as u16).to_be_bytes());
    f.extend_from_slice(&id.to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes()); // flags/fragment
    f.push(64); // TTL
    f.push(17); // UDP
    let checksum_at = f.len();
    f.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&dst.octets());
    let checksum = checksum(&f[ip_start..ip_start + 20]);
    f[checksum_at..checksum_at + 2].copy_from_slice(&checksum.to_be_bytes());

    f.extend_from_slice(&5060u16.to_be_bytes()); // src port
    f.extend_from_slice(&5060u16.to_be_bytes()); // dst port
    f.extend_from_slice(&(udp_len as u16).to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes()); // UDP checksum optional in IPv4
    f.extend_from_slice(payload);
    f
}

fn checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ---------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Block,
    Would,
    Warming,
}

struct Harness {
    engine: Engine,
    pcap: Option<Pcap>,
    seq: u32,
    last: u32,
    invites: usize,
    first: Option<(usize, u32, Kind)>,
}

impl Harness {
    fn new(mode: Mode, plan: DialPlan) -> Self {
        // Established-source scenarios: the per-source warm-up gate is tested by `cold`.
        let mut engine = Engine::new(plan, mode).with_behavioural();
        engine.params_mut().warmup_secs = 0;
        engine.params_mut().warmup_calls = 0;
        Self {
            engine,
            pcap: None,
            seq: 0,
            last: 0,
            invites: 0,
            first: None,
        }
    }

    fn cold(mode: Mode, plan: DialPlan) -> Self {
        Self {
            engine: Engine::new(plan, mode).with_behavioural(),
            pcap: None,
            seq: 0,
            last: 0,
            invites: 0,
            first: None,
        }
    }

    fn capture(mut self, name: &str) -> Self {
        let dir = pcap_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("WARNING: could not create {}: {e}", dir.display());
            return self;
        }
        let path = dir.join(format!("{name}.pcap"));
        match Pcap::create(&path) {
            Ok(p) => self.pcap = Some(p),
            Err(e) => eprintln!("WARNING: could not write {}: {e}", path.display()),
        }
        self
    }

    fn home(&mut self, isos: &[&str]) {
        self.engine.set_home_countries(isos.iter().copied());
    }

    fn send_invite(&mut self, from: &str, dest: &str, auth: bool, at: u32) -> Decision {
        self.seq += 1;
        self.last = self.seq;
        self.invites += 1;
        let payload = invite(self.seq, from, dest, auth);
        if let Some(p) = self.pcap.as_mut() {
            if let Err(e) = p.write(PEER, SWITCH, &payload, BASE + at) {
                eprintln!("WARNING: pcap write failed: {e}");
                self.pcap = None;
            }
        }
        let (_, decision) = self.engine.observe_packet(PEER, SWITCH, &payload, t(at));
        self.record(&decision);
        decision
    }

    fn respond(&mut self, status: u16, at: u32) -> Decision {
        let payload = response(self.last, status);
        if let Some(p) = self.pcap.as_mut() {
            if let Err(e) = p.write(SWITCH, PEER, &payload, BASE + at) {
                eprintln!("WARNING: pcap write failed: {e}");
                self.pcap = None;
            }
        }
        let (_, decision) = self.engine.observe_packet(SWITCH, PEER, &payload, t(at));
        self.record(&decision);
        decision
    }

    fn exchange(&mut self, from: &str, dest: &str, auth: bool, status: u16, at: u32) -> Decision {
        self.send_invite(from, dest, auth, at);
        self.respond(status, at + 1)
    }

    fn record(&mut self, decision: &Decision) {
        let call = self.invites;
        match decision {
            Decision::Block { evidence_nats, .. } => {
                self.first
                    .get_or_insert((call, *evidence_nats, Kind::Block));
            }
            Decision::WouldBlock { evidence_nats, .. } => {
                self.first
                    .get_or_insert((call, *evidence_nats, Kind::Would));
            }
            Decision::Warming { evidence_nats, .. } => {
                self.first
                    .get_or_insert((call, *evidence_nats, Kind::Warming));
            }
            _ => {}
        }
    }

    fn fired(&self) -> bool {
        self.first.is_some()
    }

    fn row(&self, name: &str, mode: &str) {
        let (first, evidence) = match self.first {
            Some((call, evidence, Kind::Would)) => {
                (format!("call {call} WOULD BLOCK"), format!("{evidence}"))
            }
            Some((call, evidence, Kind::Warming)) => {
                (format!("call {call} WARMING"), format!("{evidence}"))
            }
            Some((call, evidence, Kind::Block)) => {
                (format!("call {call} BLOCK"), format!("{evidence}"))
            }
            None => ("-".to_string(), "-".to_string()),
        };
        let s = &self.engine.stats;
        println!(
            "{name:<36} {mode:<9} {:>6} {first:<20} {:>9} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7}",
            self.invites,
            evidence,
            s.blocks,
            s.would_block,
            s.international,
            s.range_novel,
            s.prefix_novel,
            s.intl_completed,
            s.intl_failed
        );
    }
}

fn header() {
    println!(
        "{:<36} {:<9} {:>6} {:<20} {:>9} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7}",
        "scenario",
        "mode",
        "calls",
        "first verdict",
        "evidence",
        "blocks",
        "would",
        "intl",
        "range+",
        "prefix+",
        "ok",
        "fail"
    );
    println!("{}", "-".repeat(136));
}

fn main() {
    println!("TFPS behavioural scenarios — synthetic SIP, no capture, no enforcement\n");
    header();

    // 1. Route probing with one country and one dialling format. The range arm carries it.
    let mut h =
        Harness::new(Mode::Active, DialPlan::new(["00"])).capture("route_probe_one_country");
    for i in 0..30 {
        h.send_invite("200", &format!("004420{:04}1234", i * 17), false, i * 20);
        if h.fired() {
            break;
        }
    }
    h.row("route probe: 1 country", "active");

    // 2. The same attack while rotating A-numbers: the peer is the source IP, so nothing resets.
    let mut h =
        Harness::new(Mode::Active, DialPlan::new(["00"])).capture("route_probe_a_number_rotation");
    for i in 0..20 {
        h.send_invite(
            &format!("{}", 1000 + i),
            &format!("004420{:04}1234", i * 17),
            false,
            i * 20,
        );
        if h.fired() {
            break;
        }
    }
    h.row("route probe + A-number rotation", "active");

    // 3. Discovering how to dial out: six distinct outbound formats to one destination.
    let prefixes = ["+", "00", "011", "9011", "001", "000"];
    let mut h = Harness::new(
        Mode::Active,
        DialPlan::new(["+", "00", "011", "9011", "001", "000"]),
    )
    .capture("dialling_prefix_discovery");
    for (i, prefix) in prefixes.iter().enumerate() {
        h.send_invite(
            "200",
            &format!("{prefix}442039967796"),
            false,
            i as u32 * 20,
        );
        if h.fired() {
            break;
        }
    }
    h.row("dialling-prefix discovery", "active");

    // 4. The two discovery phases at once: a new format and a new range on every call.
    let mut h = Harness::new(
        Mode::Active,
        DialPlan::new(["+", "00", "011", "9011", "001", "000"]),
    )
    .capture("prefix_range_fusion");
    for (i, prefix) in prefixes.iter().enumerate() {
        h.send_invite(
            "200",
            &format!("{prefix}4420{:04}1234", i * 17),
            false,
            i as u32 * 20,
        );
        if h.fired() {
            break;
        }
    }
    h.row("prefix + range fusion", "active");

    // 5. The AT&T signature: novel destinations, nothing completes. Both the range and
    //    completion arms reach their ten-event floors; an outage against a known range does not.
    let mut h = Harness::new(Mode::Active, DialPlan::new(["00"])).capture("failed_completions");
    for i in 0..30 {
        let dest = format!("004420{:04}1234", i * 17);
        h.exchange("200", &dest, false, 404, i * 30);
        if h.fired() {
            break;
        }
    }
    h.row("failed completions (novel)", "active");

    // 6. The same, authenticated — the case that used to starve the completion arm.
    let mut h = Harness::new(Mode::Active, DialPlan::new(["00"]))
        .capture("failed_completions_authenticated");
    for i in 0..30 {
        let dest = format!("004420{:04}1234", i * 17);
        h.exchange("200", &dest, true, 404, i * 30);
        if h.fired() {
            break;
        }
    }
    h.row("failed completions (auth)", "active");

    // 6b. A legitimate outage: failures against a destination already seen are not a probe.
    let mut h = Harness::new(Mode::Active, DialPlan::new(["00"])).capture("outage_known_range");
    for i in 0..20 {
        h.exchange("200", "00442039967796", false, 404, i * 30);
    }
    h.row("outage: known ranges", "active");

    // 6c. Premium-number discovery inside one block: a different invalid B-number each
    //     time, every one answered 404. One first-contact range, so the range arm is quiet;
    //     the completion arm counts each new number that does not exist.
    let mut h = Harness::new(Mode::Active, DialPlan::new(["00"])).capture("number_probe_one_range");
    for i in 0..30 {
        h.exchange("200", &format!("0044207946{i:04}"), false, 404, i * 20);
        if h.fired() {
            break;
        }
    }
    h.row("number probe: one range (404)", "active");

    // 6d. Refusals across new ranges: the PBX is not allowed to dial there, and the source
    //     keeps trying new destinations anyway.
    let mut h = Harness::new(Mode::Active, DialPlan::new(["00"])).capture("refused_new_ranges");
    for i in 0..30 {
        let dest = format!("00{}12345678", 30 + i);
        h.exchange("200", &dest, false, 403, i * 30);
        if h.fired() {
            break;
        }
    }
    h.row("refused: new ranges (403)", "active");

    // 6e. People not answering: busy, no answer, cancelled. A person was rung each time.
    let mut h = Harness::new(Mode::Active, DialPlan::new(["00"])).capture("unanswered_calls");
    for i in 0..40u32 {
        let status = [486, 480, 487, 603][i as usize % 4];
        h.exchange(
            "200",
            &format!("00442079460{:03}", i % 6),
            false,
            status,
            i * 30,
        );
    }
    h.row("legit: busy / no answer", "active");

    // 7. Exploitation: build six scoring periods of history, then 300 calls in an hour.
    let mut h =
        Harness::new(Mode::Active, DialPlan::new(["00"])).capture("volume_spike_300_per_hour");
    for i in 0..7 {
        h.exchange("200", "00442039967796", false, 200, i * 3600);
    }
    for i in 0..300 {
        h.send_invite("200", "00442039967796", false, 7 * 3600 + i);
    }
    h.send_invite("200", "00442039967796", false, 8 * 3600 + 1);
    h.row("volume spike (300/hour)", "active");

    // 8. The same route probe, but still in the learning window: a verdict, not a block.
    let mut h = Harness::new(
        Mode::Learning {
            until: t(30 * 24 * 3600),
        },
        DialPlan::new(["00"]),
    )
    .capture("learning_route_probe");
    for i in 0..30 {
        h.send_invite("200", &format!("004420{:04}1234", i * 17), false, i * 20);
        if h.fired() {
            break;
        }
    }
    h.row("route probe (learning)", "learning");

    // 8b. The same route probe on a brand-new source: WARMING, not BLOCK.
    let mut h = Harness::cold(Mode::Active, DialPlan::new(["00"]))
        .capture("route_probe_new_source_warming");
    for i in 0..30 {
        h.send_invite("200", &format!("004420{:04}1234", i * 17), false, i * 20);
        if h.fired() {
            break;
        }
    }
    h.row("route probe (new source)", "active");

    // 9. A legitimate source: one new range per hour, every call answers.
    let mut h =
        Harness::new(Mode::Active, DialPlan::new(["00"])).capture("legit_new_range_per_hour");
    for i in 0..8 {
        h.exchange(
            "200",
            &format!("004420{:04}1234", i * 17),
            false,
            200,
            i * 3600,
        );
    }
    h.row("legit: new range per hour", "active");

    // 10. Paced novelty: two ranges, repeated, inside one window. No accumulation.
    let mut h =
        Harness::new(Mode::Active, DialPlan::new(["00"])).capture("paced_novelty_two_ranges");
    for i in 0..12 {
        let range = i % 2;
        h.send_invite("200", &format!("00442000{range}1234"), false, i * 60);
    }
    h.row("paced novelty (2 ranges)", "active");

    // Non-events: shaped like traffic, but never a behavioural verdict.
    println!("\nnot judged as international fraud");

    let mut h = Harness::new(Mode::Active, DialPlan::new(["00"])).capture("domestic_extension");
    let d = h.send_invite("200", "2005", false, 0);
    println!("  domestic extension                 {d:?}");

    let mut h = Harness::new(Mode::Active, DialPlan::new(["00"])).capture("home_country_did");
    h.home(&["BR"]);
    let d = h.send_invite("200", "00551199998888", false, 0);
    println!("  home-country E.164 DID             {d:?}");

    let mut h = Harness::new(Mode::Active, DialPlan::new(["00"])).capture("unknown_country");
    let d = h.send_invite("200", "00999123456", false, 0);
    println!("  international, unknown country     {d:?}");

    let dir = std::fs::canonicalize(pcap_dir()).unwrap_or_else(|_| pcap_dir());
    println!(
        "\nblocks counts Block verdicts. Production writes one into XDP only with --enforce-behavioural."
    );
    println!("pcaps: {}", dir.display());
}
