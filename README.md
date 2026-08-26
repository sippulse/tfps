# TFPS

**Telephony Fraud Prevention System** — IRSF fraud prevention for SIP networks.

Watches traffic on the wire, learns what normal looks like for each source, and drops the
garbage in the kernel before it ever reaches your `sngrep`.

No policy configuration. No cloud. No fraud list. One static binary.

---

## The garbage disappears from sngrep

This is what the product delivers today, and it works because of one specific ordering
inside the Linux kernel:

```
NIC → driver → XDP ← TFPS drops here
                 ↓
            sk_buff → ptype_all ← libpcap hooks here (sngrep, tcpdump, tshark)
                        ↓
                    netfilter ← iptables and nftables act here
```

A packet dropped at **XDP never reaches the libpcap tap**. That is why `nftables` would not
work for this purpose: its drop happens later, and your capture would still be polluted.

**Verified in production**: with 959 sources blocked, 40 seconds of `tcpdump` filtered to
six of them captured **zero** packets, against 5 in the control window.

It is not hermetic — one packet slipped through in a 90 s test. What the data supports is a
drastic reduction, not perfect blocking.

---

## Status — v0.1.0

| done | missing |
|---|---|
| `AF_PACKET` capture, no port bind | forged `603` for the fraud verdict |
| XDP enforcement (native or generic) | peer prior for a brand-new pair |
| perimeter: user-agent, injection, brute force | learning the dial plan in parallel |
| optional APIBAN integration | call duration via `BYE` |
| SIP parsing: request, response, keepalive | local honeypot |
| dial plan as a prefix list | IPv6 and SIP over TCP |
| destination country (240 E.164 codes) | day-31 confirmation |
| per-pair novelty with a rotating bitmap | |
| SQLite persistence | |
| memory ceilings with automatic pruning | |

**Today it filters noise and learns. It does not block fraud yet** — the behavioural layer
observes for 30 days before acting, and the fraud verdict is not enforced.

---

## How it decides

```
packet on a watched port
   │
   ├─ known scanner user-agent?             ──► condemn the source, gone from sngrep
   ├─ injection in the URI (' -- %27 ?=?)?  ──► condemn the source, gone from sngrep
   ├─ credential brute force?               ──► condemn the source, gone from sngrep
   │
   ├─ matches an international prefix? ──► NO: out of scope, pass. Done.
   │                                        (this is where most traffic leaves)
   ├─ strip, canonicalise, resolve country
   │
   └─ country never seen for this (peer, A-number) pair?
         ├─ NO  ──► pass
         └─ YES ──► how many first-time countries in the last hour?
                      ├─ < 10 ──► pass
                      └─ ≥ 10 ──► block
```

**A single new country never fires.** A first-time country happens on 0.85% of calls;
blocking that would block 0.85% of everyone's international traffic. The signal is
**accumulation**, not a single event — ten first-time countries within an hour fired 4
times across 2,829 account-days in the measurement that produced the rule.

### The perimeter does not exist to catch fraud

It exists to **keep garbage out of the behavioural baseline**. If scanning feeds an
account's baseline, the model learns that a burst to a strange destination is normal there,
and the defence poisons itself.

Three families, at different confidence levels:

- **Tool user-agents** (18 signatures: `sipcli`, `friendly`, `sipvicious`, `pplsip`,
  `sipscan`, `Nmap NSE`…). Weak as *detection* — a competent attacker forges a legitimate
  UA. Adequate as a **volume filter**, because lazy scanners with default UAs are most of
  the packets.
- **URI injection** (`'`, `%27`, `--`, `%24`, `%60`, `==`, `?=?`, `union`, `select`, and
  `;` inside the user part). **Higher** confidence: no real phone puts a single quote in
  the `From` header.
- **Credential brute force** — 20 authenticated attempts in 60 s.

### What is *not* counted as brute force

**A bare `401` means nothing.** The digest challenge is the normal flow: every legitimate
`REGISTER` gets a `401` with a nonce before resending with `Authorization`. Counting
challenges would block all of your customers within a minute.

What is counted is a **`REGISTER` carrying `Authorization`** — an actual password attempt.
A legitimate phone sends one per registration cycle (typically every 300 s); someone
testing credentials sends many per second. No response correlation, no dialog state.

Measured on the reference server: **2 challenges in 45 s** of legitimate traffic. A
threshold of 20/min leaves roughly 7× headroom. **Caveat**: a large NAT aggregates many
phones behind one IP and could approach the threshold — the same limitation `fail2ban` has,
and precisely why the block is temporary.

---

## Configuration — `/etc/tfps/config.json`

**Every field is optional and the system works without the file.** What lives here is
**installation** configuration — where to look, how to read the numbers — plus optional
integrations. Never **policy** configuration, which would say what fraud is.

```json
{
  "ports": [5060, 5061],
  "intl_prefixes": ["+", "00", "011", "9011"],

  "peers": {
    "10.0.0.5":    { "intl_prefixes": ["9011", "011"] },
    "203.0.113.7": { "bare_e164": true }
  },

  "signatures": ["MyLocalScanner", "=sipsak"],
  "injection": ["xp_cmdshell"],

  "apiban_key": "optional-key",

  "learn_days": 30,
  "block_ttl": 3600,
  "stats_every": 120,
  "checkpoint_every": 300,
  "iface": "eth0",
  "db": "/var/lib/tfps/tfps.db"
}
```

Precedence: **command line > file > built-in default**, so you can debug in production
without editing a file.

An **unknown field is an error**, not silence: an `apiban_kei` quietly ignored would make
you believe you enabled APIBAN when you did not. The same applies to malformed JSON and to
an invalid peer IP — all of it becomes a startup alarm.

### `peers` — the dial plan per PBX

Declaring beats learning because it holds on that peer's **very first** call instead of
waiting for convergence. And the weight is large: **20.3% of destinations do not resolve to
a country** without correct prefix stripping, and country is the only behavioural feature
that survived measurement.

`bare_e164` says the PBX sends plain E.164 with no prefix — common in wholesale. It is an
explicit field rather than an empty prefix because the semantics are dangerous: with it on,
`2125551234` is Morocco; with it off, it is a domestic US number.

Dial-plan learning keeps running in parallel, and disagreement becomes an alarm.

### `signatures` and `injection` — they add, never replace

The seeds are **compiled into the binary** and work with no file at all. What you list is
**added** to the 18 built-in user-agents and 11 built-in patterns.

Replacing would make someone who writes three lines silently lose the built-ins — exactly
the failure mode this project condemns. Prefix match by default; `=text` matches exactly
(the equivalent of `^…$`).

Startup reports how many came from each side, and the system warns when no signature has
matched after thousands of messages: a signature that never fires is rotten.

### `apiban_key` — optional integration

The collaborative [APIBAN](https://apiban.org) list, fed by honeypots. It runs on a
**separate thread** and delivers over a channel: HTTP never touches the packet path.

That is exactly where the 2023 TFPS died — a **synchronous `rest_get()` per INVITE**, with
no cache and 4 workers: a ceiling of ~26 INVITEs/s, and any apiban.org outage froze the
decision for every call. Here, if the network drops, the system carries on with the list it
already has.

---

## Building

```sh
cargo test                                                   # 81 tests
cargo build --release --target x86_64-unknown-linux-musl
```

The musl target produces a **~4.4 MB static binary** with no glibc dependency — it runs on
Debian 12, Ubuntu 24.04 and whatever comes next. This solved a real case: the build machine
had glibc 2.39 and the server 2.36, and glibc is not forward compatible.

SQLite is compiled in, which needs a C compiler that can target musl. If you do not have
`musl-tools`, [zig](https://ziglang.org) works and needs no root:

```sh
export CC_x86_64_unknown_linux_musl="zig cc -target x86_64-linux-musl"
export AR_x86_64_unknown_linux_musl="zig ar"
```

### The XDP program

Written in C (`ebpf/tfps_xdp.c`) because only the kernel side needs LLVM — keeping it in C
avoids requiring `bpf-linker` on the development machine. Compile it on the target:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c tfps_xdp.c -o /usr/local/lib/tfps/tfps_xdp.o
```

Requires kernel **≥ 5.15** with BTF. Tested on 6.1.

---

## Installing and running

```sh
scp target/x86_64-unknown-linux-musl/release/tfps root@server:/usr/local/bin/
tfps
```

It works with no arguments at all, on built-in defaults. To fit your installation, write
`/etc/tfps/config.json` — see the configuration section above.

Capture is `AF_PACKET`/`SOCK_DGRAM`: it hooks at the netdev layer and **does not open a UDP
socket**, so your softswitch keeps its own bind and never notices. Nothing needs
reconfiguring.

Needs `CAP_NET_RAW` (capture), plus `CAP_BPF` and `CAP_NET_ADMIN` (XDP).

| flag | effect |
|---|---|
| `--config PATH` | configuration (default `/etc/tfps/config.json`) |
| `--ports 5060,5080` | SIP ports to watch (default `5060`) |
| `--intl +,00,011,9011` | international dialling prefixes |
| `--learn-days N` | days observing without blocking fraud (default `30`) |
| `--active` | skip the learning period |
| `--iface eth0` | XDP interface (default: the default-route one) |
| `--xdp-obj PATH` | BPF object (default `/usr/local/lib/tfps/tfps_xdp.o`) |
| `--drop-map PATH` | use a drop map already pinned by another product |
| `--block-ttl N` | seconds a block lasts (default `3600`; `0` = never expires) |
| `--no-enforce` | observe only, do not touch XDP |
| `--db PATH` | SQLite database (default `/var/lib/tfps/tfps.db`) |
| `--no-db` | do not persist — learning dies on restart |
| `--apiban-key KEY` | enable APIBAN, in the background |
| `--signatures PATH` | extra signature file, on top of `config.json` |
| `--stats-every N` | seconds between reports (default `60`) |
| `-v` | print every international attempt |
| `--debug-unparsed` | show payloads that failed to parse |

### Sharing the hook with something else

Only **one** XDP program fits per interface. If a drop map is already pinned, point
`--drop-map` at it and TFPS writes into that map instead of fighting for the hook.

**Mind the blast radius**: the TFPS program drops only SIP ports, so an IP behind CGNAT does
not lose web and SSH because of a scanner sharing the address. A third-party map may have a
broader policy, and then the blast radius becomes theirs.

---

## Reading the report

```
--- mode=LEARNING (29d 23h left) packets=330 sip=98 responses=0 keepalive=232
    not_sip=0 noise=12 (12%) injection=0 auth_att=142 auth_abuse=1 invites=62
    intl=62 unknown_country=20 first_time=21 blocks=0 would_block=0
    peers=3 pairs=14 ports={5060: 330}
    XDP: dropped=1840 seen=2100 expired=3 in_map=7 blocked_by_us=7
```

| field | meaning |
|---|---|
| `mode` | learning (does not block fraud) or active |
| `keepalive` | NAT CRLF pings (RFC 5626) — on a residential 5060 these are most packets |
| `not_sip` | unclassified. **Should be ~0**; high means something is not understood |
| `noise (%)` | how much the perimeter removed — the number that measures a clean sngrep |
| `unknown_country` | international by shape, no recognisable country: a symptom of a wrong dial plan, and in practice it also catches prefix-padding evasion |
| `first_time` | country debuts; the measured reference is 0.85% of calls |
| `auth_att` | authenticated attempts seen (the denominator for brute force) |
| `auth_abuse` | sources condemned for brute force |
| `would_block` | would have blocked if it were not still learning |
| `blocked_by_us` | sources **this** process condemned |

### Silence is an alarm, not normality

This project's argument against `fail2ban` is that **the incumbent fails silently** — the
Asterisk security channel ships disabled, PJSIP does not log below 5 requests in 5 s, and no
version of fail2ban has ever warned about a filter matching zero lines.

Repeating that would forfeit the difference. So TFPS complains when it:

- stops seeing traffic on the watched ports;
- sees SIP over paths it does not analyse (IPv6, TCP);
- cannot load or attach XDP — and says it **will not block anything**;
- cannot persist — and says learning will die on restart;
- has matched no user-agent signature after thousands of messages.

---

## Persistence

A single SQLite file. No server, no daemon, no credentials, no port.

```sh
sqlite3 /var/lib/tfps/tfps.db "select * from block_log order by ts desc limit 20"
```

It stores the per-pair country bitmap, per-peer country frequencies, the block log, and —
most importantly — **when learning started**. Without that, every restart would reset the 30
days and the countdown would promise something a `systemctl restart` erases.

It is **durable storage, not the hot path**: the working set lives in memory, loaded at boot
and checkpointed every 5 minutes. Querying SQL per INVITE would be the bottleneck.

---

## Memory ceilings

Rotating the A-number is expected attacker behaviour. Without a ceiling the system would
answer that by allocating until it dies — a denial-of-service vector described in its own
specification.

Ceilings of **50,000 pairs per peer** and **10,000 peers**. When full, the system prunes
pairs not seen in the last hour: the signature of rotation is appearing once and never
again, so the ephemeral ones go and the ones that come back stay.

---

## What it does not do

**It never blocks because it failed to canonicalise.** That was `R07` in the 2014 TFPS,
which denied everything it could not classify and became 39% of all rejections — the
system's largest source of blocking was ignorance, not detection. Internal extensions,
service codes and SIP URIs are not this system's business and pass through.

**It cannot see SIP over TLS.** Cryptographic blindness, no workaround. IP-reputation
enforcement still works, because metadata stays visible.

**It does not see IPv6 or SIP over TCP** — but it warns when they show up.

**It does not cover customers with a broad international profile.** Against someone already
calling dozens of countries daily, novelty saturates by construction and no behavioural
signal fires.

**No promises to anyone who downloads it.**

---

## Documentation

- [`SPEC.md`](SPEC.md) — the architecture and the decisions, with the reasoning behind each
- [`DETECTION.md`](DETECTION.md) — how a packet is examined: every test, in the order the code applies them
- [`CONTEXT.md`](CONTEXT.md) — the vocabulary, normative for code and documentation

## License

Apache-2.0.
