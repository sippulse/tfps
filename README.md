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
- **Failed authentication** — 5 rejected credentials in 10 minutes, with a volume backstop
  of 20 authenticated attempts in 60 s for softswitches that never answer.

### What counts as a failed authentication, and what does not

**A bare `401` means nothing.** The digest challenge is the normal flow: every legitimate
`REGISTER` gets a `401` with a nonce before resending with `Authorization`. Counting
challenges would block all of your customers within a minute.

What counts is a **request that carried a credential and was answered `401`/`407` anyway**:

```
REGISTER (no Authorization)  →  401 + nonce        the normal handshake, ignored
REGISTER (Authorization)     →  200 OK             accepted — the slate is wiped
REGISTER (Authorization)     →  401 again          a rejected password. This is the signal.
```

Five rejections in ten minutes condemn the source — the `maxretry`/`findtime` defaults of
the `fail2ban` Asterisk jail, deliberately, since that threshold has a decade of field use
behind it. The difference is where the evidence comes from: **the wire, immediately**,
instead of a log file the softswitch may not be writing. The method is irrelevant —
`REGISTER` is where a password is stolen and `INVITE` is where it is spent, and both are
challenged the same way.

Requests are matched to their responses by the `Via` branch (RFC 3261 §17.1.3), falling
back to `Call-ID` + `CSeq`. `CSeq` is part of the key on purpose: a client retrying a
password keeps one `Call-ID` and increments `CSeq`, so keying on `Call-ID` alone would
collapse a whole guessing run into one countable failure. A retransmitted `401` counts
once. An accepted credential clears the count, so someone who fixes a mistyped password is
not blocked by their next slip.

Because it is failures and not volume, **a large NAT is not a problem**: a hundred phones
behind one address all succeed, and successes do not accumulate.

### APIBAN

Set `apiban_key` and the feed is synced **on a background thread**, never queried per
INVITE — that synchronous `rest_get()` is what capped the 2023 system at ~26 calls/s and
froze every decision whenever apiban.org was slow.

Two properties that matter more than they sound:

- **The cursor is persisted.** The feed is consumed by a forward-only ID, so a restart that
  forgot it would refetch the entire history; one that remembered it but forgot the
  addresses would come back protecting nothing while looking perfectly healthy. TFPS stores
  both, re-applies the last 7 days at startup, and says so: `APIBAN restored: 2140
  addresses`.
- **The feed respects the ignore list.** A curated third-party list is still not yours.

### The backstop, and why it has to exist

The rule above needs the softswitch's answer. There are real deployments where it never
comes — measured on the reference server, where opensips drops requests addressed to a
domain it does not serve **without challenging them**: 1 outbound packet in 45 seconds
against hundreds inbound.

There, the failure counter structurally cannot rise. So a volume backstop remains: **20
authenticated attempts in 60 s** with no answer observed. It is looser, because it cannot
tell success from failure — only volume. A legitimate phone sends one per registration
cycle, typically every 300 s.

And when that situation is detected — credentials presented, not one challenge seen — TFPS
**says so on the report**, because a rule that structurally cannot match is exactly the
`fail2ban` blindness this project exists to avoid.

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

On the target machine, as root, from a checkout with the binaries already built:

```sh
./packaging/install.sh
```

That compiles the XDP program against the running kernel's BTF, installs `tfps` and
`tfps_ctl`, drops in the systemd unit, writes a starting `/etc/tfps/config.json` **only if
one is not already there**, and starts the service. Run it again to upgrade — it is
idempotent and never overwrites your configuration.

Then:

```sh
journalctl -u tfps -f      # watch it decide, live
tfps_ctl status            # what it has learned, what is blocked
```

Two things it needs from the machine: `clang` and `bpftool` at install time (Debian/Ubuntu:
`apt install clang linux-tools-common`), and a kernel ≥ 5.15 with BTF.

### By hand, if you prefer

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -c ebpf/tfps_xdp.c -o /usr/local/lib/tfps/tfps_xdp.o
install -m755 target/x86_64-unknown-linux-musl/release/{tfps,tfps_ctl} /usr/local/bin/
install -D -m644 packaging/tfps.service /etc/systemd/system/tfps.service
systemctl enable --now tfps
```

**It also runs with no configuration and no arguments at all** — `tfps` on its own uses the
built-in defaults. The config file is for fitting it to your installation, not for making it
work.

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

### Addresses that are never blocked

The host's **own addresses are always exempt**, with no configuration. This is not
paranoia: during development a brute-force test fired from the softswitch host itself and
TFPS condemned the machine it was defending. The blast radius was small — inbound packets
carry the attacker's source, not yours — but a defence that can shoot its own host will
eventually do so at three in the morning.

`"ignoreip": ["10.0.0.0/8", "203.0.113.7"]` adds trusted carriers and management ranges —
the same name `fail2ban` uses for the same job. Also `--ignoreip CIDR`, repeatable.

Two rules keep it from becoming a policy knob (`SPEC.md` §11): **`0.0.0.0/0` is refused**,
because one line that disables enforcement without announcing it is the silent failure this
project exists to prevent — `--no-enforce` does that explicitly and says so in every report;
and **every entry counts its hits**, so a stale exemption shows up as cold:

```
    ignoreip: 3 exemption(s) applied, never matched: 203.0.113.0/24
```

An exempt source is still **judged and reported**, only never enforced:

```
EXEMPT peer=209.38.75.252 reason=auth-failed detail=rejected (ignore list)
```

Silently skipping the evaluation would hide a compromised trusted peer, which is the case
where an operator most needs to be told. The exemption also applies to the APIBAN feed: a
third-party list is curated, but it is not yours.

## Controlling it — `tfps_ctl`

The counterpart to `fail2ban-client`, and it exists for the same reason: a defence nobody
can inspect is a defence nobody trusts. It also serves a requirement — with no labelled
data, **how often an operator unbans is the only measure of precision this system has**, so
that act has to be one command rather than a database session.

```
tfps_ctl status                       what is running, what is blocked, how fresh the state is
tfps_ctl stats                        every counter: kernel drops, traffic mix, blocks by reason
tfps_ctl banned [--why]               condemned sources, with time left and the reason
tfps_ctl unban <ip>... | --all        lift a block — takes effect on the next packet
tfps_ctl ban <ip> [--ttl N]           condemn by hand (default 3600s, 0 = no expiry)
tfps_ctl pairs [filters]              search learned (peer, A-number) pairs
tfps_ctl pair <peer> <a-number>       everything known about one pair
tfps_ctl peers                        peers, pair counts, and where they call
tfps_ctl countries <peer>             that peer's destinations by volume
tfps_ctl log [--limit N] [--ip IP]    the block audit log, newest first
tfps_ctl forget <peer> [--a NUMBER]   erase learned state (requires tfps stopped)
```

Filters for `pairs`: `--peer IP`, `--a TEXT` (substring of the A-number), `--country ISO`,
`--limit N`.

```console
# tfps_ctl status
database          : /var/lib/tfps/tfps.db
learned state     : 293 pairs across 8 peers
last checkpoint   : 35s ago (state is a snapshot, not live)
enforcement       : own map id 7478
blocked now       : 3 (0 without expiry)

# tfps_ctl banned --why
SOURCE           EXPIRES IN  REASON
51.75.106.116           49m  user-agent (pplsip)
162.217.103.70          51m  user-agent (friendly)

# tfps_ctl peers
PEER               PAIRS      LAST  TOP COUNTRIES
149.50.107.48         60        1m  NANP:174 SS:58
149.50.107.47         59        1m  GB:171
```

```console
# tfps_ctl stats
KERNEL  (live)
  seen on SIP ports : 21486
  dropped by XDP    : 9042 (42.1% — gone before sngrep)
  condemned now     : 2140 (2140 permanent, e.g. the APIBAN feed)

TRAFFIC  (as of the last checkpoint, 2m ago)
  packets              1879   sip                   768
  keepalive            1110   not_sip                 1
  ...

BLOCKS BY REASON
  last day               48  user-agent:47 auth-failed:1
```

**Two sources of truth, and the tool never blurs them.** Blocks live in the kernel map and
are read and written directly, so an unban applies immediately. Learned state lives in
SQLite and is written at checkpoint, so `status` reports **how old that snapshot is**
instead of letting anyone draw conclusions from stale rows.

Three deliberate refusals:

- Unbanning an address that was not blocked says exactly that, rather than reporting
  success — otherwise an operator who mistypes stops looking for the real block.
- If two loaded eBPF maps share the name, it names the ambiguity instead of picking one:
  guessing would edit somebody else's enforcement plane.
- `forget` refuses while the daemon is running, because the in-memory working set would be
  written straight back at the next checkpoint and quietly undo it.

Reading blocks needs `CAP_BPF` (run as root); reading learned state only needs the
database file.

## Reading the report

```
--- mode=LEARNING (29d 23h left) packets=330 sip=98 responses=0 keepalive=232
    not_sip=0 noise=12 (12%) injection=0 auth_att=142 auth_fail=5 auth_ok=97
    auth_chal=104 auth_volume=0 invites=62
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
| `auth_att` | requests that carried a credential |
| `auth_fail` | credentials **rejected** — the brute-force signal |
| `auth_ok` | credentials accepted |
| `auth_chal` | digest challenges (`401`/`407`) seen. **Zero here with a non-zero `auth_att` means the softswitch is not answering**, so only the backstop can fire — and TFPS warns about it |
| `auth_volume` | sources condemned by the volume backstop |
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
- `tfps_ctl --help` — the control tool, above
- [`CONTEXT.md`](CONTEXT.md) — the vocabulary, normative for code and documentation

## License

Apache-2.0.
