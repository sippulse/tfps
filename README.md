# TFPS

**Telephony Fraud Prevention System** for SIP networks. One static binary, no cloud, no
policy configuration.

TFPS is **two things, and the first is the product.** By default it is a **noise filter**:
it drops SIP scanning, brute-force and known-bad sources in the kernel, before they reach
your `sngrep` — and that alone is worth running. **Behavioural IRSF detection** — learning
each source's normal and catching fraud by anomaly — is an **opt-in extra**
(`--behavioural`), off by default. Most installs will only ever want the noise filter, and
they should not pay for anything more.

- **Static musl binaries** — `tfps` ≈ 4.3 MB, `tfps_ctl` ≈ 2.3 MB. No glibc dependency;
  they run on Ubuntu 24.04, Debian 12 and forward.
- **No UDP bind** — capture is `AF_PACKET`, so your softswitch keeps its own socket on 5060
  and never notices.
- **Kernel-level drop** — condemned sources vanish from `sngrep`, `tcpdump` and `tshark`.

---

## The garbage disappears from sngrep

This is what the product delivers, and it works because of one specific ordering inside the
Linux kernel:

```
NIC → driver → XDP ← TFPS drops here
                 ↓
            sk_buff → ptype_all ← libpcap hooks here (sngrep, tcpdump, tshark)
                        ↓
                    netfilter ← iptables and nftables act here
```

A packet dropped at **XDP never reaches the libpcap tap**. That is why `nftables` would not
work for this purpose: its drop happens later, and your capture would still be polluted.

**Verified in production**: with ~2,000 sources blocked (APIBAN + perimeter), a `tcpdump`
filtered to a sample of them captured a fraction of the packets a control window did. It is
not hermetic — the occasional packet slips through — but the reduction is drastic, and the
noisiest scanners disappear from the capture entirely.

---

## Two products, one binary

| | **Noise reduction** (default) | **Fraud detection** (`--behavioural`) |
|---|---|---|
| what it does | drops scanning, injection, brute-force, known-bad IPs | learns each source's normal, blocks IRSF by anomaly |
| needs learning? | no — effective from minute one | yes — 30-day learning window before it acts |
| state | rebuilds from traffic in minutes | per-source, persisted in SQLite |
| the signal | user-agent, URI shape, failed auth, APIBAN | three-arm sequential detector (see below) |
| default | **on** | **off** |

```sh
tfps                 # noise reduction only — the product
tfps --behavioural   # add IRSF detection (or "behavioural": true in the config)
```

The banner always says which of the two you are running, so it is never ambiguous.

---

## Status — v0.1.0

| working | not yet |
|---|---|
| `AF_PACKET` capture, no port bind | enforcing the behavioural verdict (forged `603`) |
| XDP enforcement of perimeter blocks (native/generic) | SIP over TCP (detection) |
| perimeter: user-agent, URI injection, failed auth | IPv6, SIP over TLS |
| APIBAN, background-synced and persisted | call-duration signal via `BYE` |
| `ignoreip`, with the host's own addresses always exempt | day-31 activation confirmation |
| three-arm behavioural detector, self-calibrating | |
| SQLite persistence and control tool | |

**The perimeter enforces today; the behavioural layer detects and reports.** During the
30-day learning window it prints `WOULD BLOCK` lines and blocks nothing. After that it
prints `BLOCK` lines with the evidence — but pushing that verdict to the kernel (the forged
`603 Decline` of `SPEC.md` §8, or a source-level drop) is the remaining piece. Read the
`WOULD BLOCK`/`BLOCK` lines and the `tfps_ctl stats` calibration to judge the (α, β) tuning
before wiring enforcement on.

---

## The perimeter — the default product

Every packet on a watched port is checked, cheapest first. A match **condemns the source**:
its next packets die at XDP and vanish from the capture.

- **Known scanner user-agents** — 18 built-in signatures (`friendly`, `sipcli`, `sipvicious`,
  `pplsip`, `sipsorcery`, `Nmap NSE`…). Weak as *detection* — a competent attacker forges a
  legitimate UA — but most scanning traffic uses a default one, so as a *volume filter* it
  earns its place. A missing `User-Agent` is **not** noise.
- **URI injection** — 11 built-in patterns (`'`, `%27`, `--`, `?=?`, `union`, `select`, and
  `;` inside the user part), matched against the `user@host` of the Request-URI, `From` and
  `To` only — never the display name, so an Irish surname is not mistaken for SQL injection.
  Higher confidence than a user-agent: no real phone puts a single quote in a `From` header.
- **Failed authentication** — see below.
- **APIBAN** — the collaborative bad-IP list, if a key is configured.

The perimeter does **not** exist to catch fraud. It exists to keep noise out of the
behavioural baseline: if scanning fed a source's baseline, the detector would learn that
bursts to strange destinations are normal there, and poison itself.

### Failed authentication, and what does not count

**A bare `401` means nothing.** Digest is a two-step flow: every legitimate `REGISTER` gets
a `401` with a nonce and is resent with `Authorization`. Counting challenges would block
every customer.

What counts is a request that **carried a credential and was answered `401`/`407` anyway**:

```
REGISTER (no Authorization)  →  401 + nonce     the normal handshake, ignored
REGISTER (Authorization)     →  200 OK          accepted — the count is cleared
REGISTER (Authorization)     →  401 again       a rejected password. This is the signal.
```

Five rejections in ten minutes condemn the source — `fail2ban`'s `maxretry`/`findtime` for
the Asterisk jail, deliberately, but read off the wire instead of a log the softswitch may
not be writing. Requests are matched to responses by the `Via` branch (RFC 3261 §17.1.3),
falling back to `Call-ID` + `CSeq`. A retransmitted `401` counts once; an accepted credential
clears the run, so someone who fixes a typo is not blocked by their next slip. Because it
counts *failures*, a busy NAT is not a problem — a hundred phones behind one address all
succeed.

**The backstop**: where the softswitch rejects probes *without* answering (measured on the
reference server: one outbound packet in 45 s against hundreds inbound), the failure counter
cannot rise, so a volume rule remains — 20 authenticated attempts in 60 s with no challenge
seen. When that condition is detected, TFPS **says so** on the report, because a rule that
structurally cannot fire is the `fail2ban` blindness this project exists to avoid.

---

## Fraud detection — the opt-in layer

Turn it on with `--behavioural`. It learns each **source IP**'s normal behaviour and blocks
IRSF by anomaly.

> **Prerequisite — configure your international prefixes.** The behavioural layer reasons
> only about **international** destinations, and `intl_prefixes` (global and per-peer) is how
> it tells a real outbound international call from an internal extension or an inbound call to
> an E.164 DID. Get them wrong and the wrong calls are judged. The defaults are a starting
> point, not a fit for your installation — set them, and the detector's job becomes correct.

The full design and its literature are in
[`docs/anomaly-detection.md`](docs/anomaly-detection.md); in brief:

**The B-number cannot be classified.** Tested against a real libphonenumber port, classic
IRSF destinations (Latvia, Somalia, the Philippines) validate as ordinary mobile numbers,
while some genuine ranges are rejected. Neither validity nor number-type separates fraud
from legitimate traffic. Detection has to be **behavioural**.

**IRSF has a behavioural signature, in two phases**, and each maps onto a solved problem:

- **Scanning** — "they try dozens of countries to find one that routes through a partner
  ITSP." That *is* a port scan, and it is detected with a **Threshold Random Walk** (Jung et
  al., IEEE S&P 2004) — a sequential test that accumulates evidence per call and fires the
  moment it is sufficient. Two arms run: a new **prefix** (probing `00`, `011`, `+5540`…),
  and a **failed completion** (a call answered `4xx`/`5xx`/`6xx`, or never — the AT&T
  signature, "the call never came here"). A never-seen **country** is *not* one of them:
  country novelty was too fragile, because without correct international-prefix
  configuration an internal extension or an inbound E.164 DID is mis-read as a new
  international destination. The seen-country set is still tracked for the report, but it no
  longer blocks.
- **Exploitation** — hammering the route it found shows as a volume spike against the
  source's own norm, scored with **hierarchical Gamma-Poisson surprise**.

The three arms produce evidence in the same log-likelihood units, so they **add**;
enforcement fires when the total crosses a bound set by the **error rates you choose**
(α, β) — not a hand-picked threshold. Every block is one explainable sentence:
*"14 bits: 9 country-scan, 5 volume."*

**It self-calibrates.** The benign hypotheses — how often a normal source dials a new
country, how often calls fail, the population's rate distribution — are learned from the
deployment's *own* aggregate traffic during the learning window and refit at each
checkpoint. The operator sets **only α and β**, properties of their risk appetite, never a
traffic constant. `tfps_ctl stats` shows the learned values.

**Its one honest weakness**: a low-and-slow attacker who mimics a legitimate profile at low
volume. Which is exactly why this layer is opt-in, blocks are temporary, and the unban rate
is watched as the precision proxy.

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
  "ignoreip": ["10.0.0.0/8", "203.0.113.7"],

  "behavioural": false,
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
without editing a file. An **unknown field is an error**, not silence: an `apiban_kei`
quietly ignored would make you believe you enabled APIBAN when you did not. Malformed JSON
and an invalid peer IP become startup alarms too. (Renamed fields keep an alias, so a config
from an earlier version still loads rather than silently reverting to defaults.)

### `peers` — the dial plan per PBX

Declaring beats learning because it holds on that peer's **very first** call instead of
waiting for convergence, and the weight is large: **20.3% of destinations do not resolve to
a country** without correct prefix stripping. `bare_e164` says the PBX sends plain E.164 with
no prefix — common in wholesale; it is an explicit field because the semantics are
dangerous: with it on, `2125551234` is Morocco; with it off, a domestic US number.

### `signatures` and `injection` — they add, never replace

The seeds are compiled into the binary and work with no file. What you list is **added** to
the 18 built-in user-agents and 11 built-in patterns — replacing would make someone who
writes three lines silently lose the built-ins. Prefix match by default; `=text` matches
exactly. TFPS warns when no signature has matched after thousands of messages: a rule that
never fires is rotten.

### `ignoreip` — sources never enforced against

The equivalent of `fail2ban`'s field of the same name. The host's **own addresses are always
exempt** and need no entry — that is not configuration, it is read from the machine, and it
exists because a defence that can condemn its own host will eventually do so. Declared
entries add trusted carriers and management ranges. An exempt source is still evaluated,
counted and reported; only the block is withheld. Two rules keep it from becoming a policy
knob: **`0.0.0.0/0` is refused** (use `--no-enforce`, which announces itself), and every
entry counts its hits, so a stale exemption shows as cold.

### `apiban_key` — optional integration

The collaborative [APIBAN](https://apiban.org) list, fed by honeypots, on a **separate
thread**: HTTP never touches the packet path. That is exactly where the 2023 TFPS died — a
synchronous `rest_get()` per INVITE, ~26 INVITEs/s, any outage froze every call. Here the
feed is resumed from its persisted cursor, re-applied for 7 days after a restart (so the
integration never comes back protecting nothing), and honours `ignoreip`.

---

## Building

```sh
cargo test                                                   # ~180 tests
cargo build --release --target x86_64-unknown-linux-musl
```

The musl target produces **static binaries with no glibc dependency** — `tfps` ≈ 4.3 MB,
`tfps_ctl` ≈ 2.3 MB — that run on Debian 12, Ubuntu 24.04 and whatever comes next. This
solved a real case: the build machine had glibc 2.39 and the server 2.36, and glibc is not
forward compatible.

SQLite is compiled in, which needs a C compiler that can target musl. If you do not have
`musl-tools`, [zig](https://ziglang.org) works and needs no root:

```sh
export CC_x86_64_unknown_linux_musl="zig cc -target x86_64-linux-musl"
export AR_x86_64_unknown_linux_musl="zig ar"
```

The XDP program is written in C (`ebpf/tfps_xdp.c`) because only the kernel side needs LLVM.
The installer compiles it against the running kernel's BTF; requires kernel **≥ 5.15** with
BTF.

---

## Installing and running

On the target machine, as root, from a checkout with the binaries built:

```sh
./packaging/install.sh
```

That compiles the XDP program against the running kernel's BTF, installs `tfps` and
`tfps_ctl`, drops in the systemd unit, writes a starting `/etc/tfps/config.json` **only if
one is not already there**, and starts the service. Run it again to upgrade — idempotent,
and it never overwrites your configuration. It needs `clang` and `bpftool` (Debian/Ubuntu:
`apt install clang linux-tools-common`).

```sh
journalctl -u tfps -f      # watch it decide, live
tfps_ctl status            # what it has learned, what is blocked
```

**It also runs with no configuration and no arguments** — `tfps` on its own uses the
built-in defaults. Capture needs `CAP_NET_RAW`; XDP needs `CAP_BPF` and `CAP_NET_ADMIN`
(and, on some kernels, `CAP_SYS_ADMIN` — verify on your target; the packaged unit explains
why).

| flag | effect |
|---|---|
| `--behavioural` | turn on fraud detection (default: OFF, noise reduction only) |
| `--ports 5060,5080` | SIP ports to watch (default `5060`) |
| `--intl +,00,011,9011` | international dialling prefixes |
| `--ignoreip CIDR` | never enforce against this address/network (repeatable) |
| `--learn-days N` | days observing before the behavioural layer acts (default `30`) |
| `--active` | skip the learning period |
| `--no-enforce` | observe only, do not touch XDP |
| `--apiban-key KEY` | enable APIBAN, in the background |
| `--config PATH` | configuration (default `/etc/tfps/config.json`) |
| `--db PATH` / `--no-db` | SQLite database, or run without persistence |
| `-v` / `--debug-unparsed` | verbose; show payloads that failed to parse |

---

## Controlling it — `tfps_ctl`

The counterpart to `fail2ban-client`. With no labels, **how often you unban is the only
precision measure this system has**, so that act is one command.

```
tfps_ctl status                       what is running, what is blocked, how fresh the state is
tfps_ctl stats                        every counter: kernel drops, traffic mix, calibration
tfps_ctl banned [--why]               condemned sources, with time left and the reason
tfps_ctl unban <ip>... | --all        lift a block — takes effect on the next packet
tfps_ctl ban <ip> [--ttl N]           condemn by hand (default 3600s, 0 = no expiry)
tfps_ctl sources [--peer --country]   learned sources and the countries they call
tfps_ctl source <peer>                everything known about one source
tfps_ctl peers                        sources by country breadth, when last heard
tfps_ctl log [--limit N] [--ip IP]    the block audit log, newest first
```

```console
# tfps_ctl stats
KERNEL  (live)
  seen on SIP ports : 21486
  dropped by XDP    : 9042 (42.1% — gone before sngrep)
  condemned now     : 2140 (2140 permanent, e.g. the APIBAN feed)

CALIBRATION  (benign hypotheses learned from this deployment)
  theta0                 0.083
  theta0c                0.310
  prior_mean             1.90

TRAFFIC  (as of the last checkpoint, 2m ago)
  packets              1879   sip                   768
  ...
```

**Two sources of truth, never blurred.** Blocks live in the kernel map and are read and
written directly, so an unban applies immediately. Learned state lives in SQLite and is
written at checkpoint, so `status` reports **how old that snapshot is** rather than passing
stale rows off as current. Reading blocks needs `CAP_BPF` (run as root); reading learned
state needs only the database file.

---

## Reading the report

```
--- mode=NOISE REDUCTION packets=330 sip=98 responses=0 keepalive=232 not_sip=0
    noise=12 (12%) injection=0 auth_att=142 auth_fail=5 auth_ok=97 auth_chal=104
    auth_volume=0 intl_ok=0 intl_fail=0 invites=62 intl=62 unknown_country=20
    first_time=21 blocks=0 would_block=0 sources=3 ports={5060: 330}
    XDP: dropped=1840 seen=2100 expired=3 in_map=7 blocked_by_us=7
```

| field | meaning |
|---|---|
| `mode` | NOISE REDUCTION, or FRAUD DETECTION (LEARNING / ACTIVE) |
| `keepalive` | NAT CRLF pings (RFC 5626) — on a residential 5060, most packets |
| `not_sip` | unclassified. **Should be ~0**; high means something is not understood |
| `noise (%)` | how much the perimeter removed — the number behind a clean sngrep |
| `auth_fail` / `auth_ok` / `auth_chal` | rejected credentials, accepted, challenges seen |
| `auth_volume` | sources condemned by the volume backstop |
| `intl_ok` / `intl_fail` | international calls observed to complete / fail (the completion arm's fuel) |
| `unknown_country` | international by shape, no recognisable country — prefix padding |
| `first_time` | first-time-country events; feeds the learned benign rate |
| `blocks` / `would_block` | behavioural verdicts (active / during learning) |
| `sources` | distinct source IPs under watch |
| `XDP: …` | what the kernel side actually did; `blocked_by_us` is what **this** process condemned |

Silence is an alarm, not normality: TFPS complains when it stops seeing traffic, when there
is SIP on IPv6/TCP it cannot inspect, when no signature has matched in thousands of messages,
and when credentials are presented with no challenge ever seen.

---

## Persistence

**SQLite. One file. No server, no daemon, no credential, no port.** The working set lives in
memory; only the boot load and the periodic checkpoint touch disk. State splits by
durability: **perimeter** state dies with the process and rebuilds from traffic in minutes
(consistent with fail-open by not pinning the eBPF program); **behavioural** state and the
APIBAN list survive on disk, the latter because it is consumed through a forward-only cursor
and cannot rebuild itself.

---

## What it does not do

Documented, not engineered away — a limitation stated plainly beats one that fails quietly.

| not handled | why |
|---|---|
| **SIP over TLS** | encrypted payload; only metadata and IP reputation remain |
| **SIP over TCP** | L7 reassembly is not implemented; counted as a blind spot, not parsed |
| **IPv6** | the capture takes `ETH_P_IP` only; counted and warned about |
| **a broad international profile** | anomaly saturates by construction — a peer already calling 200 countries has no burst left |
| **the first 30 days** | the behavioural layer's learning window, by design and announced |
| **a low-and-slow mimic** | the residual gap no on-wire method closes — hence opt-in, TTL'd, unbannable |
| **enforcing the behavioural verdict** | detected and reported today; the forged `603` is the remaining piece |

---

## Documentation

- [`docs/anomaly-detection.md`](docs/anomaly-detection.md) — the behavioural detector: the
  research, why the constraints rule out most methods, and the three-arm design
- [`DETECTION.md`](DETECTION.md) — how a packet is examined, test by test, in code order
- [`SPEC.md`](SPEC.md) — the architecture and the decisions (§6 superseded by the doc above)
- [`CONTEXT.md`](CONTEXT.md) — the vocabulary, normative for code and documentation

## License

Apache-2.0.
