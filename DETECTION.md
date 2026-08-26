# DETECTION — how a packet is examined

This document traces one packet from the wire to a verdict, naming every test it is put
through, in the order the code applies them, with the file and function that applies it.
It is the companion to `SPEC.md`: the spec says *what was decided and why*, this says
*what actually happens to a packet*.

Nothing here is aspirational. Every threshold quoted is a constant in the source, and
every worked example at the end is real traffic captured on the test server on
2026-08-26.

---

## 0. The pipeline at a glance

```
     wire
      │
      ▼
┌─────────────────────────────────────────────────────────────────────┐
│ KERNEL                                                              │
│   XDP (tfps_filter)  ── source condemned? ──► XDP_DROP ─────────────┼──► gone.
│      │                                        never reaches libpcap │    invisible to
│      │ not condemned                                                │    sngrep/tcpdump
│      ▼                                                              │
│   ptype_all taps ──► libpcap / sngrep / tcpdump                     │
│      │                                                              │
│      ▼                                                              │
│   AF_PACKET socket (SOCK_DGRAM, ETH_P_IP)                           │
└──────┼──────────────────────────────────────────────────────────────┘
       ▼
  1. IPv4/UDP decode ....... net::parse_ipv4_udp      → else count a blind spot, stop
  2. port gate ............. main.rs, args.ports      → else stop (not counted at all)
  3. SIP recognition ....... sip::parse               → keepalive / not SIP
       └─ a response goes to the authentication path, judged against its own request
  4. perimeter: user-agent . perimeter::is_noise      → BLOCK (condemn source)
  5. perimeter: injection .. perimeter::injection_in_uri → BLOCK (condemn source)
  6. perimeter: failed auth  engine::observe_response → BLOCK (condemn source)
  7. method gate ........... engine::observe          → non-INVITE stops here
  8. dial plan ............. dialplan::to_international → domestic stops here
  9. country ............... country::resolve         → unknown country stops here
 10. novelty .............. novelty::PairState::observe → PASS / WOULD BLOCK / BLOCK
```

Two ordering facts carry the whole design:

- **The perimeter runs before any state is touched.** Noise must never enter a learning
  baseline, or the model learns that scanning is normal for that peer and poisons itself.
- **The dial-plan test is the cheapest gate on the hot path** and it comes before
  canonicalisation, country lookup and novelty. On a mostly-domestic carrier the majority
  of INVITEs leave at step 8 having allocated nothing. Cost scales with *international*
  volume, not with total volume.

---

## 1. Where the tap sits, and why that position matters

TFPS opens one socket (`crates/tfps/src/main.rs:411`):

```rust
Socket::new(Domain::from(AF_PACKET), Type::DGRAM, Some(Protocol::from(ETH_P_IP_BE)))
```

| choice | value | consequence |
|---|---|---|
| family | `AF_PACKET` (17) | taps the netdev layer, **binds no UDP port** — the softswitch keeps its own bind on 5060 and nothing has to be reconfigured |
| type | `SOCK_DGRAM` | the kernel strips the link-layer header, so the buffer starts at the IPv4 header. No Ethernet parsing, and it works the same on `eth0`, `any` and tunnels |
| protocol | `ETH_P_IP` in network order (`0x0008`) | only IPv4 frames are delivered to userspace |
| buffer | 65,536 bytes (`BUF`) | the largest possible IP datagram; no truncation, no reassembly logic |
| read timeout | 1 second | **the silence alarm depends on it** |

The read timeout is not a detail. Without it the loop would only wake when a packet
arrived, so a system that had stopped seeing traffic would also stop reporting — the exact
`fail2ban` failure mode this project exists to avoid. `WouldBlock`, `TimedOut` and
`Interrupted` are treated as "no packet", not as errors (`main.rs:456`).

Capture requires `CAP_NET_RAW`. Enforcement additionally requires `CAP_BPF` and
`CAP_NET_ADMIN`.

**Why the drop lives in XDP and not in nftables.** XDP runs in
`netif_receive_skb_internal`, *before* `__netif_receive_skb_core` hands the packet to the
`ptype_all` taps where libpcap attaches. A packet dropped in XDP never becomes an
`sk_buff` and therefore never appears in sngrep, tcpdump or tshark. An nftables drop
happens in netfilter, *after* that tap — the packet would be blocked but the capture would
stay polluted. That single ordering difference is the entire technical argument for XDP
here, and it is what produces the product's first visible result: a clean sngrep.

---

## 2. Stage 1 — IPv4/UDP decode

`crates/tfps-core/src/net.rs:85`, `parse_ipv4_udp`. No checksums are verified, no state is
built; the goal is to find the SIP datagram and the source address.

Checks, in order — any failure returns `None`:

| # | check | bytes | reject when |
|---|---|---|---|
| 1 | buffer length | — | `< 20` (minimum IPv4 header) |
| 2 | version | `pkt[0] >> 4` | `!= 4` |
| 3 | IHL | `pkt[0] & 0x0f`, ×4 | `< 20`, or longer than the buffer |
| 4 | protocol | `pkt[9]` | `!= 17` (UDP) |
| 5 | fragment offset | `pkt[6] & 0x1f`, `pkt[7]` | `!= 0` — a non-first fragment carries no L4 header, so there are no ports to read |
| 6 | UDP header present | — | fewer than 8 bytes after the IPv4 header |

Two length fields are then clamped rather than trusted:

- `total_len` (`pkt[2..4]`) is clamped to `[ihl, buffer_len]`. Some capture paths deliver a
  buffer *larger* than the declared length (Ethernet padding); trusting the larger value
  would feed trailing junk into the SIP parser as if it were payload.
- the UDP length field (`udp[4..6]`) is clamped to `[8, datagram_len]` for the same reason.

What comes out is `UdpDatagram { src, dst, src_port, dst_port, payload }`, where `src` —
the **peer** — is the only non-forgeable identity available from this observation point.
Over UDP a source address can be spoofed, but the SIP response would not come back and the
call would not complete, which is why the peer, and not the `From` header, anchors
everything downstream.

### Blind spots are counted, not ignored

When `parse_ipv4_udp` returns `None`, `classify_other` (`net.rs:59`) says what the packet
was, and the binary counts it (`main.rs:477`):

| class | how it is recognised | counted as |
|---|---|---|
| IPv6 | `pkt[0] >> 4 == 6` | `ipv6` |
| TCP | IPv4, `pkt[9] == 6` | `tcp` — **only if a port is one of the watched SIP ports** |
| later fragment | IPv4, fragment offset `!= 0` | `fragments` |
| anything else | — | not counted |

The TCP restriction exists because counting all TCP would include the administrator's own
SSH session, and an alarm that fires because of the person reading it is noise. When these
counters are non-zero the report prints a `blind spots:` line and warns once that there is
SIP on those ports the system is **not** analysing.

---

## 3. Stage 2 — the port gate

`main.rs:494`. The datagram is examined only if `dst_port` **or** `src_port` is in
`--ports` (default `[5060]`). Source-port matching is what lets responses and
non-standard client ports still be attributed to the right conversation.

Traffic that fails this gate is not counted anywhere — it is not the system's business and
inflating the counters with it would make the report unreadable. The per-port tally in the
report (`ports={5060: 1826, 5353: 1}`) shows what did pass the gate, which is how an
operator discovers they are watching the wrong port.

---

## 4. Stage 3 — is it SIP at all?

`crates/tfps-core/src/sip.rs:158`, `sip::parse`. Three outcomes, deliberately distinct,
because collapsing them would make the report lie.

**Keepalive** — checked first, being both the most common and the cheapest case: a payload
of 1–4 bytes consisting only of `\r` and `\n`. This is the NAT ping of RFC 5626 §4.4.1;
the client sends `\r\n\r\n` and the server answers `\r\n`, purely to hold the pinhole open.
On a public 5060 with residential phones **this is most of the traffic** — in the live
sample below, 1,110 of 1,879 packets. Counting it as "not SIP" would make an operator
conclude they were capturing the wrong interface.

**Response** — payload starts with `SIP/`. Status, `Via`, `Call-ID` and `CSeq` are
extracted and the packet goes to the **authentication path** (stage 6), which is the only
place a *failed* authentication can be recognised: a `401` only means "wrong password" if
the request it answers actually carried one. Responses are counted separately as
`responses`, and the `200 OK` also belongs to the learning path, which is where duration
and outcome come from.

**Request** — everything else is put through `parse_request` (`sip.rs:197`):

1. the payload must be valid UTF-8 (SIP headers are ASCII in practice; a non-UTF-8 payload
   is junk or is not SIP, and the handling is the same either way);
2. lines are split on `\r\n` **and** on bare `\n`, because real-world stacks emit both;
3. the request line must be `METHOD Request-URI SIP/x.y` — three space-separated tokens
   with the version starting `SIP/`;
4. headers are read until the first empty line. **The body is never read** — SDP is
   irrelevant to every decision this system makes.

Only these headers are kept, each for a stated reason:

| header | compact | why it is kept |
|---|---|---|
| `Via` (topmost only) | `v` | the `branch` is the transaction matcher of RFC 3261 §17.1.3; a forged response must reuse it |
| `From` | `f` | the A-number (grouping key) and the `tag` |
| `To` | `t` | needed for a forged response, and scanned for injection |
| `Call-ID` | `i` | dialog correlation on the learning path |
| `CSeq` | — | reused verbatim in a forged response |
| `User-Agent` | — | the perimeter signature |
| `P-Asserted-Identity` | — | asserted identity, where the peer sets one |
| `Authorization` / `Proxy-Authorization` | — | **presence is the brute-force signal** |

Header names are matched case-insensitively and accept the compact forms of RFC 3261 §20.
Values are borrowed from the input buffer — the parse allocates nothing, which is what
keeps the decision path free of allocation per INVITE.

A folded (continued) header line sets `folded = true` and is skipped: this parser does not
join continuations, and the flag records that a value may be truncated rather than
pretending otherwise.

Anything that fails all three is counted as `not_sip`. With `--debug-unparsed` the first
72 bytes are printed with non-printable bytes shown as `.`, because "could not parse" has
to be investigable or the counter is a number nobody can act on.

**A parse failure is never a block.** Whatever cannot be interpreted is out of scope and
passes. This is the one rule that keeps the system from repeating `R07` of the Java-era
TFPS, which denied everything it could not classify and became 39% of all its rejections —
its largest single source of blocking was its own ignorance.

---

## 5. Stages 4–6 — the perimeter

`crates/tfps-core/src/perimeter.rs`. The perimeter applies to **every method**, not just
INVITE: scanners send `OPTIONS` and `REGISTER` at least as often. It runs before any
learning state is touched, and a packet it catches condemns the *source*, not just the
packet.

It does not exist to catch fraud. It exists to keep garbage out of the behavioural
baseline, and — as a side effect the operator sees on day one — out of sngrep.

### 5.1 User-agent signature (`is_noise`, perimeter.rs:105)

18 built-in signatures, inherited from the `dialplan` table (dpid 99997) of the 2023 TFPS
and converted from regex to plain matching, since every one of them was either a start
anchor or a literal:

| match | signatures |
|---|---|
| prefix | `sipcli`, `friendly`, `VaxUserAgent`, `VaxSIPUserAgent`, `sivus`, `Nsauditor`, `SipReg`, `Custom SIP`, `Nmap NSE`, `sipscan`, `sipsorcery`, `pplsip`, `SipClient`, `sipvicious` |
| exact | `smap`, `PBX`, `Trixbox`, `opensip` |

Comparison is ASCII case-insensitive. The exact/prefix split matters: `PBX` as a prefix
would match the legitimate user-agent of a real PBX, so it is anchored at both ends.

**A missing `User-Agent` is not noise.** The Java-era TFPS saw 6,843 legitimate INVITEs
with no UA; absence proves nothing and is explicitly allowed through.

Signatures from `/etc/tfps/config.json` are appended, never substituted — a file that
replaced would let an operator who writes three lines silently lose the 18 built-ins.
File entries report as `<file>`; built-ins report their own name, so per-signature hit
counts stay stable. `=text` in the file means exact match, bare text means prefix.

Every signature carries a hit counter, and signatures that have never matched are
reportable. A filter that matches zero lines for three months is rotten, and no version of
fail2ban ever told anyone that.

### 5.2 URI injection (`injection_in_uri`, perimeter.rs:181)

11 built-in patterns — `'`, `%27`, `--`, `\`, `%24`, `%60`, `==`, `?=?`, `union`,
`select`, `;` — matched case-insensitively against **three fields only**: the Request-URI,
`From` and `To`.

The narrow scope is deliberate. Applied to the whole message these patterns would match
constantly: `Via` carries `;branch=`, `User-Agent` strings contain hyphens, SDP contains
almost everything. Restricting to URIs is what keeps the false-positive rate at zero on
real traffic.

`;` gets a special case: it is a legal SIP URI parameter separator (`;tag=`,
`;transport=tcp`), so it counts **only inside the user part** — before the `@`. A
Request-URI of `sip:a;drop@pbx.com` fires; `sip:200@pbx.com;transport=tcp` does not.

This is a *higher*-confidence signal than the user-agent list: a scanner can trivially
forge a normal UA, but no real telephone puts a single quote or `--` in a `From` header.
There is no innocent explanation.

### 5.3 Failed authentication (`observe_response`, engine.rs)

The signal is **a request that carried a credential and was answered with a digest
challenge anyway**. Not a bare `401`, and not the mere presence of `Authorization`.

That distinction is the difference between a working defence and knocking every customer
offline, and it follows directly from how digest works:

```
REGISTER (no Authorization)  →  401 + nonce     the normal handshake. Ignored.
REGISTER (Authorization)     →  200 OK          accepted. The count is cleared.
REGISTER (Authorization)     →  401 again       a rejected password. THIS is the signal.
```

The first request never carries a credential; the second one does. So a `401` is only
evidence of anything once you know which of the two it answered — which means the response
has to be **matched back to its request**.

#### Matching a response to its request

| key | source | why |
|---|---|---|
| `Via` branch | copied verbatim by the responder | the transaction identifier of RFC 3261 §17.1.3 — exact, unambiguous |
| `Call-ID` + `CSeq` | fallback | for pre-3261 stacks still in the wild |

`CSeq` is part of the fallback key **on purpose**: a client retrying a password keeps one
`Call-ID` and increments `CSeq`, so keying on `Call-ID` alone would collapse an entire
guessing run into a single countable failure.

Only requests **carrying a credential** are remembered — a request without one is of no
interest, because the `401` it receives is the normal challenge. Each peer holds at most 64
pending transactions, pruned after 32 seconds (RFC 3261 Timer B/F, 64×T1, after which no
response can still be matched). The entry is **claimed on the first matching response**, so
a retransmitted `401` counts once.

#### The subject of the decision

A request is judged on whoever **sent** it. A `401` is evidence about whoever is
**receiving** it. The engine therefore returns the subject alongside the decision, and the
block lands on the party being challenged — never on the softswitch for having answered.

| constant | value | basis |
|---|---|---|
| `AUTH_FAILURES_TO_BLOCK` | 5 | the `maxretry` default of the `fail2ban` Asterisk jail |
| `AUTH_FAILURE_WINDOW_SECS` | 600 | its `findtime` default — a decade of field use behind both |

An accepted credential **clears the count**: someone who fixes a mistyped password is not
condemned by their next slip. Only an uninterrupted run is an attack.

Because it counts failures rather than volume, **a large NAT is not a problem** — a hundred
phones behind one address all succeed, and successes do not accumulate. That was a real
limitation of the rate-based rule this replaced.

#### The backstop, and why it must exist

The rule above needs the softswitch's answer, and there are deployments where it never
comes. Measured on the reference server: opensips drops requests addressed to a domain it
does not serve **without challenging them** — 1 outbound packet in 45 seconds against
hundreds inbound. A probe with a correctly addressed `REGISTER` was challenged immediately,
so the silence is a policy, not a fault.

There, the failure counter structurally cannot rise. So a volume backstop remains: **20
authenticated attempts in 60 s**, from the measured baseline of 2 challenges in 45 s of
legitimate traffic (~2.7/min, roughly 7× headroom). It is looser because it cannot tell
success from failure, only volume.

And when that condition is detected — credentials presented, not one digest challenge seen
— TFPS **says so on the report**. A rule that structurally cannot match, sitting silent, is
the exact `fail2ban` blindness this project exists to avoid.

## 6. Stage 7 — the method gate

`engine.rs:277`. After the perimeter, anything that is not an `INVITE` leaves as
`OutOfScope("not an INVITE")`. An INVITE with no user part in its Request-URI leaves as
`OutOfScope("INVITE with no dialled number")`.

IRSF is a *call* fraud. `REGISTER`, `OPTIONS`, `BYE` and the rest matter to the perimeter
and to the learning path, never to the fraud verdict.

---

## 7. Stage 8 — the dial plan: is this international?

`crates/tfps-core/src/dialplan.rs:70`, `to_international`. This is the load-bearing step,
and the reason is measured: **20.3% of destinations in the production corpus do not resolve
to a country without prefix stripping**, and country is the only behavioural feature that
survived measurement. An error here does not degrade a secondary signal, it degrades the
only one there is.

1. **Strip visual separators** — `-`, `.`, space, `(`, `)`. `+` is preserved: it is a
   prefix, not a separator.
2. **Longest-prefix match** against the peer's declared prefixes. Longest match resolves
   the classic ambiguity with no extra rule: a PBX using `0` for the national trunk and
   `00` for international yields `0212…` national and `00212…` international.
3. **No prefix matched** → if the peer is declared `bare_e164`, the whole string is taken
   as E.164; otherwise the call is **domestic for this peer** and leaves as out of scope.
4. **Digits only** — if anything non-numeric survives the prefix, it is not a dialable
   number and leaves as out of scope.
5. **Length** must be 7–15 digits (`E164_MIN_DIGITS`, `E164_MAX_DIGITS`; the upper bound is
   ITU-T E.164 §6.2.1).

`bare_e164` is an explicit per-peer flag rather than an empty string in the prefix list,
because the semantics are dangerous: with it on, `2125551234` is Morocco; with it off it is
a domestic US number. It should never be switched on by accident.

Prefixes are configured per peer in `/etc/tfps/config.json`, with a global default used for
undeclared peers. Declaring beats learning because a declaration holds on that peer's
**very first** call, instead of waiting for convergence. Learning still runs in parallel,
and disagreement is an alarm — because the error is asymmetric:

| error | effect |
|---|---|
| one prefix too many | harmless; it fails to canonicalise and drops out on its own |
| **a missing prefix** | **serious and silent** — the international call escapes the entire system and nothing reports it |

---

## 8. Stage 9 — which country?

`crates/tfps-core/src/country.rs:298`, `resolve`. A longest-prefix match of the digits
against a table of ~240 E.164 calling codes, each mapped to an ISO 3166-1 alpha-2 label
and a **stable numeric index**.

Longest match is required because the codes are 1–3 digits and overlap: `1246` is Barbados,
not the United States; `351` is Portugal and `355` is Albania, while `35` is nothing.

The index is written explicitly in the table and **never reassigned**. This is not
fussiness: the index is a bit position in bitmaps that are persisted for 45–90 days. Were
the index derived from array position, inserting one country would shift every subsequent
one and stored bitmaps would silently start pointing at the wrong country. A new country
takes the next free index regardless of where it sorts.

The table answers *"which country is this"*, not *"is this range allocated"*. Non-geographic
entries relevant to IRSF are included: `800` freephone, `808` shared cost,
`870`/`878`/`881`/`882`/`883` satellite and network services, and `979` — the only
legitimate international premium range under ITU-T E.169.2, which no observed IRSF case
uses, because that fraud is always hijacked *national* numbering.

**Unresolvable digits do not block.** They produce `UnknownCountry(digits)`, which prints
the digits so the operator can diagnose it, and is always visible even without `-v`,
because it is the leading symptom of a wrong dial plan — and a wrong dial plan means
international calls escaping the system entirely.

---

## 9. Stage 10 — novelty: has this caller ever called this country?

`crates/tfps-core/src/novelty.rs`. There is no statistical model here — no z-score, no
Isolation Forest, no negative binomial. The signal is set membership.

### The learning unit

The key is the pair **`(peer, A-number)`**: the peer anchors trust (non-forgeable), the
A-number groups behaviour (forgeable, taken from `From`; `<no-from>` when absent).

Forgeability is turned into signal rather than fought. An attacker who **rotates**
A-numbers explodes the pair cardinality on that peer, which is visible one level up. An
attacker who **reuses** one makes that pair accumulate history and falls under ordinary
novelty. Both branches lose. This is what makes wholesale tractable: the carrier has a
broad profile, each pair has a narrow one.

### The rotating bitmap

Per pair, two 256-bit bitmaps — 64 bytes total — plus a period marker:

| field | meaning |
|---|---|
| `current` | countries seen in the current 45-day period |
| `previous` | countries seen in the previous one |
| `period` | which period `current` represents (`now / ROTATION_SECS`) |

"Has seen this country" is the **union** of the two, giving an effective memory of 45–90
days. Rotation is lazy — it happens when the pair is touched (`rotate_to`), never by a
background sweep: if the period advanced by one, `current` becomes `previous`; if it
advanced by two or more, everything is discarded.

Keeping a timestamp per country would cost ~240 timestamps per pair and is unworkable at
millions of pairs. Two bitmaps cost 64 bytes, are **exact** (no sketch, no false positives)
and are only affordable because the alphabet has ~240 members.

Ageing is also what fixes a poisoned bootstrap: if the PBX arrived already compromised and
learning absorbed the fraud, the poisoned countries **age out on their own**.

### The predicate

> **A block requires ≥ 10 first-time countries for the same pair within 1 hour.**

| constant | value | basis |
|---|---|---|
| `NOVEL_COUNTRIES_TO_BLOCK` | 10 | fired 4 times in 2,829 account-days of the reference corpus, and those four windows were its most atypical |
| `WINDOW_SECS` | 3,600 | seconds are the scale of a signalling flood; days dilute the episode |
| `ROTATION_SECS` | 45 days | must exceed the 30-day learning mode, or the baseline never stabilises |

Both constants are **universal, not per customer**. The per-customer knob that nobody ever
tuned is exactly what killed the 2023 system.

**One first-time country never fires.** A country debut occurs on 0.85% of calls after
warm-up and 0.28% for a mature unit; blocking on a single debut would be a catastrophe.
The signal is *accumulation*.

The debut window is a ring of exactly 10 timestamps — sized to the predicate, since only
the last 10 debuts can matter. Debuts are rare, so the ring stays empty for the
overwhelming majority of pairs. It is deliberately **not persisted**: it covers one hour,
and a restart loses at most an hour of accumulation.

### Verdict

| condition | decision |
|---|---|
| country already in the bitmap, or fewer than 10 debuts in the window | `Pass { country, novel }` |
| ≥ 10 debuts **and** still in learning mode | `WouldBlock` — counted and printed, nothing blocked |
| ≥ 10 debuts and active | `Block` |

Learning mode lasts 30 days by default and is announced continuously, in the startup banner
and in every periodic report. The perimeter blocks throughout; only the behavioural layer
waits.

---

## 10. The ceilings, and what happens when they are reached

Rotating the A-number is *expected* attacker behaviour, so unbounded allocation would be a
denial-of-service vector described in the system's own specification. At ~150 bytes per
pair, an attacker at 1,000 INVITEs/s with unique A-numbers would fill 192 MB in about 20
minutes.

| ceiling | value | behaviour on reaching it |
|---|---|---|
| pairs per peer | 50,000 | prune pairs unseen for over an hour; if still full, refuse the new pair and count `pairs_dropped` |
| distinct peers | 10,000 | refuse the new peer and count `peers_dropped` |

The prune is the right shape for the attack: pairs seen once and never again — the exact
signature of A-number rotation — fall out on their own, while legitimate pairs that come
back survive. A refused pair still **passes**; what is lost is learning about that
A-number, not the integrity of the process. Both counters appear in the report, because a
non-zero `pairs_dropped` is itself the symptom of a rotation attack.

The ceilings also apply on restore from SQLite: persisted state cannot be used to walk
around the limit.

---

## 11. From verdict to enforcement

Three decisions condemn the source (`main.rs:500`):

| decision | reason label | detail |
|---|---|---|
| `Noise` | `user-agent` | the signature that matched |
| `Injection` | `injection` | the pattern that matched |
| `AuthFailure` | `auth-failed` | `rejected` |
| `AuthAbuse` | `auth-volume` | `no-answer` |

Condemning writes the source IP into an eBPF map with an expiry, prints a `BLOCKED` line
and appends a row to the SQLite audit log so the decision can be reconstructed later
without the journal.

`Block` (the behavioural verdict) is reported and counted; per `SPEC.md` §8 its enforcement
pairs an `XDP_DROP` with a forged `603 Decline` from userspace, since eBPF cannot construct
a packet — no helper builds a new frame, only rewrites or redirects one.

### The map, and two endianness conventions

`crates/tfps/src/xdp.rs:186`. TFPS prefers a drop map already pinned by another product
(`/sys/fs/bpf/sipvault/drop_ips`) and only loads its own program when there is none —
because **one interface holds one XDP program**, and detaching whatever is already there
would break someone's protection in production.

| backend | key encoding | source |
|---|---|---|
| shared pinned map | IP as **big-endian** `u32` | determined empirically against the production map by matching an IP fail2ban had banned — not assumed from source |
| our own map | raw `ip->saddr`, native order, no `ntohl` | our own convention, matching what the C program reads |

The value is an expiry in monotonic nanoseconds, or `0` for "never expires". Expiry exists
because a wrong block has to undo itself — nobody will be awake at 3 a.m. to unblock a
customer.

Attachment tries `XdpMode::Driver` (native) first and falls back to `XdpMode::Skb`
(generic). Generic runs after `sk_buff` allocation and costs more per packet, but it is
still **before** the libpcap tap, which is what matters for a clean sngrep.

### What the kernel program does (`ebpf/tfps_xdp.c`)

Per packet, in order: Ethernet header bounds → `ETH_P_IP` → IPv4 header bounds →
protocol 17 → IHL bounds (the verifier requires the check after the computation, since IHL
is sender-controlled) → UDP header bounds → **is either port in the `sip_ports` map?** If
not, `XDP_PASS`. Then: is the source in `blocked`? If not, `XDP_PASS`. If it is and the
expiry has passed, delete the entry, count `expired`, and `XDP_PASS` — unblocking happens
by itself. Otherwise count `dropped` and return `XDP_DROP`.

Two properties of that program are load-bearing:

- **The blast radius is limited to SIP ports.** An IP behind CGNAT can host a scanner and a
  legitimate user simultaneously; dropping everything from that address would take down SSH
  and the web for people who did nothing.
- **The map is `BPF_MAP_TYPE_LRU_HASH` with 65,536 entries.** It evicts the least recently
  used entry when full, which is a hard memory bound — the kernel side cannot grow without
  limit no matter what userspace does.

---

## 12. What the counters prove

Every counter exists to answer a question an operator would otherwise have to guess at.

| counter | question it answers |
|---|---|
| `packets` | is the tap alive at all? Zero triggers the silence alarm |
| `sip` / `responses` / `keepalive` | is what I am seeing actually SIP, and of what kind? |
| `not_sip` | **should be ≈ 0.** Anything else means a traffic family is not understood |
| `noise (%)` | how much of the wire is scanning — the number that predicts a clean sngrep |
| `injection` | attacks with no innocent explanation |
| `auth_att` | requests that carried a credential |
| `auth_fail` | credentials **rejected** — the brute-force signal |
| `auth_ok` | credentials accepted; a run of failures is cleared by one of these |
| `auth_chal` | digest challenges seen. **Zero with a non-zero `auth_att`** means the softswitch is not answering, so only the backstop can fire — and that is warned about |
| `auth_volume` | sources condemned by the volume backstop |
| `invites` / `intl` | the fraction of calls that reach the expensive path |
| `unknown_country` | **a wrong dial plan, or evasion by padding** — see the worked examples |
| `first_time` | country debuts; the measured reference is 0.85% of calls |
| `blocks` / `would_block` | enforcement, and what enforcement *would* have been during learning |
| `peers` / `pairs` | the size of the learning state |
| `pairs_dropped` / `peers_dropped` | non-zero means a ceiling was hit — the signature of A-number rotation |
| `XDP: dropped/seen/expired/in_map/blocked_by_us` | what the kernel side actually did; `blocked_by_us` is counted separately because in shared mode the map total is mostly its owner's work |

The alarms are requirements, not features: no packets on the watched ports; SIP present on
IPv6 or TCP that is therefore uninspected; and no user-agent signature matching in over
1,000 SIP messages (a rotten list).

---

## 13. Worked examples — real traffic, 2026-08-26

Captured on the test server with `tcpdump`, then traced through the code. The peer
`149.50.107.0/24` was running a campaign against the same handful of destinations, dialling
each one in **several formats**. The default plan applies: `["+", "00", "011", "9011"]`.

| # | Request-URI user part | prefix stripped | digits | resolution | decision |
|---|---|---|---|---|---|
| 1 | `00442039967796` | `00` | `442039967796` | code `44` → **GB** | international, novelty evaluated |
| 2 | `9011442039967796` | `9011` | `442039967796` | code `44` → **GB** | same destination, same verdict |
| 3 | `01118057022684` | `011` | `18057022684` | code `1` → **NANP** | international, novelty evaluated |
| 4 | `0014422006307` | `00` | `14422006307` | code `1` → **NANP** | international, novelty evaluated |
| 5 | `00014422006307` | `00` | `014422006307` | leading `0` matches no code | **UNKNOWN COUNTRY**, passes, printed |
| 6 | `00018316103425` | `00` | `018316103425` | leading `0` matches no code | **UNKNOWN COUNTRY**, passes, printed |
| 7 | `0021442039967796` | `00` | `21442039967796` | `214` is unallocated | **UNKNOWN COUNTRY**, passes, printed |
| 8 | `002118316103425` | `00` | `2118316103425` | code `211` → **SS** | international, novelty evaluated |

Rows 1 and 2 are the finding that matters: the *same* London number reached by two
different dialling formats from two addresses in one /24. That rules out "the PBX declared
its dial plan wrongly" as an explanation — a misdeclared plan is consistent, and this is
not. It is deliberate format variation.

Rows 5–7 are what padding buys the attacker today: the destination becomes
`unknown_country` and is not attributed to a country, so it contributes no country debut.
It is **loud** — printed on every occurrence without `-v`, 44 times for row 5 in one day —
but it is not, on its own, a block.

Row 8 is the case worth being explicit about. Padding `21` in front of a US number yields
digits beginning `211`, which is South Sudan's real calling code, so the call resolves to
**SS instead of NANP**. The country attribution is wrong. The effect on the verdict is
not, however, an escape: a country the pair has never called is a *debut*, so a padded
destination feeds the accumulation predicate rather than avoiding it. What is corrupted is
the label in the audit log, not the defence.

### The authentication rule, verified against a live softswitch

Five `REGISTER`s carrying a deliberately wrong credential, sent to the reference server's
opensips, which challenged each one. Observed by a second TFPS instance running
`--no-enforce`, so nothing was actually blocked:

```
AUTH FAILURES peer=209.38.75.252 rejected_credentials_in_window=5
```

The same server, on its live internet traffic, reports `auth_att=5 auth_fail=0 auth_ok=0
auth_chal=0` — credentials presented, not one challenge answered — and warns that failed
authentication blocking cannot fire there. Both facts are true at once, and the report says
so rather than implying protection it does not have.

For contrast, the same period's perimeter activity:

```
BLOCKED peer=108.178.17.26  reason=user-agent detail=friendly ttl=3600s
BLOCKED peer=212.83.170.244 reason=user-agent detail=pplsip   ttl=3600s
```

Two scanners condemned by signature. From that moment their packets die in XDP and
disappear from sngrep for an hour.

And the traffic mix that same hour, which is the argument for counting keepalives
separately:

```
--- mode=LEARNING (29d 15h left) packets=1879 sip=768 responses=0 keepalive=1110
    not_sip=1 noise=12 (1%) injection=0 auth_att=60 auth_abuse=0 invites=435 intl=389
    unknown_country=103 first_time=123 blocks=0 would_block=0
    peers=11 pairs=266 ports={5060: 1878, 5353: 1}
```

59% of the packets were NAT keepalives. Had they been counted as `not_sip`, the operator's
reasonable conclusion would have been that the capture was broken.

---

## 14. What is never detected

Documented, not engineered away. A limitation stated plainly is worth more than a promise
that fails quietly.

| not detected | why |
|---|---|
| **SIP over TLS** | the payload is encrypted; nothing above L4 is readable. Only metadata and IP reputation remain |
| **SIP over TCP** | L7 reassembly inside XDP is unworkable; the packets are counted as a blind spot, never parsed |
| **IPv6** | the capture socket takes `ETH_P_IP` only; counted and warned about, never inspected |
| **later fragments** | carry no L4 header, so there are no ports to match; counted |
| **traffic on undeclared ports** | not examined and not counted — declaring the ports is the operator's job |
| **a customer with a broad international profile** | novelty saturates by construction: a peer that already calls 200 countries has no debuts left to accumulate. A minority of customers, the majority of the loss |
| **the first 30 days of fraud** | learning mode, by design and announced continuously |
| **a PBX already compromised at install time** | partially: the day-31 confirmation and 45-day bitmap ageing are the two defences, and neither is complete |
| **Chain B** (credentials stolen through provisioning) | the precursor is an HTTP fetch, outside the SIP plane entirely |

---

## Source map

| stage | file | entry point |
|---|---|---|
| capture socket, main loop | `crates/tfps/src/main.rs` | `main`, line 411 and 455 |
| IPv4/UDP decode | `crates/tfps-core/src/net.rs` | `parse_ipv4_udp:85`, `classify_other:59`, `tcp_ports:44` |
| SIP parse | `crates/tfps-core/src/sip.rs` | `parse:158`, `parse_request:197`, `parse_response:170` |
| perimeter | `crates/tfps-core/src/perimeter.rs` | `is_noise`, `injection_in_uri`, `SlidingCount::record` |
| orchestration and verdict | `crates/tfps-core/src/engine.rs` | `observe_packet`, `observe_response`, `decide` |
| dial plan | `crates/tfps-core/src/dialplan.rs` | `to_international:70` |
| country | `crates/tfps-core/src/country.rs` | `resolve:298` |
| novelty | `crates/tfps-core/src/novelty.rs` | `PairState::observe:192`, `RotatingBitmap::rotate_to:80` |
| enforcement (userspace) | `crates/tfps/src/xdp.rs` | `attach:75`, `load:120`, `block:186` |
| enforcement (kernel) | `ebpf/tfps_xdp.c` | `tfps_filter` |
