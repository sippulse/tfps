# TFPS — Architecture specification

IRSF fraud prevention for SIP networks. Rust + eBPF, no policy configuration, offline, open source.

This document is the **destination** of the map in `.scratch/tfps-next/`. It consolidates thirteen locked decisions; each one has a ticket with the full rationale, referenced alongside. What is here is the **what**, not the **why** — go to the ticket when you need the latter. The vocabulary lives in `CONTEXT.md` and is normative.

---

## 1. What the system is

A Rust binary that runs **on the softswitch host**, observes SIP traffic by packet capture, learns each source's normal behaviour, and blocks anomalous international calls in real time.

**What it is not**: not a proxy, not a B2BUA, it does not speak SIP beyond forging responses, it has no cloud, it consults no external service to decide, it has no fraud list, it has no statistical model.

**The case it exists to solve**: the **compromised downstream PBX** — the one where the attacker already holds a valid credential, the traffic arrives authenticated from the usual IP, and every perimeter signal is clean. That is where `fail2ban` and APIBAN are structurally blind: the first counts authentication failures that never happen, the second checks the reputation of an IP that belongs to the customer.

**Scale target**: wholesale. `[ticket 11]`

---

## 2. Topology and deployment `[ticket 06]`

- **On the softswitch host itself.** Bump-in-the-wire and mirrored ports are out of scope.
- **Capture without binding.** XDP and/or `AF_PACKET` hook into the netdev and **do not open the UDP socket**. The softswitch keeps its bind; there is no port conflict and nothing already running needs reconfiguring.
- **Promiscuous mode is not required** — the traffic is already addressed to the host.
- **Captured ports are declared**, default `5060/UDP`, multiple accepted (a wholesale requirement, where 5060/5080/5061 coexist). A port map read by the XDP program.
- **Kernel floor: ≥ 5.15**, ideally ≥ 6.2. Check RHEL/Rocky/Alma 9, which ships 5.14 with backports.
- **Tooling: `aya`.** `redbpf` has been archived since 2023.

### Fail-open, structurally

**The eBPF program is not pinned to bpffs.** With no pin, the refcount drops when the loading process dies and the kernel detaches on its own — fail-open **by construction**, not by error-handling code that can carry a bug.

Telephony down is worse than fraud getting through. But the system **shouts** when it stops.

---

## 3. The path of an INVITE

```
packet on a captured port
   │
   ├─ perimeter (XDP) ──── known noise? ──► XDP_DROP, total silence
   │                       (user-agent, IP, rate)      [never answers]
   │
   ├─ event to userspace over a ring buffer (always, even when dropped)
   │
   └─ Rust userspace
        │
        ├─ does it match one of the peer's declared international prefixes?
        │     └─ NO ──► out of scope, pass. Done.        ◄── cheapest filter
        │
        ├─ strip the prefix, canonicalise (libphonenumber), resolve the country
        │
        ├─ learning mode on? ──► record, do not block
        │
        └─ country never seen for the pair (peer, A-number)?
              │
              ├─ NO ──► pass
              └─ YES ──► count the pair's first-time countries in the 1h window
                          │
                          ├─ < N ──► pass
                          └─ ≥ N ──► XDP_DROP the INVITE
                                     + userspace forges a 603 Decline
```

**Two properties of this flow:**

The **prefix filter comes before everything else** and is the cheapest operation there is. At a carrier whose traffic is mostly domestic, most calls leave through there without ever being canonicalised. **The system's cost scales with international volume, not with the total.**

The **decision path holds no dialog state**. `[ticket 09]` Duration and outcome are after the fact and belong to the learning path, which is asynchronous and **can lose events without compromising protection**.

---

## 4. Canonicalisation `[ticket 12]`

**Why it is critical**: 20.3% of the destinations in the production corpus do not resolve to a country without prefix stripping — and country is the **only** behavioural feature that survived measurement. Getting this wrong does not degrade a secondary feature; it degrades the only one there is.

**A list of international prefixes per switch**, declared, with **longest match**:

```json
{ "peers": { "10.0.0.5": { "intl_prefixes": ["+", "011", "9011", "00", ""] } } }
```

An empty entry `""` = the peer sends plain E.164, common in wholesale.

Longest match resolves the classic ambiguity on its own: a switch using `0` for the national trunk and `00` for international yields `0212…` national and `00212…` international.

**Validation: `libphonenumber`** — Apache-2.0 **including the metadata**, therefore embeddable. And `isValidNumber` **is not a format check: it is a statement about the allocated range** (*"a valid number range is one from which numbers can be freely assigned by carriers to users"*), reproducing the commercial baseline of the NDSS paper (72.3%/27.7% against 70.0%/30.0%).

### Declare, learn in parallel, complain on disagreement — a **requirement, not a refinement**

The error is **asymmetric**:

| error | effect |
|---|---|
| one prefix too many | harmless — it does not canonicalise to a valid country and drops out by itself |
| **a missing prefix** | **serious and silent** — the international call escapes the entire system and nothing flags it |

The second is the `fail2ban` failure mode this project uses as its differentiator. Therefore: dial-plan learning runs all the time, in the background, and **shouts** if it sees traffic that looks international under a prefix that is not on the list.

### What does not canonicalise is never blocked

**IRSF is, by definition, international.** An internal extension, a service code, a short number, a SIP URI — if it does not resolve to international E.164, it **is not the system's business and passes**. That is not a failure; it is out of scope.

Blocking on a canonicalisation failure would repeat **R07** of the Java TFPS, which denied everything it could not classify and became **39% of all rejections** — the largest source of blocking was ignorance, not detection.

"Not canonicalisable" is **a novelty category of its own**: a peer that always sends clean numbers and starts sending garbage is anomalous.

---

## 5. Learning unit `[ticket 09]`

**Hierarchical key `(peer, A-number)`.**

The trustworthy key and the useful key are opposites. The **A-number is forgeable** — a text field in `From`. The **peer's IP is not**: over UDP it could be spoofed, but the SIP response would not come back and the call would not complete. Except that the peer is the **broad-profile** entity, which saturates every behavioural signal.

By anchoring on the peer and grouping by A-number, **forgeability becomes signal**:

- whoever **rotates** A-numbers blows up the cardinality of new A-numbers on that peer — detected one level up;
- whoever **reuses** an A-number makes that pair accumulate history and falls under ordinary novelty.

The attacker loses on both branches. This is what makes wholesale tractable: the carrier has a broad profile, **each pair has a narrow one**.

---

## 6. The signal `[ticket 10]`

**There is no statistical model.** No Isolation Forest, no Random Forest, no z-score, no negative binomial. Only **novelty detection** — set membership.

### Structures

| structure | where | size | content |
|---|---|---|---|
| **rotating bitmap** | per pair `(peer, A-number)` | **64 bytes** | two 256-bit bitmaps: countries seen in the current period and in the previous one |
| **frequency distribution** | per peer | ~200 counters | how many calls per country — the prior |
| dial plan | per peer | small | declared + learned prefixes |

A million pairs ≈ **64 MB**. The bitmap is **exact**, with no sketch and no false positive — possible only because the alphabet holds ~200 countries.

### Blocking predicate

> **Count of first-time countries for the pair, within a 1-hour window, ≥ N.**

- **Window = 1 hour** — a universal constant, derived from the physics of the fraud: seconds are the scale of a signalling flood, days dilute the episode.
- **N = 10** — a universal constant in v1. It fired **4 times in 2,829 account-days** in the measurement, and those four windows were the most atypical in the corpus.

**A single first-time country does not fire**: a country debut happens in **0.85% of calls** after warm-up (0.28% on a mature unit). Blocking that would be a catastrophe. The signal is **accumulation**.

Both constants are **universal, not per customer**. The species of number that killed the 2023 TFPS was the per-customer one nobody ever tuned.

### Prior for a new pair

Inheriting the peer's **entire** country set would not work — a wholesale peer calls 200 countries and saturation would be back.

- **mature pair** → is the country in its bitmap? an exact lookup;
- **new pair** → how common is this country **for the peer**? Common does not surprise; rare does, even with no history of its own.

The weight migrates continuously from the peer to the pair. This is hierarchical shrinkage (**Rubin, 1981**), and the prior comes from the **parallel units of the installation itself** — no cloud required.

### Ageing

Every `T` = **45 days**: discard the previous bitmap, promote the current one, zero the new one. Effective memory of 45 to 90 days. `T` must be larger than learning mode.

**The effect that solves poisoned bootstrap**: if the PBX arrived already compromised and learning absorbed the fraud, the poisoned countries **age out on their own — the system heals itself**.

### v1 features, a closed list

Destination country, hour of day in **24 learned categories** (the evidence from both papers is that this beats any notion of "business hours" — AUC 0.96 against 0.92 — and "fraud happens at night" is a property of a dataset, not of the phenomenon), peer, A-number. From the learning path: duration and outcome.

**Out, with the reason**: range novelty (would demand sketches to sustain an unmeasured bet); distance to test IPRN, dispersion digit, `IRSF likelihood` (all require a corpus); `Test call ratio` and `spreadness` (require test-call logs that do not exist); burst and fan-out ratio (**refuted by measurement** — see `CONTEXT.md`).

---

## 7. Perimeter

**It does not exist to catch fraud. It exists to stop garbage contaminating the behavioural baseline.** If scanner traffic feeds a pair's baseline, the model learns that a burst to an odd destination is normal there, and the defence poisons itself.

Sources: a list of user-agents and IP ranges in the JSON; rate; optionally APIBAN. Active **from installation**, without waiting for learning.

**Observing and dropping happen in the same XDP program** — the event goes to the ring buffer **before** the `XDP_DROP`, so that the silence does not blind the sensor itself.

---

## 8. Enforcement `[ticket 07]`

**Two verdicts in v1: block or pass.** No challenge.

| case | eBPF | userspace |
|---|---|---|
| scanner / perimeter | drops | **nothing — total silence** |
| fraud, legitimate customer | drops | forges `603 Decline` |
| clean | passes | nothing |

### The perimeter stays quiet, fraud gets an answer

Any response to a scanner — `403`, `404`, even `401` — confirms a live SIP endpoint and invites escalation; differentiated responses still leak extension enumeration. But silently dropping a **legitimate customer** costs 32 seconds of retransmission under RFC 3261's A/B timers, and the product's central case is a paying customer, where silence looks like an outage.

**Exception**: **decoys answer deliberately.** Silence protects the production surface; an answer feeds the trap. Different surfaces, different roles.

### Drop-then-forge

XDP **drops** the INVITE and userspace **forges** the response through a raw socket (`CAP_NET_RAW`). This **eliminates the race** against the softswitch instead of trying to win it. RFC 3261 §17.1.3 makes the forgery mechanical: the response reuses the INVITE's own `Via`/`branch`, `From` tag, `Call-ID` and `CSeq` — only the `To-tag` and `Contact` have to be generated.

**eBPF cannot create a packet from scratch** — no helper builds a new frame, only rewrites or redirects. Hence the forgery lives in userspace.

---

## 9. Lifecycle

**Layers with different activation dates:**

| layer | active on |
|---|---|
| perimeter | minute 1 |
| behaviour | **day 31** |

For those 30 days the behavioural layer **observes and does not block**, and the system **announces that the whole time**. Novelty warm-up stabilises in 7 days; 30 is conservative.

**Day 31 is the product's only human interaction** — a confirmation, not configuration:

> *"Over these 30 days I saw traffic to these N countries, with this pattern. Turn protection on with this baseline?"*

It is the defence against a PBX that arrived already compromised. One question in the lifetime of the product is not continuous configuration. Cost on the record: it is friction, and friction was identified as the cause of death of the 2023 TFPS — if production shows it kills adoption, the alternative is to activate automatically and **offer** the review instead of demanding it.

---

## 10. Persistence `[ticket 06]`

**SQLite. One file.** No server, no daemon, no credential, no port.

Two reasons beyond simplicity: it is genuinely zero configuration — the 2023 TFPS had a MySQL password in clear text at six points of the generated `.cfg`; and **the operator can open it and see what the system learned**, which in a product that is silent by design separates "I trust this" from "I don't know whether it works". Precedent: SentryPeer does the same.

**It is durable storage, not the hot path.** The working set lives in memory, loaded at boot, checkpointed periodically. Querying SQL per INVITE would be a write bottleneck at wholesale scale.

**State split**: **perimeter** state dies with the process and rebuilds itself in minutes from the traffic — consistent with fail-open by not pinning. **Behavioural** state, 45 to 90 days old, survives on disk.

**One exception, and it is named here rather than argued in a code comment**: the APIBAN feed. It is perimeter state, but it does **not** rebuild itself from traffic, because it is consumed through a forward-only cursor — a restart that remembered the cursor but forgot the addresses would come back protecting nothing while reporting itself healthy. Feed addresses are therefore persisted and re-applied for 7 days. Everything else in the perimeter still dies with the process.

The block audit log goes straight there, being low volume.

---

## 11. Configuration

**Nothing is mandatory.** An optional JSON that ships with the product:

| field | category | mandatory |
|---|---|---|
| captured ports | installation | no (default `5060/UDP`) |
| international prefixes per peer | installation | no (learned in parallel) |
| noise user-agents and IP ranges | product data | no |
| APIBAN key | optional integration | no |
| structural regex for the operation | override | no, **empty by default** |
| `ignoreip` — sources never enforced against | enforcement scope | no, **empty by default** |

**Normative distinction**: **installation** configuration tells the system *where to look and how to read*; **policy** configuration would say *what fraud is*. The first is admitted, the second **does not exist in this product**. The fourteen knobs of the 2023 TFPS `defines.m4` have no equivalent here.

**`ignoreip` is admitted as a third category**, and the distinction is load-bearing. Policy configuration would say *what fraud is*; `ignoreip` says *who this system may act against*. An exempt source is still evaluated, still counted, and still reported — the entry changes enforcement scope, never a verdict. That is what separates it from R07: a destination whitelist decides that a call is not fraud, while this decides that a peer is not ours to punish.

Two constraints keep it from becoming policy by the back door: **`0.0.0.0/0` is refused**, since one line that disables enforcement without saying so is precisely the silent failure §12 exists to prevent (`--no-enforce` does it explicitly and announces it in every report); and **every entry counts its hits**, so an exemption that has matched nothing is reported as cold, like any other rule.

The **host's own addresses are always exempt and are not configuration at all** — they are discovered from the machine. This exists because it happened: a brute-force verification fired from the softswitch host and the system condemned the address it was defending.

**The override regex** serves a structural rule specific to the operation (*"our traffic never goes to satellite"*), **not** a destination whitelist — that last one is R07 with different syntax. If filled in, the system **reports each pattern's hit rate**: a regex that matches zero times in three months has rotted and the user needs to know.

**APIBAN**, if configured: synchronised in the **background** through the incremental API, feeding a local map. **Never queried per INVITE** — that was the fatal bottleneck of 2023 (synchronous `rest_get()` with no cache, a ceiling of ~26 INVITEs/s, a third party's outage freezing everything). The system runs on a stale list if the network drops.

---

## 12. Observability — requirements, not features

The project's declared differentiator against `fail2ban` is that **the incumbent fails silently and you never find out**. Three facts sustain that: Asterisk's security channel ships disabled, so `failregex` #6 never matches on a default installation; PJSIP does not log below 5 requests in 5 s, creating an attack rate that is invisible by construction; and no version of fail2ban has ever warned about a filter matching zero lines.

**This system cannot repeat that.** These are requirements:

1. **Silence alarm.** If it stops seeing traffic, stops firing entirely, or cannot canonicalise anything — it **shouts**.
2. **Dial-plan disagreement.** International traffic under an undeclared prefix — it **shouts**.
3. **Hit rate as a thermometer.** Reference: 0.85% of calls with a country debut after warm-up, 0.28% on a mature unit. Far above is an attack **or** a broken model; far below is blindness.
4. **Regexes and lists that match zero** — reported.
5. **Every block records why**, legibly: which unit, which country, when that unit last called there.
6. **Manual unblocking is the precision proxy.** With no labels it is the only measure available: if the operator never unblocks, precision is probably good.
7. **Which mode it is in** — learning or active — visible the whole time.

### The user's first success

**A clean sngrep.** A packet dropped in XDP never becomes an `sk_buff` and therefore **does not show up in sngrep, tcpdump or tshark** — libpcap hooks into `AF_PACKET`, at netdev level, after XDP. The user installs it, opens sngrep, and the garbage is gone. There need be no fraud, the model need not fire, no dashboard is needed.

This is the product's retention hook, and it **discriminates against nftables**, whose drop happens after the `AF_PACKET` tap and would keep polluting the capture.

The developer's estimate, **to be measured and not presumed**: ~90% of the noise removed by user-agent, +9% by authentication failure, ~99% in total with APIBAN. `[ticket 17]`

---

## 13. Out of scope, and known limitations

The project **makes no promise to whoever downloads it**. A known limitation is **documented, not engineered away**.

| limitation | nature |
|---|---|
| **A customer with a broad international profile** | novelty, fan-out and rate **saturate by construction**; no behavioural signal fires. A minority of customers, the majority of the loss. |
| **SIP over TLS** | cryptographic blindness to the content. Metadata only. Enforcement by IP reputation still works. |
| **SIP over TCP** | L7 reassembly inside XDP is unworkable; delegate to userspace or do not support it in v1. |
| **30 days with no behavioural blocking** | by design, announced. |
| **A PBX already compromised at install time** | two partial defences: the day-31 confirmation and bitmap ageing. |
| **Chain B** (credentials stolen through provisioning) | the precursor is in HTTP, outside SIP. `[ticket 13]` |

**Out of scope by decision**: Wangiri; subscription fraud and SIM boxes; rewriting the SIP stack; bump-in-the-wire and mirrored ports; a corpus of fraud numbers; cloud; captcha challenge.

---

## 14. Deferred to production

None of this blocks v1. All of it is decided with data, not with discussion.

- **A predicate relative to the peer** instead of a universal `N` — calibrated against the measurement in ticket 17.
- **SPRT / Threshold Random Walk** — evidence per call instead of per window. No precedent in telecom.
- **Range novelty** — only if measurement justifies the cost of sketches.
- **Format variation as a signal** — falls out of the learned dial plan for free; measure before building.
- **Concurrency throttling and duration cutoff** — if production reveals an ambiguous middle that is not foreseeable today.
- **Local honeypot**, **collaborative telemetry**, **precursor chain**. `[tickets 13, 14, 16]`
- **Packaging, licence, verified kernel floor.** `[ticket 15]`

---

## 15. The principle that ties it together

The 2023 TFPS was a good attempt. **Had the parameters been dynamic, it would have worked** — `params_training.sql` already computed µ+2σ per account over 90 days, but **never applied it**, and the four columns it read did not exist in the table. The `TODO-LIST` had two lines, one of them `Auto-Training`.

What killed it was **friction** and **lack of focus** — and the second is measurable in the audit: `globalblacklist` with 18,033 numbers loaded and never queried; `ip_blacklist` with 2,129 IPs and no consumer; `countries.risk` for 231 countries with no consumer; z-score commented out; STIR/SHAKEN commented out; a daily quota made unreachable by a `route()` sitting outside the `if`.

**A half-built machine everywhere.**

This spec cuts the corpus, the cloud, the statistical model, the challenge, range novelty and the telemetry collector — not out of modesty, but because **a system with no model has no half-built model**.
