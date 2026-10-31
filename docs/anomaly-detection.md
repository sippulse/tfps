# Behavioural detection for IRSF

How TFPS decides that a source is committing **International Revenue Share Fraud** when
there is no labelled corpus, the decision must be made in real time, and every block has to
be explainable. This is the design behind the `--behavioural` layer. The perimeter (noise
reduction) is a separate, always-on product and is not covered here.

**Status.** Opt-in and **highly experimental**. By default the behavioural verdict is
computed and **report-only**. With `--enforce-behavioural` (or `"enforce_behavioural": true`)
a `Block` writes the source into XDP for `block_ttl` and logs `BLOCKED ... reason=behavioural`;
the forged SIP `603` is **not wired yet**. The perimeter enforces normally regardless.
Vocabulary is normative in [`../CONTEXT.md`](../CONTEXT.md); this document is the design and
operator guide.

> **At a glance.** Four non-negative arms are fused in nats: **dialling prefix**, **destination
> range**, **completion**, **volume**. Firing needs `ln((1−β)/α)` = **9.21 nats** with the
> shipped defaults. Learning mode is 30 days; in it the layer prints `WOULD BLOCK` and blocks
> nothing. Country is tracked for reporting, not fused. By default a `BLOCK` line is a
> verdict; with `--enforce-behavioural` it becomes an XDP source block. The forged `603` is
> not wired.

## Quick start: enable the behavioural block

The block is **opt-in**. Nothing in the perimeter changes when you enable it; it adds a
second, learned layer.

**1. Configure the installation.** The two fields that matter most are the dial plan and
your own country:

```json
{
  "behavioural": true,
  "enforce_behavioural": false,
  "intl_prefixes": ["+", "00", "011", "9011"],
  "home_countries": ["BR"],
  "learn_days": 30,
  "ignoreip": ["10.0.0.0/8"]
}
```

The same from the command line:

```sh
tfps --behavioural                 # 30-day learning window, report-only
tfps --behavioural --enforce-behavioural  # block the source after learning
tfps --behavioural --active --enforce-behavioural  # skip learning; do not do this on day one
```

**2. Get the prerequisites right, in this order.**

1. **`intl_prefixes`** — the layer only reasons about **international** calls. Wrong
   prefixes make extensions and inbound E.164 DIDs look international. Declare per-peer
   plans where PBXs differ; use `bare_e164` for wholesale.
2. **`home_countries`** — your own country/countries. Otherwise your own inbound DIDs look
   like new international destinations.
3. **`ignoreip`** — inbound gateways and trusted carriers. They are still evaluated and
   reported; the exemption only withholds enforcement.

**3. Read the learning window.** For 30 days it prints `WOULD BLOCK` and does not block.
Each line has source, country, evidence and distinct destinations. Investigate every line
before day 31. A new source also has its own **24 h / 20 international call** warm-up and
prints `WARMING`.

**4. After learning.** The verdict is printed as
`BLOCK (report-only, not enforced)` unless `--enforce-behavioural` (or
`"enforce_behavioural": true`) is set. With it, the source is written into XDP for
`block_ttl` and logged as `BLOCKED ... reason=behavioural`; the forged SIP `603` is still
missing. `tfps_ctl stats` shows the traffic counters and the `CALIBRATION` line. See §11 for
the full operator routine and §6 for the enforcement path.

**5. Disable it.** Remove `--behavioural` / set `"behavioural": false`. The learned state
stays on disk, unused; it can be deleted with `tfps_ctl forget <peer>` (daemon stopped).

For spoofable one-way perimeter evidence, keep `--no-enforce-one-way` (or
`"no_enforce_one_way": true`) on. It does not change the behavioural detector; it keeps
request-only perimeter verdicts report-only.

## Contents

- [Quick start: enable the behavioural block](#quick-start-enable-the-behavioural-block)
1. [What it decides, and about whom](#1-what-it-decides-and-about-whom)
2. [Why behaviour, and why these signals](#2-why-behaviour-and-why-these-signals)
3. [Where it runs in the pipeline](#3-where-it-runs-in-the-pipeline)
4. [The four arms](#4-the-four-arms)
5. [The statistics, exactly](#5-the-statistics-exactly)
6. [Learning mode and what “BLOCK” means today](#6-learning-mode-and-what-block-means-today)
7. [State, persistence, restart](#7-state-persistence-restart)
8. [Self-calibration](#8-self-calibration)
9. [Observability](#9-observability)
10. [Performance and memory](#10-performance-and-memory)
11. [Operator guide](#11-operator-guide)
12. [Limitations, stated](#12-limitations-stated)
13. [Code map](#13-code-map)
14. [Tests: what is pinned](#14-tests-what-is-pinned)
15. [References](#15-references)
16. [Disclaimer](#16-disclaimer)

---

## 1. What it decides, and about whom

The unit is the **source IP — the peer**. It is the only identity observable without
trusting SIP headers, but it is **not non-forgeable**: UDP source addresses can be spoofed,
and enforcement depends on ingress filtering (see §12). The A-number is forgeable and is
deliberately **not** a key: keying on
`(peer, A-number)` let an attacker rotate A-numbers to escape a learned profile. Behaviour
is therefore learned per source, and the source is the only thing a verdict can be attached
to.

For each **international call attempt** (an `INVITE`) the engine issues one of:

| decision | meaning |
|---|---|
| `Pass` | international, not enough evidence; carries the country and whether it was a country first-contact |
| `WouldBlock` | evidence crossed the bound, but the layer is still in learning mode |
| `Block` | evidence crossed the bound, in active mode |
| `UnknownCountry` | international by shape, no country resolved — **never a block** |
| `OutOfScope` | not SIP, not an INVITE, not international, home country, or behavioural off |

The design vocabulary also contains **Challenge** (voice captcha/PIN instead of deny). The
current engine does not emit it; the response path that would issue it is not built.

Two properties of the flow are structural:

- **The perimeter runs first.** Scanning, injection, brute force, known tool user-agents and
  the APIBAN feed are removed before behavioural state is touched, so noise cannot poison a
  source's baseline.
- **The decision path keeps no dialog state.** `BYE` and duration are post-call data and
  belong to the learning path; the verdict is issued about the attempt. The one exception is
  the short-lived transaction table that matches a final response to an INVITE for the
  completion arm: 32 seconds, 32 entries per peer, no dialog reconstruction.

---

## 2. Why behaviour, and why these signals

IRSF, as it actually happens (field description, confirmed against live traffic):

1. A fraudster partners with an **IPRN** (International Premium Rate Number) provider and is
   given ranges.
2. From **one IP**, they scan the internet for an exploitable PBX or open route.
3. From **another IP**, they generate calls, probing destinations to find one that routes
   through a partner ITSP, which **short-answers** the call (bills minutes without
   terminating to the real carrier) and shares the revenue.
4. The destination numbers are **invalid in the real country** — "the call never came here,
   and this number is invalid in our country." Invalid ranges are used *deliberately*:
   for a valid destination, LCR has many competing carriers and the partner rarely wins; for
   an unallocated range, the partner is one of the few advertising a route, so it reliably
   wins.

Two empirical findings shaped the method:

- **The B-number cannot be classified statically.** A real libphonenumber port
  (`phonenumber` 0.3) was tested on classic IRSF destinations: `+37122123456` (Latvia),
  `+25261234567` (Somalia), `+63280000000` (Philippines) all return `valid=true`, typed as
  ordinary `Mobile`/`FixedLine`; meanwhile a genuine UK range returned `valid=false`. Neither
  validity nor number-type separates fraud from legitimate traffic. Detecting the individual
  bad number is a dead end.
- **The signal is behavioural, and it has three phases.** *Target discovery* — SIP scanning
  for an exploitable PBX; this belongs to the perimeter. *International-completion
  discovery* — learning which outbound format the PBX or route accepts (`00`, `011`, `9011`,
  `+`). *Premium-destination discovery* — probing many B-number ranges to find the one that
  routes through the partner. Exploitation is a volume spike to the route that was found.

The constraints eliminate most of the anomaly-detection field:

| requirement | consequence |
|---|---|
| no labels (no corpus) | unsupervised only; no supervised ML, no neural nets |
| real-time enforcement | score and decide within call setup; no batch inference |
| must explain every block | no black box; the decision has to be a stateable quantity |
| per-source, heterogeneous population | a carrier and a small PBX cannot share one threshold |
| cold-start safety | a rare caller's first few calls must not false-positive |
| count/rate data, bursty | count-native models (Poisson/Negative Binomial), not Gaussian |
| thousands of sources in 192 MB | a few floats per source; no stored reference sets |

That rules out autoencoders/LSTM/VAE (labels, opacity, no cold start), kNN/LOF (stored
reference set, O(n) per query), PCA/subspace (batch, overkill for a handful of features),
and batch Isolation Forest. Their streaming cousins (RRCF — Guha et al., ICML 2016;
Half-Space Trees) are real but not naturally per-source and are harder to interpret.

---

## 3. Where it runs in the pipeline

Stages 1–9 are described in [`../DETECTION.md`](../DETECTION.md). Behaviour starts after
them:

```
capture → IPv4/UDP → port gate → SIP parse → perimeter → method gate
        → dial plan: is this international for this peer?
        → canonicalise → country resolve
        → home country?            (national, out of scope)
        → behavioural arms (four)  → Pass / WouldBlock / Block
```

Details that matter:

- **International is decided by the peer's dial plan**, not by string shape. A source may
  declare its own prefixes; otherwise the global list applies. `bare_e164` covers wholesale
  peers that send plain E.164. Matching is longest-prefix, so `9011` beats `011`.
- **Visual separators** (`-`, `.`, space, parentheses) are stripped; `+` is a prefix, not a
  separator. A non-digit left after the prefix means "not dialable" → out of scope.
- **E.164 length gate**: 7–15 digits after the prefix. Outside it: out of scope.
- **Home countries** (`home_countries`) are national, not international, even when the
  number arrived as `+E164`. This is what stops an inbound call to the operator's own DID
  from being judged as a new international destination.
- **Unknown country** is counted and reported (`UNKNOWN COUNTRY … digits=…`) and **never
  blocked**. That is the R07 lesson: never condemn what you cannot classify.
- **A-number is ignored** for state. The `From` header is attacker-controlled.
- **Exemptions are enforcement gates, not evaluation filters.** `ignoreip` and registered
  peers are consulted by `disposition` when a block is enforced. The behavioural verdict is
  computed for every source, exempt ones included; with `--enforce-behavioural` the
  `ignoreip` gate is applied (and logged as `EXEMPT`), while a registered peer still does
  not bypass the layer's own evidence.

---

## 4. The four arms

All arms are per source. Three are sequential tests that accumulate evidence over calls; one
is a count-rate change detector. Their evidence is non-negative and adds.

```
                    one international INVITE
                              │
        ┌─────────────────────┼──────────────────────┐
        │                     │                      │
  dialling prefix       destination range      (final response)
        │                     │                      │
   SPRT Λ_prefix         SPRT Λ_range          SPRT Λ_completion
        │                     │                      │
        └─────────────────────┼──────────────────────┘
                              │            volume: Gamma-Poisson surprise
                              │                      │
                              └──────────┬───────────┘
                                         ▼
                    fused = Σ max(0, Λ_arm) + volume_bits · ln 2
                                         │
                              fused ≥ 9.21 nats ?
                                         │
                         Pass / WouldBlock / Block
```

### 4.1 Dialling-prefix discovery — Threshold Random Walk

**Phase:** "how do I get out?" Before sending real traffic, the fraudster tests which
outbound format the compromised PBX or route accepts: `00`, `011`, `9011`, `+`, sometimes a
technology prefix in front.

Each international call is a Bernoulli trial: was the **dialling prefix** one this source
has never used? A legitimate PBX settles on one format; probing four formats is
first-contact after first-contact. The alphabet is small, so membership is an exact 64-bit
bitmap keyed by a 64-bit FNV-1a hash of the prefix string. A hash collision can only make a
novel prefix look seen — a false negative, which is the safe direction.

The walk is the standard **Threshold Random Walk** (Jung, Paxson, Berger, Balakrishnan,
*Fast Portscan Detection Using Sequential Hypothesis Testing*, IEEE S&P 2004), an
application of **Wald's Sequential Probability Ratio Test** (Wald, 1945):

```
Λ ← Λ · decay(dt)
on a novel prefix:  Λ += ln(θ₁ / θ₀_prefix)
on a known prefix:  Λ += ln((1−θ₁) / (1−θ₀_prefix))
fire when Λ ≥ ln((1−β) / α)
```

`decay(dt) = 0.5^(dt / 600)` — a 10-minute half-life. This is the cold-start fix: a fresh
source legitimately discovers its handful of prefixes over a day, and novelty spread over
hours leaks away, while a burst in minutes accumulates. The arm contributes only after
**four distinct prefixes inside the 15-minute window** (`PREFIX_MIN_NOVEL`).

### 4.2 Destination-range discovery — Threshold Random Walk

**Phase:** "which premium numbers hit?" The generator probes many B-number ranges in a burst
to find the one that routes through its IPRN partner. This is the signal that catches
probing **within one country and one dialling format**, which neither prefix variety nor
country novelty can see.

The compared value is the **destination range**:

```
range = canonical E.164 digits with the last four digits dropped
        +44 20 3996 7796  →  digits 442039967796  →  range 44203996
```

Four digits groups 10,000 numbers — the scale of an IPRN block and the durable unit measured
in the corpus (41–68% persistence over 24 months, versus 0% for the exact number).

Membership uses two rotating Bloom filters (current and previous 15-minute window), so a
probe that straddles a window boundary is not counted twice:

- **1,024 bits, three hashes** per filter, double-hashed from one FNV-1a value.
- **256 bytes per source** for the two filters.
- About **80 ranges at ~1% false-positive**, 200 at ~9%. A false positive only *misses*
  novelty — the safe direction.
- Rotation is lazy, on a call: one window elapsed swaps current→previous and clears
  current; two or more clear both.

The same SPRT as the prefix arm, with its own benign rate `θ₀_range`:

```
on a novel range:  Λ += ln(θ₁ / θ₀_range)
on a known range:  Λ += ln((1−θ₁) / (1−θ₀_range))
```

The arm contributes only after **ten first-seen ranges in the window**
(`RANGE_MIN_NOVEL`); the walk still decides once the burst is real. A probe of six or seven
ranges is reported but cannot fire on its own.

**Not fan-out.** Fan-out (distinct destinations *per call*) was measured and refuted; a
legitimate median is 0.60 and three of four real fraud cases fell below it. Range novelty
counts *first-seen ranges per source over a short window*, which is the route-probing burst,
not the per-call destination count.

### 4.3 Completion — Threshold Random Walk

**Phase:** corroboration — "the call never came here." This is the original TRW mapping:
connection failed = scan evidence.

Every observed **final** response to an international INVITE is a Bernoulli trial:

- `2xx` → completed (benign evidence).
- final `4xx`/`5xx`/`6xx` **to a first-contact range** → did not complete (scan evidence).
- a failure to a range the source already calls → ignored: that is an outage, not a route
  probe.
- `3xx` → neither; ignored.
- **Provisional `1xx`** → not an outcome; ignored.
- **`401`/`407` digest challenge** → the normal authentication handshake, **not** a failed
  completion, whether or not the INVITE carried a credential.
- **Silence** → never fed. A softswitch that rejects probes without answering leaves this
  arm no evidence rather than false evidence. This is the same honesty the auth-failure rule
  keeps.

```
on a failure:  Λ += ln(θ₁c / θ₀c)
on a success:  Λ += ln((1−θ₁c) / (1−θ₀c))
```

The completion arm has its own decay clock (`last_completion`), so an INVITE never dilutes
its decay. An **authenticated** INVITE is fed here too: the auth path and the completion
path claim their transactions independently. (An earlier implementation let the auth path
consume the response first, leaving this arm blind to exactly the traffic it exists to
watch.) The arm contributes only after **ten novel-range failures**
(`COMPLETION_MIN_NOVEL_FAILURES`); a completed call resets the run.

### 4.4 Volume — hierarchical Gamma-Poisson surprise

**Phase:** exploitation. Hammering the one route that works shows as a count-rate change
against the source's own norm.

Each source's international-call rate λ is modelled as **Gamma(a, b)**; the predictive
distribution of a period's count is **Negative Binomial** (Gamma-Poisson conjugacy, which
absorbs the overdispersion a plain Poisson cannot). A source starts at the **population
prior**, not at zero — empirical-Bayes shrinkage, so a rare caller's first few calls are not
anomalous by construction.

- `a = prior_mean · prior_strength`, `b = prior_strength`.
- On a closed window: score `count`, then fold it in with exponential forgetting:
  `a = a·decay + count`, `b = b·decay + 1`.
- Surprise is `−log₂ P(X ≥ count)` where `X ~ NegBin(r=a, p=b/(b+1))`.
- It is computed with the **regularized incomplete beta**,
  `P(X ≥ count) = I_{1−p}(count, a)`, in O(1) — not by looping once per call. The old
  lower-tail sum cost 3.4 ms at 100k calls and 29 ms at 1M, **inline on the capture thread**;
  the beta form costs tens of nanoseconds.
- The survival probability is floored at `1e-12`, so surprise saturates at **39.9 bits**.
- `VOLUME_WINDOW_SECS = 3600`. A window is scored when the next call arrives after the
  window elapsed — a burst is compared with the baseline it has not yet polluted. If traffic
  stops, the last window is never scored, and no further decision needs it.
- Standing volume evidence is decayed by ½ at each roll (`volume_evidence = 0.5·old + new`),
  so one quiet hour does not erase a spike but sustained calm does.
- The arm contributes only after **six completed periods** (`VOLUME_MIN_PERIODS`), so a new
  high-volume source is learned for a few hours rather than judged against the cold-start
  prior on its first busy hour.

### 4.5 Country — tracked, not fused

The seen-country set is a 256-bit bitmap per source. It feeds the report (`first_time`,
`tfps_ctl` country listings) and is persisted. It is **not a fifth arm**: every new country
is already a new range, so counting both would double the same first-contact event. The
original reason country novelty stopped blocking still stands — without correct
international-prefix configuration, an internal extension or an inbound E.164 DID is read as
a new international destination; `intl_prefixes` and `home_countries` fix that at the source.

---

## 5. The statistics, exactly

### 5.1 Shipped parameters

| parameter | value | meaning |
|---|---|---|
| `α` | `1e-4` | tolerated false-alarm rate per decision |
| `β` | `1e-2` | tolerated miss rate |
| fire bound | `ln((1−β)/α)` = **9.2103 nats** | fuse threshold |
| floor | `ln(β/(1−α))` = **−4.6051 nats** | lower clamp on each walk |
| `θ₁` | `0.70` | scanner hypothesis, prefix and range |
| `θ₀_prefix` | `0.05` | benign first-contact rate, dialling prefix |
| `θ₀_range` | `0.15` | benign first-contact rate, destination range |
| `θ₀c` / `θ₁c` | `0.20` / `0.85` | benign / scanner failure rate, completion |
| `prior_mean` / `prior_strength` | `2.0` / `1.0` | volume prior (calls per hour) |
| volume `decay` | `0.98` | forgetting per window |
| `SCAN_HALFLIFE_SECS` | `600` | 10-minute half-life for the scan walks |
| `RANGE_WINDOW_SECS` | `900` | one range Bloom window (current + previous) |
| `RANGE_DIGITS` | `4` | trailing digits ignored when forming a range |
| `VOLUME_WINDOW_SECS` | `3600` | volume scoring period |
| `PREFIX_MIN_NOVEL` | `4` | hard floor: novel prefixes in the 15-min window |
| `RANGE_MIN_NOVEL` | `10` | hard floor: novel ranges in the 15-min window |
| `COMPLETION_MIN_NOVEL_FAILURES` | `10` | hard floor: failed first-contact ranges |
| `VOLUME_MIN_PERIODS` | `6` | hard floor: completed scoring periods |
| per-source warm-up | `24 h` / `20` international calls | no block before this |

### 5.2 Step sizes and the fire point

Each walk is clamped to `[floor, upper+1]` and contributes `max(0, Λ)`. The clamp prevents a
long-benign source from banking unbounded credit that a later burst would have to erase; the
`max(0, ·)` is why one benign arm cannot mask another.

| arm | novel step | repeat step | novel hits alone to 9.21 nats |
|---|---|---|---|
| dialling prefix | `ln(0.70/0.05)` = **2.639** | `ln(0.30/0.95)` = **−1.153** | 4 |
| destination range | `ln(0.70/0.15)` = **1.540** | `ln(0.30/0.85)` = **−1.042** | 6 (≈7 with 20 s decay) |
| completion | `ln(0.85/0.20)` = **1.447** | `ln(0.15/0.80)` = **−1.674** | 7 |

A measured route-probe burst — same country, same `00`, a new range every 20 seconds —
fires on **call 10**, not call 6: the range arm now requires ten first-contact ranges. The
walk's own 6 is the statistical point; the floor is the false-positive control. Prefix
discovery fires on call 4, completion on ten novel failures, volume after six periods. This
is the intended shape: a burst of novel destinations, not one or two over a day.

### 5.3 Fusion

```
evidence_nats = prefix_Λ + range_Λ + completion_Λ + volume_bits · ln 2
fired = evidence_nats ≥ 9.2103
```

- Bits from the volume arm are converted to nats so all arms share units.
- Each arm contributes only its non-negative part.
- This is **evidence fusion, not one jointly optimal test**. Each arm is a proper
  sequential/Bayesian test on its own; the sum is a stated engineering choice, and it is
  what makes every block explainable: `"14 nats: 9 range-scan (7 new, 0 completed),
  3.5 volume"`.
- The arms are correlated by nature (a new country is a new range; a dead route often
  implies novelty). The design accepts that correlation rather than pretending to model it.

---

## 6. Learning mode and what “BLOCK” means today

| mode | behaviour |
|---|---|
| **Prevention** (default) | perimeter only; no behavioural state, no fraud verdict |
| **Learning** (default with `--behavioural`, first 30 days) | arms run, `WOULD BLOCK` is printed, `would_block` counts; nothing is blocked |
| **Active** (`--active` or `--learn-days 0`) | arms run, `Block` is returned; report-only by default, or an XDP source block with `--enforce-behavioural` |
| **Warming** (a new source) | evidence is reported as `WARMING … (source warm-up; not blocked)` until 24 h and 20 international calls |

The learning start is persisted in the database (`meta.learning_started`). A restart does not
restart the 30 days. `--learn-days N` moves the end; `--active` skips it.

**Enforcement status.** By default the behavioural verdict is report-only; the forged SIP
`603` is still missing. With `--enforce-behavioural` (or `"enforce_behavioural": true`):

- `main.rs` turns the behavioural `Block` into a `("behavioural", detail)` reason and passes
  it through the same `tfps_core::disposition` gate as every perimeter block. `ignoreip`
  is honoured first; a registered peer no longer bypasses the perimeter's or the
  behavioural layer's active evidence.
- The enforcer writes the source into XDP for `block_ttl` and the block log records
  `reason=behavioural`; the operator sees `BLOCKED peer=... reason=behavioural ...`.
- Learning mode still never blocks, and a source still in its 24 h / 20-call warm-up still
  returns `WARMING`. `--active` + `--enforce-behavioural` is the way to block immediately.
- Without the option the line is `BLOCK (report-only, not enforced)`; with it, the
  `BLOCK` report line is replaced by the `BLOCKED`/`EXEMPT`/`WOULD BLOCK` line from the
  disposition gate. The forged SIP `603` remains the missing SIP-level reject.

This gap is deliberately visible: a system that looks like it blocks while doing nothing is
the failure this project argues against.

---

## 7. State, persistence, restart

### 7.1 What is kept, and what is not

| state | persisted? | why |
|---|---|---|
| seen-country bitmap (256 bits) | **yes** | report and `tfps_ctl`; rebuilding is slow |
| learned rate posterior `a`, `b` | **yes** | the volume baseline is the point of the 30 days |
| `n_countries`, `last_seen` | **yes** | reporting and retention |
| dialling-prefix bitmap | no | intra-burst; a restart loses at most a burst |
| range Bloom filters + window | no | same |
| scan walks (prefix, range, completion) | no | same |
| volume window count and standing evidence | no | same; the posterior survives |
| pending transactions, auth windows, REG probes | no | perimeter state; rebuilds in minutes |
| per-source warm-up (`first_seen`, `calls_seen`) | no | a restart restarts the short warm-up, the safe direction; country set and rate survive |

A restart loses at most a burst's worth of walk evidence. It does not lose the country set
or the rate posterior, and it does not reset the global learning window. The per-source
warm-up deliberately restarts: persisting a peer after a few minutes must not let a restart
turn a cold source into a warm one.

### 7.2 Checkpoints

- Written every `--checkpoint-every` seconds (default **300**, floor 30), never per packet.
- **Only dirty peers are written.** A peer becomes dirty when an international INVITE or a
  completion outcome changes its state. A quiet installation writes nothing.
- After a successful commit, `Engine::clear_anomaly_dirty` marks everything clean. A failed
  commit leaves it dirty, so the next checkpoint retries.
- On boot, rows older than **90 days** (`PEER_RETENTION_SECS`) are ignored, and the same
  retention is enforced by a prune at each checkpoint. A source silent for longer starts
  fresh instead of resurrecting a stale baseline.

### 7.3 The peer ceiling

`MAX_PEERS = 10_000`. When full, a new source is refused (`peers_dropped`) rather than
growing memory without bound. There is **no eviction by last-seen**, so a spoofed-source
flood can fill the table and deny behavioural coverage to new legitimate sources until a
restart. This is a documented limitation, not an accident.

---

## 8. Self-calibration

The traffic constants are learned from the deployment's **own aggregate traffic** — never a
corpus. At each checkpoint, with behavioural detection on, `Engine::recalibrate` refits:

| parameter | source | minimum data | clamp |
|---|---|---|---|
| `θ₀_prefix` | first-time prefixes / international calls | 500 international | 0.005–0.3 |
| `θ₀_range` | first-time ranges / international calls | 500 international | 0.02–0.4 |
| `θ₀c` | failed / (completed + failed) final responses | 200 finals | 0.05–0.7 |
| volume `prior_mean`, `prior_strength` | method of moments over per-source rates | 20 sources | strength 0.1–50 |

Then every source's walks are recalibrated in place: the step sizes and bound change, the
accumulated walk stays where it is. `θ₁`, `θ₁c`, `α`, `β`, the windows and the decay are
**not** learned.

Two caveats:

- **Recalibration lives inside the database checkpoint.** With `--no-db` it never runs; the
  cold-start defaults stand for the life of the process.
- The learned values are written to `meta.calibration` and shown by `tfps_ctl stats` under
  `CALIBRATION`.

---

## 9. Observability

### 9.1 Report lines

```
pass peer=203.0.113.9 country=GB first_time=false              # -v only
BLOCK (report-only, not enforced) peer=203.0.113.9 country=GB evidence_nats=11 distinct_countries=7
BLOCKED peer=203.0.113.9 reason=behavioural detail=country=GB evidence=11nats distinct_countries=7 ttl=3600s
WOULD BLOCK (learning) peer=203.0.113.9 country=GB evidence_nats=11 distinct_countries=7
WARMING peer=203.0.113.9 country=GB evidence_nats=10 distinct_countries=10 (source warm-up; not blocked)
UNKNOWN COUNTRY peer=203.0.113.9 digits=999123456              # never blocks
```

The completion arm has no country context, so its verdicts carry `country="?"`.

### 9.2 Counters

Userspace counters survive in the checkpoint's `stats` line and are readable by
`tfps_ctl stats`:

`invites`, `international`, `domestic`, `unknown_country`, `first_time` (country),
`range_novel`, `intl_ok`, `intl_fail`, `blocks`, `would_block`, `peers_dropped`, plus the
perimeter counters. The prefix first-contact count (`prefix_novel`) is used for
calibration but is not in the stats line.

### 9.3 Control tool

| command | shows |
|---|---|
| `tfps_ctl stats` | live kernel counters, traffic snapshot, `CALIBRATION`, learned blocklist |
| `tfps_ctl sources` | peers with persisted state, countries seen, rate, last seen |
| `tfps_ctl peers` | sources by distinct-country breadth |
| `tfps_ctl countries <peer>` | the range of countries a source has dialled |
| `tfps_ctl forget <peer>` | deletes learned state — **daemon must be stopped**, or the next checkpoint writes it back |

---

## 10. Performance and memory

The behavioural layer is O(1) per international call: one FNV hash per prefix and range,
constant-size bitmap/Bloom tests, three constant-time walk updates, and a constant-time
incomplete beta at a window roll. It allocates only what the parser and dial-plan
canonicalisation already need (the canonical digits string, the matched prefix string, the
transaction key); it does not allocate in the arms themselves.

Measured on an Apple Silicon laptop, release build, single core (`tfps-core`):

| operation | before | now |
|---|---|---|
| `country::resolve` | 599 ns (240-entry scan) | **89 ns** (binary search) |
| volume roll, 100k calls | 3.4 ms | **~25–60 ns** |
| volume roll, 1M calls | 28.8 ms | **~25–60 ns** |
| international INVITE, behavioural marginal | ~822 ns | **~200–500 ns** |
| allocations / international INVITE | 13 / 335 B | **10 / 299 B** |

The perimeter and SIP parse still dominate the per-call cost; the behavioural marginal is a
small fraction of it. Treat the absolute numbers as a shape, not a capacity promise: measure
on the deployment's own hardware and SIP mix.

Memory is bounded by construction:

- `SourceAnomaly` ≈ **600 bytes** per peer (two 128-byte range filters, three walks, the
  rate posterior, the 256-bit country set); 10,000 peers ≈ **6 MB**.
- Pending transactions: at most 32 per peer, 32 s TTL.
- Known peers: at most 50,000, persisted; 24-hour TTL (APIBAN exemption only).
- The peer ceiling bounds everything else.

The checkpoint is the only tail-latency concern left: it runs inline with capture and writes
only dirty peers, but a large active population still produces a write burst every 5 minutes.
A background writer is the next step if that shows up on a small VPS.

---

## 11. Operator guide

### 11.1 Enable it

```json
{
  "behavioural": true,
  "intl_prefixes": ["+", "00", "011", "9011"],
  "home_countries": ["BR"],
  "learn_days": 30,
  "ignoreip": ["10.0.0.0/8"]
}
```

```sh
tfps --behavioural                              # 30-day learning window, report-only
tfps --behavioural --enforce-behavioural        # block the source after learning
tfps --behavioural --active --enforce-behavioural # block now; do not do this on day one
```

**Prerequisites, in order of importance:**

1. **`intl_prefixes`** — behavioural detection reasons only about international calls. Wrong
   prefixes mean extensions and inbound DIDs are judged as international. Declare per-peer
   plans where PBXs differ; use `bare_e164` for wholesale.
2. **`home_countries`** — your own country/countries. Otherwise your inbound DIDs look like
   new international destinations.
3. **`ignoreip`** — inbound gateways and trusted carriers. The behaviour layer still
   evaluates them; exemption is an enforcement gate, not a blindfold.

### 11.2 What to watch during the 30 days

- `WOULD BLOCK` lines: source, country, evidence, distinct countries. Investigate each one
  before day 31; a line you cannot explain is a tuning or configuration signal.
- If `--enforce-behavioural` is set, the same event becomes `BLOCKED ... reason=behavioural`
  and the source is in XDP for `block_ttl`; check `tfps_ctl banned --why`.
- `UNKNOWN COUNTRY`: usually a wrong dial plan, not fraud.
- `tfps_ctl stats` → `CALIBRATION`: `theta0_prefix`, `theta0_range`, `theta0c`,
  `prior_mean`. Falling novelty rates are normal as the population matures.
- `peers_dropped` > 0: the source table is full; suspect spoofing or an undersized ceiling.

### 11.3 Tuning: what is actually adjustable

Configurable today: `behavioural`, `enforce_behavioural`, `no_enforce_one_way`,
`learn_days`, `intl_prefixes` (global and per peer), `bare_e164`, `home_countries`,
`ignoreip`, `ports`, `checkpoint_every`, `db`, `stats_every`, `block_ttl`, `apiban_key`.

Not yet exposed: `α`, `β`, `θ₁`, `θ₀c`, `θ₁c`, `RANGE_DIGITS`, `RANGE_WINDOW_SECS`,
`SCAN_HALFLIFE_SECS`, `VOLUME_WINDOW_SECS`, the volume `decay`, and the peer ceiling. The
benign rates `θ₀_prefix` and `θ₀_range` are learned, not configured. The rest are
compiled-in constants in `anomaly.rs` and `engine.rs`. If you need to change them for a
deployment, change them in code and measure — do not add a knob per install.

The two levers are the **learning window** and **enforcement**. Keep the window at 30 days
unless you have a reason; `--active` on day one converts cold-start novelty into false
positives. Leave enforcement off until you have read the learning-window lines; when you
turn it on, the source is blocked in XDP for `block_ttl` (a forged SIP `603` is still not
implemented).

---

## 12. Limitations, stated

- **The slow evader.** A source that paces novelty below `θ₀` evades the scan arms. Mitigated,
  not solved, by the volume arm and by decay rather than a hard reset.
- **A range probe slower than the window.** The range filter remembers two 15-minute windows;
  ranges spread over hours do not accumulate range evidence. The prefix and completion arms
  still apply, and the volume arm catches a slow build-up.
- **Completion depends on seeing the response side.** Where the softswitch rejects probes
  silently, the completion arm has little to work with. `intl_ok`/`intl_fail` near zero is
  the visible symptom. TLS and SIP-over-TCP detection are out of scope; TCP enforcement still
  covers condemned addresses.
- **A broad international profile.** A peer already calling 200 countries and hundreds of
  ranges has little novelty left; anomaly saturates by construction.
- **The first 30 days.** By design and announced: learning only, no behavioural blocking.
- **A source younger than 24 h / 20 international calls** is `WARMING`, not blocked. This is
  the per-source false-positive guard; it also gives an attacker a short window on a fresh
  source, which the perimeter still covers.
- **The hard floors are a deliberate trade-off.** A legitimate source adding ten new ranges
  in 15 minutes, or four dialling formats in 15 minutes, can still be reported. The floors
  are lower than the field's "dozens"; measure against your own traffic before enabling
  enforcement.
- **A low-and-slow mimic** of a legitimate profile is the residual gap no on-wire method
  closes. This is why the layer is opt-in, and why enforcement carries a TTL and remains
  unbannable.
- **Source-IP spoofing.** The peer is the anchor because it is the only identity observable
  without trusting SIP headers, but UDP source addresses can be spoofed. A spoofer can evade
  a per-source profile and fill the peer table; the perimeter and the completion arm still
  see the traffic, but the behavioural profile does not accumulate.
- **The peer ceiling has no eviction.** Spoofed-source floods can deny coverage to new
  legitimate sources until restart.
- **The default verdict is report-only.** `--enforce-behavioural` adds a source-level XDP
  block (and the block log); the forged SIP `603` is still missing. The XDP block is subject
  to the source-spoofing caveat above.
- **α and β are not configurable** in this version. See §11.3.

---

## 13. Code map

| file / symbol | role |
|---|---|
| `crates/tfps-core/src/anomaly.rs::SeqTest` | one SPRT walk with decay, clamping and non-negative evidence |
| `anomaly.rs::RateModel` | Gamma posterior, Negative-Binomial surprise, O(1) incomplete beta |
| `anomaly.rs::RangeBloom` | 1,024-bit, 3-hash rotating membership filter for ranges |
| `anomaly.rs::SourceAnomaly` | per-source state: prefix arm, range arm, completion arm, volume arm, country set |
| `anomaly.rs::Params` | α/β, hypotheses, priors, fire bound |
| `engine.rs::PeerState` | per-source perimeter state + `SourceAnomaly` + dirty flag |
| `engine.rs::observe_request` | perimeter → method gate → dial plan → country → home country → decide |
| `engine.rs::decide` | feeds the arms, updates counters, returns Pass/WouldBlock/Block |
| `engine.rs::observe_response` | auth outcome **and** completion outcome, claimed independently |
| `engine.rs::recalibrate` | refits θ₀s and the volume prior from aggregate traffic |
| `engine.rs::export_anomaly` / `clear_anomaly_dirty` | dirty-only checkpoint support |
| `dialplan.rs::DialPlan` | longest-prefix international detection, canonical digits, prefix identity |
| `country.rs::resolve` | E.164 calling code → country, longest match, binary search |
| `crates/tfps/src/store.rs` | `peer_anomaly` persistence, retention, checkpoint |
| `crates/tfps/src/main.rs` | checkpoint cadence, calibration write, report lines, enforcement gate |
| `crates/tfps/src/bin/tfps_ctl.rs` | operator views: stats, sources, peers, countries, forget |

---

## 14. Tests: what is pinned

`cargo test -p tfps-core` (143 tests) includes the behavioural contract:

- `anomaly::tests::a_known_country_is_evidence_against_scanning` — the walk moves down on a
  repeat.
- `the_prefix_arm_treats_each_new_prefix_as_a_first_contact` — distinct dialling prefixes
  add evidence; reuse subtracts.
- `the_range_arm_fires_on_route_probing_within_one_country` — same country, same prefix,
  many ranges fires; `repeating_one_range_is_evidence_against_probing` pins the negative.
- `failed_completions_are_evidence_of_scanning` — failures accumulate, successes do not.
- `a_settled_source_spiking_is_many_bits`, `cold_start_does_not_punish_the_rare_caller` —
  volume separation and cold-start safety.
- `surprise_matches_the_brute_force_tail` — the beta form against the definition; the huge
  window test pins the saturation value, not a timing.
- `evidence_never_goes_negative_so_one_arm_cannot_mask_another` — fusion property.
- `engine::tests::authenticated_invites_still_feed_the_completion_arm` — the regression for
  the auth/completion collision.
- `a_digest_challenge_to_an_unauthenticated_invite_is_not_a_failure` and
  `a_rejected_credential_on_an_invite_is_an_auth_failure_not_a_completion` — handshake
  semantics.
- `route_probing_within_one_country_is_caught` — end-to-end through `Engine`.
- `international_calls_that_never_complete_are_a_scan`,
  `international_calls_that_answer_are_not_a_scan`,
  `recalibration_refits_and_still_catches_a_scan` — end-to-end separation and calibration.
- `country::tests::binary_search_resolution_matches_the_linear_reference` — the fast
  resolver is byte-for-byte the old longest-match.
- `store` tests (run with the `tfps` crate on Linux): learned state survives a restart,
  dirty-only checkpoints, and 90-day retention.
- `crates/tfps/tests/behavioural_enforcement_e2e.rs` — the real 24 h / 20-call warm-up is
  kept: 20 calls stay inside it, then after 24 h the same packet path reaches `Block`;
  the disposition gate enforces it with `block_ttl`, the audit row is written, `ignoreip`
  exempts, and report-only mode does not enforce.
- `crates/tfps/tests/xdp_kernel_e2e.rs` (ignored by default) — attaches the real XDP
  program, writes a block into the kernel map, opens it with `Blocklist`, and lifts it.
  Requires root, `CAP_BPF`/`CAP_NET_ADMIN`, a clang-built `tfps_xdp.o`, and an
  XDP-capable interface; run it on the target with
  `TFPS_XDP_OBJ=/tmp/tfps_xdp.o cargo test -p tfps --test xdp_kernel_e2e -- --ignored`.

Run the throughput example with:

```sh
cargo run --release -p tfps-core --example decision_throughput
```
### Synthetic scenarios

`crates/tfps-core/examples/behaviour_scenarios.rs` runs ten scenarios through a real
`Engine` and prints the first verdict that would block, with the fused evidence and
counters:

```sh
cargo run --release -p tfps-core --example behaviour_scenarios
```

It covers route probing in one country, A-number rotation, dialling-prefix discovery,
prefix+range fusion, failed completions (plain and authenticated), a 300-call volume
spike, learning mode, a legitimate source, and paced novelty. Each scenario also writes an
Ethernet/IPv4/UDP pcap to `sim/pcaps/`, named after the scenario, for sngrep, tcpdump or
Wireshark. The pcaps contain no real traffic and no credentials.


---

## 15. References

- A. Wald. *Sequential Analysis*. 1945. (SPRT.)
- J. Jung, V. Paxson, A. W. Berger, H. Balakrishnan. *Fast Portscan Detection Using
  Sequential Hypothesis Testing*. IEEE Symposium on Security and Privacy, 2004. (Threshold
  Random Walk.)
- E. S. Page. *Continuous Inspection Schemes*. Biometrika, 1954. (CUSUM.)
- D. B. Rubin. *Estimation in Parallel Randomized Experiments*. 1981. (Hierarchical
  shrinkage / empirical Bayes.)
- R. P. Adams, D. J. C. MacKay. *Bayesian Online Changepoint Detection*. 2007.
- S. Guha, N. Mishra, G. Roy, O. Schrijvers. *Robust Random Cut Forest Based Anomaly
  Detection on Streams*. ICML, 2016.

---

## 16. Disclaimer

**TFPS cannot catch every possible type of fraud.** It is one layer that sees SIP on the
wire. It does not see billing, CRM, provisioning, identity, social engineering, insider
fraud, or traffic it cannot parse (SIP over TLS, SIP over TCP content, IPv6). A determined
low-and-slow attacker can mimic a legitimate profile. Behavioural detection is experimental
and report-only by default (source-level XDP blocking is opt-in); every verdict can be
wrong.

Use it at your own risk. Validate it on your own traffic, keep the perimeter and the
learning window, and do not treat it as a substitute for a security audit, fraud controls,
or your carrier/billing reconciliation. The software is provided **AS IS**, under the
Apache-2.0 licence, without warranty of any kind.

## Appendix A — definitions in one place

| term | definition |
|---|---|
| **call attempt** | an observed `INVITE`; the unit a verdict is about |
| **peer** | source IP; the trust anchor and the learning unit |
| **dialling prefix** | outbound format (`+`, `00`, `011`, `9011`); not a destination range |
| **destination range** | canonical E.164 digits with the last four digits dropped |
| **novel** | first occurrence for this peer in the current window |
| **evidence** | the non-negative part of one arm's log-likelihood ratio, in nats |
| **fire bound** | `ln((1−β)/α)`; the fused total that means "block" |
| **learning mode** | 30 days of observing and reporting `WOULD BLOCK`, never blocking |
| **would-block** | a verdict recorded and printed during learning |
| **volume backstop** | the *authentication* rule for unanswered credentialed floods — unrelated to the volume arm |
