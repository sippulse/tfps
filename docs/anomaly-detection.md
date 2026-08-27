# Anomaly detection for IRSF

How TFPS decides that a source is committing International Revenue Share Fraud, when there
is no labelled corpus, the decision must be made in real time, and every block has to be
explainable. This is the design behind the `--behavioural` layer. The perimeter (noise
reduction) is a separate, always-on product and is not covered here.

## The problem shapes the method

IRSF, as it actually happens (field description, confirmed against live traffic):

1. A fraudster partners with an **IPRN** (International Premium Rate Number) provider and is
   given ranges.
2. From **one IP**, they scan the internet for an exploitable PBX or open route.
3. From **another IP**, they generate calls, **probing many countries and prefixes** to
   find a destination that routes through a partner ITSP, which **short-answers** the call
   (bills the minutes without terminating it to the real carrier) and shares the revenue.
4. The destination numbers are **invalid in the real country** — "the call never came here,
   and this number is invalid in our country." Invalid ranges are used *deliberately*:
   for a valid destination, LCR (Least Cost Routing) has many competing carriers and the
   partner rarely wins; for an unallocated range, the partner is one of the few advertising
   a route, so it reliably wins.

Two empirical findings from the reference deployment shaped the method:

- **The B-number cannot be classified statically.** A real libphonenumber port
  (`phonenumber` 0.3) was tested on classic IRSF destinations: `+37122123456` (Latvia),
  `+25261234567` (Somalia), `+63280000000` (Philippines) all return `valid=true`, typed as
  ordinary `Mobile`/`FixedLine`; meanwhile a genuine UK range returned `valid=false`. Neither
  validity nor number-type separates fraud from legitimate traffic. Detecting the individual
  bad number is a dead end.
- **The signal is behavioural, and it has two phases.** *Scanning* — many distinct
  countries and prefixes attempted quickly, most not completing. *Exploitation* — high call
  volume to the one route that was found, against the source's own norm.

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

## Each phase is a solved problem

### Scanning → Threshold Random Walk (sequential hypothesis testing)

The scanning phase *is* a port scan: one source, many first-contact attempts, most failing.
The gold-standard scan detector is **Threshold Random Walk** (Jung, Paxson, Berger,
Balakrishnan, *Fast Portscan Detection Using Sequential Hypothesis Testing*, IEEE S&P 2004),
an application of **Wald's Sequential Probability Ratio Test** (Wald, 1945). The mapping is
exact: *a host never contacted before* → *a country this source has never dialled*; *the
connection failed* → *the call did not complete*.

Each international call is a Bernoulli trial. Under a benign source the probability that a
call is to a brand-new country is low (θ₀); under a scanner it is high (θ₁). Maintain a
running log-likelihood ratio:

```
on a novel-country call:  Λ += ln(θ₁/θ₀)
on a known-country call:  Λ += ln((1−θ₁)/(1−θ₀))     # negative — evidence against
fire when Λ ≥ ln((1−β)/α)      clear (reset toward 0) when Λ ≤ ln(β/(1−α))
```

**One addition the implementation forced.** Naive TRW has its own cold-start flaw: every
source *discovers* its countries at the start, so a legitimate business's first few calls
are all first-contacts and look like the opening of a scan. The fix is a **time-decay on the
walk** — the accumulated evidence leaks toward zero with a ~10-minute half-life (matching the
"5–15 min" burst the field description calls out). Novelty spread over hours never
accumulates; a burst in minutes does. This is what lets a *fresh* source legitimately call
five countries across a day without firing, while a scanner hitting ten in ten minutes does.

The decision bounds come from the **error rates you choose** — α (tolerated false-alarm
rate) and β (tolerated miss rate) — not from a hand-picked count. This is the difference
between "≥ 10 countries in an hour" (a brittle magic number the attacker paces under) and a
test with a stated operating characteristic that fires as soon as the evidence is
sufficient.

Demonstrated separation (illustrative θ₀=0.05, θ₁=0.60, α=10⁻³, β=10⁻²; bound ≈ 6.9 nats).
The **shipped** defaults are θ₀=0.15, θ₁=0.70, α=10⁻⁴ with the time-decay above — pushing the
fire point out to "many rapid novel countries" and away from an unlucky legitimate three:

| source | outcome |
|---|---|
| scanner: 12 calls, 10 to new countries | **fires at call 3** |
| legit call centre: 40 calls, 3 new | never alarms (Λ = −4.6) |
| small office: 6 calls, 2 new | safe (Λ = 1.5) |
| slow evader: alternating new/known | never fires (Λ = −0.77) — see Limitations |

**Prefix variety** is a second, independent Threshold Random Walk over the same calls, with
"a dialling prefix this source has never used" as the first-contact event. A legitimate PBX
dials one consistent format; probing `00`, `011`, `+`, `+5540` is first-contact after
first-contact.

### Exploitation → hierarchical Gamma-Poisson surprise

The volume spike is count-rate change detection. Model each source's international-call rate
λ as **Gamma(a, b)**; the predictive distribution of a period's count is **Negative
Binomial** (Gamma-Poisson conjugacy — Negative Binomial absorbs the overdispersion a plain
Poisson cannot). Score an observed count by its predictive-tail surprise, `−log₂ P(X ≥ k)`,
in bits.

Cold-start — the false-positive worry — is solved **by construction**. A new source starts
at the **population prior** (empirical Bayes; hierarchical shrinkage — Rubin, 1981, already
cited in `SPEC.md` §6): its rate estimate is dominated by the population until it accrues its
own history, so a rare caller's jump from 0 to 3 is a *modest* surprise, not the divide-by-
tiny-variance blow-up a naïve z-score produces. The prior *is* the minimum-samples guard,
with no arbitrary sample cutoff.

Demonstrated (population prior mean 2/day; settled source posterior after 30 days at ~2/day):

| scenario | surprise |
|---|---|
| new source, 3 calls (prior only) | 1.8 bits — no alarm |
| settled source (norm 2/day), 3 today | 1.6 bits |
| settled source, 40 today | 39.9 bits — fires |
| settled source, 200 today | 39.9 bits |

Concept drift is handled by **exponential forgetting**: decay (a, b) by a factor before each
update, so the baseline tracks a source that legitimately grows.

## Fusion

Both arms produce evidence in log-likelihood units. The source carries a combined evidence
total to which the country-scan walk, the prefix-scan walk, and the volume surprise each
contribute their non-negative part; enforcement fires when the total crosses the (α, β)
bound. Every block is then one sentence — *"14 bits: 9 country-scan (7 new, 0 completed),
5 volume"* — which satisfies the explain-every-block requirement and makes the manual-unban
rate (`SPEC.md` §12) a meaningful precision measure.

The combination of a bounded random walk with an unbounded surprise is **evidence fusion,
not a single provably-optimal joint test**; it is stated that way rather than dressed up.
Each arm on its own is a proper sequential/Bayesian test.

## Unit of analysis

The **source IP (peer)**. It is the only non-forgeable identity on the wire; it sidesteps
the two-IP structure of the fraud (the generator has its own IP and its own accumulator);
and it removes the `(peer, A-number)` keying whose A-number-rotation ceiling was a
documented bypass. Simpler and stronger than the previous per-pair bitmap.

## Self-calibration

The benign hypotheses are learned from the deployment's **own aggregate traffic** (permitted
— aggregate data, never a corpus): θ₀ is the observed rate of novel-country calls across
mature sources; the population Gamma prior is a method-of-moments fit to per-source rates.
No per-install threshold tuning. Only α and β are set, and they are properties of the
operator's risk appetite, not of the traffic.

## Limitations, stated

- **The slow evader.** A source that paces its novelty below θ₀ evades the scan arm (the
  demo's alternating case never fired). Mitigated — not solved — by the volume arm, by a slow
  decay rather than a hard reset on the benign side, and by a long-window backstop.
- **Completion is a missing multiplier.** The scan arm is good on novelty alone and
  *AT&T-grade* with completion ("attempted 15 countries, 14 never answered"). That needs
  response-side correlation (`200 OK`/`BYE`), which `SPEC.md` §3 currently excludes from the
  decision path. It is the one architectural addition worth making.
- **Low-and-slow mimicry** of a legitimate profile at low volume is the residual gap no
  on-wire method closes. This is why behavioural detection is opt-in, blocks carry a TTL, and
  every block is unbannable with the unban rate watched as the precision proxy.

## References

Standard references, cited from established literature:

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
