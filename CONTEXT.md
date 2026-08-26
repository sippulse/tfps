# CONTEXT

The TFPS vocabulary. One term, one meaning, everywhere in the system.

This file exists for a concrete reason: in the 2023 TFPS, `off_hours` meant *"outside
09:00–17:00 Mon–Fri"* in the proxy and *"weekend"* in the statistics cron. The two
definitions never matched, and neither was wrong on its own. An ambiguous term is a silent
bug.

Glossary only. No implementation decisions.

---

## Traffic and calls

**Call attempt** — an observed `INVITE`. This is the unit a verdict is issued about. It
exists before any response and regardless of whether the call completes.

**Call** — an attempt that was answered (`200 OK`). It only exists in retrospect. **Not a
synonym for attempt**, and the distinction matters: the verdict is issued about an
*attempt*, while duration and outcome belong to a *call*.

**Dialog** — the `INVITE` → response → `BYE` sequence of one conversation, correlated by
`Call-ID` and tags. Reconstructed from observed packets, never read from a softswitch
database.

**Duration** — seconds between `200 OK` and `BYE`. **Post-call** data: it feeds learning,
never the decision.

---

## Identities

**A-number** — the calling number, taken from the `From` header. **It is forgeable**, and
the vocabulary must always treat it as the sender's assertion, never as verified identity.

**B-number** — the dialled destination, taken from the Request-URI. It arrives **not
canonical**: it may come as `+E164`, `00…`, `011…`, `9011…`, `0…` or bare.

**Peer** — the interconnection entity sending the traffic, identified by source IP address.
It is the only **non-forgeable** identity from the system's observation point, which is why
it serves as the trust anchor. A peer may be a wholesale carrier, a customer PBX, or a
trunk.

**Learning unit** — the `(peer, A-number)` pair. Behaviour is learned about this.

**Tenant** — avoid. The word implies a provisioned customer, which this system does not
have. Use **peer** or **learning unit**, depending on the level.

---

## Destination

**Canonicalisation** — converting the dialled B-number into E.164. A prerequisite for any
statement about the destination, including behavioural ones: 20.3% of destinations in the
historical corpus do not resolve to a country without prefix stripping.

**Destination country** — the country of the canonicalised B-number. An alphabet of ~200
values. This is the granularity at which novelty works.

**Range** — a B-number prefix with the last N digits ignored. The **durable** unit of
destination intelligence: measured persistence of 41–68% over 24 months, against 0% for the
exact number.

**IPRN** — *International Premium Rate Number*. The number fraud calls, and the source of
the shared revenue. Under ITU-T E.169.2 the only legitimate international premium range is
`+979`; **every observed IRSF case is hijacked ordinary national numbering**, which is why
it keeps looking like ordinary numbering.

**Destination structure** — what is known about the B-number from public numbering plans:
valid length, allocated range, number type. Not an enemy list, and it does not age.

**Destination reputation** — what is known about the B-number from a fraud corpus. It rots,
and it is not the foundation of this system.

---

## Signals

**Novelty** — the first occurrence of a categorical value for a learning unit: first
country, first range, first hour. **This is the system's primary behavioural signal.** It
self-calibrates: the novelty rate falls as the unit matures.

**Warm-up** — the initial period during which a unit lacks enough history for its novelty to
mean anything. Measured at 7 days for country novelty.

**Burst** and **fan-out** — **rejected terms**. Recorded here so they do not creep back by
accident. *Burst* (call rate) was measured as marginal: it varies 30× across real cases.
*Fan-out* (distinct destinations per call) was **refuted**: a legitimate median of 0.60,
with three of four real fraud cases falling below it. The fraudster **repeats** a few
destinations with long calls, because the revenue is per minute.

**Chain A** — the attack that breaks in: a burst of `401`/`407`, then a successful
`REGISTER` from a new IP, then a first-time international destination.

**Chain B** — the attack that already has the password: credentials stolen from the
provisioning server over HTTP, then a `REGISTER` that succeeds **on the first try**. It
produces no authentication failures at all and is invisible in the SIP plane.

---

## Decision and action

**Verdict** — the outcome of evaluating an attempt: **pass**, **challenge** or **block**.

**Challenge** — diverting a suspicious attempt to verification (voice captcha, PIN) instead
of denying it. It exists so the ambiguous case never needs a risk-appetite threshold.

**Perimeter** — the layer that removes noise: scanning, brute force, bad-reputation IPs,
known tool user-agents. **It does not exist to catch fraud**; it exists to keep garbage out
of the behavioural baseline. Active from installation.

**Behaviour** — the layer that decides about fraud, from what it has learned about each
unit. Active after the learning period.

**Learning mode** — the first 30 days, during which the behaviour layer observes and **does
not block**, announcing that explicitly. The perimeter blocks normally during this period.

**Silence** — not answering an attempt. Applied to **production addresses** against
attackers, because any response confirms a live endpoint and invites escalation. It does
**not** apply to legitimate customers, who get a response, nor to **decoys**, which answer
deliberately.

**Decoy** — an idle extension or DID used as a trap. Traffic aimed at a decoy is suspicious
by definition.

---

## Paths

**Decision path** — from `INVITE` to verdict. No dialog state, no external lookup, no heavy
model inference. A failure here is a failure to protect.

**Learning path** — asynchronous. Reconstructs dialogs, measures duration and outcome,
updates profiles. **It can lose events without compromising protection**; a failure here
degrades learning, not blocking.
