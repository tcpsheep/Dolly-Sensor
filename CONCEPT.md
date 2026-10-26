# Dolly Sensor — Concept, Behavior, and Intent

> **What this document is:** the conceptual source of truth for rebuilding Dolly Sensor from scratch.
>
> **What this document is not:** a file layout, API specification, function list, or code blueprint. It deliberately avoids implementation details. It describes the idea, the behavior, the operating model, and the qualities the finished system should have.
>
> **How to use it when rebuilding:** treat this as product intent and a behavioral contract. Choose a clean, idiomatic implementation. Preserve the observable behavior described here, not the incidental flaws of any previous version. Where a detail is unspecified, choose the simplest robust option that is consistent with the rest of this document. The goal is not to reproduce old code — it is to produce a system that *feels* like this document.

---

## 1. The idea in one paragraph

Dolly Sensor watches sampled traffic going to the network prefixes you own, learns what normal looks like for every protected destination, recognizes attacks through a layered funnel of deterministic, behavioral, and statistical evidence, and asks the network edge to block or rate-limit only what is confidently malicious — then cleans up after itself when the attack stops. It is a passive observer and an automated mitigation controller, not an inline firewall. Its value is not just detecting a flood; it is making a *defensible decision* about when to act, acting quickly when the evidence is clear, and leaving the routing table clean afterward.

---

## 2. The problem it exists to solve

DDoS detection on sampled data is fundamentally noisy:

- The sensor does not see every packet. It sees samples.
- A single sample proves almost nothing. A burst of samples to one destination might be an attack, a backup, a software update, a game server filling up, or a monitoring artifact.
- Attacks change shape. Some are huge and obvious; some are small, precise, and aimed at one protocol or one service.
- False positives are expensive. Blocking a legitimate customer, game session, or backup job can be worse than missing a small attack.
- Manual response is slow. By the time a human notices, reads graphs, and announces a route, the damage is often done.
- Bad automation is worse than no automation. A controller that flaps routes, blocks the wrong prefix, or never withdraws a rule creates a second incident.

Dolly Sensor exists to sit between raw sampled traffic and the network edge: observe continuously, build memory, require corroboration, act only when the evidence is strong enough, and make every action visible and reversible.

---

## 3. What Dolly Sensor is

At its heart, Dolly Sensor is a **real-time traffic observer with a memory and a decision loop**.

It:

1. Receives sampled packet observations from network devices.
2. Decodes them into useful network facts: who sent what, to whom, using which protocol, with which flags, at what size, at what rate.
3. Narrows the view to the destinations the operator actually protects.
4. Remembers recent behavior and long-term behavior.
5. Builds a baseline for each protected destination.
6. Evaluates traffic through a layered detection funnel.
7. Turns evidence into an alert and, when appropriate, a mitigation action.
8. Announces that action to the network edge through BGP, usually as Flowspec or RTBH.
9. Watches the action expire and withdraws it automatically.
10. Learns from the traffic it sees, so future decisions are better.

It also gives the operator a live view of all of this: what is happening, what is being learned, what is being blocked, and why.

---

## 4. What Dolly Sensor is not

Being clear about non-goals keeps the system honest and the engineering focused.

- **It is not inline.** It does not sit in the packet path and drop packets itself. It observes samples and asks routers to act through BGP. If BGP is disabled, it is a monitoring and recommendation system.
- **It is not a full packet capture system.** It stores a bounded window of recent sampled observations for inspection, not a forensic archive.
- **It is not a complete view of the network.** It sees what the sFlow exporters choose to sample. It can miss low-and-slow attacks, traffic on unsampled paths, and encrypted payload semantics.
- **It is not a general IDS/IPS.** It focuses on DDoS, flood behavior, protocol abuse, and traffic anomalies against protected destinations.
- **It is not a replacement for edge routing policy.** The operator still decides which prefixes are protected, which BGP communities mean “blackhole,” and which sources are trusted.
- **It is not multi-tenant.** There is one operator view, one protected set, one mitigation policy. Authentication and role separation are out of scope for the core idea.
- **It is not an ML platform.** Statistics and behavioral scoring are enough. The system should be explainable; a human should be able to read an alert and understand why it fired.

---

## 5. The core loop

Everything in Dolly Sensor follows the same loop. The loop is the product.

```
   OBSERVE
      |
      v
   NORMALIZE  ->  REMEMBER  ->  BASELINE
                                   |
                                   v
                              CORROBORATE
                                   |
                                   v
                                DECIDE
                                   |
                                   v
                                  ACT
                                   |
                                   v
                                EXPIRE
                                   |
                                   v
                                 LEARN
                                   |
                                   +---------> back to OBSERVE
```

### 5.1 Observe

Receive sampled traffic from the network. Decode enough of each sample to understand the conversation: source, destination, protocol, ports, TCP flags, size, TTL, and a bounded payload preview when available.

The sensor should be forgiving of malformed datagrams, partial headers, unknown protocols, and unusual encapsulations. Bad input must never crash ingestion.

### 5.2 Normalize

Turn a raw sample into a comparable observation:

- Correct rates for the sampling ratio.
- Classify the protocol using port knowledge and lightweight payload inspection.
- Associate the observation with TCP session state when possible.
- Replace “one packet” with “an estimated number of real packets and bytes.”

The output of this stage is not truth; it is a *scaled estimate*. The rest of the system must treat it as an estimate and avoid pretending otherwise.

### 5.3 Remember

Keep three kinds of memory:

- **Hot memory:** recent sampled packets and alerts, measured in seconds to minutes. This powers the inspector, the live feed, and recent-rate calculations.
- **Warm memory:** per-destination statistics and per-source reputations, measured in minutes to days. This is what lets the system say “this destination usually does 30 Mbps” or “this source has completed handshakes before.”
- **Cold memory:** durable destination profiles, measured in days to indefinitely. This is what survives a restart and makes the system smarter over time.

### 5.4 Baseline

For every protected destination, learn the normal rhythm. A baseline is not one number; it is a sense of:

- typical packets per second,
- typical bits per second,
- typical packet size,
- typical protocol mix,
- typical TCP flag mix,
- typical source diversity,
- typical TTL fingerprints.

The baseline must adapt, but not too quickly. If it adapts instantly to every spike, it learns to accept attacks. If it never adapts, it slowly becomes wrong about legitimate growth. The right behavior is a slow, smooth baseline that can still notice a sudden, sustained departure.

### 5.5 Corroborate

No single weak signal should trigger a mitigation. Evidence should stack:

- A rate spike alone is suspicious.
- A rate spike plus tiny packets plus a SYN bias plus low source reputation is a strong case.
- A deterministic rule hit plus matching traffic is already a strong case.
- A high-trust source doing something mildly unusual deserves patience, not a blackhole.

The system should be able to explain which signals contributed. “It was blocked because the score was high” is not enough. “It was blocked because destination X rose from 4k to 180k pps, 92% of packets were 60-byte SYNs, and the top source had never completed a handshake” is enough.

### 5.6 Decide

Convert evidence into a decision:

- **Ignore:** normal, or too weak to matter.
- **Observe:** record and show it, but do not act.
- **Alert:** notify the operator.
- **Mitigate:** announce a route or flowspec rule.

The decision must account for trust, history, severity, whether the source is inside or outside the protected network, whether BGP is enabled, and whether a similar action is already active. Deduplication and cooldowns are part of the decision, not an afterthought.

### 5.7 Act

Action is expressed to the network edge through BGP:

- **RTBH** for a blunt, confident blackhole of a source.
- **Flowspec** for a precise match on source, destination, protocol, ports, and packet length, with either discard or rate-limit.
- **Alert-only** when BGP is disabled, when the source is protected/internal, or when policy says “show me, don’t touch it.”

Every action has a reason, a start time, a duration, and an owner. It is visible in the UI.

### 5.8 Expire

Mitigations are temporary by default. When the duration ends:

- Withdraw the route or rule.
- Mark the action as expired.
- Allow a new action later if the attack persists.

The routing table should not accumulate stale blackholes. “Never forget to clean up” is a core design rule.

### 5.9 Learn

After the fact, improve the system’s memory:

- Update destination profiles.
- Update source reputations.
- Adjust baselines.
- Record what happened for the operator.

Learning is not a separate machine-learning subsystem. It is disciplined accumulation of statistics and reputation.

---

## 6. The network model

### 6.1 Where the sensor sits

Dolly Sensor is a collector. Routers and switches are configured to export sFlow samples to it over UDP. The sensor may be on the same network as the exporters or across a management network. It is passive: it receives datagrams and never sits in the forwarding path.

### 6.2 What “owned” means

The operator configures a set of CIDR ranges that represent the network they protect. Only traffic involving those ranges is interesting:

- Traffic **to** an owned destination is analyzed for attacks.
- Traffic **from** an owned source may be stored for visibility, but it is not treated as an external attacker by default.
- Everything else is ignored or kept only as context.

This distinction matters. The sensor must never accidentally blackhole its own infrastructure because it saw an outbound packet with a strange flag combination.

### 6.3 Trusted sources

Some sources are known-good: monitoring systems, partner networks, load-test generators, internal scanners, backups. The operator can mark them as trusted.

Trust is not a blindfold. A trusted source can still be shown in the UI and can still contribute to volumetric baselines. But it should be exempt from application-layer penalties and should require much stronger evidence before any mitigation. Manual trust is per protected destination, because a source may be legitimate for one service and abusive toward another.

### 6.4 The BGP edge

The sensor does not route traffic itself. It speaks to a BGP speaker at the edge — for example, a router, a route reflector, or a GoBGP process. The edge decides whether to accept the announcement and how to distribute it.

Typical actions:

- A host route for RTBH, tagged with a configured community that the operator’s routers interpret as “discard.”
- A Flowspec rule that matches a subset of traffic and applies discard or rate-limit.

The sensor’s responsibility ends at making a correct, well-formed announcement and withdrawing it on time. The operator remains responsible for routing policy, communities, and safety rails.

---

## 7. The layers of knowledge

Dolly Sensor is easiest to understand as a stack of increasingly abstract knowledge.

### Layer 1 — Packet observation

One sampled packet header, decoded into facts:

- when it was observed,
- which exporter and sample it came from,
- source and destination MAC/IP,
- protocol and ports,
- TCP flags, sequence, acknowledgment,
- packet size, IP length, TTL,
- a bounded payload preview and a human-readable summary.

This layer is raw, noisy, and incomplete. It is for inspection and for feeding the higher layers, not for making decisions by itself.

### Layer 2 — Flow aggregate

Counts and rates grouped by dimensions that matter:

- per destination,
- per source,
- per source-to-destination pair,
- per protocol,
- per destination port,
- per TCP flag combination,
- per TTL,
- per packet-size bucket.

Aggregates are where patterns start to appear: a destination receiving 90% SYN packets, a source sending only 60-byte UDP packets, a TTL distribution that suggests spoofing.

### Layer 3 — Destination profile

The long-term identity of a protected service:

- lifetime maxima,
- total packets and bytes,
- protocol mix,
- destination-port mix,
- source-port mix,
- TTL fingerprint,
- TCP flag distribution,
- average packet size,
- dominant TTL,
- source reputations.

A destination profile answers: “What does this service normally look like, and what has it survived?”

### Layer 4 — Source reputation

The behavior of a source *toward a particular destination*:

- when it was first and last seen,
- which days it was active,
- which protocols and ports it used,
- whether it ever completed a TCP handshake,
- how many SYNs, ACKs, and PSH packets it has sent,
- its trust score and the history of that score.

Reputation is scoped per destination because trust is contextual. A source that behaves like a normal client to the web server may behave like a scanner toward the mail server.

### Layer 5 — Alert

A decision with a story:

- what happened,
- where,
- how strong the evidence was,
- which layer fired,
- what the recommended action is,
- whether an action was taken,
- how long it lasted.

Alerts are the operator’s unit of work. They should be deduplicated, readable, and honest about uncertainty.

### Layer 6 — Mitigation

An announced network action:

- type (RTBH or Flowspec),
- match conditions,
- action (discard or rate-limit),
- target,
- reason,
- start time,
- expiry,
- status (simulated, active, withdrawing, failed).

This layer is the system’s hand on the network. It must be conservative, auditable, and temporary.

---

## 8. Time scales

Different questions need different memories.

| Time scale | What lives there | Why |
|---|---|---|
| Sub-second to seconds | current rates, live TCP state, threat score | detect sudden changes quickly |
| Seconds to minutes | recent packet buffer, active alerts, cooldowns, mitigation timers | inspection, deduplication, response lifecycle |
| Minutes to hours | adaptive baselines, per-source-destination rates, active sessions | distinguish a spike from a new normal |
| Days to weeks | destination profiles, source reputations, trust history | recognize repeat behavior and avoid re-learning every day |
| Indefinite | lifetime maxima and totals | capacity planning and long-term context |

A common failure mode is mixing these scales: treating a one-second spike as permanent truth, or treating a month-old reputation as current fact. The design should keep them separate.

---

## 9. The detection funnel

Detection is a funnel, not a single detector. Each layer has a different cost, confidence, and failure mode. The order matters: cheap and certain checks run first; expensive and probabilistic checks run last.

### Layer 1 — Blocklist

**Question:** Is this source already known to be bad?

**Behavior:** A source IP or CIDR matching a loaded blocklist produces an immediate critical alert. If automatic blocking is enabled and the source is external, the system may announce an RTBH or a matching Flowspec rule.

**Why first:** It is cheap, deterministic, and easy to explain. Known-bad traffic should not consume the rest of the detection pipeline.

**Caveat:** Blocklists are static and can be stale or spoofed. A hit is a strong signal, not an infallible one.

### Layer 2 — Behavioral reputation and flood history

**Question:** Has this source behaved like a flooder toward this destination before?

**Behavior:** The system looks at the source’s historical SYN and ACK counts for the destination. A source with many SYNs and very few completed handshakes is treated as a probable SYN flooder. A source with a healthy handshake history gets the benefit of the doubt.

**Why here:** It is still cheap, and it protects the more expensive stateful layer from known abusers.

**Caveat:** Spoofed sources can look new every time. Reputation is evidence, not proof.

### Layer 3 — TCP state validation

**Question:** Is this TCP traffic even plausible?

**Behavior:** Track the three-way handshake per connection. Packets that claim to be part of a session but have no plausible session can be flagged. A flood of SYNs with few ACKs is suspicious. An ACK/PSH/RST with no session, especially at high rate, is suspicious.

**Why here:** It catches protocol-level abuse that a simple volume threshold would miss, and it helps explain a volumetric spike.

**Caveat:** Sampled traffic does not always include the handshake. A legitimate mid-stream packet can look out-of-state simply because the sensor missed the beginning. This layer must therefore be corroborated by rate or other evidence, never used alone on a single packet.

### Layer 4 — Application and protocol filters

**Question:** Is this traffic abusing a specific service in a way that violates how that service should be used?

**Behavior:** Protocol-aware filters inspect the traffic that reaches known service ports. The first implemented family is FTP:

- Control traffic on port 21.
- Data traffic on port 20.
- Non-TCP traffic to a TCP service port is suspicious.
- A client using a privileged source port toward the service is suspicious.
- Per-source rate above the configured limit is a flood.
- An oversized or malformed command in an established session is suspicious.

The same pattern can later cover SSH, DNS, HTTP, and other services.

**Why here:** These checks are more expensive and more specific than volume, but they produce precise, explainable evidence.

**Caveat:** Port-based classification is imperfect. Modern services run on arbitrary ports, and encrypted traffic hides semantics. Filters must be direction-aware and must not punish legitimate server responses.

### Layer 5 — Volumetric and behavioral anomaly detection

**Question:** Is the destination receiving significantly more traffic than its own normal?

**Behavior:** Maintain an adaptive baseline of packets per second and bits per second for each protected destination. Compare the current short-term rate to that baseline. Combine the deviation with other signals:

- absolute rate above a floor for the network type,
- z-score or equivalent deviation from the baseline,
- small average packet size,
- SYN-dominant or UDP-dominant mix,
- source concentration or, conversely, extreme source diversity,
- low source trust.

The combination becomes a threat score. The score is smoothed, and the system requires persistence over several evaluation windows before confirming an attack. A cooldown prevents repeated alerts for the same destination.

**Why last:** It is the most expensive and the most prone to false positives, but it is the only layer that can catch a novel attack with no known signature.

**Caveat:** Cold start is dangerous. With no baseline, a large but legitimate burst can look like an attack. The system should rely on absolute floors and deterministic layers until it has enough history, and it should prefer “observe” over “mitigate” during warm-up.

### Layer 6 — Correlation and decision

**Question:** Given everything we know, what should we do?

**Behavior:** Combine the outputs of the lower layers into a severity and an action. Deterministic hits can act immediately. Statistical hits need persistence and corroboration. Trusted sources need stronger evidence. Internal sources are alerted on, not externally blackholed. If BGP is disabled or simulation mode is on, the decision is recorded but not executed.

**Why a separate layer:** Detection and response are different responsibilities. Keeping the decision explicit makes the system auditable and tunable.

---

## 10. TrustScore

TrustScore is the system’s memory of whether a source has behaved like a legitimate participant.

### 10.1 What it represents

A score from 0 to 100:

- **0–20:** unknown, new, or repeatedly inactive.
- **20–40:** seen before, but little evidence of legitimate behavior.
- **40–60:** some history, possibly mixed.
- **60–80:** established, likely legitimate.
- **80–100:** strongly established or manually trusted.

The exact bands are less important than the behavior: trust is earned slowly, lost slowly, and never granted by a single packet.

### 10.2 How trust is earned

Trust increases when a source demonstrates behavior that is hard to fake at scale:

- being seen for the first time (small credit),
- returning on multiple distinct days (small credit per day),
- completing a TCP handshake (meaningful credit, rate-limited so it cannot be farmed instantly),
- sending many ACK or PSH packets inside established sessions (credit at milestones),
- maintaining a long-lived session (credit at 15 and 30 minutes),
- being manually trusted by the operator (full trust).

Spoofed sources generally cannot complete handshakes, which is why handshake evidence is weighted more heavily than raw packet volume.

### 10.3 How trust is lost

Trust decays when a source disappears:

- After a full day of inactivity, apply a small penalty, at most once per day.
- If a source remains inactive for a long time and its score reaches zero, eventually forget it.
- Manual trust never decays.

The decay should be slow and bounded. A source should not lose all reputation because the profiler ran twice in one afternoon.

### 10.4 How trust is used

- Sources above the exemption threshold are skipped by application-layer filters.
- High trust makes the system slower to mitigate on weak statistical evidence.
- Low trust makes a source a stronger suspect when combined with flood-like behavior.
- Trust is shown in the UI with the history of how it changed, so the operator can understand and override it.

Trust never completely disables volumetric detection. A trusted source that suddenly sends a terabit at a protected destination is still a problem, even if the reason is a compromised machine or a misconfigured client.

---

## 11. Stateful TCP intuition

TCP has a grammar. Dolly Sensor uses that grammar as evidence.

### 11.1 The handshake

A normal connection looks like:

```
client -> server : SYN
server -> client : SYN/ACK
client -> server : ACK
```

The sensor tracks the conversation by its four-tuple and sequence numbers. When the handshake completes, the connection becomes “established” in the sensor’s memory. Established connections are shown in the UI, used for trust, and used to judge later packets.

### 11.2 Out-of-state traffic

A packet that claims to belong to a connection but has no plausible session is “out of state.” Examples:

- an ACK with no handshake,
- a PSH or RST from nowhere,
- a flood of packets that never establish anything.

Out-of-state traffic is suspicious, but sampled traffic makes it easy to be wrong. The sensor may simply have missed the handshake. Therefore, out-of-state evidence should only matter when the rate is meaningfully high or when other signals agree.

### 11.3 SYN flood signature

A SYN flood looks like:

- many SYNs from the same source (or many sources) toward one destination,
- very few completed handshakes,
- a high SYN-to-ACK ratio,
- often small packets.

The sensor should flag this when the volume is meaningful and the ratio is extreme, not when a single SYN happens to be unpaired.

### 11.4 Cleanup

TCP state is temporary. Pending handshakes expire in seconds. Established sessions expire after inactivity. Otherwise the sensor slowly turns into a memory leak with a dashboard.

---

## 12. Application filters: FTP as the first example

FTP is a useful first protocol because it has two channels and clear client/server roles.

### 12.1 FTP control (port 21)

The control channel carries commands and replies. The sensor should treat client-to-server traffic differently from server-to-client traffic:

- **Non-TCP traffic to the control port** is suspicious.
- **A client using a privileged source port** toward the control port is suspicious; normal clients use ephemeral ports.
- **A high per-source rate** toward the control port is a control-channel flood.
- **An oversized or malformed command** in an established session is suspicious.
- **Server replies from port 21** are normal and must not be penalized for having a privileged source port. Directionality is essential.

### 12.2 FTP data (port 20)

The data channel is for bulk transfer, so its rate limits are higher. The same directional logic applies:

- non-TCP to the data port is suspicious,
- a client using a privileged source port toward the data port is suspicious,
- a high per-source rate is a data-channel flood.

### 12.3 Trust exemption

A source with sufficient TrustScore is exempt from these application-layer penalties. The idea is to avoid punishing a known-good backup or partner because it briefly exceeds a rate limit.

### 12.4 Why this pattern generalizes

Every protocol filter should answer four questions:

1. Which direction is the client?
2. What does a normal client do?
3. What does abuse look like?
4. What is the least destructive action that stops it?

This is more valuable than a grab-bag of port-specific hacks.

---

## 13. Volumetric and behavioral detection

### 13.1 Sampling correction

Every sample represents more than one packet. The exporter tells the sensor the sampling ratio. Rates must be corrected for that ratio; otherwise a 1-in-1000 sample of a 100k pps flood looks like 100 pps.

Correction is an estimate, not a measurement. The system should use consistent units and never multiply the same observation twice.

### 13.2 Per-destination baseline

For each protected destination, track:

- current packets per second,
- current bits per second,
- an adaptive mean and spread for each,
- the number of observations used.

The baseline should be smoothed so that a single spike does not become the new normal, but adaptive enough to follow legitimate growth over hours and days. A short-term rate versus a smooth baseline is the core comparison.

### 13.3 Per-source-destination attribution

A destination spike is more actionable when the system knows who is causing it. Track a second baseline for each source-to-destination pair, so the system can say:

- “one source is responsible for 80% of the increase,”
- “the increase is spread across thousands of sources,”
- “this source is far above its own normal.”

This distinction changes the response: a single-source flood can be blocked precisely; a distributed spoofed flood may need a destination-oriented Flowspec rule or RTBH.

### 13.4 Signals that matter

The system should not rely on rate alone. Useful signals include:

- absolute rate above the network’s floor,
- deviation from the destination baseline,
- average packet size (tiny packets suggest SYN/UDP floods),
- protocol mix (SYN-heavy, UDP-heavy, ICMP-heavy),
- source concentration (one source) versus source diversity (many sources),
- SYN-to-ACK ratio,
- trust of the sources involved,
- whether the destination is newly observed or well established.

### 13.5 Threat score and persistence

Each evaluation produces a threat score from the weighted signals. The score is smoothed over time. A single high score is an observation; a sustained high score is an attack.

The system should require the score to stay above a threshold for several consecutive evaluation windows. The exact number depends on sensitivity:

- **Relaxed:** high threshold, long persistence. Fewer alerts, slower response.
- **Balanced:** the default. Reasonable response without being jumpy.
- **Aggressive:** lower threshold, shorter persistence. Faster response, more false positives.
- **Ultra:** for environments that prefer action over patience.
- **Instant:** for testing or extremely low-latency needs; expect noise.

Network type scales the absolute floors:

- **Home:** low floors; a few thousand packets per second can matter.
- **Office:** higher floors; normal business traffic is larger.
- **Datacenter:** high floors; only significant volume should trigger statistical detection.

The presets are not a substitute for tuning. They are sane starting points.

### 13.6 Cooldown

Once an attack is confirmed for a destination, do not alert again immediately. Use a cooldown (for example, ten minutes) keyed by destination and attack type. The attack may continue; the operator does not need a new alert every second.

Cooldown is about attention, not detection. The system can keep evaluating and keep mitigation active without spamming the alert feed.

### 13.7 Cold start and warm-up

A new destination has no baseline. The system should:

- rely on absolute floors and deterministic filters,
- avoid strong statistical conclusions until enough observations exist,
- prefer alert-only or simulation during warm-up,
- show “learning” status in the UI.

A cold-start false positive is one of the fastest ways to lose operator trust.

---

## 14. From evidence to action

### 14.1 Severity

Not every alert means “blackhole something.”

- **Info:** interesting but not actionable (new source, unusual port, baseline warming up).
- **Warning:** suspicious behavior that may be benign; observe and notify.
- **Critical:** strong evidence of an attack; mitigation is appropriate.

### 14.2 Action selection

| Evidence | Typical action |
|---|---|
| Blocklist hit, external source, auto-block enabled | RTBH or precise Flowspec, critical alert |
| Known SYN flooder with extreme ratio | Flowspec discard or rate-limit |
| Out-of-state TCP at meaningful rate | Flowspec for the offending source/destination |
| FTP control/data abuse | Flowspec with protocol/port match, rate-limit or discard |
| Confirmed volumetric attack, single source | Precise Flowspec or RTBH |
| Confirmed volumetric attack, many spoofed sources | Destination-oriented Flowspec (protocol, packet size) or RTBH if severe |
| Trusted source, weak statistical evidence | Alert only; do not mitigate |
| Source inside owned prefixes | Alert only by default; internal quarantine is an operator decision |
| BGP disabled or simulation mode | Record intended action; do not announce |

### 14.3 Deduplication

The same source should not generate a new BGP announcement for the same reason every second. Deduplicate by action identity (for example, source + reason + match). When the mitigation expires, clear the deduplication so a persistent attack can be re-mitigated.

Deduplication must have a lifetime. A permanent “already triggered” flag is a bug waiting to happen.

### 14.4 Rate-limit versus discard

- **Discard** is simple and absolute. Use it when the traffic is clearly malicious and the source is precise.
- **Rate-limit** is gentler. Use it when some traffic may be legitimate, or when the goal is to protect a service without fully cutting off a source.
- **RTBH** is the bluntest tool. Use it for confirmed severe attacks, not for ambiguous behavior.

### 14.5 Refresh

If an attack continues past the mitigation duration, the system may re-announce after the previous action expires. This should be deliberate, not an accidental loop. The UI should show a clean sequence of announcements, not a wall of duplicates.

---

## 15. Mitigation lifecycle

A mitigation is a small state machine:

```
proposed -> announced -> active -> expiring -> withdrawn
                   \-> failed
                   \-> simulated
```

### 15.1 RTBH

A host route for the offending source, tagged with a community that tells edge routers to discard it. It is fast, widely supported, and coarse: the entire source is blocked, not just the attack traffic.

Use it when the source is clearly malicious and the collateral risk is acceptable.

### 15.2 Flowspec

A rule that matches some combination of:

- source prefix,
- destination prefix,
- protocol,
- source port,
- destination port,
- packet length.

And applies:

- discard, or
- rate-limit.

Flowspec is the precision tool. It can block only the attack traffic while leaving the rest of the source’s traffic alone.

### 15.3 Duration and auto-withdraw

Every announced action has a duration. The default should be short — on the order of a minute — because attacks are dynamic and stale rules are dangerous. When the duration ends, the action is withdrawn automatically.

The operator should be able to see the remaining time and the reason in the UI.

### 15.4 Simulation mode

When BGP is disabled, the system should still do everything except touch the network:

- build the exact intended announcement,
- record it,
- show it in the UI as simulated,
- log it,
- let the operator validate the logic.

Simulation is not a degraded mode; it is a first-class operating mode and the safest way to onboard.

### 15.5 Failure handling

BGP commands can fail: the session may be down, the binary may be missing, the router may reject the rule. The system should:

- record the failure,
- surface it in the UI,
- avoid tight retry loops,
- keep the detection and alerting working,
- not pretend the mitigation succeeded.

### 15.6 Shutdown

On graceful shutdown:

- stop accepting new mitigations,
- withdraw what can be withdrawn,
- save profiles and reputations,
- stop timers and background workers.

A crash cannot clean up after itself. The operator should assume that a hard crash may leave announcements behind and should have an operational procedure (BGP session reset, maximum lifetime at the edge, or manual cleanup).

---

## 16. Blocklists

Blocklists are the deterministic floor of the system.

### 16.1 Sources

- One or more files in a configured directory.
- Plain IP addresses.
- CIDR ranges.
- Comments and blank lines ignored.
- A manual list that the operator can append to from the dashboard.

### 16.2 Behavior

- Load at startup.
- Reload on demand without restarting.
- Reload atomically: there should never be a moment when the list is empty and traffic slips through.
- Show the number of entries and the source files in the UI.
- A hit is a critical alert.
- If automatic blocking is enabled, a hit can trigger an RTBH or a precise Flowspec action.
- Deduplicate repeated hits for the same source.

### 16.3 Safety

- Do not let the operator accidentally block an owned prefix or a trusted source without a clear warning.
- Validate entries before writing them.
- Keep manual entries in a separate file so a reload does not erase them.
- Do not silently rewrite operator files.

---

## 17. Profiles, memory, and persistence

### 17.1 Recent packet buffer

A bounded ring of recent observations. It powers:

- the live inspector,
- recent-rate calculations,
- the profiler’s incremental updates,
- incident context.

When it fills, the oldest observations are overwritten. The buffer is not a database; it is a window.

### 17.2 Destination statistics

Per protected destination, keep counters for:

- sources,
- source ports,
- TCP flags,
- last seen.

These statistics are sharded or otherwise partitioned so that many destinations can be updated concurrently without a global bottleneck. Idle entries are cleaned up.

### 17.3 Destination profile

The durable, long-term view:

- first seen and last updated,
- lifetime maxima for PPS and Mbps,
- total packets and bytes,
- protocol distribution,
- destination-port distribution,
- source-port distribution,
- TCP flag distribution,
- TTL distribution,
- dominant TTL,
- average packet size,
- per-source reputations.

Profiles are the system’s institutional memory. They should survive restarts and be saved atomically so a crash does not leave half-written JSON.

### 17.4 Snapshots versus source of truth

The UI needs readable snapshots: “current PPS, average, top protocols, risk level.” The durable profile needs raw counters. These are related but not the same. The system should be able to regenerate a snapshot from the durable data and should not confuse a display value with the underlying state.

### 17.5 Incremental processing

The profiler should process each buffered observation exactly once. If it rescans the entire buffer every interval, it will double-count traffic, inflate lifetime totals, and distort reputations. A watermark or equivalent “last processed” boundary is essential.

### 17.6 Restart behavior

After a restart:

- Load destination profiles and reputations.
- Reload blocklists.
- Start with empty recent packets and alerts unless persistence says otherwise.
- Rebuild baselines from new traffic; do not pretend old baselines are current.
- Show which destinations are warming up.

### 17.7 Deep copies

Any data handed to the dashboard, JSON encoder, or another goroutine must be a snapshot, not a pointer into live maps. This is both a correctness rule and a concurrency-safety rule.

---

## 18. Visibility: dashboard and API

The dashboard is the operator’s window into the loop. It should answer questions, not just display numbers.

### 18.1 Overview

Answers: “What is happening right now?”

- current throughput,
- current packets per second,
- number of active protected targets,
- number of active alerts,
- a live chart of load over time,
- top protected targets by current load.

The tone should be calm. Red is for real problems, not decoration.

### 18.2 Protected IPs

Answers: “Which of my destinations are under pressure?”

A table of protected destinations with:

- current load,
- average load,
- threat level,
- top protocols or ports,
- last activity,
- an action to inspect.

Threat level should be explainable: clean, anomalous, under attack.

### 18.3 Destination detail

Answers: “What does this destination look like, and who is talking to it?”

- lifetime maxima and totals,
- dominant TTL and average packet size,
- number of active sources,
- PPS history,
- L4 protocol distribution,
- TCP flag distribution,
- TTL distribution,
- top destination ports,
- top source IPs,
- top source ports,
- source reputations with trust history,
- manual trust controls.

This is the deep-dive view. It should make an attack legible.

### 18.4 Intelligence

Answers: “What has happened recently, and who should I remember?”

- recent critical alerts,
- top source reputations,
- score history,
- manual trust actions.

### 18.5 Inspector

Answers: “What is actually on the wire right now?”

- a live stream of sampled packets,
- filters by source, destination, port, protocol, and keyword,
- pause and resume,
- a bounded table so the browser does not melt,
- summaries that are readable by a human,
- optional payload details for the selected packet.

### 18.6 Connections

Answers: “Which TCP sessions are established?”

- source and destination,
- protocol,
- duration,
- last activity.

This view is useful for validating that the state tracker is sane and for understanding whether a spike is backed by real sessions.

### 18.7 Blocklist

Answers: “What is blocked, and where did it come from?”

- manual entry form,
- loaded files,
- entry count,
- manual trust / whitelist table,
- revoke action.

### 18.8 Mitigation

Answers: “What is the network edge doing right now?”

- BGP enabled or simulation,
- active announcements,
- type, prefix, community, reason, age, remaining time,
- reload blocklists,
- a clear warning when actions are simulated.

### 18.9 Settings / status

Answers: “Where is the collector? Where is the dashboard? What version is running?”

This is a status view, not a full configuration editor. Configuration is managed in the config file; the dashboard shows what is active.

### 18.10 Live updates

The dashboard should receive a live stream of packet and alert events. The stream must be resilient:

- reconnect automatically,
- show connection state,
- not block ingestion if a browser is slow,
- drop old events for a slow client rather than stalling the sensor.

### 18.11 API character

The JSON API should be:

- read-mostly for monitoring,
- explicit for control actions (trust, block, reload),
- predictable in naming,
- safe under concurrent use,
- free of pointers to live state,
- documented enough that a user can script it.

The core control actions are trust, blocklist add/reload, and test alert. There is no need for a full CRUD API over every internal map.

---

## 19. Alerting and notifications

The dashboard is for operators who are watching. Webhooks are for operators who are not.

### 19.1 What deserves a notification

Critical alerts:

- confirmed volumetric attack,
- blocklist hit,
- severe protocol abuse,
- mitigation announced or failed.

Warnings can be displayed in the UI without paging anyone.

### 19.2 Notification content

A good notification answers:

- what happened,
- which destination,
- which source or sources,
- how strong the evidence is,
- what action was taken,
- when it happened.

### 19.3 Cooldown

Notifications are subject to the same cooldown as the underlying alert. A flooding attacker should not generate a message per second.

### 19.4 Test alerts

The operator should be able to send a test notification to verify the webhook without waiting for a real attack.

### 19.5 Non-blocking

Webhook delivery must never block packet ingestion or detection. Slow or failing webhooks are a notification problem, not a sensor problem.

---

## 20. Configuration philosophy

Configuration should be small enough to understand and explicit enough to be safe.

### 20.1 Categories

- **Ingestion:** collector address, sampling defaults, polling.
- **Dashboard:** HTTP listen address.
- **Memory and performance:** buffer size, number of shards, cleanup interval, stats TTL, profiler interval.
- **Ownership:** protected CIDRs, trusted IPs.
- **Detection:** sensitivity preset, network type.
- **BGP:** enabled, local AS, peer IP, peer AS, community, next hop.
- **Mitigation:** blocklist path, automatic blocking, default duration, deduplication window.
- **Protocol tuning:** per-protocol rate limits and block durations.
- **Trust tuning:** exemption threshold.
- **Alerting:** Discord/webhook URL.

### 20.2 Safe defaults

- BGP disabled by default.
- Dashboard bound to localhost by default.
- Simulation rather than action when BGP is off.
- Conservative sensitivity.
- Short mitigation duration.
- No trusted sources unless the operator adds them.
- Protected CIDRs must be explicit; the system should refuse to run with an empty set.

### 20.3 Validation

Validate at startup and fail clearly:

- collector port range,
- dashboard address,
- parseable CIDRs,
- BGP AS numbers and peer address when BGP is enabled,
- non-negative durations and limits.

Warn, but do not necessarily fail, for suspicious values:

- a protected CIDR that covers the entire internet,
- a blocklist entry inside a protected prefix,
- an empty blocklist directory,
- a very high sampling ratio.

### 20.4 Reload

Configuration is read at startup. Blocklists are the exception: they are operational data and must be reloadable without a restart. If the operator wants to change detection sensitivity, that is a deliberate restart-level change, not a hot toggle.

### 20.5 Secrets

Webhook URLs, BGP passwords if any, and API tokens are secrets. Do not log them. Do not ship a real config in the repository. Provide a template with placeholders.

---

## 21. Operating model

### 21.1 First deployment

1. Install the binary.
2. Create a config with the protected CIDRs and a localhost dashboard.
3. Start with BGP disabled.
4. Point an sFlow exporter at the collector.
5. Confirm packets appear in the inspector.
6. Watch the dashboard long enough to learn the normal rhythm.
7. Tune sensitivity and trust.
8. Configure BGP in a lab or with a canary prefix.
9. Enable mitigation only after simulation looks correct.

### 21.2 sFlow configuration

The exporter must be configured to send samples to the sensor. The sampling ratio matters:

- Too sparse: detection is noisy and slow.
- Too dense: the sensor works harder and stores more, with little extra benefit.

A ratio that gives the sensor enough samples per second to see the shape of traffic is the right one. The sensor should tolerate varied rates from different exporters.

### 21.3 BGP configuration

The sensor needs a BGP session to the edge. The operator must ensure:

- the session is healthy,
- the edge accepts the configured RTBH community and Flowspec address family,
- there is a policy that prevents the sensor from announcing protected prefixes or default routes,
- there is an operational way to clear stale announcements after a crash.

### 21.4 Day-2 operations

- Watch for false positives and adjust sensitivity or trust.
- Keep blocklists current.
- Monitor collector health and sample rate.
- Watch memory and cleanup behavior.
- Review active mitigations and failures.
- Back up profiles if long-term history matters.
- Test the webhook and BGP path periodically.

### 21.5 Security

- The dashboard is not authenticated by default. Bind it to localhost or protect it with a firewall/reverse proxy.
- The collector is UDP; anyone who can reach it can inject samples. Use network segmentation and, where possible, source validation.
- The BGP session is powerful. Use a dedicated peer, strong policy, and least privilege.
- Treat the webhook URL as a secret.
- Do not expose the sensor directly to the public internet.

---

## 22. Safety, accuracy, and failure modes

### 22.1 False positives

A false positive mitigation can be worse than a missed attack. The system should reduce them through:

- persistence over time,
- corroborating signals,
- trust exemptions,
- absolute floors,
- cooldowns,
- simulation mode,
- manual override,
- conservative defaults.

### 22.2 False negatives

The system will miss things:

- traffic that is not sampled,
- low-and-slow attacks below the floor,
- attacks hidden in encrypted payloads,
- attacks that look exactly like legitimate traffic,
- spoofed sources that never repeat.

The UI should not pretend the system sees everything.

### 22.3 Spoofing

Source-based reputation and blocklists can be evaded by spoofing. This is why destination-oriented detection and aggregate behavior matter. A spoofed flood may have thousands of “new” sources; the destination still shows a clear anomaly.

### 22.4 Alert fatigue

Deduplicate, cooldown, and separate severity. An operator who receives a hundred messages per minute will stop reading them.

### 22.5 BGP mistakes

- Never announce a default route.
- Never announce a protected prefix as a blackhole unless that is the explicit intent.
- Validate source addresses.
- Cap the number of simultaneous announcements.
- Withdraw on schedule.
- Show failures clearly.

### 22.6 Self-blocking

An outbound packet from an owned source with a strange flag combination must not cause the sensor to blackhole its own network. Internal sources are alert-only by default.

### 22.7 Resource exhaustion

- Bound the recent packet buffer.
- Bound alert history.
- Clean up idle destination, source, TCP, and baseline state.
- Shard hot data structures.
- Avoid spawning unbounded goroutines or timers per packet.
- Use non-blocking fan-out to slow consumers.

### 22.8 Races and stale views

- Copy data before handing it to the UI or JSON encoder.
- Do not iterate live maps while another goroutine writes them.
- Use atomic swaps for blocklist reloads.
- Make profile saves atomic.

### 22.9 Clock and sampling artifacts

- Use monotonic time for rate calculations.
- Use wall-clock time for display and persistence.
- Expect out-of-order samples.
- Do not treat missing samples as proof of absence.

### 22.10 Restart and crash

A graceful shutdown should save profiles and withdraw mitigations. A hard crash cannot. The operator should have a procedure for clearing stale announcements and should not assume the sensor’s in-memory baseline survived.

---

## 23. Hard-won design constraints

These are the lessons that matter most when rebuilding. They are stated as behavior, not code.

1. **Directionality is non-negotiable.** A rule about “port 21” must know whether the packet is client-to-server or server-to-client. Otherwise it will punish the server for replying from a privileged port.
2. **Update session state before judging the packet.** The final ACK of a legitimate handshake must be seen as completing a session, not as an out-of-state packet.
3. **Store the enriched observation.** If session state is updated after the packet is copied into history, the profiler and UI will see a packet that never completed its handshake.
4. **Handle more than Ethernet.** sFlow can carry raw IPv4 or IPv6 headers. A decoder that assumes every sample starts with a MAC address will misread a valid capture.
5. **Handle both flow sample forms.** Normal and expanded samples have different field layouts. Bounds-check everything.
6. **Process each buffered packet once.** A profiler that rescans the whole buffer every interval double-counts history and corrupts lifetime totals.
7. **Deduplication must expire.** A permanent “already triggered” marker either blocks future legitimate alerts or never clears.
8. **Clean up every map.** Per-destination baselines, per-source-destination baselines, cooldowns, TCP state, destination stats, and alert history all need expiration policies.
9. **Deep-copy across boundaries.** Never hand a live map or pointer to the JSON encoder, the dashboard, or another goroutine.
10. **Slow consumers must not stall ingestion.** Bounded channels and non-blocking sends are mandatory.
11. **Decay trust once per inactive day, not once per profiler tick.** Otherwise trust collapses while the operator watches.
12. **Manual trust must survive reloads and restarts.** It is an operator decision, not a cache.
13. **Blocklist reload must be atomic.** There must be no empty-list window.
14. **Do not create unbounded timers or goroutines per packet.** Use a small number of schedulers or a lifecycle manager.
15. **Be explicit about units.** Bytes versus bits, packets versus samples, per-second versus totals. Most “detection bugs” are unit bugs.
16. **Cooldown keys need context.** A global cooldown hides real attacks on other destinations; a per-destination, per-type cooldown is the right granularity.
17. **Cold start needs humility.** Do not z-score against zero variance or an empty baseline.
18. **Internal sources are different.** Do not announce external blackholes for owned addresses by default.
19. **Withdraw on shutdown, and document crash cleanup.** Routing tables should not accumulate ghosts.
20. **Every alert needs a reason.** If the system cannot explain it, the operator cannot trust it.

---

## 24. Scenarios

These walkthroughs show how the pieces behave together.

### 24.1 Normal browsing

- Samples arrive steadily.
- Handshakes complete; trust rises slowly.
- PPS and Mbps stay near the destination’s baseline.
- No alerts.
- The dashboard is calm.

### 24.2 SYN flood against one destination

- Many small SYN samples arrive at one protected destination.
- Current PPS rises sharply above the baseline.
- The SYN/ACK ratio is extreme; many sources never complete a handshake.
- The threat score rises and stays high across several windows.
- The system confirms an attack and emits a critical alert with the contributing signals.
- If the flood is concentrated, a precise Flowspec rule discards the offending source’s SYNs.
- If it is distributed, a destination-oriented rule or RTBH is considered.
- The announcement is visible in the UI and withdraws automatically.
- The destination profile records the event; reputations are updated.

### 24.3 Spoofed UDP flood

- Thousands of sources send small UDP packets to one destination.
- Source diversity is extreme; per-source baselines are useless.
- The destination PPS and packet-size signals are strong.
- The system detects the aggregate anomaly, not individual sources.
- A Flowspec rule matches the destination, protocol, and packet size; RTBH is reserved for severe cases.
- The UI shows “distributed” rather than pretending to identify every source.

### 24.4 FTP control abuse

- A source sends non-TCP traffic to port 21, or uses a privileged source port, or floods the control channel.
- The protocol filter produces a precise alert.
- If the rate is high, a Flowspec rule matches the source, destination, protocol, and port.
- A trusted backup source is exempt from the rate penalty.
- Server replies from port 21 are never penalized.

### 24.5 Internal compromised host

- An owned source sends attack traffic to an external destination.
- The sensor may store and display it, but it does not announce an external blackhole for an owned address.
- The operator sees a warning and can quarantine the host through internal policy.
- This is a deliberate boundary between DDoS mitigation and internal incident response.

### 24.6 Trusted source during a legitimate spike

- A trusted backup source pushes a large transfer.
- PPS rises, but the source has high trust and the destination’s baseline adapts.
- The application filters are exempt.
- The volumetric layer may still observe, but persistence and trust prevent a hasty mitigation.
- The operator sees the spike and can decide whether it is expected.

### 24.7 BGP disabled

- Everything runs normally.
- Intended announcements are built, logged, and shown as simulated.
- No routing changes occur.
- The operator can validate the logic before enabling BGP.

### 24.8 BGP failure

- The sensor tries to announce a rule and the command fails.
- The alert is still recorded.
- The mitigation is marked failed with the error.
- The sensor does not spin in a retry loop.
- Detection and dashboard keep working.

### 24.9 Restart

- Profiles and reputations load from disk.
- Blocklists reload.
- Recent packets and alerts start empty.
- Baselines warm up again.
- The UI shows which destinations are learning.
- If shutdown was graceful, prior mitigations were withdrawn.

### 24.10 Blocklist reload

- The operator adds a new file or edits an existing one.
- Reload swaps the in-memory set atomically.
- New hits are detected immediately.
- No packets are lost during the swap.
- The UI shows the new count and files.

### 24.11 Manual trust

- The operator marks a source as trusted for a destination.
- The score becomes 100 and is persisted.
- Application filters exempt the source.
- The trust appears in the whitelist view.
- Revoking trust restores normal scoring.

---

## 25. What “a similar ending” means

A rebuilt system is successful when an operator can use it and recognize the same product.

### 25.1 Functional acceptance

- It runs as a single service, receives sFlow, and serves a dashboard.
- It filters traffic to protected CIDRs.
- It decodes IPv4, IPv6, ARP, TCP, UDP, ICMP, DNS, HTTP, and SSH banners to the extent the samples allow.
- It maintains recent packets, destination stats, TCP sessions, profiles, and reputations.
- It detects blocklist hits, SYN floods, out-of-state TCP, FTP control/data abuse, and volumetric anomalies.
- It produces BGP Flowspec and RTBH actions, with simulation mode, deduplication, duration, and auto-withdraw.
- It reloads blocklists without a restart.
- It persists destination profiles and reputations.
- It sends critical alerts to a webhook.
- The dashboard shows the overview, protected IPs, destination detail, intelligence, inspector, connections, blocklist, and mitigation views.
- Live updates work and do not stall ingestion.

### 25.2 Behavioral acceptance

- Normal traffic does not produce mitigations.
- A sustained SYN flood produces a timely, explainable mitigation.
- A trusted source is not punished for a brief spike.
- Server replies are never mistaken for client abuse.
- Every mitigation is withdrawn.
- Repeated alerts for the same destination and type are coalesced.
- A slow browser does not slow the sensor.
- A malformed sFlow datagram does not crash the sensor.
- A restart preserves profiles and reputations.
- The UI can explain why an alert fired.
- The system shows simulation clearly and never pretends a simulated action was real.

### 25.3 Engineering acceptance

- The code is race-free under the `-race` detector for the tested paths.
- Hot data structures are bounded and cleaned up.
- Profiles are saved atomically.
- Configuration is validated at startup.
- Unit tests cover the detection math, TCP state, blocklist behavior, configuration, and store concurrency.
- An integration test proves the full path from an attack observation to a mitigation command.
- The build is reproducible and does not require external Go modules for the core sensor.

### 25.4 Operator acceptance

- The system feels calm when nothing is happening.
- A real attack is obvious without reading logs.
- Every action has a reason and an expiry.
- The operator can start in simulation, tune, and then enable mitigation.
- The operator can trust the cleanup.

---

## 26. Non-goals and future directions

### 26.1 Non-goals for the first rebuild

- Inline dropping.
- Full packet capture.
- NetFlow/IPFIX ingestion.
- Multi-sensor clustering.
- Authentication and RBAC for the dashboard.
- Machine learning.
- GeoIP/ASN enrichment.
- Automated forensic reports.
- Kubernetes-native deployment.

These are not bad ideas; they are simply beyond the core idea. Keeping them out protects the first version from becoming vague.

### 26.2 Natural future directions

- Additional protocol filters (SSH brute force, DNS amplification patterns, HTTP floods).
- IPv6 Flowspec and RTBH.
- NetFlow/IPFIX support alongside sFlow.
- ASN and geography enrichment for source attribution.
- Multi-sensor aggregation and a global view.
- Prometheus metrics and Grafana dashboards.
- Alert history persistence and search.
- Policy engine for per-destination mitigation rules.
- Explicit allowlists and maintenance windows.
- Signed/audited mitigation actions.
- A “dry-run replay” mode for testing detection against captured samples.

The concept should be able to grow in these directions without changing its core loop.

---

## 27. Glossary

**Agent / exporter** — A router or switch that sends sFlow samples to the sensor.

**Alert** — A recorded decision that something noteworthy happened, with a reason and severity.

**Baseline** — An adaptive model of what is normal for a destination or source-destination pair.

**Blocklist** — A set of source IPs or CIDRs that are known to be bad.

**CIDR** — A range of IP addresses.

**Cooldown** — A period during which repeated alerts or actions for the same context are suppressed.

**Destination** — The protected IP or service receiving traffic.

**Flowspec** — A BGP address family that distributes traffic-match rules with actions such as discard or rate-limit.

**Mitigation** — A network action announced to the edge in response to an attack.

**Owned / protected prefix** — A network range the operator has declared as theirs and wants to protect.

**PPS** — Packets per second, corrected for sampling.

**RTBH** — Remotely Triggered Black Hole; a host route tagged so edge routers discard traffic to it.

**Sample** — One observation exported by sFlow, representing one or more real packets.

**Sampling rate** — How many real packets one sample represents.

**Severity** — Info, warning, or critical; guides attention and action.

**Source** — The sender of traffic, usually external to the protected network.

**Threat score** — A weighted, smoothed summary of suspicious signals for a destination.

**TrustScore** — A 0–100 behavioral reputation for a source toward a destination.

**Warm-up** — The period after startup or first observation when baselines are not yet trustworthy.

---

## 28. Closing thought

Dolly Sensor is not valuable because it can print a large number on a dashboard. It is valuable because it can watch a noisy, sampled network, remember what normal looks like, recognize an attack with enough confidence to act, ask the edge to stop it, and then clean up without leaving a mess.

The rebuild should preserve that character: **observant, evidence-driven, conservative under uncertainty, fast when certain, and honest about what it does not know.**
