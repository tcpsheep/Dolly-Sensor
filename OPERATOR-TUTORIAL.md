# Lab-to-production: wiring Dolly to a real router

This tutorial turns the safe, simulated sensor into a real mitigation controller. It is
deliberately conservative: you get visibility first, real announcements only after you
have reviewed a dry run against your own routers.

## 1. Topology you will produce

```
   ┌─────────────┐   sFlow   ┌─────────────┐   BGP      ┌──────────┐
   │   Leaf /    │──────────▶│   Dolly     │◀──────────▶│  Edge    │
   │   Spine     │  (v5 UDP) │  sensor     │   TCP/179  │  router  │
   └─────────────┘           └─────────────┘            └──────────┘
```

- One or more sFlow exporters point UDP/6343 flow samples at the sensor.
- The sensor opens a TCP/179 session to the edge router and announces Flowspec/RTBH
  for decisions it owns.
- Protected prefixes are announced downstream by your IGP/BGP as usual; the sensor
  only adds filter rules for traffic *toward* those prefixes.

## 2. Protect a prefix and start collecting

Edit `config.json`:

```jsonc
{
  "sflow": { "listen": "0.0.0.0:6343" },
  "dashboard": { "listen": "127.0.0.1:8080" },
  "protected_cidrs": ["203.0.113.0/24", "198.51.100.0/24"],   // your real prefixes
  "detection": { "threshold": 70, "persistence": 5, "pps_floor": 50000, "bps_floor": 1000000000 },
  "mitigation": {
    "auto_block": false,                                     // stay in simulation
    "rate_limit_mbps": 100,
    "blocklist_dir": "./data/blocklists"
  },
  "bgp": { "enabled": false }                                 // off for now
}
```

Point your exporters at the sensor's sFlow port. Generate a few minutes of background
traffic and watch the Overview and Destination detail pages populate. At this stage the
dashboard shows real estimated packet/byte counts and learned reputations, but BGP
stays disabled: every mitigation shows as `simulated`.

## 3. Dry-run announcements against a lab peer

BGP being off is the default for a reason — let Dolly build actions and print them
without your router ever seeing them. To verify the *wire format* before touching a
production peer, run the test peer included in the BGP test suite, or stand up a lab
router (FRR/Gluon/BIRD all accept Flowspec):

1. Allocate a lab subnet pair, e.g. `192.0.2.0/30`:
   - sensor `local_addr` = `192.0.2.2`, `peer_ip` = `192.0.2.1`
   - local AS = peer AS = `64512` (a private ASN) and a unique `router_id`.
2. On the lab peer, enable IPv4 unicast + IPv4 Flowspec address families for that
   session and apply an export policy that accepts Dolly's NLRI. A minimal FRR:

```
router bgp 64512
 neighbor 192.0.2.2 remote-as 64512
 !
 address-family ipv4 flowspec
  neighbor 192.0.2.2 activate
  neighbor 192.0.2.2 route-map FLOW_IN in
 exit-address-family
!
route-map FLOW_IN permit 10
 set community 65535:666
```

3. Arm the sensor with `bgp.enabled = true` **but keep `mitigation.auto_block = false`**.
   Trigger a detection (a short flood from `sflowgen` is enough). Inspect the action in
   the Mitigation view — it should go `announcing → active → expired/withdrawn` on the
   lab peer, and the lab router should show the matching Flowspec rule installed in its
   filter. This is your "does the wire encoding decode" checkpoint.

## 4. Arm automatic mitigation

Only after the dry run succeeds, on your production peer too:

- Confirm the edge router accepts IPv4 Flowspec and advertises it via the Multiprotocol
  capability, and that its inbound policy accepts Dolly's NLRI.
- Set `mitigation.auto_block = true` and `mitigation.community` / `next_hop` /
  `peer_addr` to the production edge.
- Choose one action type as the entry point:
  - **RTBH** for a single, confirmed extreme source. Dolly only ever sends RTBH for an
    external SYN-flood source it has high confidence in, and it carries your
    blackhole community.
  - **Flowspec rate-limit** as the first automated action for volumetric attacks —
    this is gentler than a discard and lets you observe whether the rate hurt the
    attack without nuking the service.
- Leave `rules.allow_destination_discard = false` (the default). Destination-only
  discards are refused precisely so an operator can't accidentally blackhole a whole
  protected prefix.

## 5. Add your standing and conditional rules

Now bring the rules engine online. This is usually where operators see the biggest win,
because rules encode network knowledge detection can't infer:

- A standing `allow` for your APM/monitoring source so it is never auto-blocked even if
  it trips a volume threshold.
- A standing `rate-limit` for a known-benign scanner prefix you want throttled, not
  dropped.
- A conditional `discard` whose payload condition matches a signature of your application
  abuse (e.g. a malformed first packet), scoped to the conversation so only that flow
  is killed.
- A `min_sources` conditional rule to catch distributed scans that no single-source
  heuristic would flag loudly enough.

Review the preview output in the dashboard before enabling each rule — the preview
runs a draft rule against the recent sample ring and reports matched observations,
flows, and estimated rates.

## 6. Operational checklist

- The sensor connects *outbound* to the edge's BGP port; the edge must accept the
  TCP session. `connect_timeout` bounds the retries; the sensor reconnects with bounded
  backoff.
- `next_hop` and `community` are router-specific — match your edge's import policy.
- Flowspec rules expire and are withdrawn automatically. RTBH host routes use the
  blackhole community so the edge routes them to a discard next-hop.
- On graceful shutdown the sensor withdraws what it can and saves profiles. A hard
  crash cannot clean up; keep a runbook item to clear stale announcements after a
  host-level restart (a session reset or a configured maximum announcement lifetime on
  the edge are the usual fallbacks).
- Treat the webhook URL in `alerting` as a secret.

## 7. Roll back if needed

Because rules are evaluated in explicit, persisted order and each carries its own
action, rolling back is a matter of disabling the rule (which withdraws its actions)
or deleting it and reverting the order. Standing `allow` rules always win for the
traffic they match, so even a misconfigured automatic mitigation can't override an
operator-defined bypass.
