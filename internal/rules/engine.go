package rules

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dollysensor/internal/mitigate"
	"dollysensor/internal/model"
	"dollysensor/internal/netutil"
)

const bucketCount = 61

type bucket struct {
	second  int64
	packets uint64
	bytes   uint64
	sources []netip.Addr
}

func (b *bucket) addSource(addr netip.Addr) {
	for _, existing := range b.sources {
		if existing == addr {
			return
		}
	}
	if len(b.sources) < 1024 {
		b.sources = append(b.sources, addr)
	}
}

type flowState struct {
	seen     int
	found    bool
	resolved bool
	last     time.Time
}

type runtime struct {
	mu              sync.Mutex
	buckets         [bucketCount]bucket
	above           int
	nextEligible    time.Time
	flows           map[string]*flowState
	lastObservation *model.Observation
	actionID        string
	actionStatus    string
	lastError       string

	hits           atomic.Uint64
	matchedPackets atomic.Uint64
	matchedBytes   atomic.Uint64
	triggers       atomic.Uint64
	suppressed     atomic.Uint64
	lastHit        atomic.Int64
	lastTrigger    atomic.Int64
}

func newRuntime(stats Stats) *runtime {
	rt := &runtime{flows: map[string]*flowState{}}
	rt.hits.Store(stats.Hits)
	rt.matchedPackets.Store(stats.MatchedPackets)
	rt.matchedBytes.Store(stats.MatchedBytes)
	rt.triggers.Store(stats.Triggers)
	rt.suppressed.Store(stats.Suppressed)
	if !stats.LastHit.IsZero() {
		rt.lastHit.Store(stats.LastHit.UnixNano())
	}
	if !stats.LastTrigger.IsZero() {
		rt.lastTrigger.Store(stats.LastTrigger.UnixNano())
	}
	return rt
}

func (rt *runtime) resetForRuleChange(now time.Time) {
	rt.mu.Lock()
	rt.buckets = [bucketCount]bucket{}
	rt.above = 0
	rt.nextEligible = time.Time{}
	rt.flows = map[string]*flowState{}
	rt.lastObservation = nil
	rt.actionID = ""
	rt.actionStatus = ""
	rt.lastError = ""
	rt.mu.Unlock()
}

func (rt *runtime) snapshot(rule *Rule, now time.Time) Stats {
	stats := Stats{
		Hits:           rt.hits.Load(),
		MatchedPackets: rt.matchedPackets.Load(),
		MatchedBytes:   rt.matchedBytes.Load(),
		Triggers:       rt.triggers.Load(),
		Suppressed:     rt.suppressed.Load(),
	}
	if value := rt.lastHit.Load(); value > 0 {
		stats.LastHit = time.Unix(0, value).UTC()
	}
	if value := rt.lastTrigger.Load(); value > 0 {
		stats.LastTrigger = time.Unix(0, value).UTC()
	}
	rt.mu.Lock()
	stats.ActionID = rt.actionID
	stats.ActionStatus = rt.actionStatus
	stats.LastError = rt.lastError
	nextEligible := rt.nextEligible
	hasFlow := len(rt.flows) > 0
	rt.mu.Unlock()
	stats.State = stateForRule(*rule, stats, now, nextEligible, hasFlow)
	return stats
}

func (rt *runtime) recordMatch(obs model.Observation, now time.Time, addBucket bool) {
	packets := obs.EstimatedPackets
	if packets == 0 {
		packets = 1
	}
	bytes := obs.EstimatedBytes
	rt.hits.Add(1)
	rt.matchedPackets.Add(packets)
	rt.matchedBytes.Add(bytes)
	rt.lastHit.Store(now.UnixNano())

	rt.mu.Lock()
	snapshot := cloneObservation(obs)
	rt.lastObservation = &snapshot
	if addBucket {
		rt.addBucketLocked(now, packets, bytes, obs.SrcIP.Unmap())
	}
	rt.mu.Unlock()
}

func (rt *runtime) addBucketLocked(now time.Time, packets, bytes uint64, source netip.Addr) {
	second := now.Unix()
	index := int(second % bucketCount)
	entry := &rt.buckets[index]
	if entry.second != second {
		*entry = bucket{second: second}
	}
	entry.packets += packets
	entry.bytes += bytes
	entry.addSource(source)
}

func (rt *runtime) windowTotalsLocked(now time.Time, seconds int) (packets, bytes uint64, sources int) {
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 60 {
		seconds = 60
	}
	cutoff := now.Unix() - int64(seconds) + 1
	nowSecond := now.Unix()
	distinct := map[netip.Addr]struct{}{}
	for i := range rt.buckets {
		entry := &rt.buckets[i]
		if entry.second >= cutoff && entry.second <= nowSecond {
			packets += entry.packets
			bytes += entry.bytes
			for _, addr := range entry.sources {
				distinct[addr] = struct{}{}
			}
		}
	}
	return packets, bytes, len(distinct)
}

func (rt *runtime) cleanupFlowsLocked(now time.Time, ttl time.Duration) {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	cutoff := now.Add(-ttl)
	for key, flow := range rt.flows {
		if flow.last.Before(cutoff) {
			delete(rt.flows, key)
		}
	}
}

func (rt *runtime) triggerLocked(rule *Rule, obs model.Observation, now time.Time, reason string, defaultDuration time.Duration) *Trigger {
	if now.Before(rt.nextEligible) {
		return nil
	}
	duration := time.Duration(rule.Action.DurationSeconds) * time.Second
	if duration <= 0 {
		duration = defaultDuration
	}
	if duration <= 0 {
		duration = time.Minute
	}
	cooldown := time.Duration(rule.Condition.CooldownSeconds) * time.Second
	if cooldown < 0 {
		cooldown = 0
	}
	rt.nextEligible = now.Add(duration + cooldown)
	rt.above = 0
	rt.triggers.Add(1)
	rt.lastTrigger.Store(now.UnixNano())
	copy := *rule
	return &Trigger{
		Rule:        copy,
		At:          now,
		Observation: cloneObservation(obs),
		Reason:      reason,
	}
}

// Observe evaluates one sampled observation. It returns at most one trigger per
// rule. It is safe to call from a single evaluator goroutine while rules are
// being edited.
func (s *Store) Observe(obs model.Observation, now time.Time) []Trigger {
	if s.opts.Disabled {
		return nil
	}
	if now.IsZero() {
		now = s.clock()
	}
	s.mu.RLock()
	type pair struct {
		rule    *Rule
		runtime *runtime
	}
	pairs := make([]pair, 0, len(s.rules))
	for _, id := range s.order {
		rule := s.rules[id]
		rt := s.runtime[id]
		if rule == nil || rt == nil || !rule.Enabled {
			continue
		}
		pairs = append(pairs, pair{rule: rule, runtime: rt})
	}
	s.mu.RUnlock()

	var triggers []Trigger
	for _, item := range pairs {
		rule := item.rule
		rt := item.runtime
		if rule.Mode == ModeStanding || rule.Action.Type == ActionAllow {
			if rule.Match.matches(obs, rule.compiled) {
				rt.recordMatch(obs, now, false)
			}
			continue
		}
		if !rule.Match.matches(obs, rule.compiled) {
			continue
		}
		payload := rule.compiled.payload
		switch rule.Condition.Payload.Mode {
		case PayloadNone:
			rt.recordMatch(obs, now, true)
		case PayloadContains:
			if payload == nil || !payload.matches(obs.Payload) {
				continue
			}
			rt.recordMatch(obs, now, true)
			if !hasRateThreshold(rule.Condition) {
				rt.mu.Lock()
				trigger := rt.triggerLocked(rule, obs, now, "Sampled payload matched the rule condition.", s.opts.DefaultDuration)
				rt.mu.Unlock()
				if trigger != nil {
					triggers = append(triggers, *trigger)
				}
			}
		case PayloadAbsentN, PayloadPresentN:
			rt.recordMatch(obs, now, false)
			if trigger := s.observeFirstN(rule, rt, payload, obs, now); trigger != nil {
				triggers = append(triggers, *trigger)
			}
		}
	}
	return triggers
}

func (s *Store) observeFirstN(rule *Rule, rt *runtime, payload *compiledPayload, obs model.Observation, now time.Time) *Trigger {
	if payload == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	key := flowKey(obs)
	flow := rt.flows[key]
	if flow == nil {
		rt.cleanupFlowsLocked(now, s.opts.FlowTTL)
		if len(rt.flows) >= s.opts.MaxFlowsPerRule {
			return nil
		}
		flow = &flowState{last: now}
		rt.flows[key] = flow
	}
	flow.last = now
	if flow.resolved {
		return nil
	}
	flow.seen++
	found := payload.matches(obs.Payload)
	if found {
		flow.found = true
	}
	switch rule.Condition.Payload.Mode {
	case PayloadAbsentN:
		if found {
			flow.resolved = true
			return nil
		}
		if flow.seen >= payload.firstN {
			flow.resolved = true
			reason := fmt.Sprintf("Required payload %q was absent from the first %d sampled packets of this conversation.", payload.display, payload.firstN)
			return rt.triggerLocked(rule, obs, now, reason, s.opts.DefaultDuration)
		}
	case PayloadPresentN:
		if found && flow.seen <= payload.firstN {
			flow.resolved = true
			reason := fmt.Sprintf("Required payload %q appeared within the first %d sampled packets of this conversation.", payload.display, payload.firstN)
			return rt.triggerLocked(rule, obs, now, reason, s.opts.DefaultDuration)
		}
		if flow.seen >= payload.firstN {
			flow.resolved = true
		}
	}
	return nil
}

func hasRateThreshold(condition Condition) bool {
	return condition.MinPPS > 0 || condition.MinBPS > 0 || condition.MinPackets > 0 || condition.MinBytes > 0 || condition.MinSources > 0
}

// Tick advances volume rules and expires per-flow evaluation state. It returns
// conditional rule triggers. It should run at roughly the detection evaluation
// interval.
func (s *Store) Tick(now time.Time) []Trigger {
	if s.opts.Disabled {
		return nil
	}
	if now.IsZero() {
		now = s.clock()
	}
	s.mu.RLock()
	type pair struct {
		rule    *Rule
		runtime *runtime
	}
	pairs := make([]pair, 0, len(s.rules))
	for _, id := range s.order {
		rule := s.rules[id]
		rt := s.runtime[id]
		if rule == nil || rt == nil || !rule.Enabled || rule.Mode != ModeConditional {
			continue
		}
		pairs = append(pairs, pair{rule: rule, runtime: rt})
	}
	s.mu.RUnlock()

	var triggers []Trigger
	for _, item := range pairs {
		rule := item.rule
		rt := item.runtime
		rt.mu.Lock()
		rt.cleanupFlowsLocked(now, s.opts.FlowTTL)
		if now.Before(rt.nextEligible) {
			rt.above = 0
			rt.mu.Unlock()
			continue
		}
		if !hasRateThreshold(rule.Condition) || rule.Condition.Payload.Mode == PayloadAbsentN || rule.Condition.Payload.Mode == PayloadPresentN {
			// hasRateThreshold includes min_sources: any numeric condition
			// makes this rule eligible for the windowed Tick evaluation.
			rt.mu.Unlock()
			continue
		}
		seconds := rule.Condition.WindowSeconds
		packets, bytes, sources := rt.windowTotalsLocked(now, seconds)
		pps := float64(packets) / float64(seconds)
		bps := float64(bytes) * 8 / float64(seconds)
		met := true
		if rule.Condition.MinPPS > 0 && pps < rule.Condition.MinPPS {
			met = false
		}
		if rule.Condition.MinBPS > 0 && bps < rule.Condition.MinBPS {
			met = false
		}
		if rule.Condition.MinPackets > 0 && packets < rule.Condition.MinPackets {
			met = false
		}
		if rule.Condition.MinBytes > 0 && bytes < rule.Condition.MinBytes {
			met = false
		}
		if rule.Condition.MinSources > 0 && sources < rule.Condition.MinSources {
			met = false
		}
		if !met {
			rt.above = 0
			rt.mu.Unlock()
			continue
		}
		rt.above++
		if rt.above < rule.Condition.Consecutive || rt.lastObservation == nil {
			rt.mu.Unlock()
			continue
		}
		obs := *rt.lastObservation
		reason := fmt.Sprintf("Sampled volume exceeded the rule threshold: %.2f pps, %.2f bps, %d estimated packets, %d bytes, %d distinct sources over %ds.", pps, bps, packets, bytes, sources, seconds)
		trigger := rt.triggerLocked(rule, obs, now, reason, s.opts.DefaultDuration)
		rt.mu.Unlock()
		if trigger != nil {
			triggers = append(triggers, *trigger)
		}
	}
	return triggers
}

// NoteAction records the most recent enforcement outcome for a rule.
func (s *Store) NoteAction(ruleID, actionID, status, errText string) {
	if strings.TrimSpace(ruleID) == "" {
		return
	}
	s.mu.RLock()
	rt := s.runtime[ruleID]
	s.mu.RUnlock()
	if rt == nil {
		return
	}
	rt.mu.Lock()
	if actionID != "" {
		rt.actionID = actionID
	}
	if status != "" {
		rt.actionStatus = status
	}
	if errText != "" {
		rt.lastError = errText
	} else if status == "active" || status == "simulated" {
		rt.lastError = ""
	}
	rt.mu.Unlock()
}

// AllowCovers reports whether an enabled allow/bypass rule covers an automatic
// mitigation request. Allow rules only suppress Dolly's automatic actions;
// they do not alter a router's forwarding policy.
func (s *Store) AllowCovers(req mitigate.Request) (Rule, bool) {
	if s.opts.Disabled || req.Kind == mitigate.KindRTBH {
		return Rule{}, false
	}
	destination, ok := requestPrefix(req.DestinationPrefix, req.Destination)
	if !ok {
		return Rule{}, false
	}
	source, hasSource := requestPrefix(req.SourcePrefix, req.Source)

	s.mu.RLock()
	type pair struct {
		rule    *Rule
		runtime *runtime
	}
	pairs := make([]pair, 0)
	for _, id := range s.order {
		rule := s.rules[id]
		rt := s.runtime[id]
		if rule == nil || rt == nil || !rule.Enabled || rule.Action.Type != ActionAllow {
			continue
		}
		pairs = append(pairs, pair{rule: rule, runtime: rt})
	}
	s.mu.RUnlock()

	for _, item := range pairs {
		rule := item.rule
		if rule.compiled == nil || !prefixCovers(rule.compiled.destination, destination) {
			continue
		}
		if rule.Match.Direction == DirectionInternal {
			continue
		}
		if rule.compiled.hasSource {
			if !hasSource || !prefixCovers(rule.compiled.source, source) {
				continue
			}
		}
		if rule.Match.Protocol != 0 && req.Protocol != rule.Match.Protocol {
			continue
		}
		if rule.Match.TCPFlags != 0 && (req.TCPFlags&rule.Match.TCPFlags) != rule.Match.TCPFlags {
			continue
		}
		if rule.Match.Fragment && !req.Fragment {
			continue
		}
		if !coversU16(rule.Match.SrcPort, rule.Match.SrcPortMin, rule.Match.SrcPortMax, req.SrcPort) {
			continue
		}
		if !coversU16(rule.Match.DstPort, rule.Match.DstPortMin, rule.Match.DstPortMax, req.DstPort) {
			continue
		}
		if !coversU16(rule.Match.PacketLength, rule.Match.PacketLengthMin, rule.Match.PacketLengthMax, req.PacketLength) {
			continue
		}
		item.runtime.suppressed.Add(1)
		item.runtime.lastHit.Store(s.clock().UnixNano())
		copy := *rule
		return copy, true
	}
	return Rule{}, false
}

// coversU16 reports whether a rule's exact-or-range field covers a request's
// field. A rule field that is unset covers anything; a request field that is
// unset is only covered when the rule field is unset too.
func coversU16(ruleExact, ruleMin, ruleMax, reqValue uint16) bool {
	if ruleExact == 0 && ruleMin == 0 && ruleMax == 0 {
		return true
	}
	if reqValue == 0 {
		return false
	}
	return matchU16(ruleExact, ruleMin, ruleMax, reqValue)
}

func requestPrefix(explicit netip.Prefix, address netip.Addr) (netip.Prefix, bool) {
	if explicit.IsValid() {
		if !explicit.Addr().Is4() {
			return netip.Prefix{}, false
		}
		return explicit.Masked(), true
	}
	if !address.IsValid() {
		return netip.Prefix{}, false
	}
	address = address.Unmap()
	if !address.Is4() {
		return netip.Prefix{}, false
	}
	return netutil.ClampHost(address), true
}

// SetContext is intentionally absent: all evaluator methods are synchronous and
// bounded. The sensor runs them on a dedicated worker so a slow BGP operation
// never blocks packet decoding.
