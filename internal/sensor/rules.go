package sensor

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"dollysensor/internal/alerts"
	"dollysensor/internal/detect"
	"dollysensor/internal/events"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/netutil"
	"dollysensor/internal/rules"
)

// RulesData is the complete rules catalog view returned by the API.
type RulesData struct {
	Rules    []rules.Rule       `json:"rules"`
	Summary  rules.Summary      `json:"summary"`
	Limits   rules.Limits       `json:"limits"`
	Defaults rules.Defaults     `json:"defaults"`
	Save     rules.SaveState    `json:"save"`
	Enabled  bool               `json:"enabled"`
	Packs    []rules.PackSummary `json:"packs"`
	Warnings []string           `json:"warnings,omitempty"`
}

func (s *Sensor) ruleEvaluationLoop(ctx context.Context) {
	defer s.loopWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case obs, ok := <-s.ruleObservations:
			if !ok {
				return
			}
			at := obs.ReceivedAt
			if at.IsZero() {
				at = time.Now()
			}
			for _, trigger := range s.ruleStore.Observe(obs, at) {
				s.enqueueFinding(s.ruleTriggerFinding(trigger), at)
			}
		}
	}
}

// RuleData returns the catalog, limits, and persistence health.
func (s *Sensor) RuleData() RulesData {
	data := RulesData{
		Rules:    s.ruleStore.List(),
		Summary:  s.ruleStore.Summary(),
		Limits:   s.ruleStore.Limits(),
		Defaults: s.ruleStore.Defaults(),
		Save:     s.ruleStore.SaveState(),
		Enabled:  !s.ruleStore.Disabled(),
	}
	data.Summary.DroppedObservations += s.counters.droppedRules.Load()
	if data.Limits.AllowDestinationDiscard {
		data.Warnings = append(data.Warnings, "Destination-only discard is enabled. A rule-scoped discard can affect every source sending to the selected destination prefix.")
	}
	packs, err := rules.BuiltinPacks()
	if err != nil {
		data.Warnings = append(data.Warnings, "Built-in rule packs could not be read: "+err.Error())
	} else {
		data.Packs = packs
	}
	return data
}

// ImportPackByName imports one of the packs embedded in the binary. The
// result reports the created rules and any pack rules that already existed.
func (s *Sensor) ImportPackByName(ctx context.Context, name string) (rules.ImportResult, error) {
	pack, err := rules.BuiltinPack(name)
	if err != nil {
		return rules.ImportResult{}, err
	}
	return s.importPack(ctx, pack)
}

// ImportPackData imports a user-supplied .dly pack document.
func (s *Sensor) ImportPackData(ctx context.Context, data []byte) (rules.ImportResult, error) {
	pack, err := rules.ParsePack(data)
	if err != nil {
		return rules.ImportResult{}, err
	}
	return s.importPack(ctx, pack)
}

func (s *Sensor) importPack(ctx context.Context, pack rules.Pack) (rules.ImportResult, error) {
	result, err := s.ruleStore.ImportPack(pack)
	if err != nil {
		return rules.ImportResult{}, err
	}
	for _, rule := range result.Imported {
		s.afterRuleMutation(ctx, rule.ID)
	}
	s.publishRulesSummary()
	return result, nil
}

// CreateRule persists and applies a new operator rule.
func (s *Sensor) CreateRule(ctx context.Context, input rules.Rule) (rules.Rule, error) {
	rule, err := s.ruleStore.Create(input)
	if err != nil {
		return rules.Rule{}, err
	}
	s.afterRuleMutation(ctx, rule.ID)
	return s.ruleStore.Get(rule.ID)
}

// UpdateRule replaces and reconciles an operator rule.
func (s *Sensor) UpdateRule(ctx context.Context, id string, input rules.Rule) (rules.Rule, error) {
	rule, err := s.ruleStore.Update(id, input)
	if err != nil {
		return rules.Rule{}, err
	}
	s.afterRuleMutation(ctx, rule.ID)
	return s.ruleStore.Get(rule.ID)
}

// SetRuleEnabled toggles a rule and withdraws or applies its action.
func (s *Sensor) SetRuleEnabled(ctx context.Context, id string, enabled bool) (rules.Rule, error) {
	rule, err := s.ruleStore.SetEnabled(id, enabled)
	if err != nil {
		return rules.Rule{}, err
	}
	s.afterRuleMutation(ctx, rule.ID)
	return s.ruleStore.Get(rule.ID)
}

// DeleteRule removes a rule and withdraws rule-owned actions.
func (s *Sensor) DeleteRule(ctx context.Context, id string) (rules.Rule, error) {
	rule, err := s.ruleStore.Delete(id)
	if err != nil {
		return rules.Rule{}, err
	}
	s.afterRuleMutation(ctx, id)
	return rule, nil
}

// ReorderRules applies a new evaluation order for the whole catalog. The
// order is persisted and used by every subsequent evaluation.
func (s *Sensor) ReorderRules(ctx context.Context, ids []string) ([]rules.Rule, error) {
	list, err := s.ruleStore.Reorder(ids)
	if err != nil {
		return nil, err
	}
	s.publishRulesSummary()
	for _, rule := range list {
		s.publishRuleState(rule.ID)
	}
	return list, nil
}

// MoveRule moves one rule to a new zero-based position in the evaluation
// order and persists the change.
func (s *Sensor) MoveRule(ctx context.Context, id string, position int) ([]rules.Rule, error) {
	list, err := s.ruleStore.MoveRule(id, position)
	if err != nil {
		return nil, err
	}
	s.publishRulesSummary()
	for _, rule := range list {
		s.publishRuleState(rule.ID)
	}
	return list, nil
}

// PreviewRule evaluates a draft definition against recent sampled traffic.
func (s *Sensor) PreviewRule(input rules.Rule) (rules.PreviewResult, error) {
	return s.ruleStore.Preview(input, s.ring.All())
}

func (s *Sensor) afterRuleMutation(ctx context.Context, ruleID string) {
	s.ruleOpsMu.Lock()
	defer s.ruleOpsMu.Unlock()
	s.withdrawRuleActionsLocked(ctx, ruleID, false)
	s.syncStandingRulesLocked(ctx)
	s.publishRulesSummary()
	s.publishRuleState(ruleID)
}

func (s *Sensor) publishRuleState(ruleID string) {
	if s.ruleStore == nil || ruleID == "" {
		return
	}
	rule, err := s.ruleStore.Get(ruleID)
	if err != nil {
		return
	}
	s.hub.Publish(events.Event{Type: "rule", Data: rule})
}

func (s *Sensor) publishRulesSummary() {
	if s.ruleStore == nil {
		return
	}
	s.hub.Publish(events.Event{Type: "rules", Data: map[string]any{
		"summary": s.ruleStore.Summary(),
		"enabled": !s.ruleStore.Disabled(),
	}})
}

// syncStandingRules reconciles persistent rule actions. It is called at
// startup, after mutations, on BGP reconnect, and periodically. Conditional
// rule actions are not touched here: they expire on their own and are
// withdrawn explicitly when their rule changes.
func (s *Sensor) syncStandingRules(ctx context.Context) {
	s.ruleOpsMu.Lock()
	defer s.ruleOpsMu.Unlock()
	s.syncStandingRulesLocked(ctx)
}

func (s *Sensor) syncStandingRulesLocked(ctx context.Context) {
	if s.ruleStore == nil || s.closed.Load() {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
	}

	desired := map[string]rules.Rule{}
	if !s.ruleStore.Disabled() {
		for _, rule := range s.ruleStore.EnabledStandingRules() {
			if rule.Action.Type == rules.ActionAllow {
				continue
			}
			desired[rule.ID] = rule
		}
	}

	active := s.mitigator.Active()
	standingActive := map[string]mitigate.Action{}
	for _, action := range active {
		if action.RuleID == "" || !action.Permanent {
			continue
		}
		if _, keep := desired[action.RuleID]; !keep {
			s.withdrawActionLocked(ctx, action, "rule removed or disabled")
			continue
		}
		standingActive[action.RuleID] = action
	}

	for id, rule := range desired {
		request, err := s.standingRuleRequest(rule)
		if err != nil {
			s.logger.Warn("rule cannot be enforced", "rule", rule.Name, "error", err.Error())
			s.ruleStore.NoteAction(rule.ID, "", "failed", err.Error())
			s.publishRuleState(rule.ID)
			continue
		}
		if existing, ok := standingActive[id]; ok {
			if standingActionMatches(existing, request) {
				s.ruleStore.NoteAction(rule.ID, existing.ID, string(existing.Status), existing.Error)
				continue
			}
			s.withdrawActionLocked(ctx, existing, "rule definition changed")
		}
		if err := ctx.Err(); err != nil {
			return
		}
		request.DedupKey = fmt.Sprintf("standing-rule|%s|%d", rule.ID, time.Now().UnixNano())
		action, proposeErr := s.mitigator.Propose(ctx, request)
		switch {
		case action != nil:
			s.publishAction(*action)
			s.ruleStore.NoteAction(rule.ID, action.ID, string(action.Status), action.Error)
			s.publishRuleState(rule.ID)
			if proposeErr != nil {
				s.logger.Warn("standing rule enforcement failed", "rule", rule.Name, "error", proposeErr.Error())
			}
		case proposeErr != nil:
			s.ruleStore.NoteAction(rule.ID, "", "failed", proposeErr.Error())
			s.publishRuleState(rule.ID)
			s.logger.Warn("standing rule enforcement rejected", "rule", rule.Name, "error", proposeErr.Error())
		}
	}
}

func (s *Sensor) withdrawRuleActions(ctx context.Context, ruleID string, permanentOnly bool) {
	s.ruleOpsMu.Lock()
	defer s.ruleOpsMu.Unlock()
	s.withdrawRuleActionsLocked(ctx, ruleID, permanentOnly)
}

func (s *Sensor) withdrawRuleActionsLocked(ctx context.Context, ruleID string, permanentOnly bool) {
	for _, action := range s.mitigator.Active() {
		if action.RuleID != ruleID {
			continue
		}
		if permanentOnly && !action.Permanent {
			continue
		}
		s.withdrawActionLocked(ctx, action, "rule changed or disabled")
	}
}

func (s *Sensor) withdrawActionLocked(ctx context.Context, action mitigate.Action, reason string) {
	if ctx == nil {
		ctx = context.Background()
	}
	withdrawCtx, cancel := context.WithTimeout(ctx, 14*time.Second)
	updated, err := s.mitigator.WithdrawNow(withdrawCtx, action.ID, reason)
	cancel()
	if updated != nil {
		s.publishAction(*updated)
		s.ruleStore.NoteAction(action.RuleID, updated.ID, string(updated.Status), updated.Error)
		s.publishRuleState(action.RuleID)
	}
	if err != nil && !strings.Contains(err.Error(), "not found") {
		s.logger.Warn("rule action withdrawal failed", "rule", action.RuleID, "action", action.ID, "error", err.Error())
	}
}

func (s *Sensor) standingRuleRequest(rule rules.Rule) (mitigate.Request, error) {
	destination, err := parseRulePrefix(rule.Match.Destination)
	if err != nil {
		return mitigate.Request{}, fmt.Errorf("destination: %w", err)
	}
	var source string
	if strings.TrimSpace(rule.Match.Source) != "" {
		prefix, err := parseRulePrefix(rule.Match.Source)
		if err != nil {
			return mitigate.Request{}, fmt.Errorf("source: %w", err)
		}
		source = prefix.String()
	}
	request := mitigate.Request{
		Kind:              mitigate.KindFlowspec,
		DestinationPrefix: destination,
		Protocol:          rule.Match.Protocol,
		SrcPort:           rule.Match.SrcPort,
		DstPort:           rule.Match.DstPort,
		SrcPortMin:        rule.Match.SrcPortMin,
		SrcPortMax:        rule.Match.SrcPortMax,
		DstPortMin:        rule.Match.DstPortMin,
		DstPortMax:        rule.Match.DstPortMax,
		TCPFlags:          rule.Match.TCPFlags,
		PacketLength:      rule.Match.PacketLength,
		PacketLengthMin:   rule.Match.PacketLengthMin,
		PacketLengthMax:   rule.Match.PacketLengthMax,
		Fragment:          rule.Match.Fragment,
		Action:            rule.Action.Type,
		RateLimitBPS:      rule.Action.RateLimitBPS,
		Reason:            fmt.Sprintf("Standing rule %q", rule.Name),
		Owner:             "rule:" + rule.ID,
		RuleID:            rule.ID,
		Permanent:         true,
	}
	if source != "" {
		prefix, _ := parseRulePrefix(source)
		request.SourcePrefix = prefix
	}
	if request.Action == rules.ActionRateLimit && request.RateLimitBPS == 0 {
		request.RateLimitBPS = uint64(s.cfg.Mitigation.RateLimitMbps * 1_000_000)
	}
	return request, nil
}

func standingActionMatches(action mitigate.Action, request mitigate.Request) bool {
	if action.Kind != request.Kind || !action.Permanent {
		return false
	}
	if action.Action != request.Action || action.RateLimitBPS != request.RateLimitBPS {
		return false
	}
	if action.Match.Destination != request.DestinationPrefix.Masked().String() {
		return false
	}
	source := ""
	if request.SourcePrefix.IsValid() {
		source = request.SourcePrefix.Masked().String()
	}
	if action.Match.Source != source {
		return false
	}
	return action.Match.Protocol == request.Protocol &&
		action.Match.SrcPort == request.SrcPort &&
		action.Match.DstPort == request.DstPort &&
		action.Match.SrcPortMin == request.SrcPortMin &&
		action.Match.SrcPortMax == request.SrcPortMax &&
		action.Match.DstPortMin == request.DstPortMin &&
		action.Match.DstPortMax == request.DstPortMax &&
		action.Match.TCPFlags == request.TCPFlags &&
		action.Match.PacketLength == request.PacketLength &&
		action.Match.PacketLengthMin == request.PacketLengthMin &&
		action.Match.PacketLengthMax == request.PacketLengthMax &&
		action.Match.Fragment == request.Fragment
}

func (s *Sensor) ruleTriggerFinding(trigger rules.Trigger) detect.Finding {
	rule := trigger.Rule
	request := mitigate.Request{
		Kind:            mitigate.KindFlowspec,
		Protocol:        rule.Match.Protocol,
		SrcPort:         rule.Match.SrcPort,
		DstPort:         rule.Match.DstPort,
		SrcPortMin:      rule.Match.SrcPortMin,
		SrcPortMax:      rule.Match.SrcPortMax,
		DstPortMin:      rule.Match.DstPortMin,
		DstPortMax:      rule.Match.DstPortMax,
		TCPFlags:        rule.Match.TCPFlags,
		PacketLength:    rule.Match.PacketLength,
		PacketLengthMin: rule.Match.PacketLengthMin,
		PacketLengthMax: rule.Match.PacketLengthMax,
		Fragment:        rule.Match.Fragment,
		Action:          rule.Action.Type,
		RateLimitBPS:    rule.Action.RateLimitBPS,
		Reason:          fmt.Sprintf("Rule %q: %s", rule.Name, trigger.Reason),
		Owner:           "rule:" + rule.ID,
		RuleID:          rule.ID,
		Duration:        time.Duration(rule.Action.DurationSeconds) * time.Second,
	}
	destinationLabel := rule.Match.Destination
	sourceLabel := rule.Match.Source
	switch {
	case rule.Action.Scope == rules.ScopeFlow && trigger.Observation.SrcIP.IsValid() && trigger.Observation.DstIP.IsValid():
		request.SourcePrefix = netutil.ClampHost(trigger.Observation.SrcIP)
		request.DestinationPrefix = netutil.ClampHost(trigger.Observation.DstIP)
		request.Protocol = trigger.Observation.Protocol
		request.SrcPort = trigger.Observation.SrcPort
		request.DstPort = trigger.Observation.DstPort
		destinationLabel = request.DestinationPrefix.String()
		sourceLabel = request.SourcePrefix.String()
	case rule.Action.Scope == rules.ScopeSource && trigger.Observation.SrcIP.IsValid():
		// Source-scoped enforcement: the rule's header match pinned to the
		// address that actually tripped the threshold. The destination comes
		// from the observation for wildcard rules ("@protected") and from
		// the rule header otherwise.
		request.SourcePrefix = netutil.ClampHost(trigger.Observation.SrcIP)
		sourceLabel = request.SourcePrefix.String()
		if rule.Match.Destination == rules.DestinationWildcard {
			request.DestinationPrefix = netutil.ClampHost(trigger.Observation.DstIP)
			destinationLabel = request.DestinationPrefix.String()
		} else if prefix, err := parseRulePrefix(rule.Match.Destination); err == nil {
			request.DestinationPrefix = prefix
		}
	default:
		if prefix, err := parseRulePrefix(rule.Match.Destination); err == nil {
			request.DestinationPrefix = prefix
		}
		if strings.TrimSpace(rule.Match.Source) != "" {
			if prefix, err := parseRulePrefix(rule.Match.Source); err == nil {
				request.SourcePrefix = prefix
			}
		}
	}
	if request.Action == rules.ActionRateLimit && request.RateLimitBPS == 0 {
		request.RateLimitBPS = uint64(s.cfg.Mitigation.RateLimitMbps * 1_000_000)
	}
	severity := alerts.SeverityWarning
	if request.Action == "discard" {
		severity = alerts.SeverityCritical
	}
	key := "rule|" + rule.ID + "|" + rule.Action.Scope
	if rule.Action.Scope == rules.ScopeFlow {
		key = fmt.Sprintf("rule|%s|%s|%d|%s|%d|%d", rule.ID,
			trigger.Observation.SrcIP, trigger.Observation.SrcPort,
			trigger.Observation.DstIP, trigger.Observation.DstPort, trigger.Observation.Protocol)
	}
	if rule.Action.Scope == rules.ScopeSource {
		key = fmt.Sprintf("rule|%s|%s|%s", rule.ID, trigger.Observation.SrcIP, destinationLabel)
	}
	signals := []string{
		fmt.Sprintf("rule: %s", rule.Name),
		fmt.Sprintf("mode: %s", rule.Mode),
		fmt.Sprintf("scope: %s", rule.Action.Scope),
		"sampled sFlow evaluation, not inline packet inspection",
	}
	if rule.Pack != "" {
		signals = append(signals, "pack: "+rule.Pack)
	}
	if rule.Condition.PerSource {
		signals = append(signals, "thresholds judged per source address")
	}
	if rule.Condition.Payload.Mode != rules.PayloadNone {
		signals = append(signals, "payload evaluated on sampled packets (up to the capture budget)")
	}
	if rule.Action.Scope == rules.ScopeFlow {
		signals = append(signals, "enforcement narrowed to the observed conversation")
	}
	if rule.Action.Scope == rules.ScopeSource {
		signals = append(signals, "enforcement narrowed to the triggering source")
	}
	return detect.Finding{
		Alert: alerts.Candidate{
			Key:         key,
			Severity:    severity,
			Type:        "rule_trigger",
			Layer:       "rules",
			Destination: destinationLabel,
			Source:      sourceLabel,
			Reason:      request.Reason,
			Signals:     signals,
		},
		Action: &request,
	}
}

func parseRulePrefix(value string) (netip.Prefix, error) {
	prefix, err := netutil.ParseIPOrPrefix(strings.TrimSpace(value))
	if err != nil {
		return netip.Prefix{}, err
	}
	return prefix.Masked(), nil
}
