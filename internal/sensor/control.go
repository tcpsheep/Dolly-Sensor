package sensor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"dollysensor/internal/alerts"
	"dollysensor/internal/detect"
	"dollysensor/internal/events"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/model"
	"dollysensor/internal/netutil"
	"dollysensor/internal/notify"
	"dollysensor/internal/tcpstate"
)

func (s *Sensor) evaluationLoop(ctx context.Context) {
	defer s.loopWG.Done()
	interval := s.cfg.Detection.EvaluationInterval.Std()
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case at := <-ticker.C:
			s.evaluateOnce(at)
		}
	}
}

// evaluateOnce runs one detection round. The evaluation loop calls it; tests
// may call it directly to advance detection without waiting for wall time.
func (s *Sensor) evaluateOnce(now time.Time) {
	window := s.cfg.Detection.RateWindowSeconds
	snapshots := s.aggregate.SnapshotAll(now, window)
	var oos map[netip.Addr]tcpstate.OOSStat
	if s.tcp != nil {
		oos = s.tcp.OutOfStateStats(now, window)
	}
	results := s.detector.Evaluate(now, snapshots, oos)
	for _, result := range results {
		dst, err := parseAddr(result.State.Destination)
		if err != nil {
			continue
		}
		s.aggregate.RecordEvaluation(dst, now, result.State.PPS, result.State.BPS, result.State.SmoothedScore)
		s.intel.RecordRates(dst, result.State.PPS, result.State.BPS)
		for _, finding := range result.Findings {
			s.enqueueFinding(finding, now)
		}
	}
	if s.ruleStore != nil {
		for _, trigger := range s.ruleStore.Tick(now) {
			s.enqueueFinding(s.ruleTriggerFinding(trigger), now)
		}
	}
	s.counters.evaluations.Add(1)
	s.lastEval.Store(now.UnixNano())

	global := s.aggregate.Global(now, window, 1)
	attacks := 0
	for _, state := range s.detector.States() {
		if state.Attack {
			attacks++
		}
	}
	s.hub.Publish(events.Event{Type: "tick", Data: map[string]any{
		"at":               now,
		"pps":              global.PPS,
		"bps":              global.BPS,
		"destinations":     s.aggregate.DestinationCount(),
		"attacks":          attacks,
		"alerts":           s.alerts.Stats(),
		"mitigation":       s.mitigator.Counts(),
		"queue_depth":      len(s.datagrams),
		"finding_queue":    len(s.findings),
		"accepted":         s.counters.accepted.Load(),
		"evaluations":      s.counters.evaluations.Load(),
		"last_packet_time": timeFromUnixNano(s.last.packet.Load()),
	}})
}

func (s *Sensor) maintenanceLoop(ctx context.Context) {
	defer s.loopWG.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.maintenanceOnce(ctx, now)
		}
	}
}

// trustDecayLoop honors memory.trust_decay_interval independently of the
// general maintenance cadence. Decay itself is still idempotent per source per
// day, so a short interval can never accelerate reputation loss beyond policy.
func (s *Sensor) trustDecayLoop(ctx context.Context) {
	defer s.loopWG.Done()
	interval := s.cfg.Memory.TrustDecayInterval.Std()
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.intel.Decay(now)
		}
	}
}

// mitigationLoop runs the expiry state machine on a short cadence. Maintenance
// cleanup is deliberately slower; a stale BGP rule is more urgent than GC.
func (s *Sensor) mitigationLoop(ctx context.Context) {
	defer s.loopWG.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.publishMitigationChanges(ctx)
		}
	}
}

func (s *Sensor) maintenanceOnce(ctx context.Context, now time.Time) {
	if now.UnixNano()-s.lastReload.Load() >= int64(time.Minute) {
		if warnings, err := s.blocklist.Reload(); err != nil {
			s.logger.Warn("blocklist reload failed; keeping previous snapshot", "error", err.Error())
		} else if len(warnings) > 0 {
			s.logger.Warn("blocklist reload completed with warnings", "warnings", len(warnings))
		}
		s.lastReload.Store(now.UnixNano())
	}
	s.aggregate.Cleanup(now, s.cfg.Memory.DestinationStatsTTL.Std())
	s.detector.Cleanup(now, s.cfg.Memory.BaselineTTL.Std())
	s.gate.cleanup(now)
	if s.tcp != nil {
		for _, event := range s.tcp.Sweep(now) {
			switch event.Kind {
			case tcpEventHandshake:
				s.intel.CreditHandshake(event.Destination, event.Source, event.At)
			case tcpEventLongSession:
				s.intel.CreditLongSession(event.Destination, event.Source, event.At, event.Duration)
			}
		}
	}
	s.publishMitigationChanges(ctx)
	s.syncStandingRules(ctx)
}

func (s *Sensor) publishMitigationChanges(ctx context.Context) {
	for _, action := range s.mitigator.Tick(ctx) {
		s.publishAction(action)
		if action.RuleID != "" && s.ruleStore != nil {
			s.ruleStore.NoteAction(action.RuleID, action.ID, string(action.Status), action.Error)
			s.publishRuleState(action.RuleID)
		}
		if action.AlertID == "" {
			continue
		}
		summary := summarizeAction(&action)
		s.alerts.AttachAction(action.AlertID, action.ID, string(action.Status), summary)
		if alert, ok := s.alerts.Get(action.AlertID); ok {
			s.hub.Publish(events.Event{Type: "alert", Data: alert})
		}
	}
}

func (s *Sensor) saveLoop(ctx context.Context) {
	defer s.loopWG.Done()
	interval := s.cfg.Persistence.SaveInterval.Std()
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.intel.Save(false); err != nil {
				s.logger.Warn("profile save failed", "error", err.Error())
			}
		}
	}
}

func (s *Sensor) controlWorker(ctx context.Context) {
	defer s.controlWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case finding, ok := <-s.findings:
			if !ok {
				return
			}
			s.handleFinding(ctx, finding)
		}
	}
}

func (s *Sensor) handleFinding(ctx context.Context, finding detect.Finding) {
	now := time.Now()
	alert, created, escalated := s.alerts.Record(finding.Alert, now)
	if created {
		s.logger.Info("alert raised",
			"alert", alert.ID,
			"severity", alert.Severity,
			"type", alert.Type,
			"destination", alert.Destination,
			"source", alert.Source,
		)
	}
	var action *mitigate.Action
	var actionErr error
	newAction := false
	attempted := finding.Action != nil
	if finding.Action != nil {
		request := *finding.Action
		request.AlertID = alert.ID
		if request.Owner == "" {
			request.Owner = finding.Alert.Layer
		}
		allowedBy := ""
		ruleDisabled := false
		if s.ruleStore != nil {
			switch {
			case request.RuleID != "" && !s.ruleStore.Enabled(request.RuleID):
				ruleDisabled = true
				attempted = false
				s.alerts.AttachAction(alert.ID, "", "skipped", "Rule is no longer enabled; queued action was not applied.")
			case request.RuleID == "":
				if allow, ok := s.ruleStore.AllowCovers(request); ok {
					allowedBy = allow.Name
					attempted = false
					s.alerts.AttachAction(alert.ID, "", "suppressed", "Automatic mitigation suppressed by allow/bypass rule "+allow.Name+".")
				}
			}
		}
		if !ruleDisabled && allowedBy == "" {
			if covering, ok := s.coveringAction(request); ok {
				// A live action already protects this flow. Do not announce a
				// near-duplicate just because scoring or match selection moved a
				// little; attach the existing action so the alert's story is honest.
				action = &covering
				s.alerts.AttachAction(alert.ID, covering.ID, string(covering.Status), "Existing "+summarizeAction(&covering)+" already covers this flow.")
			} else {
				opCtx, cancel := context.WithTimeout(ctx, 14*time.Second)
				action, actionErr = s.mitigator.Propose(opCtx, request)
				cancel()
				newAction = true
				switch {
				case actionErr == nil && action != nil:
					summary := summarizeAction(action)
					s.alerts.AttachAction(alert.ID, action.ID, string(action.Status), summary)
					s.publishAction(*action)
				case action != nil:
					summary := "Failed: " + action.Error
					s.alerts.AttachAction(alert.ID, action.ID, string(action.Status), summary)
					s.publishAction(*action)
					s.logger.Warn("mitigation failed", "alert", alert.ID, "action", action.ID, "error", actionErr.Error())
				case errors.Is(actionErr, mitigate.ErrDuplicate):
					s.alerts.AttachAction(alert.ID, "", "deduplicated", "An equivalent mitigation is already active.")
				default:
					s.alerts.ActionFailed(alert.ID, actionErr.Error())
					s.logger.Warn("mitigation rejected", "alert", alert.ID, "error", actionErr.Error())
				}
			}
			if request.RuleID != "" && s.ruleStore != nil {
				actionID := ""
				status := ""
				errText := ""
				if action != nil {
					actionID = action.ID
					status = string(action.Status)
					errText = action.Error
				} else if actionErr != nil {
					errText = actionErr.Error()
					if errors.Is(actionErr, mitigate.ErrDuplicate) {
						status = "deduplicated"
					}
				}
				s.ruleStore.NoteAction(request.RuleID, actionID, status, errText)
				s.publishRuleState(request.RuleID)
			}
		}
	}
	updated, ok := s.alerts.Get(alert.ID)
	if !ok {
		return
	}
	if created || escalated || action != nil || actionErr != nil {
		s.hub.Publish(events.Event{Type: "alert", Data: updated})
	}
	duplicate := errors.Is(actionErr, mitigate.ErrDuplicate)
	if duplicate {
		newAction = false
	}
	notifyErr := actionErr
	if duplicate {
		notifyErr = nil
	}
	// Notify once for a new critical alert, once when an existing alert
	// escalates, and once when a new mitigation is proposed or fails. Repeated
	// observations that only coalesce or reuse a covering action stay quiet.
	if updated.Severity == alerts.SeverityCritical && (created || escalated || newAction) {
		s.notifyAlert(updated, finding, action, notifyErr, attempted)
	}
}

func (s *Sensor) notifyAlert(alert alerts.Alert, finding detect.Finding, action *mitigate.Action, actionErr error, attempted bool) {
	value := notify.Notification{
		Title:       alertTitle(alert, finding.Alert),
		Severity:    string(alert.Severity),
		Type:        alert.Type,
		Destination: alert.Destination,
		Source:      alert.Source,
		Reason:      alert.Reason,
		Signals:     append([]string(nil), alert.Signals...),
		At:          alert.Time,
	}
	switch {
	case action != nil:
		value.Action = summarizeAction(action)
		value.Simulated = action.Simulated
	case attempted && actionErr != nil:
		value.Action = "Failed: " + actionErr.Error()
	}
	s.notifier.Enqueue(value)
}

func (s *Sensor) publishAction(action mitigate.Action) {
	s.hub.Publish(events.Event{Type: "mitigation", Data: action})
}

func summarizeAction(action *mitigate.Action) string {
	if action == nil {
		return ""
	}
	var b strings.Builder
	switch action.Status {
	case mitigate.StatusSimulated:
		b.WriteString("Simulated ")
	case mitigate.StatusActive:
		b.WriteString("Announced ")
	case mitigate.StatusFailed:
		b.WriteString("Failed ")
	case mitigate.StatusWithdrawn, mitigate.StatusExpired:
		b.WriteString("Withdrawn ")
	default:
		b.WriteString(strings.Title(string(action.Status)))
		b.WriteByte(' ')
	}
	if action.Kind == mitigate.KindRTBH {
		fmt.Fprintf(&b, "RTBH discard of source %s", action.Target)
		if action.Community != "" {
			fmt.Fprintf(&b, " (community %s)", action.Community)
		}
	} else {
		b.WriteString("Flowspec ")
		b.WriteString(action.Action)
		if action.RateLimitBPS > 0 {
			fmt.Fprintf(&b, " at %.2f Mbps", float64(action.RateLimitBPS)/1_000_000)
		}
		if action.Match.Source != "" {
			fmt.Fprintf(&b, " from %s", action.Match.Source)
		}
		if action.Match.Destination != "" {
			fmt.Fprintf(&b, " to %s", action.Match.Destination)
		}
		if action.Match.Protocol != 0 {
			fmt.Fprintf(&b, " proto %s", model.ProtocolName(action.Match.Protocol))
		}
		if action.Match.DstPort != 0 {
			fmt.Fprintf(&b, " port %d", action.Match.DstPort)
		}
		if action.Match.TCPFlags != 0 {
			fmt.Fprintf(&b, " flags 0x%02x", action.Match.TCPFlags)
		}
	}
	if action.Status == mitigate.StatusFailed && action.Error != "" {
		b.WriteString(": ")
		b.WriteString(action.Error)
	} else if !action.ExpiresAt.IsZero() {
		duration := action.ExpiresAt.Sub(action.CreatedAt).Round(time.Second)
		if duration > 0 {
			fmt.Fprintf(&b, " for %s", duration)
		}
	}
	return b.String()
}

// coveringAction returns a live action that already protects the requested
// flow. The detector can change its mind as evidence accumulates (for example
// rate-limit -> discard, or a more precise Flowspec match). Announcing every
// revision would produce a wall of overlapping BGP rules, so a live covering
// action is reused until it expires or is withdrawn.
func (s *Sensor) coveringAction(req mitigate.Request) (mitigate.Action, bool) {
	wantedSource := ""
	if req.Source.IsValid() {
		wantedSource = netutil.ClampHost(req.Source).String()
	}
	wantedDestination := ""
	if req.Destination.IsValid() {
		wantedDestination = netutil.ClampHost(req.Destination).String()
	}
	for _, active := range s.mitigator.Active() {
		// A withdrawing rule is on its way out and must not suppress a fresh
		// action that still has evidence behind it.
		if active.Status == mitigate.StatusWithdrawing {
			continue
		}
		if !actionStrongEnough(active.Action, req.Action) {
			continue
		}
		if actionCovers(active, req.Kind, wantedSource, wantedDestination, req.Protocol, req.SrcPort, req.DstPort, req.TCPFlags, req.PacketLength) {
			return active, true
		}
	}
	return mitigate.Action{}, false
}

// actionStrongEnough avoids treating a broad rate-limit as coverage for a
// requested discard. The reverse is fine: an existing discard already does
// everything a new rate-limit would do.
func actionStrongEnough(existing, requested string) bool {
	if strings.EqualFold(requested, "discard") && !strings.EqualFold(existing, "discard") {
		return false
	}
	return true
}

func actionCovers(action mitigate.Action, kind mitigate.Kind, source, destination string, protocol uint8, srcPort, dstPort, tcpFlags, packetLength uint16) bool {
	if kind == mitigate.KindRTBH {
		return action.Kind == mitigate.KindRTBH && action.Match.Source == source
	}
	if action.Kind == mitigate.KindRTBH {
		// A blackholed source covers every FlowSpec variant for that source.
		return source != "" && action.Match.Source == source
	}
	if action.Match.Destination != destination {
		return false
	}
	// An empty existing source means "any source"; a precise existing source
	// only covers the same source.
	if action.Match.Source != "" && action.Match.Source != source {
		return false
	}
	if action.Match.Protocol != 0 && action.Match.Protocol != protocol {
		return false
	}
	if action.Match.SrcPort != 0 && action.Match.SrcPort != srcPort {
		return false
	}
	if action.Match.DstPort != 0 && action.Match.DstPort != dstPort {
		return false
	}
	if action.Match.TCPFlags != 0 && action.Match.TCPFlags != tcpFlags {
		return false
	}
	if action.Match.PacketLength != 0 && action.Match.PacketLength != packetLength {
		return false
	}
	return true
}

func alertTitle(alert alerts.Alert, candidate alerts.Candidate) string {
	label := candidate.Type
	switch candidate.Type {
	case "volumetric":
		label = "Volumetric attack"
	case "tcp_out_of_state":
		label = "Out-of-state TCP flood"
	case "blocklist":
		label = "Blocklisted source"
	case "rule_trigger":
		label = "Operator rule triggered"
	case "ftp_control", "ftp_data":
		label = "FTP flood"
	case "ftp_protocol":
		label = "Protocol mismatch on FTP service"
	case "ftp_privileged_port":
		label = "Privileged source port on FTP"
	case "ftp_command":
		label = "Malformed FTP command"
	default:
		label = strings.Title(strings.ReplaceAll(label, "_", " "))
	}
	if alert.Destination != "" {
		return fmt.Sprintf("%s on %s", label, alert.Destination)
	}
	return label
}

func timeFromUnixNano(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

// Constants exist to avoid importing tcpstate just for event kind names in the
// maintenance loop. They intentionally match tcpstate.Event*.
const (
	tcpEventHandshake   = "handshake"
	tcpEventLongSession = "long_session"
)
