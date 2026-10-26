package sensor

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"dollysensor/internal/alerts"
	"dollysensor/internal/config"
	"dollysensor/internal/detect"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/model"
	"dollysensor/internal/rules"
)

func newRulesTestSensor(t *testing.T, dir string) (*Sensor, *recordingAnnouncer, config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.Collector.Listen = freeCollectorAddress(t)
	cfg.Collector.Workers = 1
	cfg.Collector.Queue = 512
	cfg.ProtectedCIDRs = []string{"203.0.113.0/24"}
	cfg.Protocols.FTP.Enabled = false
	cfg.Mitigation.BlocklistDir = filepath.Join(dir, "blocklists")
	cfg.Mitigation.DefaultDuration = config.Duration(20 * time.Second)
	cfg.Mitigation.DedupWindow = config.Duration(5 * time.Second)
	cfg.Mitigation.MaxActive = 8
	cfg.Persistence.ProfileFile = filepath.Join(dir, "profiles.json")
	cfg.Persistence.SaveInterval = config.Duration(time.Hour)
	cfg.Memory.PacketBuffer = 256
	cfg.Memory.AlertHistory = 50
	cfg.Rules.Enabled = true
	cfg.Rules.File = filepath.Join(dir, "rules.json")
	cfg.Rules.MaxRules = 32
	cfg.Rules.MaxFlowsPerRule = 256
	cfg.Rules.EvaluationQueue = 256

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := New(cfg, nil, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	announcer := &recordingAnnouncer{}
	s.mitigator = mitigate.New(mitigate.Options{
		Protected:               s.protected,
		Announcer:               announcer,
		Simulated:               false,
		Duration:                cfg.Mitigation.DefaultDuration.Std(),
		DedupWindow:             cfg.Mitigation.DedupWindow.Std(),
		MaxActive:               cfg.Mitigation.MaxActive + cfg.Rules.MaxRules,
		MaxAutomatic:            cfg.Mitigation.MaxActive,
		MaxRules:                cfg.Rules.MaxRules,
		HistoryLimit:            50,
		Community:               "65535:666",
		NextHop:                 "192.0.2.1",
		RateLimitBPS:            uint64(cfg.Mitigation.RateLimitMbps * 1_000_000),
		OpTimeout:               2 * time.Second,
		AllowDestinationDiscard: false,
	})
	return s, announcer, cfg
}

func startRulesTestSensor(t *testing.T, s *Sensor) {
	t.Helper()
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})
}

func actionForRule(s *Sensor, ruleID string) (mitigate.Action, bool) {
	for _, action := range s.mitigator.Active() {
		if action.RuleID == ruleID {
			return action, true
		}
	}
	return mitigate.Action{}, false
}

func countRuleActions(s *Sensor, ruleID string) int {
	count := 0
	for _, action := range s.mitigator.Active() {
		if action.RuleID == ruleID {
			count++
		}
	}
	return count
}

// TestStandingRuleLifecycleAndReplay verifies that a persisted standing rule is
// enforced, withdrawn on disable and delete, re-applied on enable, and replayed
// from the rules file by a fresh sensor instance.
func TestStandingRuleLifecycleAndReplay(t *testing.T) {
	dir := t.TempDir()
	s, announcer, _ := newRulesTestSensor(t, dir)
	startRulesTestSensor(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rule, err := s.CreateRule(ctx, rules.Rule{
		Name:        "Block test source",
		Description: "Integration test standing discard",
		Enabled:     true,
		Mode:        rules.ModeStanding,
		Match: rules.Match{
			Destination: "203.0.113.0/24",
			Source:      "198.51.100.0/24",
			Protocol:    6,
		},
		Action: rules.Action{Type: rules.ActionDiscard},
	})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if rule.ID == "" {
		t.Fatal("CreateRule returned an empty id")
	}

	waitFor(t, 3*time.Second, func() bool { return countRuleActions(s, rule.ID) == 1 }, "standing rule did not create an action")
	action, _ := actionForRule(s, rule.ID)
	if !action.Permanent {
		t.Fatal("standing action is not permanent")
	}
	if action.Match.Source != "198.51.100.0/24" || action.Match.Destination != "203.0.113.0/24" {
		t.Fatalf("action match = %+v", action.Match)
	}
	if action.Match.Protocol != 6 {
		t.Fatalf("action protocol = %d, want 6", action.Match.Protocol)
	}
	if action.Action != rules.ActionDiscard {
		t.Fatalf("action = %q, want discard", action.Action)
	}
	if _, ok := actionForRule(s, rule.ID); !ok {
		t.Fatal("rule action missing from active set")
	}

	if _, err := s.SetRuleEnabled(ctx, rule.ID, false); err != nil {
		t.Fatalf("SetRuleEnabled(false): %v", err)
	}
	if count := countRuleActions(s, rule.ID); count != 0 {
		t.Fatalf("disable left %d rule actions active", count)
	}
	_, withdrawn := announcer.snapshot()
	if len(withdrawn) == 0 || withdrawn[len(withdrawn)-1].ID != action.ID {
		t.Fatalf("disable did not withdraw action %s; withdrawals=%+v", action.ID, withdrawn)
	}

	if _, err := s.SetRuleEnabled(ctx, rule.ID, true); err != nil {
		t.Fatalf("SetRuleEnabled(true): %v", err)
	}
	waitFor(t, 3*time.Second, func() bool { return countRuleActions(s, rule.ID) == 1 }, "re-enabled rule did not create an action")

	if err := s.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A fresh sensor must load the rule file and replay the standing action.
	restarted, restartedAnnouncer, _ := newRulesTestSensor(t, dir)
	defer func() { _ = restarted.Close(context.Background()) }()
	if _, err := restarted.ruleStore.Get(rule.ID); err != nil {
		t.Fatalf("rule not persisted: %v", err)
	}
	restarted.syncStandingRules(context.Background())
	replayed, ok := actionForRule(restarted, rule.ID)
	if !ok {
		announced, _ := restartedAnnouncer.snapshot()
		t.Fatalf("standing rule was not replayed; active=%+v announced=%+v", restarted.mitigator.Active(), announced)
	}
	if !replayed.Permanent || replayed.Match.Source != "198.51.100.0/24" {
		t.Fatalf("replayed action = %+v", replayed)
	}

	if _, err := restarted.DeleteRule(context.Background(), rule.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if count := countRuleActions(restarted, rule.ID); count != 0 {
		t.Fatalf("delete left %d rule actions active", count)
	}
}

// TestConditionalRuleTriggersFlowScopedAction feeds one sampled observation
// directly into the rule evaluation queue and verifies the full sensor path
// from rule trigger to finding to a flow-scoped Flowspec action.
func TestConditionalRuleTriggersFlowScopedAction(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := newRulesTestSensor(t, dir)
	startRulesTestSensor(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rule, err := s.CreateRule(ctx, rules.Rule{
		Name:    "Admin path probe",
		Enabled: true,
		Mode:    rules.ModeConditional,
		Match: rules.Match{
			Destination: "203.0.113.0/24",
			Protocol:    6,
			DstPort:     80,
		},
		Condition: rules.Condition{
			WindowSeconds: 5,
			Consecutive:   1,
			Payload: rules.PayloadCondition{
				Mode:     rules.PayloadPresentN,
				Pattern:  "GET /admin",
				Encoding: rules.PayloadText,
				Kind:     rules.PayloadKindContains,
				FirstN:   5,
			},
		},
		Action: rules.Action{
			Type:            rules.ActionDiscard,
			Scope:           rules.ScopeFlow,
			DurationSeconds: 10,
		},
	})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if rule.Action.Scope != rules.ScopeFlow {
		t.Fatalf("action scope = %q, want flow", rule.Action.Scope)
	}

	source := netip.MustParseAddr("198.51.100.9")
	destination := netip.MustParseAddr("203.0.113.50")
	s.ruleObservations <- model.Observation{
		ID:               1,
		ReceivedAt:       time.Now(),
		SrcIP:            source,
		DstIP:            destination,
		Protocol:         6,
		ProtocolName:     "TCP",
		SrcPort:          41000,
		DstPort:          80,
		TCPFlags:         model.TCPPSH | model.TCPACK,
		PacketSize:       220,
		Payload:          []byte("GET /admin HTTP/1.1\r\nHost: example\r\n\r\n"),
		DstProtected:     true,
		Direction:        model.DirectionInbound,
		EstimatedPackets: 10,
		EstimatedBytes:   2200,
	}

	waitFor(t, 4*time.Second, func() bool { return countRuleActions(s, rule.ID) == 1 }, "conditional rule did not create a flow-scoped action")
	action, _ := actionForRule(s, rule.ID)
	if action.Permanent {
		t.Fatal("conditional action should not be permanent")
	}
	if action.Match.Source != source.String()+"/32" || action.Match.Destination != destination.String()+"/32" {
		t.Fatalf("flow scope match = %+v", action.Match)
	}
	if action.Match.Protocol != 6 || action.Match.SrcPort != 41000 || action.Match.DstPort != 80 {
		t.Fatalf("flow scope header fields = %+v", action.Match)
	}
	if action.Action != rules.ActionDiscard {
		t.Fatalf("action = %q, want discard", action.Action)
	}

	stored, err := s.ruleStore.Get(rule.ID)
	if err != nil {
		t.Fatalf("Get rule: %v", err)
	}
	if stored.Stats.Triggers == 0 || stored.Stats.Hits == 0 {
		t.Fatalf("rule stats = %+v, want hits and triggers", stored.Stats)
	}
}

// TestAllowRuleSuppressesAutomaticMitigation verifies that an allow rule
// prevents an automatic finding from creating a Flowspec action, and that the
// same finding is mitigated once the allow rule is disabled.
func TestAllowRuleSuppressesAutomaticMitigation(t *testing.T) {
	dir := t.TempDir()
	s, _, _ := newRulesTestSensor(t, dir)
	startRulesTestSensor(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	allow, err := s.CreateRule(ctx, rules.Rule{
		Name:    "Trusted partner",
		Enabled: true,
		Mode:    rules.ModeStanding,
		Match: rules.Match{
			Destination: "203.0.113.0/24",
			Source:      "198.51.100.0/24",
			Protocol:    6,
		},
		Action: rules.Action{Type: rules.ActionAllow},
	})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if allow.Action.Type != rules.ActionAllow {
		t.Fatalf("action = %q, want allow", allow.Action.Type)
	}
	if count := countRuleActions(s, allow.ID); count != 0 {
		t.Fatalf("allow rule created %d enforcement actions", count)
	}

	source := netip.MustParseAddr("198.51.100.9")
	destination := netip.MustParseAddr("203.0.113.50")
	finding := detect.Finding{
		Alert: alerts.Candidate{
			Key:         "automatic|allow-test",
			Severity:    alerts.SeverityCritical,
			Type:        "test",
			Layer:       "detector",
			Destination: destination.String(),
			Source:      source.String(),
			Reason:      "automatic throttle test",
		},
		Action: &mitigate.Request{
			Kind:              mitigate.KindFlowspec,
			DestinationPrefix: netip.PrefixFrom(destination, 32),
			SourcePrefix:      netip.PrefixFrom(source, 32),
			Protocol:          6,
			SrcPort:           41000,
			DstPort:           80,
			Action:            "discard",
			Owner:             "detector",
		},
	}
	s.handleFinding(context.Background(), finding)
	if active := s.mitigator.Active(); len(active) != 0 {
		t.Fatalf("allow rule did not suppress automatic mitigation; active=%+v", active)
	}
	suppressed := false
	for _, alert := range s.alerts.Snapshot(20, "") {
		if alert.Type == "test" && alert.ActionStatus == "suppressed" {
			suppressed = true
			break
		}
	}
	if !suppressed {
		t.Fatal("suppressed automatic alert was not recorded with a suppressed action status")
	}

	if _, err := s.SetRuleEnabled(ctx, allow.ID, false); err != nil {
		t.Fatalf("SetRuleEnabled(false): %v", err)
	}
	finding.Alert.Key = "automatic|allow-test-2"
	finding.Alert.Reason = "automatic throttle test after allow disabled"
	s.handleFinding(context.Background(), finding)
	active := s.mitigator.Active()
	if len(active) != 1 {
		t.Fatalf("automatic mitigation did not proceed after disabling allow; active=%+v", active)
	}
	if active[0].Action != "discard" || active[0].Match.Destination != destination.String()+"/32" {
		t.Fatalf("automatic action = %+v", active[0])
	}
}
