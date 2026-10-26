package detect

import (
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"dollysensor/internal/aggregate"
	"dollysensor/internal/alerts"
	"dollysensor/internal/config"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/netutil"
	"dollysensor/internal/tcpstate"
)

type fakeIntel struct {
	trust      float64
	syn        uint64
	ack        uint64
	handshakes uint64
	manual     bool
}

func (f *fakeIntel) TrustScore(_, _ netip.Addr) float64 { return f.trust }

func (f *fakeIntel) SourceSummary(_, _ netip.Addr) (uint64, uint64, uint64, float64, bool) {
	return f.syn, f.ack, f.handshakes, f.trust, f.manual
}

func testDetector(t *testing.T, intel *fakeIntel) *Detector {
	t.Helper()
	protected, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := netutil.ParsePrefixes(nil)
	if err != nil {
		t.Fatal(err)
	}
	detection := config.Default().Detection
	detection.Sensitivity = "instant"
	detection.NetworkType = "home"
	detection.WarmupWindows = 1
	detection.ThreatThreshold = 40
	detection.Persistence = 1
	detection.PPSFloor = 100
	detection.BPSFloor = 1_000
	detection.OutOfStateMinPPS = 100
	detection.RateWindowSeconds = 1
	return New(Options{
		Detection: detection,
		Intel:     intel,
		Protected: protected,
		Trusted:   trusted,
	})
}

func trafficSnapshot(now time.Time, packets uint64, pps, bps float64, syn, ack uint64) aggregate.DestSnapshot {
	src := netip.MustParseAddr("198.51.100.77")
	dst := netip.MustParseAddr("203.0.113.10")
	recent := aggregate.Recent{
		Packets:       packets,
		Bytes:         packets * 60,
		Samples:       10,
		AvgPacketSize: 60,
		Sources: []aggregate.SourceCount{{
			Source:     src.String(),
			SourceAddr: src,
			Count:      packets,
		}},
		SourceCount: 1,
		Protocols:   []aggregate.Count{{Name: "TCP", Count: packets}},
		DestPorts:   []aggregate.PortCount{{Port: 443, Count: packets}},
		TCPFlags:    []aggregate.Count{},
	}
	if syn > 0 {
		recent.TCPFlags = append(recent.TCPFlags, aggregate.Count{Name: "SYN", Count: syn})
	}
	if ack > 0 {
		recent.TCPFlags = append(recent.TCPFlags, aggregate.Count{Name: "ACK", Count: ack})
	}
	return aggregate.DestSnapshot{
		Destination: dst.String(),
		Addr:        dst,
		FirstSeen:   now.Add(-time.Minute),
		LastSeen:    now,
		PPS:         pps,
		BPS:         bps,
		Recent:      recent,
	}
}

func TestDetectionMathHelpers(t *testing.T) {
	if got := zScore(12, 10, 4, 1); math.Abs(got-1) > 1e-9 {
		t.Fatalf("zScore = %v, want 1", got)
	}
	if got := zScore(12, 10, 0, 2); math.Abs(got-1) > 1e-9 {
		t.Fatalf("zScore with minStd = %v, want 1", got)
	}
	if got := zScore(10, 10, 0, 2); got != 0 {
		t.Fatalf("zScore at mean = %v, want 0", got)
	}
	if got := ratio(3, 0); got != 0 {
		t.Fatalf("ratio zero denominator = %v", got)
	}
	if got := safeRatio(5, 0); got != 0 {
		t.Fatalf("safeRatio zero reference = %v", got)
	}
	if got := round(1.23456, 3); got != 1.235 {
		t.Fatalf("round = %v, want 1.235", got)
	}
	if got := chooseProtocol(map[string]float64{"TCP": .7, "UDP": .2}); got != 6 {
		t.Fatalf("chooseProtocol = %d, want TCP", got)
	}
	if got := chooseProtocol(map[string]float64{"OTHER": 1}); got != 0 {
		t.Fatalf("chooseProtocol unknown = %d, want 0", got)
	}
}

func TestSustainedSynFloodBecomesAttackAndProposesPreciseDiscard(t *testing.T) {
	now := time.Now()
	intel := &fakeIntel{trust: 0, syn: 500, ack: 0, handshakes: 0}
	d := testDetector(t, intel)
	snapshot := trafficSnapshot(now, 10_000, 10_000, 50_000_000, 10_000, 0)

	first := d.Evaluate(now, []aggregate.DestSnapshot{snapshot}, nil)
	if len(first) != 1 {
		t.Fatalf("first evaluate results = %d", len(first))
	}
	if !first[0].State.Warmup {
		t.Fatal("first observation should still be warming up")
	}
	if first[0].State.Score != 45 {
		t.Fatalf("warm-up score = %v, want capped 45", first[0].State.Score)
	}
	if first[0].State.Attack {
		t.Fatal("attack must not be declared during the first warm-up sample")
	}

	second := d.Evaluate(now.Add(100*time.Millisecond), []aggregate.DestSnapshot{snapshot}, nil)
	if len(second) != 1 {
		t.Fatalf("second evaluate results = %d", len(second))
	}
	result := second[0]
	if !result.State.Attack || result.State.Threat != "under_attack" {
		t.Fatalf("state = %+v, want under_attack", result.State)
	}
	if result.State.SmoothedScore < result.State.Threshold {
		t.Fatalf("smoothed score %v below threshold %v", result.State.SmoothedScore, result.State.Threshold)
	}
	var finding *Finding
	for i := range result.Findings {
		if result.Findings[i].Action != nil {
			finding = &result.Findings[i]
			break
		}
	}
	if finding == nil {
		t.Fatalf("no actionable finding in %+v", result.Findings)
	}
	if finding.Alert.Type != "volumetric" || finding.Alert.Severity != alerts.SeverityCritical {
		t.Fatalf("alert = %+v, want critical volumetric", finding.Alert)
	}
	action := finding.Action
	if action.Kind != mitigate.KindFlowspec {
		t.Fatalf("kind = %q, want flowspec", action.Kind)
	}
	if action.Action != "discard" {
		t.Fatalf("action = %q, want precise discard", action.Action)
	}
	if action.Source != netip.MustParseAddr("198.51.100.77") ||
		action.Destination != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("match = %s -> %s", action.Source, action.Destination)
	}
	if action.Protocol != 6 || action.DstPort != 443 || action.TCPFlags != 0x02 {
		t.Fatalf("flowspec match = proto %d port %d flags %#x", action.Protocol, action.DstPort, action.TCPFlags)
	}
}

func TestExtremeSingleSourceSynFloodUsesRTBH(t *testing.T) {
	now := time.Now()
	intel := &fakeIntel{trust: 0, syn: 10_000, handshakes: 0}
	d := testDetector(t, intel)
	snapshot := trafficSnapshot(now, 2_000_000, 2_000_000, 500_000_000, 2_000_000, 0)
	d.Evaluate(now, []aggregate.DestSnapshot{snapshot}, nil)
	results := d.Evaluate(now.Add(100*time.Millisecond), []aggregate.DestSnapshot{snapshot}, nil)
	if len(results) != 1 || !results[0].State.Attack {
		t.Fatalf("severe flood did not enter attack state: %+v", results)
	}
	var action *mitigate.Request
	var alert *alerts.Candidate
	for i := range results[0].Findings {
		if results[0].Findings[i].Action != nil {
			action = results[0].Findings[i].Action
			alert = &results[0].Findings[i].Alert
			break
		}
	}
	if action == nil {
		t.Fatalf("no action for severe flood: %+v", results[0].Findings)
	}
	if action.Kind != mitigate.KindRTBH || action.Action != "discard" {
		t.Fatalf("action = %+v, want RTBH discard", action)
	}
	if action.Source.String() != "198.51.100.77" || action.Destination.IsValid() {
		t.Fatalf("RTBH match = %+v, want source-only", action)
	}
	if alert == nil || !strings.Contains(alert.Reason, "RTBH") {
		t.Fatalf("alert reason does not explain RTBH: %+v", alert)
	}
}

func TestIdleDestinationLeavesAttackState(t *testing.T) {
	now := time.Now()
	intel := &fakeIntel{trust: 0, syn: 500}
	d := testDetector(t, intel)
	snapshot := trafficSnapshot(now, 10_000, 10_000, 50_000_000, 10_000, 0)
	d.Evaluate(now, []aggregate.DestSnapshot{snapshot}, nil)
	attacked := d.Evaluate(now.Add(100*time.Millisecond), []aggregate.DestSnapshot{snapshot}, nil)
	if len(attacked) != 1 || !attacked[0].State.Attack {
		t.Fatalf("setup did not enter attack state: %+v", attacked)
	}
	samplesBefore := attacked[0].State.Samples
	idle := snapshot
	idle.LastSeen = now.Add(-11 * time.Second)
	idle.PPS = 0
	idle.BPS = 0
	idle.Recent = aggregate.Recent{}

	var state State
	for i := 0; i < 12; i++ {
		results := d.Evaluate(now.Add(time.Duration(i+1)*time.Second), []aggregate.DestSnapshot{idle}, nil)
		if len(results) != 1 {
			t.Fatalf("idle evaluation %d returned %d results", i, len(results))
		}
		state = results[0].State
		if i == 0 && state.PPS != 0 {
			t.Fatalf("idle evaluation reported stale PPS %v", state.PPS)
		}
	}
	if state.Attack || state.Threat != "clean" {
		t.Fatalf("idle state = %+v, want clean after calm window", state)
	}
	if state.Score != 0 || state.SmoothedScore >= state.Threshold {
		t.Fatalf("idle score = raw %v smoothed %v threshold %v", state.Score, state.SmoothedScore, state.Threshold)
	}
	if len(state.Signals) != 0 {
		t.Fatalf("idle state retained stale signals: %v", state.Signals)
	}
	if state.Samples != samplesBefore {
		t.Fatalf("idle zeroes polluted baseline samples: before %d after %d", samplesBefore, state.Samples)
	}
	if !state.LastEvaluation.After(now) {
		t.Fatalf("idle evaluation time was not advanced: %s", state.LastEvaluation)
	}
}

func TestTrustedSourceDowngradesModerateEvidenceToWarning(t *testing.T) {
	now := time.Now()
	intel := &fakeIntel{trust: 90, syn: 500, handshakes: 0}
	d := testDetector(t, intel)
	snapshot := trafficSnapshot(now, 1_000, 500, 5_000, 600, 400)

	d.Evaluate(now, []aggregate.DestSnapshot{snapshot}, nil)
	second := d.Evaluate(now.Add(100*time.Millisecond), []aggregate.DestSnapshot{snapshot}, nil)
	if len(second) != 1 {
		t.Fatalf("results = %d", len(second))
	}
	result := second[0]
	if !result.State.Attack {
		t.Fatalf("expected sustained anomalous traffic to enter attack state: %+v", result.State)
	}
	if len(result.Findings) == 0 {
		t.Fatal("missing finding")
	}
	finding := result.Findings[0]
	if finding.Alert.Severity != alerts.SeverityWarning {
		t.Fatalf("severity = %s, want warning for trusted moderate traffic", finding.Alert.Severity)
	}
	if finding.Action != nil {
		t.Fatalf("trusted moderate traffic must not be mitigated: %+v", finding.Action)
	}
}

func TestOutOfStateRateProducesCriticalSourceRateLimit(t *testing.T) {
	now := time.Now()
	d := testDetector(t, &fakeIntel{})
	snapshot := trafficSnapshot(now, 100, 50, 500, 0, 0)
	oos := map[netip.Addr]tcpstate.OOSStat{
		netip.MustParseAddr("203.0.113.10"): {
			OutOfState: 600,
			Total:      650,
			Rate:       600,
		},
	}
	results := d.Evaluate(now, []aggregate.DestSnapshot{snapshot}, oos)
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	if results[0].State.Attack {
		t.Fatal("out-of-state evidence alone should not declare a volumetric attack")
	}
	var finding *Finding
	for i := range results[0].Findings {
		if results[0].Findings[i].Alert.Type == "tcp_out_of_state" {
			finding = &results[0].Findings[i]
			break
		}
	}
	if finding == nil {
		t.Fatalf("missing tcp_out_of_state finding: %+v", results[0].Findings)
	}
	if finding.Alert.Severity != alerts.SeverityCritical {
		t.Fatalf("severity = %s, want critical", finding.Alert.Severity)
	}
	if finding.Action == nil {
		t.Fatal("critical out-of-state finding must propose a mitigation")
	}
	if finding.Action.Kind != mitigate.KindFlowspec || finding.Action.Action != "rate-limit" {
		t.Fatalf("action = %+v", finding.Action)
	}
	if finding.Action.Source.String() != "198.51.100.77" {
		t.Fatalf("source = %s, want dominant external source", finding.Action.Source)
	}
	if finding.Action.Destination != netip.MustParseAddr("203.0.113.10") {
		t.Fatalf("destination = %s", finding.Action.Destination)
	}
}

func TestTrustedAndInternalOutOfStateTrafficIsNotMitigated(t *testing.T) {
	now := time.Now()
	oos := map[netip.Addr]tcpstate.OOSStat{
		netip.MustParseAddr("203.0.113.10"): {OutOfState: 600, Total: 650, Rate: 600},
	}
	t.Run("trusted", func(t *testing.T) {
		d := testDetector(t, &fakeIntel{trust: 90})
		results := d.Evaluate(now, []aggregate.DestSnapshot{trafficSnapshot(now, 100, 50, 500, 0, 0)}, oos)
		finding := findTCPStateFinding(t, results)
		if finding.Alert.Severity != alerts.SeverityWarning || finding.Action != nil {
			t.Fatalf("trusted OOS finding = %+v, want warning without action", finding)
		}
	})
	t.Run("internal", func(t *testing.T) {
		d := testDetector(t, &fakeIntel{})
		snapshot := trafficSnapshot(now, 100, 50, 500, 0, 0)
		internal := netip.MustParseAddr("203.0.113.50")
		snapshot.Recent.Sources[0] = aggregate.SourceCount{Source: internal.String(), SourceAddr: internal, Count: 100}
		results := d.Evaluate(now, []aggregate.DestSnapshot{snapshot}, oos)
		finding := findTCPStateFinding(t, results)
		if finding.Action != nil {
			t.Fatalf("internal OOS source got an external action: %+v", finding.Action)
		}
	})
}

func findTCPStateFinding(t *testing.T, results []Result) *Finding {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	for i := range results[0].Findings {
		if results[0].Findings[i].Alert.Type == "tcp_out_of_state" {
			return &results[0].Findings[i]
		}
	}
	t.Fatalf("missing tcp_out_of_state finding: %+v", results[0].Findings)
	return nil
}
