package rules

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"dollysensor/internal/mitigate"
	"dollysensor/internal/model"
	"dollysensor/internal/netutil"
)

func testOptions(t *testing.T) Options {
	t.Helper()
	protected, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Path:                filepath.Join(t.TempDir(), "rules.json"),
		Protected:           protected,
		MaxRules:            32,
		MaxFlowsPerRule:     64,
		DefaultDuration:     time.Minute,
		DefaultRateLimitBPS: 10_000_000,
	}
}

func testObservation(now time.Time, payload string) model.Observation {
	return model.Observation{
		ReceivedAt:       now,
		SrcIP:            netip.MustParseAddr("198.51.100.7"),
		DstIP:            netip.MustParseAddr("203.0.113.10"),
		Protocol:         17,
		SrcPort:          40000,
		DstPort:          53,
		PacketSize:       120,
		Direction:        model.DirectionInbound,
		Payload:          []byte(payload),
		EstimatedPackets: 10,
		EstimatedBytes:   1200,
	}
}

func standingRule(name string) Rule {
	return Rule{
		Name:    name,
		Enabled: true,
		Mode:    ModeStanding,
		Match: Match{
			Destination: "203.0.113.0/24",
			Source:      "198.51.100.0/24",
			Protocol:    17,
			DstPort:     53,
		},
		Action: Action{Type: ActionRateLimit, RateLimitBPS: 5_000_000},
	}
}

func TestValidationSafety(t *testing.T) {
	opts := testOptions(t)
	noSource := standingRule("destination-only")
	noSource.Action.Type = ActionDiscard
	noSource.Match.Source = ""
	if err := normalizeAndValidate(&noSource, opts); err == nil {
		t.Fatal("destination-only rule-scoped discard should be rejected by default")
	}
	opts.AllowDestinationDiscard = true
	if err := normalizeAndValidate(&noSource, opts); err != nil {
		t.Fatalf("destination-only discard should be allowed with opt-in: %v", err)
	}

	protectedSource := standingRule("protected source")
	protectedSource.Match.Source = "203.0.113.128/25"
	if err := normalizeAndValidate(&protectedSource, opts); err == nil {
		t.Fatal("source overlapping protected network should be rejected")
	}

	outsideDestination := standingRule("outside")
	outsideDestination.Match.Destination = "192.0.2.0/24"
	if err := normalizeAndValidate(&outsideDestination, opts); err == nil {
		t.Fatal("destination outside protected network should be rejected")
	}

	emptyConditional := standingRule("conditional with no condition")
	emptyConditional.Mode = ModeConditional
	emptyConditional.Condition = Condition{}
	if err := normalizeAndValidate(&emptyConditional, opts); err == nil {
		t.Fatal("conditional rule with no condition should be rejected")
	}

	conditionalAllow := standingRule("conditional allow")
	conditionalAllow.Mode = ModeConditional
	conditionalAllow.Action.Type = ActionAllow
	conditionalAllow.Condition.MinPPS = 10
	if err := normalizeAndValidate(&conditionalAllow, opts); err == nil {
		t.Fatal("conditional allow should be rejected")
	}

	firstNWithRate := standingRule("first n with rate")
	firstNWithRate.Mode = ModeConditional
	firstNWithRate.Condition.MinPPS = 10
	firstNWithRate.Condition.Payload = PayloadCondition{
		Mode: PayloadAbsentN, Pattern: "x", FirstN: 3,
	}
	if err := normalizeAndValidate(&firstNWithRate, opts); err == nil {
		t.Fatal("first-N payload condition with rate thresholds should be rejected")
	}
}

func TestStandingRuleMatchesAndPersists(t *testing.T) {
	opts := testOptions(t)
	store, err := Open(opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := store.Create(standingRule("dns rate limit"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	triggers := store.Observe(testObservation(now, ""), now)
	if len(triggers) != 0 {
		t.Fatalf("standing rule should not produce triggers: %+v", triggers)
	}
	view, err := store.Get(rule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Stats.Hits != 1 || view.Stats.MatchedPackets != 10 || view.Stats.State == "" {
		t.Fatalf("unexpected stats: %+v", view.Stats)
	}

	reopened, err := Open(opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Get(rule.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != rule.Name || loaded.Mode != ModeStanding || !loaded.Enabled {
		t.Fatalf("persisted rule mismatch: %+v", loaded)
	}
	if len(reopened.Observe(testObservation(now, ""), now)) != 0 {
		t.Fatal("loaded rule should still match without triggering")
	}
}

func TestConditionalPayloadContains(t *testing.T) {
	store, err := Open(testOptions(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	rule := Rule{
		Name:    "payload match",
		Enabled: true,
		Mode:    ModeConditional,
		Match: Match{
			Destination: "203.0.113.0/24",
			Source:      "198.51.100.0/24",
			Protocol:    17,
			DstPort:     53,
		},
		Condition: Condition{Payload: PayloadCondition{
			Mode: PayloadContains, Pattern: "EVIL", CaseInsensitive: true,
		}},
		Action: Action{Type: ActionRateLimit, RateLimitBPS: 2_000_000, DurationSeconds: 1},
	}
	created, err := store.Create(rule)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_100, 0).UTC()
	if triggers := store.Observe(testObservation(now, "benign"), now); len(triggers) != 0 {
		t.Fatalf("benign payload should not trigger: %+v", triggers)
	}
	triggers := store.Observe(testObservation(now.Add(time.Second), "prefix-evil-suffix"), now.Add(time.Second))
	if len(triggers) != 1 {
		t.Fatalf("payload match should trigger once, got %d", len(triggers))
	}
	if triggers[0].Rule.ID != created.ID || triggers[0].Rule.Action.Scope != ScopeFlow {
		t.Fatalf("unexpected trigger: %+v", triggers[0])
	}
}

func TestFirstNAbsentAndPresent(t *testing.T) {
	now := time.Unix(1_700_000_200, 0).UTC()
	makeRule := func(mode string) Rule {
		return Rule{
			Name:    mode,
			Enabled: true,
			Mode:    ModeConditional,
			Match: Match{
				Destination: "203.0.113.0/24",
				Source:      "198.51.100.7",
				Protocol:    17,
				DstPort:     53,
			},
			Condition: Condition{Payload: PayloadCondition{
				Mode: mode, Pattern: "MAGIC", FirstN: 3,
			}},
			Action: Action{Type: ActionRateLimit, RateLimitBPS: 1_000_000, DurationSeconds: 10, Scope: ScopeFlow},
		}
	}

	store, err := Open(testOptions(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	absent, err := store.Create(makeRule(PayloadAbsentN))
	if err != nil {
		t.Fatal(err)
	}
	for i, expect := range []bool{false, false, true} {
		triggers := store.Observe(testObservation(now.Add(time.Duration(i)*time.Second), "ordinary"), now.Add(time.Duration(i)*time.Second))
		if got := len(triggers) == 1; got != expect {
			t.Fatalf("absent trigger on sample %d = %v, want %v", i+1, got, expect)
		}
	}
	view, err := store.Get(absent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Stats.Triggers != 1 || view.Stats.Hits != 3 {
		t.Fatalf("unexpected absent stats: %+v", view.Stats)
	}

	presentStore, err := Open(testOptions(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	present, err := presentStore.Create(makeRule(PayloadPresentN))
	if err != nil {
		t.Fatal(err)
	}
	if triggers := presentStore.Observe(testObservation(now, "ordinary"), now); len(triggers) != 0 {
		t.Fatal("present rule should not trigger before pattern")
	}
	triggers := presentStore.Observe(testObservation(now.Add(time.Second), "payload MAGIC"), now.Add(time.Second))
	if len(triggers) != 1 {
		t.Fatalf("present rule should trigger on pattern, got %d", len(triggers))
	}
	if view, _ := presentStore.Get(present.ID); view.Stats.Triggers != 1 {
		t.Fatalf("unexpected present stats: %+v", view.Stats)
	}
}

func TestRateThresholdConsecutive(t *testing.T) {
	store, err := Open(testOptions(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	rule := Rule{
		Name:    "dns volume",
		Enabled: true,
		Mode:    ModeConditional,
		Match: Match{
			Destination: "203.0.113.0/24",
			Source:      "198.51.100.7",
			Protocol:    17,
			DstPort:     53,
		},
		Condition: Condition{
			WindowSeconds: 5, MinPPS: 20, Consecutive: 2, CooldownSeconds: 30,
		},
		Action: Action{Type: ActionRateLimit, RateLimitBPS: 1_000_000, DurationSeconds: 30},
	}
	created, err := store.Create(rule)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_300, 0).UTC()
	for i := 0; i < 10; i++ {
		store.Observe(testObservation(now, ""), now)
	}
	if triggers := store.Tick(now); len(triggers) != 0 {
		t.Fatalf("first consecutive window should not trigger: %+v", triggers)
	}
	triggers := store.Tick(now.Add(time.Second))
	if len(triggers) != 1 {
		t.Fatalf("second consecutive window should trigger, got %d", len(triggers))
	}
	if triggers[0].Rule.ID != created.ID {
		t.Fatalf("wrong rule trigger: %+v", triggers[0])
	}
}

func TestAllowCoversAutomaticMitigation(t *testing.T) {
	store, err := Open(testOptions(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	allow := standingRule("allow dns")
	allow.Action = Action{Type: ActionAllow, Scope: ScopeRule}
	allow.Match.Protocol = 0
	allow.Match.DstPort = 0
	if _, err := store.Create(allow); err != nil {
		t.Fatal(err)
	}
	req := mitigate.Request{
		Kind:         mitigate.KindFlowspec,
		Source:       netip.MustParseAddr("198.51.100.7"),
		Destination:  netip.MustParseAddr("203.0.113.10"),
		Protocol:     17,
		DstPort:      53,
		Action:       "discard",
		RateLimitBPS: 0,
	}
	rule, ok := store.AllowCovers(req)
	if !ok {
		t.Fatal("allow rule should cover automatic mitigation")
	}
	if rule.Name != allow.Name {
		t.Fatalf("unexpected allow rule: %+v", rule)
	}
	if summary := store.Summary(); summary.Suppressed != 1 {
		t.Fatalf("allow suppression not counted: %+v", summary)
	}
	outside := req
	outside.Destination = netip.MustParseAddr("192.0.2.10")
	if _, ok := store.AllowCovers(outside); ok {
		t.Fatal("allow rule must not cover a different destination")
	}
}

func TestPreviewFirstNAbsent(t *testing.T) {
	store, err := Open(testOptions(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	rule := Rule{
		Name:    "preview absent",
		Enabled: true,
		Mode:    ModeConditional,
		Match: Match{
			Destination: "203.0.113.0/24",
			Source:      "198.51.100.0/24",
			Protocol:    17,
			DstPort:     53,
		},
		Condition: Condition{Payload: PayloadCondition{
			Mode: PayloadAbsentN, Pattern: "MAGIC", FirstN: 2,
		}},
		Action: Action{Type: ActionRateLimit, RateLimitBPS: 1_000_000, Scope: ScopeFlow},
	}
	now := time.Unix(1_700_000_400, 0).UTC()
	observations := []model.Observation{
		testObservation(now, "a"),
		testObservation(now.Add(time.Second), "b"),
		testObservation(now.Add(2*time.Second), "MAGIC"),
		testObservation(now.Add(3*time.Second), "d"),
	}
	result, err := store.Preview(rule, observations)
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched != 4 || result.Flows != 1 || result.PotentialTriggers != 1 {
		t.Fatalf("unexpected preview: %+v", result)
	}
}

func TestDeleteAndCapacity(t *testing.T) {
	opts := testOptions(t)
	opts.MaxRules = 1
	store, err := Open(opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(standingRule("one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(standingRule("two")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expected capacity error, got %v", err)
	}
	if _, err := store.Delete(created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
	if _, err := store.Create(standingRule("two")); err != nil {
		t.Fatalf("create after delete: %v", err)
	}
}
func TestValidationRanges(t *testing.T) {
	opts := testOptions(t)

	both := standingRule("exact and range")
	both.Match.SrcPort = 40000
	both.Match.SrcPortMin = 1024
	if err := normalizeAndValidate(&both, opts); err == nil {
		t.Fatal("exact src_port plus src_port range should be rejected")
	}

	badProtocol := standingRule("range on icmp")
	badProtocol.Match.Protocol = 1
	badProtocol.Match.DstPort = 0
	badProtocol.Match.DstPortMin = 1024
	if err := normalizeAndValidate(&badProtocol, opts); err == nil {
		t.Fatal("port range on a non-TCP/UDP protocol should be rejected")
	}

	openMax := standingRule("open ended max")
	openMax.Match.PacketLengthMin = 500
	if err := normalizeAndValidate(&openMax, opts); err != nil {
		t.Fatalf("open-ended packet-length range should validate: %v", err)
	}
	if openMax.Match.PacketLengthMin != 500 || openMax.Match.PacketLengthMax != 65535 {
		t.Fatalf("open-ended range should normalize, got %d-%d", openMax.Match.PacketLengthMin, openMax.Match.PacketLengthMax)
	}

	swapped := standingRule("swapped range")
	swapped.Match.PacketLengthMin = 900
	swapped.Match.PacketLengthMax = 100
	if err := normalizeAndValidate(&swapped, opts); err != nil {
		t.Fatalf("swapped range should normalize: %v", err)
	}
	if swapped.Match.PacketLengthMin != 100 || swapped.Match.PacketLengthMax != 900 {
		t.Fatalf("swapped range should be ordered, got %d-%d", swapped.Match.PacketLengthMin, swapped.Match.PacketLengthMax)
	}
}

func TestMatchRangesFragmentAndLength(t *testing.T) {
	opts := testOptions(t)
	now := time.Now()

	lengthRange := standingRule("length range")
	lengthRange.Match.PacketLength = 0
	lengthRange.Match.PacketLengthMin = 100
	lengthRange.Match.PacketLengthMax = 200
	lengthRange.Match.SrcPort = 0
	lengthRange.Match.DstPort = 0
	if err := normalizeAndValidate(&lengthRange, opts); err != nil {
		t.Fatal(err)
	}
	base := testObservation(now, "")
	inRange := base
	inRange.PacketSize = 150
	outOfRange := base
	outOfRange.PacketSize = 400
	if !lengthRange.Match.matches(inRange, lengthRange.compiled) {
		t.Fatal("150-byte packet should match the 100-200 range")
	}
	if lengthRange.Match.matches(outOfRange, lengthRange.compiled) {
		t.Fatal("400-byte packet should not match the 100-200 range")
	}

	below := base
	below.PacketSize = 60
	openMin := standingRule("open min")
	openMin.Match.PacketLength = 0
	openMin.Match.PacketLengthMin = 100
	openMin.Match.SrcPort = 0
	openMin.Match.DstPort = 0
	if err := normalizeAndValidate(&openMin, opts); err != nil {
		t.Fatal(err)
	}
	if openMin.Match.matches(below, openMin.compiled) {
		t.Fatal("60-byte packet should not match >=100")
	}

	portRange := standingRule("port range")
	portRange.Match.SrcPort = 0
	portRange.Match.SrcPortMin = 32768
	if err := normalizeAndValidate(&portRange, opts); err != nil {
		t.Fatal(err)
	}
	highPort := base
	highPort.SrcPort = 50000
	lowPort := base
	lowPort.SrcPort = 1234
	if !portRange.Match.matches(highPort, portRange.compiled) {
		t.Fatal("source port 50000 should match >=32768")
	}
	if portRange.Match.matches(lowPort, portRange.compiled) {
		t.Fatal("source port 1234 should not match >=32768")
	}

	fragmentRule := standingRule("fragment only")
	fragmentRule.Match.Fragment = true
	fragmentRule.Match.SrcPort = 0
	fragmentRule.Match.DstPort = 0
	if err := normalizeAndValidate(&fragmentRule, opts); err != nil {
		t.Fatal(err)
	}
	unfragmented := base
	fragmented := base
	fragmented.Fragmented = true
	if !fragmentRule.Match.matches(fragmented, fragmentRule.compiled) {
		t.Fatal("fragmented packet should match the fragment condition")
	}
	if fragmentRule.Match.matches(unfragmented, fragmentRule.compiled) {
		t.Fatal("unfragmented packet should not match the fragment condition")
	}
}

func TestMinSourcesCondition(t *testing.T) {
	opts := testOptions(t)
	store, err := Open(opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	rule := standingRule("distributed flood")
	rule.Match.Source = ""
	rule.Mode = ModeConditional
	rule.Action.Type = ActionRateLimit
	rule.Condition = Condition{
		WindowSeconds: 5,
		MinSources:    3,
		Consecutive:   1,
	}
	if _, err := store.Create(rule); err != nil {
		t.Fatal(err)
	}

	// Three distinct sources in the same window must fire.
	now := start
	for _, source := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		obs := testObservation(now, "")
		obs.SrcIP = netip.MustParseAddr(source)
		store.Observe(obs, now)
	}
	triggers := store.Tick(now)
	if len(triggers) != 1 {
		t.Fatalf("expected one trigger for 3 distinct sources, got %d", len(triggers))
	}

	// The same single source, no matter how many packets, must not fire.
	now = now.Add(2 * time.Minute)
	store.SetClock(func() time.Time { return now })
	for i := 0; i < 20; i++ {
		obs := testObservation(now, "")
		obs.SrcIP = netip.MustParseAddr("198.51.100.9")
		store.Observe(obs, now)
	}
	if triggers := store.Tick(now); len(triggers) != 0 {
		t.Fatalf("single source should not satisfy min_sources, got %d triggers", len(triggers))
	}

	// min_sources rejects a pinned source prefix.
	pinned := standingRule("pinned source min_sources")
	pinned.Match.Source = "198.51.100.0/24"
	pinned.Mode = ModeConditional
	pinned.Action.Type = ActionRateLimit
	pinned.Condition = Condition{WindowSeconds: 5, MinSources: 2, Consecutive: 1}
	if err := normalizeAndValidate(&pinned, opts); err == nil {
		t.Fatal("min_sources with a pinned source prefix should be rejected")
	}
}

func TestReorderPersistence(t *testing.T) {
	opts := testOptions(t)
	store, err := Open(opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Create(standingRule("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create(standingRule("second"))
	if err != nil {
		t.Fatal(err)
	}
	third, err := store.Create(standingRule("third"))
	if err != nil {
		t.Fatal(err)
	}
	if got := store.List(); len(got) != 3 || got[0].ID != first.ID {
		t.Fatalf("creation order should list first, got %+v", idsOf(got))
	}

	moved, err := store.MoveRule(first.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := idsOf(moved); got[0] != second.ID || got[1] != third.ID || got[2] != first.ID {
		t.Fatalf("move to end failed: %v", got)
	}

	if _, err := store.MoveRule(first.ID, 0); err != nil {
		t.Fatal(err)
	}
	if got := idsOf(store.List()); got[0] != first.ID {
		t.Fatalf("move to front failed: %v", got)
	}

	// An incomplete or duplicated order is rejected.
	if _, err := store.Reorder([]string{first.ID, second.ID}); err == nil {
		t.Fatal("partial order should be rejected")
	}
	if _, err := store.Reorder([]string{first.ID, first.ID, second.ID, third.ID}); err == nil {
		t.Fatal("duplicate ids should be rejected")
	}
	if _, err := store.Reorder([]string{first.ID, second.ID, third.ID, "rule-missing"}); err == nil {
		t.Fatal("unknown id should be rejected")
	}

	// The persisted file preserves the new order.
	reordered, err := store.Reorder([]string{third.ID, first.ID, second.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got := idsOf(reordered); got[0] != third.ID || got[1] != first.ID || got[2] != second.ID {
		t.Fatalf("reorder failed: %v", got)
	}
	reloaded, err := Open(opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := idsOf(reloaded.List()); got[0] != third.ID || got[1] != first.ID || got[2] != second.ID {
		t.Fatalf("order did not survive reload: %v", got)
	}
}

func idsOf(rules []Rule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.ID)
	}
	return out
}
