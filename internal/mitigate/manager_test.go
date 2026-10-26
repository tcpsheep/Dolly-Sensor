package mitigate

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"dollysensor/internal/netutil"
)

type blockingAnnouncer struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (a *blockingAnnouncer) Announce(context.Context, Action) error {
	return nil
}

func (a *blockingAnnouncer) Withdraw(context.Context, Action) error {
	a.once.Do(func() { close(a.started) })
	<-a.release
	return nil
}

func TestUDPFlowspecPortMatchIsAccepted(t *testing.T) {
	protected, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	manager := New(Options{
		Protected: protected,
		Duration:  time.Minute,
		MaxActive: 4,
		Simulated: true,
	})
	action, err := manager.Propose(context.Background(), Request{
		Kind:        KindFlowspec,
		Source:      netip.MustParseAddr("198.51.100.7"),
		Destination: netip.MustParseAddr("203.0.113.10"),
		Protocol:    17,
		DstPort:     53,
		Action:      "discard",
		Reason:      "UDP DNS flood",
	})
	if err != nil {
		t.Fatalf("UDP flow specification was rejected: %v", err)
	}
	if action.Match.Protocol != 17 || action.Match.DstPort != 53 {
		t.Fatalf("UDP match = protocol %d port %d, want 17/53", action.Match.Protocol, action.Match.DstPort)
	}
}

func TestWithdrawingActionCanBeReplacedWithoutLosingNewDedup(t *testing.T) {
	protected, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	announcer := &blockingAnnouncer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	manager := New(Options{
		Protected:   protected,
		Announcer:   announcer,
		Duration:    time.Minute,
		DedupWindow: time.Minute,
		MaxActive:   4,
		OpTimeout:   5 * time.Second,
	})
	request := Request{
		Kind:        KindFlowspec,
		Source:      netip.MustParseAddr("198.51.100.7"),
		Destination: netip.MustParseAddr("203.0.113.10"),
		Protocol:    6,
		DstPort:     443,
		Action:      "discard",
		Reason:      "test replacement",
		DedupKey:    "test-key",
	}
	first, err := manager.Propose(context.Background(), request)
	if err != nil {
		t.Fatalf("first Propose: %v", err)
	}

	withdrawDone := make(chan error, 1)
	go func() {
		_, err := manager.WithdrawNow(context.Background(), first.ID, "test")
		withdrawDone <- err
	}()
	select {
	case <-announcer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("withdrawal did not start")
	}

	second, err := manager.Propose(context.Background(), request)
	if err != nil {
		t.Fatalf("Propose while the first action is withdrawing: %v", err)
	}
	if second.ID == first.ID {
		t.Fatal("replacement reused the withdrawing action")
	}
	close(announcer.release)
	select {
	case err := <-withdrawDone:
		if err != nil {
			t.Fatalf("WithdrawNow: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("withdrawal did not finish")
	}

	if _, err := manager.Propose(context.Background(), request); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("dedup after replacement = %v, want ErrDuplicate", err)
	}
}

func TestPermanentPrefixActionNeverExpires(t *testing.T) {
	protected, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	manager := New(Options{
		Protected: protected,
		Simulated: true,
		Duration:  time.Minute,
		MaxActive: 4,
	})
	now := time.Unix(1_700_000_000, 0).UTC()
	manager.SetClock(func() time.Time { return now })
	action, err := manager.Propose(context.Background(), Request{
		Kind:              KindFlowspec,
		SourcePrefix:      netip.MustParsePrefix("198.51.100.0/24"),
		DestinationPrefix: netip.MustParsePrefix("203.0.113.0/24"),
		Protocol:          17,
		DstPort:           53,
		Action:            "rate-limit",
		RateLimitBPS:      5_000_000,
		Reason:            "standing test",
		Owner:             "rule:test",
		RuleID:            "test",
		Permanent:         true,
	})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !action.Permanent || !action.ExpiresAt.IsZero() {
		t.Fatalf("permanent action has expiry: %+v", action)
	}
	if action.Match.Source != "198.51.100.0/24" || action.Match.Destination != "203.0.113.0/24" {
		t.Fatalf("unexpected prefix match: %+v", action.Match)
	}
	if action.Target != "203.0.113.0/24" {
		t.Fatalf("target = %q", action.Target)
	}
	now = now.AddDate(10, 0, 0)
	if changed := manager.Tick(context.Background()); len(changed) != 0 {
		t.Fatalf("permanent action expired: %+v", changed)
	}
	if active := manager.Active(); len(active) != 1 || active[0].ID != action.ID {
		t.Fatalf("permanent action is not active: %+v", active)
	}
}

func TestDestinationOnlyDiscardRequiresExplicitOptIn(t *testing.T) {
	protected, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		Kind:              KindFlowspec,
		DestinationPrefix: netip.MustParsePrefix("203.0.113.0/24"),
		Protocol:          6,
		DstPort:           443,
		Action:            "discard",
		Owner:             "rule:test",
		RuleID:            "test",
		Permanent:         true,
	}
	strict := New(Options{Protected: protected, Simulated: true})
	if _, err := strict.Propose(context.Background(), request); err == nil {
		t.Fatal("destination-only discard should require opt-in")
	}
	permissive := New(Options{Protected: protected, Simulated: true, AllowDestinationDiscard: true})
	if _, err := permissive.Propose(context.Background(), request); err != nil {
		t.Fatalf("opt-in destination-only discard rejected: %v", err)
	}
}

func TestRuleAndAutomaticCapacityAreSeparate(t *testing.T) {
	protected, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	manager := New(Options{
		Protected: protected,
		Simulated: true,
		MaxActive: 3, MaxAutomatic: 1, MaxRules: 2,
	})
	if _, err := manager.Propose(context.Background(), Request{
		Kind: KindFlowspec, Source: netip.MustParseAddr("198.51.100.7"),
		Destination: netip.MustParseAddr("203.0.113.10"), Protocol: 6, DstPort: 80,
		Action: "discard", Owner: "detector",
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := manager.Propose(context.Background(), Request{
			Kind:              KindFlowspec,
			SourcePrefix:      netip.MustParsePrefix("192.0.2.0/24"),
			DestinationPrefix: netip.MustParsePrefix("203.0.113.0/24"),
			Protocol:          17, DstPort: uint16(1000 + i), Action: "rate-limit", RateLimitBPS: 1000,
			Owner: "rule:r", RuleID: "r", Permanent: true,
			DedupKey: "rule-" + string(rune('a'+i)),
		}); err != nil {
			t.Fatalf("rule %d: %v", i, err)
		}
	}
	if _, err := manager.Propose(context.Background(), Request{
		Kind: KindFlowspec, SourcePrefix: netip.MustParsePrefix("192.0.2.0/24"),
		DestinationPrefix: netip.MustParsePrefix("203.0.113.0/24"), Protocol: 6,
		Action: "rate-limit", RateLimitBPS: 1000, Owner: "rule:r", RuleID: "r",
	}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("third rule action = %v, want capacity", err)
	}
	if _, err := manager.Propose(context.Background(), Request{
		Kind: KindFlowspec, Source: netip.MustParseAddr("198.51.100.8"),
		Destination: netip.MustParseAddr("203.0.113.11"), Protocol: 6, DstPort: 443,
		Action: "discard", Owner: "detector",
	}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("second automatic action = %v, want capacity", err)
	}
}
