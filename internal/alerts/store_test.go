package alerts

import (
	"fmt"
	"testing"
	"time"
)

func TestRecordCoalescesAndKeepsLatestEvidence(t *testing.T) {
	store := New(10, time.Minute)
	now := time.Now()
	first, created, upgraded := store.Record(Candidate{
		Key:      "volumetric|203.0.113.10",
		Severity: SeverityWarning,
		Type:     "volumetric",
		Reason:   "first reason",
		Signals:  []string{"old signal"},
	}, now)
	if !created || upgraded {
		t.Fatal("first record should be new without an upgrade")
	}
	secondNow := now.Add(5 * time.Second)
	second, created, upgraded := store.Record(Candidate{
		Key:      "volumetric|203.0.113.10",
		Severity: SeverityCritical,
		Type:     "volumetric",
		Reason:   "latest reason",
		Signals:  []string{"latest signal", "latest signal"},
	}, secondNow)
	if created {
		t.Fatal("duplicate within cooldown should coalesce")
	}
	if !upgraded {
		t.Fatal("warning-to-critical coalescing should report an upgrade")
	}
	if second.ID != first.ID || second.Occurrences != 2 {
		t.Fatalf("coalesced alert = %+v", second)
	}
	if second.Reason != "latest reason" || second.Severity != SeverityCritical {
		t.Fatalf("latest reason/severity not retained: %+v", second)
	}
	if len(second.Signals) != 1 || second.Signals[0] != "latest signal" {
		t.Fatalf("signals = %v, want bounded latest evidence", second.Signals)
	}
	if !second.UpdatedAt.Equal(secondNow) {
		t.Fatalf("updated_at = %s, want %s", second.UpdatedAt, secondNow)
	}
}

func TestRecordBoundsHistoryAndDedupState(t *testing.T) {
	store := New(2, time.Hour)
	now := time.Now()
	for i := 0; i < 100; i++ {
		store.Record(Candidate{
			Key:      fmt.Sprintf("key-%d", i),
			Severity: SeverityInfo,
			Type:     "test",
			Reason:   "bounded",
		}, now.Add(time.Duration(i)*time.Second))
	}
	if got := store.Snapshot(100, ""); len(got) != 2 {
		t.Fatalf("snapshot length = %d, want 2", len(got))
	}
	store.mu.Lock()
	alertsLen := len(store.alerts)
	dedupLen := len(store.dedup)
	store.mu.Unlock()
	if alertsLen != 2 || dedupLen > 2 {
		t.Fatalf("state grew past capacity: alerts=%d dedup=%d", alertsLen, dedupLen)
	}
	if got := store.Snapshot(-1, ""); len(got) != 2 {
		t.Fatalf("unbounded snapshot returned %d alerts, want 2", len(got))
	}
}

func TestAlertIDsRemainUniqueAcrossSequences(t *testing.T) {
	store := New(2, 0)
	now := time.Unix(1_700_000_000, 0)
	seen := make(map[string]bool)
	for i := 0; i < 10_000; i++ {
		alert, _, _ := store.Record(Candidate{
			Key:      fmt.Sprintf("key-%d", i),
			Severity: SeverityInfo,
			Type:     "test",
			Reason:   "unique",
		}, now)
		if seen[alert.ID] {
			t.Fatalf("duplicate alert ID %q at sequence %d", alert.ID, i)
		}
		seen[alert.ID] = true
	}
}
