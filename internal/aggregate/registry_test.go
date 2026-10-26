package aggregate

import (
	"net/netip"
	"testing"
	"time"

	"dollysensor/internal/model"
)

func TestObserveRotatesWindowsWithoutNilMaps(t *testing.T) {
	registry := New()
	now := time.Now()
	obs := model.Observation{
		ReceivedAt:       now,
		SrcIP:            netip.MustParseAddr("198.51.100.10"),
		DstIP:            netip.MustParseAddr("203.0.113.10"),
		DstProtected:     true,
		Protocol:         6,
		ProtocolName:     "TCP",
		SrcPort:          40000,
		DstPort:          443,
		PacketSize:       60,
		EstimatedPackets: 100,
		EstimatedBytes:   6000,
	}
	registry.Observe(obs, now)
	// The next observation crosses the rotation boundary in Observe itself,
	// before any evaluator has had a chance to call SnapshotAll.
	registry.Observe(obs, now.Add(rotateEvery+time.Second))
	snapshots := registry.SnapshotAll(now.Add(rotateEvery+2*time.Second), 5)
	if len(snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snapshots))
	}
	if snapshots[0].Recent.Samples != 2 {
		t.Fatalf("recent samples = %d, want both rotated observations", snapshots[0].Recent.Samples)
	}
	if snapshots[0].PPS <= 0 {
		t.Fatalf("PPS = %v, want positive", snapshots[0].PPS)
	}
}

func TestOneSecondWindowSurvivesSecondBoundary(t *testing.T) {
	registry := New()
	base := time.Unix(1_700_000_000, 0)
	obs := model.Observation{
		ReceivedAt:       base.Add(900 * time.Millisecond),
		SrcIP:            netip.MustParseAddr("198.51.100.10"),
		DstIP:            netip.MustParseAddr("203.0.113.10"),
		DstProtected:     true,
		Protocol:         6,
		ProtocolName:     "TCP",
		SrcPort:          40000,
		DstPort:          443,
		PacketSize:       60,
		EstimatedPackets: 100,
		EstimatedBytes:   6000,
	}
	registry.Observe(obs, obs.ReceivedAt)
	snapshots := registry.SnapshotAll(base.Add(1050*time.Millisecond), 1)
	if len(snapshots) != 1 {
		t.Fatalf("snapshots = %d, want 1", len(snapshots))
	}
	if snapshots[0].PPS <= 0 {
		t.Fatalf("PPS = %v immediately after a second boundary, want positive", snapshots[0].PPS)
	}
	expired := registry.SnapshotAll(base.Add(2050*time.Millisecond), 1)
	if len(expired) != 1 || expired[0].PPS != 0 {
		t.Fatalf("expired snapshot = %+v, want zero PPS", expired)
	}
}
