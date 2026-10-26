package tcpstate

import (
	"net/netip"
	"testing"
	"time"

	"dollysensor/internal/model"
)

func tcpObservation(src, dst string, srcPort, dstPort uint16, flags model.TCPFlags, seq, ack uint32, packets uint64, at time.Time) model.Observation {
	return model.Observation{
		SrcIP:            netip.MustParseAddr(src),
		DstIP:            netip.MustParseAddr(dst),
		SrcPort:          srcPort,
		DstPort:          dstPort,
		Protocol:         6,
		ProtocolName:     "TCP",
		TCPFlags:         flags,
		Seq:              seq,
		Ack:              ack,
		EstimatedPackets: packets,
		EstimatedBytes:   packets * 60,
		PacketSize:       60,
		ReceivedAt:       at,
	}
}

func TestHandshakeEstablishesTrackedSession(t *testing.T) {
	tracker := New(Options{MaxSessions: 8})
	now := time.Unix(1_700_000_000, 0)
	syn := tcpObservation("198.51.100.10", "203.0.113.20", 40000, 443, model.TCPSYN, 1000, 0, 10, now)
	tracker.Process(&syn)
	if syn.SessionState != "pending" {
		t.Fatalf("SYN state = %q, want pending", syn.SessionState)
	}
	synack := tcpObservation("203.0.113.20", "198.51.100.10", 443, 40000, model.TCPSYN|model.TCPACK, 7000, 1001, 10, now.Add(time.Millisecond))
	tracker.Process(&synack)
	if synack.SessionState != "pending" {
		t.Fatalf("SYN/ACK state = %q, want pending", synack.SessionState)
	}
	ack := tcpObservation("198.51.100.10", "203.0.113.20", 40000, 443, model.TCPACK, 1001, 7001, 10, now.Add(2*time.Millisecond))
	events := tracker.Process(&ack)
	if !ack.HandshakeCompleted || ack.SessionState != "established" {
		t.Fatalf("final ACK = %+v, want established", ack)
	}
	if len(events) != 1 || events[0].Kind != EventHandshake {
		t.Fatalf("events = %+v, want one handshake", events)
	}
	connections := tracker.Established(10)
	if len(connections) != 1 {
		t.Fatalf("established connections = %d", len(connections))
	}
	if connections[0].Source != "198.51.100.10" || connections[0].DestPort != 443 {
		t.Fatalf("connection = %+v", connections[0])
	}
	stats := tracker.Stats()
	if stats.Established != 1 || stats.OutOfState != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestOutOfStateUsesEstimatedPacketVolume(t *testing.T) {
	tracker := New(Options{})
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 3; i++ {
		obs := tcpObservation("198.51.100.99", "203.0.113.30", 50000+uint16(i), 80, model.TCPACK, 42, 7, 100, now)
		tracker.Process(&obs)
		if !obs.OutOfState || obs.SessionState != "out-of-state" {
			t.Fatalf("observation %d = state %q oos=%v", i, obs.SessionState, obs.OutOfState)
		}
	}
	stats := tracker.OutOfStateStats(now, 1)
	stat, ok := stats[netip.MustParseAddr("203.0.113.30")]
	if !ok {
		t.Fatal("missing out-of-state stats")
	}
	if stat.OutOfState != 300 || stat.Total != 300 {
		t.Fatalf("packet volume = OOS %d total %d, want 300/300", stat.OutOfState, stat.Total)
	}
	if stat.Rate != 300 {
		t.Fatalf("rate = %v, want 300 pps", stat.Rate)
	}
	if got := tracker.Stats(); got.OutOfState != 3 {
		t.Fatalf("sample-level out-of-state count = %d, want 3", got.OutOfState)
	}
}

func TestClosedTupleReuseResetsClientISN(t *testing.T) {
	tracker := New(Options{})
	now := time.Unix(1_700_000_000, 0)
	syn := tcpObservation("198.51.100.11", "203.0.113.21", 41000, 80, model.TCPSYN, 100, 0, 1, now)
	tracker.Process(&syn)
	ack := tcpObservation("198.51.100.11", "203.0.113.21", 41000, 80, model.TCPACK, 101, 0, 1, now.Add(time.Millisecond))
	if events := tracker.Process(&ack); len(events) != 1 || !ack.HandshakeCompleted {
		t.Fatalf("initial handshake failed: %+v events=%v", ack, events)
	}
	fin := tcpObservation("198.51.100.11", "203.0.113.21", 41000, 80, model.TCPFIN|model.TCPACK, 101, 0, 1, now.Add(2*time.Millisecond))
	tracker.Process(&fin)
	if fin.SessionState != "closed" {
		t.Fatalf("FIN state = %q, want closed", fin.SessionState)
	}

	newSyn := tcpObservation("198.51.100.11", "203.0.113.21", 41000, 80, model.TCPSYN, 9000, 0, 1, now.Add(3*time.Millisecond))
	tracker.Process(&newSyn)
	if newSyn.SessionState != "pending" {
		t.Fatalf("new SYN state = %q, want pending", newSyn.SessionState)
	}
	// The new ACK carries the new sequence space. If the closed session's old
	// ISN survived the tuple reset, this would be treated as implausible.
	newAck := tcpObservation("198.51.100.11", "203.0.113.21", 41000, 80, model.TCPACK, 9001, 0, 1, now.Add(4*time.Millisecond))
	events := tracker.Process(&newAck)
	if len(events) != 1 || !newAck.HandshakeCompleted {
		t.Fatalf("reused tuple did not establish a fresh session: %+v events=%v", newAck, events)
	}
}

func TestSessionCapacityIsBounded(t *testing.T) {
	tracker := New(Options{MaxSessions: 2})
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 4; i++ {
		obs := tcpObservation("198.51.100."+string(rune('1'+i)), "203.0.113.40", uint16(42000+i), 443, model.TCPSYN, uint32(100+i), 0, 1, now.Add(time.Duration(i)*time.Millisecond))
		tracker.Process(&obs)
	}
	stats := tracker.Stats()
	if stats.Tracked > 2 {
		t.Fatalf("tracked sessions = %d, want <= 2", stats.Tracked)
	}
	if stats.Evicted == 0 {
		t.Fatal("expected capacity eviction")
	}
	if got := tracker.Established(10); len(got) != 0 {
		t.Fatalf("unexpected established sessions: %+v", got)
	}
}

func TestEstablishedRejectsNegativeLimit(t *testing.T) {
	tracker := New(Options{})
	if got := tracker.Established(-1); len(got) != 0 {
		t.Fatalf("Established(-1) = %v, want empty", got)
	}
}
