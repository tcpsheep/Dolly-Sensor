package sensor

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dollysensor/internal/config"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/model"
	"dollysensor/internal/sflowgen"
)

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

type recordingAnnouncer struct {
	mu        sync.Mutex
	announced []mitigate.Action
	withdrawn []mitigate.Action
}

func (r *recordingAnnouncer) Announce(_ context.Context, action mitigate.Action) error {
	r.mu.Lock()
	r.announced = append(r.announced, action)
	r.mu.Unlock()
	return nil
}

func (r *recordingAnnouncer) Withdraw(_ context.Context, action mitigate.Action) error {
	r.mu.Lock()
	r.withdrawn = append(r.withdrawn, action)
	r.mu.Unlock()
	return nil
}

func (r *recordingAnnouncer) snapshot() ([]mitigate.Action, []mitigate.Action) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]mitigate.Action(nil), r.announced...), append([]mitigate.Action(nil), r.withdrawn...)
}

func freeCollectorAddress(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(message)
}

// TestObservationToMitigationAndShutdownWithdrawal exercises the real ingest,
// evaluation, detection, alert, and mitigation path. Only the BGP announcer is
// replaced; everything else is the production wiring.
func TestObservationToMitigationAndShutdownWithdrawal(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Collector.Listen = freeCollectorAddress(t)
	cfg.Collector.Workers = 2
	cfg.Collector.Queue = 2048
	cfg.ProtectedCIDRs = []string{"203.0.113.0/24"}
	cfg.Detection.EvaluationInterval = config.Duration(50 * time.Millisecond)
	cfg.Detection.RateWindowSeconds = 1
	cfg.Detection.WarmupWindows = 1
	cfg.Detection.Persistence = 1
	cfg.Detection.Threshold = 40
	cfg.Detection.PPSFloor = 100
	cfg.Detection.BPSFloor = 1_000
	cfg.Detection.OutOfStateMinPPS = 100
	cfg.Detection.Cooldown = config.Duration(time.Minute)
	cfg.Protocols.FTP.Enabled = false
	cfg.Mitigation.BlocklistDir = filepath.Join(dir, "blocklists")
	cfg.Mitigation.DefaultDuration = config.Duration(30 * time.Second)
	cfg.Mitigation.DedupWindow = config.Duration(30 * time.Second)
	cfg.Mitigation.MaxActive = 4
	cfg.Persistence.ProfileFile = filepath.Join(dir, "profiles.json")
	cfg.Persistence.SaveInterval = config.Duration(time.Hour)
	cfg.Memory.PacketBuffer = 256
	cfg.Memory.AlertHistory = 50

	logger := slog.New(slog.NewTextHandler(testLogWriter{t}, nil))
	s, err := New(cfg, nil, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	announcer := &recordingAnnouncer{}
	s.mitigator = mitigate.New(mitigate.Options{
		Protected:    s.protected,
		Announcer:    announcer,
		Simulated:    false,
		Duration:     cfg.Mitigation.DefaultDuration.Std(),
		DedupWindow:  cfg.Mitigation.DedupWindow.Std(),
		MaxActive:    cfg.Mitigation.MaxActive,
		HistoryLimit: 50,
		Community:    "65535:666",
		NextHop:      "192.0.2.1",
		RateLimitBPS: uint64(cfg.Mitigation.RateLimitMbps * 1_000_000 / 8),
		OpTimeout:    2 * time.Second,
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Close(ctx)
	}()

	source := netip.MustParseAddr("198.51.100.23")
	destination := netip.MustParseAddr("203.0.113.50")
	packets := make([]sflowgen.PacketSpec, 64)
	for i := range packets {
		packets[i] = sflowgen.PacketSpec{
			SrcIP:       source,
			DstIP:       destination,
			SrcPort:     uint16(40000 + i),
			DstPort:     443,
			Protocol:    6,
			TCPFlags:    uint8(model.TCPSYN),
			TTL:         57,
			FrameLength: 60,
		}
	}
	datagram, err := sflowgen.Datagram(sflowgen.DatagramSpec{
		Agent:        netip.MustParseAddr("192.0.2.200"),
		SamplingRate: 1000,
		Packets:      packets,
	})
	if err != nil {
		t.Fatalf("build sFlow: %v", err)
	}
	if decoded := s.ProcessDatagram(datagram, time.Now()); decoded != len(packets) {
		t.Fatalf("decoded observations = %d, want %d", decoded, len(packets))
	}
	deadline := time.Now().Add(6 * time.Second)
	for {
		announced, _ := announcer.snapshot()
		if len(announced) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no mitigation announcement; states=%+v snapshots=%+v alerts=%+v findings=%d", s.detector.States(), s.aggregate.SnapshotAll(time.Now(), cfg.Detection.RateWindowSeconds), s.alerts.Snapshot(10, ""), len(s.findings))
		}
		time.Sleep(20 * time.Millisecond)
	}

	announced, _ := announcer.snapshot()
	action := announced[0]
	if action.Simulated {
		t.Fatal("announcement was marked simulated despite a real announcer")
	}
	if action.Kind != mitigate.KindFlowspec {
		t.Fatalf("kind = %q, want flowspec", action.Kind)
	}
	if action.Match.Source != source.String()+"/32" || action.Match.Destination != destination.String()+"/32" {
		t.Fatalf("match = %+v", action.Match)
	}
	if action.Match.Protocol != 6 || action.Match.TCPFlags != 0x02 {
		t.Fatalf("flowspec match = %+v, want TCP SYN", action.Match)
	}
	if action.Action != "discard" && action.Action != "rate-limit" {
		t.Fatalf("action = %q", action.Action)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, withdrawn := announcer.snapshot()
	if len(withdrawn) == 0 {
		t.Fatal("shutdown did not withdraw the announcement")
	}
	found := false
	for _, withdrawal := range withdrawn {
		if withdrawal.ID == action.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("withdrawals = %+v, want action %s", withdrawn, action.ID)
	}
}

func TestStatelessProtectionDoesNotStartTCPTracker(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Detection.Stateful = false
	cfg.ProtectedCIDRs = []string{"203.0.113.0/24"}
	cfg.Mitigation.BlocklistDir = filepath.Join(dir, "blocklists")
	cfg.Persistence.ProfileFile = filepath.Join(dir, "profiles.json")
	cfg.Rules.File = filepath.Join(dir, "rules.json")
	cfg.Protocols.FTP.Enabled = false
	cfg.Memory.PacketBuffer = 64

	logger := slog.New(slog.NewTextHandler(testLogWriter{t}, nil))
	s, err := New(cfg, nil, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.tcp != nil {
		t.Fatal("stateful TCP tracker was created while protection is stateless")
	}
	if params := s.detector.Parameters(); params.Stateful {
		t.Fatal("detector reports stateful protection while disabled")
	}
	connections := s.Connections(10)
	if connections.Stateful || connections.Stats.Tracked != 0 || len(connections.Connections) != 0 {
		t.Fatalf("stateless connections view = %+v", connections)
	}
	status := s.Status()
	if status.TCP.Tracked != 0 || status.TCP.TotalSeen != 0 {
		t.Fatalf("stateless status TCP = %+v", status.TCP)
	}

	// These paths dereference the tracker when stateful is enabled; they must
	// stay safe when it is absent.
	s.evaluateOnce(time.Now())
	s.maintenanceOnce(context.Background(), time.Now())
}
