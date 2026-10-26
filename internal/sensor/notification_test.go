package sensor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"dollysensor/internal/alerts"
	"dollysensor/internal/detect"
	"dollysensor/internal/events"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/netutil"
	"dollysensor/internal/notify"
)

type notificationSink struct {
	mu       sync.Mutex
	messages []notify.Notification
	notify   chan struct{}
}

func newNotificationSink() *notificationSink {
	return &notificationSink{notify: make(chan struct{}, 8)}
}

func (s *notificationSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var value notify.Notification
	if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.messages = append(s.messages, value)
	s.mu.Unlock()
	s.notify <- struct{}{}
	w.WriteHeader(http.StatusNoContent)
}

func (s *notificationSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.messages)
}

func (s *notificationSink) last() notify.Notification {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.messages[len(s.messages)-1]
}

func notificationTestSensor(t *testing.T, announcer mitigate.Announcer, simulated bool) (*Sensor, *notify.Notifier, *notificationSink) {
	t.Helper()
	protected, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	sink := newNotificationSink()
	server := httptest.NewServer(sink)
	t.Cleanup(server.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	notifier := notify.New(notify.Options{
		URL:     server.URL,
		Format:  "generic",
		Timeout: time.Second,
		Retries: 0,
		Logger:  logger,
	})
	ctx, cancel := context.WithCancel(context.Background())
	notifier.Start(ctx)
	t.Cleanup(cancel)
	manager := mitigate.New(mitigate.Options{
		Protected:    protected,
		Announcer:    announcer,
		Simulated:    simulated,
		Duration:     time.Minute,
		DedupWindow:  time.Minute,
		MaxActive:    4,
		HistoryLimit: 10,
		OpTimeout:    time.Second,
	})
	return &Sensor{
		logger:    logger,
		alerts:    alerts.New(10, time.Minute),
		hub:       events.New(),
		notifier:  notifier,
		mitigator: manager,
	}, notifier, sink
}

func criticalFinding(key string) detect.Finding {
	return detect.Finding{
		Alert: alerts.Candidate{
			Key:         key,
			Severity:    alerts.SeverityCritical,
			Type:        "volumetric",
			Layer:       "volumetric",
			Destination: "203.0.113.10",
			Source:      "198.51.100.7",
			Score:       91,
			Reason:      "test attack",
			Signals:     []string{"test signal"},
		},
		Action: &mitigate.Request{
			Kind:        mitigate.KindFlowspec,
			Source:      netip.MustParseAddr("198.51.100.7"),
			Destination: netip.MustParseAddr("203.0.113.10"),
			Protocol:    6,
			DstPort:     443,
			Action:      "discard",
			Reason:      "test attack",
		},
	}
}

func TestCriticalAlertNotifiesOnceAndReusesCoveringAction(t *testing.T) {
	sensor, _, sink := notificationTestSensor(t, nil, true)
	ctx := context.Background()
	finding := criticalFinding("volumetric|203.0.113.10")
	sensor.handleFinding(ctx, finding)
	select {
	case <-sink.notify:
	case <-time.After(2 * time.Second):
		t.Fatal("critical alert did not reach the webhook")
	}
	first := sink.last()
	if first.Action == "" || first.Destination != "203.0.113.10" {
		t.Fatalf("notification = %+v", first)
	}

	// A repeated observation that reuses the live action must respect the
	// alert cooldown and stay quiet.
	sensor.handleFinding(ctx, finding)
	select {
	case <-sink.notify:
		t.Fatalf("repeat observation generated another notification")
	case <-time.After(300 * time.Millisecond):
	}
	if got := sink.count(); got != 1 {
		t.Fatalf("notifications = %d, want 1", got)
	}
}

type failingAnnouncer struct{}

func (failingAnnouncer) Announce(context.Context, mitigate.Action) error {
	return errors.New("peer rejected the update")
}

func (failingAnnouncer) Withdraw(context.Context, mitigate.Action) error {
	return nil
}

func TestFailedMitigationIsNotified(t *testing.T) {
	sensor, _, sink := notificationTestSensor(t, failingAnnouncer{}, false)
	sensor.handleFinding(context.Background(), criticalFinding("volumetric|failed"))
	select {
	case <-sink.notify:
	case <-time.After(2 * time.Second):
		t.Fatal("failed mitigation did not reach the webhook")
	}
	value := sink.last()
	if value.Action == "" {
		t.Fatalf("notification omitted the mitigation failure: %+v", value)
	}
}
