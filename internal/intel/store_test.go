package intel

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dollysensor/internal/model"
)

func observation(dst, src string, at time.Time, flags model.TCPFlags) model.Observation {
	return model.Observation{
		SrcIP:            netip.MustParseAddr(src),
		DstIP:            netip.MustParseAddr(dst),
		DstProtected:     true,
		SrcPort:          41000,
		DstPort:          443,
		Protocol:         6,
		ProtocolName:     "TCP",
		TCPFlags:         flags,
		TTL:              57,
		PacketSize:       80,
		EstimatedPackets: 10,
		EstimatedBytes:   800,
		ReceivedAt:       at,
	}
}

func TestStoreConcurrentObservationReadsAndSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	opts := Options{MaxSourcesPerDestination: 64, MaxPortEntries: 32, HistoryLimit: 20}
	store, err := Open(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	var wg sync.WaitGroup
	errs := make(chan error, 64)

	for g := 0; g < 8; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			src := fmt.Sprintf("198.51.100.%d", g+1)
			for i := 0; i < 300; i++ {
				dst := fmt.Sprintf("203.0.113.%d", g%4+1)
				flags := model.TCPSYN
				if i%2 == 1 {
					flags = model.TCPACK | model.TCPPSH
				}
				store.Observe(observation(dst, src, base.Add(time.Duration(i)*time.Millisecond), flags))
				if i%17 == 0 {
					_ = store.TrustScore(netip.MustParseAddr(dst), netip.MustParseAddr(src))
					_, _, _, _, _ = store.SourceSummary(netip.MustParseAddr(dst), netip.MustParseAddr(src))
					_ = store.Summaries()
					_, _ = store.Detail(netip.MustParseAddr(dst), 10)
					_ = store.Reputations(10)
					_ = store.SaveState()
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		dst := netip.MustParseAddr("203.0.113.1")
		src := netip.MustParseAddr("198.51.100.1")
		for i := 0; i < 25; i++ {
			if err := store.SetTrust(dst, src, i%2 == 0, base.Add(time.Duration(i)*time.Second)); err != nil {
				errs <- err
				return
			}
			store.RecordRates(dst, float64(i*100), float64(i*1000))
			store.CreditHandshake(dst, src, base.Add(time.Duration(i)*time.Second))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if err := store.Save(i%3 == 0); err != nil {
				errs <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent operation: %v", err)
	}
	if err := store.Save(true); err != nil {
		t.Fatalf("final Save: %v", err)
	}
	if count := store.Count(); count == 0 {
		t.Fatal("no profiles were recorded")
	}
	state := store.SaveState()
	if state.Error != "" || state.LastSave.IsZero() {
		t.Fatalf("save state = %+v", state)
	}

	reopened, err := Open(path, opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if reopened.Count() != store.Count() {
		t.Fatalf("reopened profiles = %d, original = %d", reopened.Count(), store.Count())
	}
	summary, ok := reopened.Summary(netip.MustParseAddr("203.0.113.1"))
	if !ok || summary.TotalPackets == 0 {
		t.Fatalf("reopened summary = %+v, ok=%v", summary, ok)
	}
}

func TestStoreCapsDestinationProfiles(t *testing.T) {
	store, err := Open("", Options{MaxProfiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1_700_000_000, 0)
	for i := 1; i <= 3; i++ {
		dst := fmt.Sprintf("203.0.113.%d", i)
		store.Observe(observation(dst, "198.51.100.1", base.Add(time.Duration(i)*time.Second), model.TCPSYN))
	}
	if got := len(store.Summaries()); got != 2 {
		t.Fatalf("profiles = %d, want cap of 2", got)
	}
	store.mu.Lock()
	_, oldestPresent := store.profiles[netip.MustParseAddr("203.0.113.1")]
	store.mu.Unlock()
	if oldestPresent {
		t.Fatal("oldest profile was not evicted")
	}
}

func TestManualTrustPersistsAndRevokes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	store, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddr("203.0.113.9")
	src := netip.MustParseAddr("198.51.100.9")
	now := time.Unix(1_700_000_000, 0)
	if err := store.SetTrust(dst, src, true, now); err != nil {
		t.Fatal(err)
	}
	if score := store.TrustScore(dst, src); score != 100 {
		t.Fatalf("manual trust score = %v, want 100", score)
	}
	if trust := store.ManualTrust(); len(trust) != 1 || trust[0].Source != src.String() {
		t.Fatalf("manual trust = %+v", trust)
	}
	if err := store.Save(true); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if trust := reopened.ManualTrust(); len(trust) != 1 {
		t.Fatalf("persisted manual trust = %+v", trust)
	}
	if score := reopened.TrustScore(dst, src); score != 100 {
		t.Fatalf("persisted score = %v, want 100", score)
	}
	if err := reopened.SetTrust(dst, src, false, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if trust := reopened.ManualTrust(); len(trust) != 0 {
		t.Fatalf("revoked trust remains: %+v", trust)
	}
}

func TestOpenRejectsCorruptProfileFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(`{"version":999,"profiles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, Options{}); !errors.Is(err, ErrCorruptProfile) {
		t.Fatalf("Open error = %v, want ErrCorruptProfile", err)
	}
}
