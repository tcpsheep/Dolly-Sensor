package blocklist

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"dollysensor/internal/netutil"
)

func protectedSet(t *testing.T) *netutil.PrefixSet {
	t.Helper()
	set, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestReloadParsesFeedsAndWarns(t *testing.T) {
	dir := t.TempDir()
	feed := strings.Join([]string{
		"# a comment",
		"198.51.100.0/24",
		"198.51.100.7",
		"198.51.100.0/24 # duplicate",
		"192.0.2.2 extra",
		"not-an-ip",
		"0.0.0.0/0",
		"203.0.113.55",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "feed.txt"), []byte(feed), 0o600); err != nil {
		t.Fatal(err)
	}
	list := New(dir, "manual.txt", protectedSet(t))
	warnings, err := list.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(warnings) < 4 {
		t.Fatalf("warnings = %v, want at least whitespace, invalid, default route, protected overlap", warnings)
	}
	info := list.Info()
	if info.Entries != 3 {
		t.Fatalf("entries = %d, want 3: %+v", info.Entries, info)
	}
	if len(info.Files) != 1 || info.Files[0].Name != "feed.txt" || info.Files[0].Entries != 3 {
		t.Fatalf("files = %+v", info.Files)
	}

	if prefix, ok := list.Lookup(netip.MustParseAddr("198.51.100.7")); !ok || prefix.String() != "198.51.100.7/32" {
		t.Fatalf("exact lookup = %s %v", prefix, ok)
	}
	if prefix, ok := list.Lookup(netip.MustParseAddr("198.51.100.200")); !ok || prefix.String() != "198.51.100.0/24" {
		t.Fatalf("prefix lookup = %s %v", prefix, ok)
	}
	if prefix, ok := list.Lookup(netip.MustParseAddr("203.0.113.55")); !ok || prefix.String() != "203.0.113.55/32" {
		t.Fatalf("protected overlap should still be visible for warning/refusal = %s %v", prefix, ok)
	}
	if _, ok := list.Lookup(netip.MustParseAddr("192.0.2.99")); ok {
		t.Fatal("unlisted address matched")
	}
}

func TestManualLifecycleAndSafetyRefusals(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "lists")
	list := New(dir, "manual.txt", protectedSet(t))
	if _, err := list.Reload(); err != nil {
		t.Fatalf("Reload should create missing directory: %v", err)
	}
	if info := list.Info(); info.Entries != 0 {
		t.Fatalf("new list entries = %d", info.Entries)
	}
	if err := list.AddManual("198.51.100.9"); err != nil {
		t.Fatalf("AddManual: %v", err)
	}
	if prefix, ok := list.Lookup(netip.MustParseAddr("198.51.100.9")); !ok || prefix.String() != "198.51.100.9/32" {
		t.Fatalf("manual lookup = %s %v", prefix, ok)
	}
	info := list.Info()
	if len(info.Manual) != 1 || info.Manual[0] != "198.51.100.9/32" {
		t.Fatalf("manual info = %+v", info.Manual)
	}
	if err := list.AddManual("198.51.100.9"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate err = %v, want ErrExists", err)
	}
	if err := list.AddManual("203.0.113.44"); !errors.Is(err, ErrProtected) {
		t.Fatalf("protected err = %v, want ErrProtected", err)
	}
	if err := list.AddManual("0.0.0.0/0"); !errors.Is(err, ErrDefaultRoute) {
		t.Fatalf("default-route err = %v, want ErrDefaultRoute", err)
	}
	if err := list.AddManual("not an address"); !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("invalid err = %v, want ErrInvalidEntry", err)
	}
	if err := list.RemoveManual("198.51.100.9"); err != nil {
		t.Fatalf("RemoveManual: %v", err)
	}
	if _, ok := list.Lookup(netip.MustParseAddr("198.51.100.9")); ok {
		t.Fatal("removed manual entry still active")
	}
	if err := list.RemoveManual("198.51.100.9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove err = %v, want ErrNotFound", err)
	}
}

func TestConcurrentLookupReloadAndManualChanges(t *testing.T) {
	dir := t.TempDir()
	list := New(dir, "manual.txt", protectedSet(t))
	if _, err := list.Reload(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				list.Lookup(netip.MustParseAddr("198.51.100.7"))
				_ = list.Info()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 20; j++ {
			_ = list.AddManual("198.51.100.7")
			_ = list.RemoveManual("198.51.100.7")
			_, _ = list.Reload()
		}
	}()
	wg.Wait()
}
