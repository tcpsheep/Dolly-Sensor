package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, cfg Config) string {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSafeDefaultsRequireExplicitProtectedNetworks(t *testing.T) {
	cfg := Default()
	if cfg.BGP.Enabled {
		t.Fatal("BGP must be disabled by default")
	}
	if !strings.HasPrefix(cfg.Dashboard.Listen, "127.0.0.1:") && !strings.HasPrefix(cfg.Dashboard.Listen, "[::1]:") {
		t.Fatalf("dashboard default listen %q is not loopback", cfg.Dashboard.Listen)
	}
	if cfg.Mitigation.AutoBlock {
		t.Fatal("automatic blocking must be opt-in")
	}
	if cfg.Detection.Sensitivity != "balanced" {
		t.Fatalf("default sensitivity = %q", cfg.Detection.Sensitivity)
	}
	warnings, err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "protected_cidrs") {
		t.Fatalf("Validate error = %v, want missing protected_cidrs", err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warnings for empty webhook/missing blocklist directory")
	}
}

func TestLoadValidConfiguration(t *testing.T) {
	cfg := Default()
	dir := t.TempDir()
	cfg.ProtectedCIDRs = []string{"203.0.113.0/24", "2001:db8:1234::/48"}
	cfg.Mitigation.BlocklistDir = filepath.Join(dir, "lists")
	cfg.Persistence.ProfileFile = filepath.Join(dir, "profiles.json")
	cfg.Detection.EvaluationInterval = Duration(250 * time.Millisecond)
	path := writeConfig(t, cfg)
	loaded, warnings, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v (warnings: %v)", err, warnings)
	}
	if len(loaded.ProtectedCIDRs) != 2 {
		t.Fatalf("protected = %v", loaded.ProtectedCIDRs)
	}
	if loaded.Detection.EvaluationInterval.Std() != 250*time.Millisecond {
		t.Fatalf("duration = %v", loaded.Detection.EvaluationInterval.Std())
	}
	if loaded.Detection.Sensitivity != "balanced" {
		t.Fatalf("defaults were not retained: %q", loaded.Detection.Sensitivity)
	}
	if loaded.BGP.Enabled {
		t.Fatal("BGP unexpectedly enabled")
	}
}

func TestLocalhostListenAddressesAreValid(t *testing.T) {
	cfg := Default()
	cfg.ProtectedCIDRs = []string{"203.0.113.0/24"}
	cfg.Mitigation.BlocklistDir = t.TempDir()
	cfg.Dashboard.Listen = "localhost:8080"
	cfg.Collector.Listen = "localhost:6343"
	warnings, err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate: %v (warnings: %v)", err, warnings)
	}
	for _, warning := range warnings {
		if strings.Contains(warning, "not loopback") {
			t.Fatalf("localhost was not treated as loopback: %v", warnings)
		}
	}

	cfg.Dashboard.Listen = ":8080"
	warnings, err = cfg.Validate()
	if err != nil {
		t.Fatalf("Validate wildcard: %v", err)
	}
	found := false
	for _, warning := range warnings {
		if strings.Contains(warning, "not loopback") {
			found = true
		}
	}
	if !found {
		t.Fatalf("wildcard dashboard bind did not produce a warning: %v", warnings)
	}
}

func TestLoadRejectsUnknownFieldsAndTrailingData(t *testing.T) {
	dir := t.TempDir()
	unknown := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"protected_cidrs":["203.0.113.0/24"],"typo":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
	trailing := filepath.Join(dir, "trailing.json")
	if err := os.WriteFile(trailing, []byte(`{"protected_cidrs":["203.0.113.0/24"]} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(trailing); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing data error = %v", err)
	}
}

func TestValidationWarnsButAllowsRiskyExplicitChoices(t *testing.T) {
	cfg := Default()
	cfg.ProtectedCIDRs = []string{"0.0.0.0/0"}
	cfg.Dashboard.Listen = "0.0.0.0:8080"
	cfg.Mitigation.BlocklistDir = t.TempDir()
	warnings, err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "default route") {
		t.Fatalf("missing default-route warning: %v", warnings)
	}
	if !strings.Contains(joined, "not loopback") {
		t.Fatalf("missing dashboard warning: %v", warnings)
	}
}

func TestValidationRejectsUnsafeOrIncompleteBGP(t *testing.T) {
	cfg := Default()
	cfg.ProtectedCIDRs = []string{"203.0.113.0/24"}
	cfg.Mitigation.BlocklistDir = t.TempDir()
	cfg.BGP.Enabled = true
	cfg.BGP.PeerIP = ""
	cfg.BGP.NextHop = ""
	cfg.BGP.RouterID = ""
	cfg.BGP.Community = "0:0"
	cfg.BGP.HoldTime = Duration(time.Second)
	_, err := cfg.Validate()
	if err == nil {
		t.Fatal("incomplete BGP configuration was accepted")
	}
	for _, want := range []string{"bgp.peer_ip", "bgp.next_hop", "bgp.router_id", "bgp.community", "bgp.hold_time"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestValidationRejectsUnsafeFilesystemAndLimits(t *testing.T) {
	cfg := Default()
	cfg.ProtectedCIDRs = []string{"203.0.113.0/24"}
	cfg.Mitigation.BlocklistDir = t.TempDir()
	cfg.Mitigation.ManualFile = "sub/manual.txt"
	cfg.Mitigation.MaxActive = 0
	cfg.Mitigation.RateLimitMbps = 0
	cfg.Memory.PacketBuffer = 0
	cfg.Memory.MaxProfiles = 0
	cfg.Detection.RateWindowSeconds = 0
	cfg.Alerting.WebhookURL = "ftp://example.com/hook"
	_, err := cfg.Validate()
	if err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	for _, want := range []string{"manual_file", "max_active", "rate_limit_mbps", "packet_buffer", "max_profiles", "rate_window_seconds", "webhook_url"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestParseCommunity(t *testing.T) {
	if got, err := ParseCommunity("65535:666"); err != nil || got == 0 {
		t.Fatalf("ParseCommunity = %#x, %v", got, err)
	}
	for _, value := range []string{"", "65535", "70000:1", "1:70000", "x:y"} {
		if _, err := ParseCommunity(value); err == nil {
			t.Errorf("ParseCommunity(%q) unexpectedly succeeded", value)
		}
	}
}
