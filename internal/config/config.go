// Package config defines, loads, and validates Dolly Sensor configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"dollysensor/internal/netutil"
)

// Duration is a time.Duration that unmarshals from strings such as "30s" or
// from a number of seconds.
type Duration time.Duration

func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

func (d *Duration) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return errors.New("empty duration")
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}
	var seconds float64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\" or a number of seconds: %w", err)
	}
	*d = Duration(time.Duration(seconds * float64(time.Second)))
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Config is the complete, validated configuration of one sensor.
type Config struct {
	Collector      CollectorConfig   `json:"collector"`
	Dashboard      DashboardConfig   `json:"dashboard"`
	ProtectedCIDRs []string          `json:"protected_cidrs"`
	TrustedSources []string          `json:"trusted_sources"`
	Detection      DetectionConfig   `json:"detection"`
	Mitigation     MitigationConfig  `json:"mitigation"`
	Rules          RulesConfig       `json:"rules"`
	Protocols      ProtocolConfig    `json:"protocols"`
	BGP            BGPConfig         `json:"bgp"`
	Alerting       AlertingConfig    `json:"alerting"`
	Persistence    PersistenceConfig `json:"persistence"`
	Memory         MemoryConfig      `json:"memory"`
}

type CollectorConfig struct {
	Listen          string `json:"listen"`
	Workers         int    `json:"workers"`
	Queue           int    `json:"queue"`
	ReadBufferBytes int    `json:"read_buffer_bytes"`
}

type DashboardConfig struct {
	Listen string `json:"listen"`
}

type DetectionConfig struct {
	Sensitivity         string   `json:"sensitivity"`
	NetworkType         string   `json:"network_type"`
	EvaluationInterval  Duration `json:"evaluation_interval"`
	RateWindowSeconds   int      `json:"rate_window_seconds"`
	Cooldown            Duration `json:"cooldown"`
	WarmupWindows       int      `json:"warmup_windows"`
	TrustExemptionScore float64  `json:"trust_exemption_score"`
	OutOfStateMinPPS    float64  `json:"out_of_state_min_pps"`
	PPSFloor            float64  `json:"pps_floor_override"`
	BPSFloor            float64  `json:"bps_floor_override"`
	ThreatThreshold     float64  `json:"threat_threshold_override"`
	Persistence         int      `json:"persistence_override"`
}

type MitigationConfig struct {
	BlocklistDir    string   `json:"blocklist_dir"`
	ManualFile      string   `json:"manual_file"`
	AutoBlock       bool     `json:"auto_block"`
	DefaultDuration Duration `json:"duration"`
	DedupWindow     Duration `json:"dedup_window"`
	MaxActive       int      `json:"max_active"`
	RateLimitMbps   float64  `json:"rate_limit_mbps"`
	HistoryLimit    int      `json:"history_limit"`
}

// RulesConfig controls persisted operator rules. Rules are evaluated against
// sampled observations and enforced as BGP Flowspec header matches.
type RulesConfig struct {
	Enabled                 bool   `json:"enabled"`
	File                    string `json:"file"`
	MaxRules                int    `json:"max_rules"`
	MaxFlowsPerRule         int    `json:"max_flows_per_rule"`
	EvaluationQueue         int    `json:"evaluation_queue"`
	AllowDestinationDiscard bool   `json:"allow_destination_discard"`
}

type ProtocolConfig struct {
	FTP FTPConfig `json:"ftp"`
}

type FTPConfig struct {
	Enabled             bool     `json:"enabled"`
	ControlRateLimitPPS float64  `json:"control_rate_limit_pps"`
	DataRateLimitPPS    float64  `json:"data_rate_limit_pps"`
	ExemptTrustScore    float64  `json:"exempt_trust_score"`
	MaxCommandBytes     int      `json:"max_command_bytes"`
	BlockDuration       Duration `json:"block_duration"`
}

type BGPConfig struct {
	Enabled        bool     `json:"enabled"`
	LocalAS        uint32   `json:"local_as"`
	PeerAS         uint32   `json:"peer_as"`
	PeerIP         string   `json:"peer_ip"`
	PeerPort       int      `json:"peer_port"`
	LocalAddr      string   `json:"local_addr"`
	Community      string   `json:"community"`
	NextHop        string   `json:"next_hop"`
	RouterID       string   `json:"router_id"`
	HoldTime       Duration `json:"hold_time"`
	ConnectTimeout Duration `json:"connect_timeout"`
}

type AlertingConfig struct {
	WebhookURL string   `json:"webhook_url"`
	Format     string   `json:"format"`
	Timeout    Duration `json:"timeout"`
	Retries    int      `json:"retries"`
}

type PersistenceConfig struct {
	ProfileFile  string   `json:"profile_file"`
	SaveInterval Duration `json:"save_interval"`
}

type MemoryConfig struct {
	PacketBuffer        int      `json:"packet_buffer"`
	AlertHistory        int      `json:"alert_history"`
	DestinationStatsTTL Duration `json:"destination_stats_ttl"`
	BaselineTTL         Duration `json:"baseline_ttl"`
	TCPSessionTTL       Duration `json:"tcp_session_ttl"`
	TCPPendingTTL       Duration `json:"tcp_pending_ttl"`
	MaxTCPSessions      int      `json:"max_tcp_sessions"`
	MaxProfiles         int      `json:"max_profiles"`
	TrustDecayInterval  Duration `json:"trust_decay_interval"`
	FTPStateTTL         Duration `json:"ftp_state_ttl"`
}

// Default returns safe, conservative defaults. Protected CIDRs intentionally
// remain empty: the sensor refuses to start without an explicit protected set.
func Default() Config {
	return Config{
		Collector: CollectorConfig{
			Listen:          "0.0.0.0:6343",
			Workers:         4,
			Queue:           8192,
			ReadBufferBytes: 8 << 20,
		},
		Dashboard:      DashboardConfig{Listen: "127.0.0.1:8080"},
		ProtectedCIDRs: nil,
		TrustedSources: nil,
		Detection: DetectionConfig{
			Sensitivity:         "balanced",
			NetworkType:         "office",
			EvaluationInterval:  Duration(time.Second),
			RateWindowSeconds:   5,
			Cooldown:            Duration(10 * time.Minute),
			WarmupWindows:       30,
			TrustExemptionScore: 70,
			OutOfStateMinPPS:    100,
		},
		Mitigation: MitigationConfig{
			BlocklistDir:    "./blocklists",
			ManualFile:      "manual.txt",
			AutoBlock:       false,
			DefaultDuration: Duration(time.Minute),
			DedupWindow:     Duration(5 * time.Minute),
			MaxActive:       64,
			RateLimitMbps:   10,
			HistoryLimit:    500,
		},
		Rules: RulesConfig{
			Enabled:         true,
			File:            "./data/rules.json",
			MaxRules:        128,
			MaxFlowsPerRule: 8192,
			EvaluationQueue: 4096,
		},
		Protocols: ProtocolConfig{FTP: FTPConfig{
			Enabled:             true,
			ControlRateLimitPPS: 50,
			DataRateLimitPPS:    500,
			ExemptTrustScore:    70,
			MaxCommandBytes:     512,
			BlockDuration:       Duration(time.Minute),
		}},
		BGP: BGPConfig{
			Enabled:        false,
			LocalAS:        64512,
			PeerAS:         64512,
			PeerPort:       179,
			Community:      "65535:666",
			HoldTime:       Duration(90 * time.Second),
			ConnectTimeout: Duration(5 * time.Second),
		},
		Alerting: AlertingConfig{
			Format:  "discord",
			Timeout: Duration(5 * time.Second),
			Retries: 2,
		},
		Persistence: PersistenceConfig{
			ProfileFile:  "./data/profiles.json",
			SaveInterval: Duration(30 * time.Second),
		},
		Memory: MemoryConfig{
			PacketBuffer:        5000,
			AlertHistory:        500,
			DestinationStatsTTL: Duration(10 * time.Minute),
			BaselineTTL:         Duration(30 * time.Minute),
			TCPSessionTTL:       Duration(5 * time.Minute),
			TCPPendingTTL:       Duration(10 * time.Second),
			MaxTCPSessions:      100000,
			MaxProfiles:         10000,
			TrustDecayInterval:  Duration(15 * time.Minute),
			FTPStateTTL:         Duration(5 * time.Minute),
		},
	}
}

// Load reads and validates a JSON configuration file. Unknown fields are
// rejected so typos do not silently disable safety controls.
func Load(path string) (Config, []string, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, nil, fmt.Errorf("read config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return cfg, nil, errors.New("config contains trailing JSON data")
		}
		return cfg, nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	warnings, err := cfg.Validate()
	if err != nil {
		return cfg, warnings, err
	}
	return cfg, warnings, nil
}

var (
	validSensitivities = map[string]bool{
		"relaxed": true, "balanced": true, "aggressive": true, "ultra": true, "instant": true,
	}
	validNetworkTypes = map[string]bool{
		"home": true, "office": true, "datacenter": true,
	}
)

// Validate checks the configuration and returns non-fatal warnings.
func (c *Config) Validate() ([]string, error) {
	var warnings []string
	var errs []error

	if err := validateListen("collector.listen", c.Collector.Listen); err != nil {
		errs = append(errs, err)
	}
	if err := validateListen("dashboard.listen", c.Dashboard.Listen); err != nil {
		errs = append(errs, err)
	}
	if c.Collector.Workers <= 0 {
		errs = append(errs, errors.New("collector.workers must be greater than zero"))
	}
	if c.Collector.Queue <= 0 {
		errs = append(errs, errors.New("collector.queue must be greater than zero"))
	}
	if c.Collector.ReadBufferBytes < 65536 {
		errs = append(errs, errors.New("collector.read_buffer_bytes must be at least 65536"))
	}

	protected, err := netutil.ParsePrefixes(c.ProtectedCIDRs)
	if err != nil {
		errs = append(errs, fmt.Errorf("protected_cidrs: %w", err))
	} else {
		if protected.Len() == 0 {
			errs = append(errs, errors.New("protected_cidrs must contain at least one prefix; the sensor will not run without an explicit protected set"))
		}
		for _, prefix := range protected.Prefixes() {
			if prefix.Bits() == 0 {
				warnings = append(warnings, "protected_cidrs contains a default route ("+prefix.String()+"); this makes every destination protected")
			}
		}
	}
	if _, err := netutil.ParsePrefixes(c.TrustedSources); err != nil {
		errs = append(errs, fmt.Errorf("trusted_sources: %w", err))
	}
	if !validSensitivities[strings.ToLower(c.Detection.Sensitivity)] {
		errs = append(errs, fmt.Errorf("detection.sensitivity %q must be one of relaxed, balanced, aggressive, ultra, instant", c.Detection.Sensitivity))
	}
	if !validNetworkTypes[strings.ToLower(c.Detection.NetworkType)] {
		errs = append(errs, fmt.Errorf("detection.network_type %q must be one of home, office, datacenter", c.Detection.NetworkType))
	}
	if c.Detection.EvaluationInterval <= 0 {
		errs = append(errs, errors.New("detection.evaluation_interval must be positive"))
	}
	if c.Detection.RateWindowSeconds < 1 || c.Detection.RateWindowSeconds > 60 {
		errs = append(errs, errors.New("detection.rate_window_seconds must be between 1 and 60"))
	}
	if c.Detection.Cooldown < 0 {
		errs = append(errs, errors.New("detection.cooldown must not be negative"))
	}
	if c.Detection.WarmupWindows < 1 {
		errs = append(errs, errors.New("detection.warmup_windows must be at least 1"))
	}
	if c.Detection.OutOfStateMinPPS < 0 {
		errs = append(errs, errors.New("detection.out_of_state_min_pps must not be negative"))
	}
	if c.Detection.TrustExemptionScore < 0 || c.Detection.TrustExemptionScore > 100 {
		errs = append(errs, errors.New("detection.trust_exemption_score must be between 0 and 100"))
	}
	if c.Detection.PPSFloor < 0 || c.Detection.BPSFloor < 0 {
		errs = append(errs, errors.New("detection floor overrides must not be negative"))
	}
	if c.Detection.ThreatThreshold != 0 && (c.Detection.ThreatThreshold < 1 || c.Detection.ThreatThreshold > 100) {
		errs = append(errs, errors.New("detection.threat_threshold_override must be between 1 and 100"))
	}
	if c.Detection.Persistence < 0 {
		errs = append(errs, errors.New("detection.persistence_override must not be negative"))
	}

	if strings.TrimSpace(c.Mitigation.BlocklistDir) == "" {
		errs = append(errs, errors.New("mitigation.blocklist_dir must not be empty"))
	}
	if strings.TrimSpace(c.Mitigation.ManualFile) == "" {
		errs = append(errs, errors.New("mitigation.manual_file must not be empty"))
	} else if strings.ContainsAny(c.Mitigation.ManualFile, `/\`) {
		errs = append(errs, errors.New("mitigation.manual_file must be a file name, not a path"))
	}
	if c.Mitigation.DefaultDuration <= 0 {
		errs = append(errs, errors.New("mitigation.duration must be positive"))
	}
	if c.Mitigation.DedupWindow < 0 {
		errs = append(errs, errors.New("mitigation.dedup_window must not be negative"))
	}
	if c.Mitigation.MaxActive < 1 {
		errs = append(errs, errors.New("mitigation.max_active must be at least 1"))
	}
	if c.Mitigation.RateLimitMbps <= 0 {
		errs = append(errs, errors.New("mitigation.rate_limit_mbps must be positive"))
	}
	if c.Mitigation.HistoryLimit < 1 {
		errs = append(errs, errors.New("mitigation.history_limit must be at least 1"))
	}
	if c.Rules.Enabled {
		if strings.TrimSpace(c.Rules.File) == "" {
			errs = append(errs, errors.New("rules.file must not be empty"))
		}
		if c.Rules.MaxRules < 1 || c.Rules.MaxRules > 1024 {
			errs = append(errs, errors.New("rules.max_rules must be between 1 and 1024"))
		}
		if c.Rules.MaxFlowsPerRule < 1 || c.Rules.MaxFlowsPerRule > 1000000 {
			errs = append(errs, errors.New("rules.max_flows_per_rule must be between 1 and 1000000"))
		}
		if c.Rules.EvaluationQueue < 1 || c.Rules.EvaluationQueue > 1000000 {
			errs = append(errs, errors.New("rules.evaluation_queue must be between 1 and 1000000"))
		}
		if !c.BGP.Enabled {
			warnings = append(warnings, "rules are enabled but BGP is disabled; rule actions will be recorded as simulated")
		}
		if c.Rules.AllowDestinationDiscard {
			warnings = append(warnings, "rules.allow_destination_discard is enabled; a rule-scoped discard may target an entire protected destination without a source prefix")
		}
	}
	if c.Protocols.FTP.Enabled {
		if c.Protocols.FTP.ControlRateLimitPPS < 0 || c.Protocols.FTP.DataRateLimitPPS < 0 {
			errs = append(errs, errors.New("protocols.ftp rate limits must not be negative"))
		}
		if c.Protocols.FTP.MaxCommandBytes < 64 {
			errs = append(errs, errors.New("protocols.ftp.max_command_bytes must be at least 64"))
		}
		if c.Protocols.FTP.BlockDuration <= 0 {
			errs = append(errs, errors.New("protocols.ftp.block_duration must be positive"))
		}
		if c.Protocols.FTP.ExemptTrustScore < 0 || c.Protocols.FTP.ExemptTrustScore > 100 {
			errs = append(errs, errors.New("protocols.ftp.exempt_trust_score must be between 0 and 100"))
		}
	}

	if c.BGP.Enabled {
		if c.BGP.LocalAS == 0 {
			errs = append(errs, errors.New("bgp.local_as must be set when BGP is enabled"))
		}
		if c.BGP.PeerAS == 0 {
			errs = append(errs, errors.New("bgp.peer_as must be set when BGP is enabled"))
		}
		if _, err := parseIP("bgp.peer_ip", c.BGP.PeerIP); err != nil {
			errs = append(errs, err)
		}
		if c.BGP.PeerPort < 1 || c.BGP.PeerPort > 65535 {
			errs = append(errs, errors.New("bgp.peer_port must be between 1 and 65535"))
		}
		if strings.TrimSpace(c.BGP.LocalAddr) != "" {
			if _, err := parseIP("bgp.local_addr", c.BGP.LocalAddr); err != nil {
				errs = append(errs, err)
			}
		}
		if strings.TrimSpace(c.BGP.NextHop) == "" {
			errs = append(errs, errors.New("bgp.next_hop must be set when BGP is enabled"))
		} else if addr, err := parseIP("bgp.next_hop", c.BGP.NextHop); err != nil {
			errs = append(errs, err)
		} else if !addr.Is4() {
			errs = append(errs, errors.New("bgp.next_hop must be an IPv4 address"))
		}
		if strings.TrimSpace(c.BGP.RouterID) == "" {
			errs = append(errs, errors.New("bgp.router_id must be set when BGP is enabled"))
		} else if addr, err := parseIP("bgp.router_id", c.BGP.RouterID); err != nil {
			errs = append(errs, err)
		} else if !addr.Is4() {
			errs = append(errs, errors.New("bgp.router_id must be an IPv4 address"))
		}
		community, communityErr := ParseCommunity(c.BGP.Community)
		if communityErr != nil {
			errs = append(errs, fmt.Errorf("bgp.community: %w", communityErr))
		} else if community == 0 {
			errs = append(errs, errors.New("bgp.community must not be 0:0; RTBH requires a non-zero blackhole community"))
		}
		if c.BGP.HoldTime < Duration(3*time.Second) || c.BGP.HoldTime > Duration(65535*time.Second) {
			errs = append(errs, errors.New("bgp.hold_time must be between 3s and 65535s"))
		}
		if c.BGP.ConnectTimeout <= 0 {
			errs = append(errs, errors.New("bgp.connect_timeout must be positive"))
		}
	} else if c.Mitigation.AutoBlock {
		warnings = append(warnings, "mitigation.auto_block is enabled but BGP is disabled; actions will be recorded as simulated")
	}

	if c.Alerting.WebhookURL != "" {
		u, err := url.Parse(c.Alerting.WebhookURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, errors.New("alerting.webhook_url must be a valid http or https URL"))
		}
	}
	switch strings.ToLower(c.Alerting.Format) {
	case "discord", "generic":
	default:
		errs = append(errs, errors.New("alerting.format must be discord or generic"))
	}
	if c.Alerting.Timeout <= 0 {
		errs = append(errs, errors.New("alerting.timeout must be positive"))
	}
	if c.Alerting.Retries < 0 || c.Alerting.Retries > 10 {
		errs = append(errs, errors.New("alerting.retries must be between 0 and 10"))
	}
	if c.Persistence.SaveInterval <= 0 {
		errs = append(errs, errors.New("persistence.save_interval must be positive"))
	}
	if strings.TrimSpace(c.Persistence.ProfileFile) == "" {
		errs = append(errs, errors.New("persistence.profile_file must not be empty"))
	}
	if c.Memory.PacketBuffer < 1 {
		errs = append(errs, errors.New("memory.packet_buffer must be at least 1"))
	}
	if c.Memory.AlertHistory < 1 {
		errs = append(errs, errors.New("memory.alert_history must be at least 1"))
	}
	if c.Memory.DestinationStatsTTL <= 0 || c.Memory.BaselineTTL <= 0 {
		errs = append(errs, errors.New("memory destination/baseline TTLs must be positive"))
	}
	if c.Memory.TCPSessionTTL <= 0 || c.Memory.TCPPendingTTL <= 0 {
		errs = append(errs, errors.New("memory TCP TTLs must be positive"))
	}
	if c.Memory.MaxTCPSessions < 1 {
		errs = append(errs, errors.New("memory.max_tcp_sessions must be at least 1"))
	}
	if c.Memory.MaxProfiles < 1 {
		errs = append(errs, errors.New("memory.max_profiles must be at least 1"))
	}
	if c.Memory.TrustDecayInterval <= 0 {
		errs = append(errs, errors.New("memory.trust_decay_interval must be positive"))
	}
	if c.Memory.FTPStateTTL <= 0 {
		errs = append(errs, errors.New("memory.ftp_state_ttl must be positive"))
	}

	if host, _, err := net.SplitHostPort(c.Dashboard.Listen); err == nil && !isLoopbackHost(host) {
		warnings = append(warnings, "dashboard.listen is not loopback; the dashboard has no authentication, so protect it with a firewall or reverse proxy")
	}
	if h, _, err := net.SplitHostPort(c.Collector.Listen); err == nil && (h == "" || h == "0.0.0.0" || h == "::") {
		warnings = append(warnings, "collector.listen accepts sFlow samples from any reachable source; use network segmentation or source validation")
	}
	if info, err := os.Stat(c.Mitigation.BlocklistDir); err != nil {
		warnings = append(warnings, "blocklist directory "+c.Mitigation.BlocklistDir+" is not present; it will be created with no entries")
	} else if !info.IsDir() {
		errs = append(errs, errors.New("mitigation.blocklist_dir is not a directory"))
	}
	if c.Alerting.WebhookURL == "" {
		warnings = append(warnings, "no alerting webhook configured; critical alerts will only appear in the dashboard")
	}

	if len(errs) > 0 {
		return warnings, errors.Join(errs...)
	}
	return warnings, nil
}

// ProtectedSet returns the parsed protected prefixes.
func (c Config) ProtectedSet() *netutil.PrefixSet {
	set, _ := netutil.ParsePrefixes(c.ProtectedCIDRs)
	return set
}

// TrustedSet returns the parsed globally trusted sources.
func (c Config) TrustedSet() *netutil.PrefixSet {
	set, _ := netutil.ParsePrefixes(c.TrustedSources)
	return set
}

// ParseCommunity parses an RFC 1997 community in "ASN:value" form.
func ParseCommunity(value string) (uint32, error) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 2 {
		return 0, errors.New("community must be in ASN:value form")
	}
	asn, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid community ASN %q", parts[0])
	}
	val, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid community value %q", parts[1])
	}
	return uint32(asn)<<16 | uint32(val), nil
}

func parseIP(field, value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s must be a valid IP address", field)
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("%s must not be an unspecified address", field)
	}
	return addr, nil
}

func validateListen(field, value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if host != "" && !strings.EqualFold(host, "localhost") {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("%s: invalid host %q", field, host)
		}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("%s: port must be between 1 and 65535", field)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "" {
		// An empty host in a listen address means every interface. It is not a
		// loopback binding even though net.SplitHostPort accepts it.
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
