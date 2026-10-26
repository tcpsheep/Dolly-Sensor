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
	// Detection is stateless by design: sampled sFlow cannot reliably
	// reconstruct TCP connections, so no connection table is kept and no
	// out-of-state or handshake evidence is used. Scoring relies on sampled
	// rates, protocol and flag mixes, source reputation, and blocklists.
	EvaluationInterval  Duration `json:"evaluation_interval"`
	RateWindowSeconds   int      `json:"rate_window_seconds"`
	Cooldown            Duration `json:"cooldown"`
	WarmupWindows       int      `json:"warmup_windows"`
	TrustExemptionScore float64  `json:"trust_exemption_score"`
	Threshold           float64  `json:"threshold"`
	Persistence         int      `json:"persistence"`
	PPSFloor            float64  `json:"pps_floor"`
	BPSFloor            float64  `json:"bps_floor"`
	// Signals exposes every rate, share, asymmetry, and score weight the
	// detector uses. All of it is live-tunable from the dashboard.
	Signals SignalsConfig `json:"signals"`
	// Sweep configures cross-destination detection: one source spraying many
	// protected IPs (carpet bombing) and per-source TTL entropy.
	Sweep SweepConfig `json:"sweep"`
}

// Default detection tuning. These are ordinary starting values, not presets:
// every field is explicit in the configuration and can be changed independently.
const (
	DefaultThreatThreshold = 70.0
	DefaultPersistence     = 5
	DefaultPPSFloor        = 10_000.0
	DefaultBPSFloor        = 100_000_000.0
)

// SignalTier is one rung of a threshold ladder: the signal scores Points when
// the measured value is at or beyond Min. Tiers are evaluated in order and the
// first match wins, so list them from most to least extreme.
type SignalTier struct {
	Min    float64 `json:"min"`
	Points float64 `json:"points"`
}

// SignalsConfig holds every tuning constant of the scoring funnel. The meaning
// of Min depends on the ladder: a share tier fires at share >= Min, a
// small-packet tier at size <= Min, a low-trust tier at trust < Min, and a
// z-score or baseline-ratio tier at value >= Min.
type SignalsConfig struct {
	// Volumetric floors.
	PPSPoints   float64 `json:"pps_points"`
	PPSLogCap   float64 `json:"pps_log_cap"`
	PPSLogScale float64 `json:"pps_log_scale"`
	BPSPoints   float64 `json:"bps_points"`
	BPSLogCap   float64 `json:"bps_log_cap"`
	BPSLogScale float64 `json:"bps_log_scale"`

	// Statistical baseline.
	ZScoreTiers                  []SignalTier `json:"z_score_tiers"`
	BaselineRatioTiers           []SignalTier `json:"baseline_ratio_tiers"`
	BaselineAlpha                float64      `json:"baseline_alpha"`
	BaselineSkipFloorMultiple    float64      `json:"baseline_skip_floor_multiple"`
	BaselineSkipBaselineMultiple float64      `json:"baseline_skip_baseline_multiple"`

	// Packet shape.
	SmallPacketTiers    []SignalTier `json:"small_packet_tiers"`
	SignalVolumeGate    float64      `json:"signal_volume_gate"`
	MalformedShareTiers []SignalTier `json:"malformed_share_tiers"`

	// TCP flag evidence.
	SynShareTiers     []SignalTier `json:"syn_share_tiers"`
	SynACKCountMin    uint64       `json:"syn_ack_count_min"`
	SynACKCountRatio  float64      `json:"syn_ack_count_ratio"`
	SynACKCountPoints float64      `json:"syn_ack_count_points"`
	SrcSynMin         uint64       `json:"src_syn_min"`
	SrcSynACKRatio    float64      `json:"src_syn_ack_ratio"`
	SrcSynShareMin    float64      `json:"src_syn_share_min"`
	SrcSynACKPoints   float64      `json:"src_syn_ack_points"`

	// PSH-ACK:pure-ACK asymmetry. A healthy conversation carries both data
	// pushes (PSH-ACK) and receiver acknowledgements (pure ACK) from the same
	// source in comparable amounts; a source whose PSH-ACKs outnumber its pure
	// ACKs by PshAckRatio with at least PshAckMin samples is a one-way blast.
	PshAckMin    uint64  `json:"psh_ack_min"`
	PshAckRatio  float64 `json:"psh_ack_ratio"`
	PshAckPoints float64 `json:"psh_ack_points"`

	// Protocol mix.
	UDPShareTiers []SignalTier `json:"udp_share_tiers"`
	ICMPShareMin  float64      `json:"icmp_share_min"`
	ICMPPoints    float64      `json:"icmp_points"`

	// TTL entropy. Legitimate stacks emit a near-constant TTL; many distinct
	// TTL values from the same traffic are forged or randomised.
	TTLDistinctMin    int     `json:"ttl_distinct_min"`
	TTLDistinctPoints float64 `json:"ttl_distinct_points"`

	// Source distribution.
	DistributedSourcesMin    int          `json:"distributed_sources_min"`
	DistributedSourcesPoints float64      `json:"distributed_sources_points"`
	SourceOverflowPoints     float64      `json:"source_overflow_points"`
	TopShareTiers            []SignalTier `json:"top_share_tiers"`

	// Trust adjustments.
	LowTrustTiers     []SignalTier `json:"low_trust_tiers"`
	HighTrustMin      float64      `json:"high_trust_min"`
	HighTrustDiscount float64      `json:"high_trust_discount"`
	TrustedDiscount   float64      `json:"trusted_discount"`

	// Attack-state machine.
	WarmupScoreCap   float64 `json:"warmup_score_cap"`
	SmoothingHistory float64 `json:"smoothing_history"`
	ArmGateFactor    float64 `json:"arm_gate_factor"`
	CalmFactor       float64 `json:"calm_factor"`
	CalmWindows      int     `json:"calm_windows"`

	// Warm-up observation (alert only, no statistical mitigation).
	WarmupVolumeMultiple  float64 `json:"warmup_volume_multiple"`
	WarmupExtremeMultiple float64 `json:"warmup_extreme_multiple"`
	WarmupSynShare        float64 `json:"warmup_syn_share"`

	// Behavioural reputation layer (fires before statistical persistence).
	RepSynTopShare     float64 `json:"rep_syn_top_share"`
	RepSynMin          uint64  `json:"rep_syn_min"`
	RepSynACKRatio     float64 `json:"rep_syn_ack_ratio"`
	RepSynShareMin     float64 `json:"rep_syn_share_min"`
	RepSynMinPPS       float64 `json:"rep_syn_min_pps"`
	RepDiscardMultiple float64 `json:"rep_discard_multiple"`

	// Volumetric finding shaping.
	PreciseSourceShare        float64 `json:"precise_source_share"`
	StrongScoreBonus          float64 `json:"strong_score_bonus"`
	StrongSynShare            float64 `json:"strong_syn_share"`
	StrongTrustBelow          float64 `json:"strong_trust_below"`
	DominantPortShare         float64 `json:"dominant_port_share"`
	TrustedStrongSynShare     float64 `json:"trusted_strong_syn_share"`
	TrustedStrongPPSMultiple  float64 `json:"trusted_strong_pps_multiple"`
	TrustedStrongSynPPSMultiple float64 `json:"trusted_strong_syn_pps_multiple"`
	TrustedStrongScoreBonus   float64 `json:"trusted_strong_score_bonus"`

	// Remotely-triggered black hole gating (deliberately rare).
	RTBHSynShare    float64 `json:"rtbh_syn_share"`
	RTBHTopShare    float64 `json:"rtbh_top_share"`
	RTBHSynMin      uint64  `json:"rtbh_syn_min"`
	RTBHSynACKRatio float64 `json:"rtbh_syn_ack_ratio"`
	RTBHScoreBonus  float64 `json:"rtbh_score_bonus"`
	RTBHPPSMultiple float64 `json:"rtbh_pps_multiple"`
	RTBHMinPPS      float64 `json:"rtbh_min_pps"`
	RTBHBPSMultiple float64 `json:"rtbh_bps_multiple"`
	RTBHMinBPS      float64 `json:"rtbh_min_bps"`
}

// SweepConfig controls the cross-destination sweep layer: one external source
// touching many protected destinations (carpet bombing / subnet scanning) and
// per-source TTL randomisation.
type SweepConfig struct {
	Enabled        bool   `json:"enabled"`
	MinDestinations int   `json:"min_destinations"`
	PrefixBits     int    `json:"prefix_bits"`
	MinPackets     uint64 `json:"min_packets"`
	// Action is the mitigation proposed for a confirmed sweep: "none",
	// "rate-limit" (default), or "discard".
	Action        string `json:"action"`
	TTLMinPackets uint64 `json:"ttl_min_packets"`
}

// DefaultSignals returns the default scoring tuning. These mirror the values
// the detector historically hardcoded; every one is operator-tunable.
func DefaultSignals() SignalsConfig {
	return SignalsConfig{
		PPSPoints:   10,
		PPSLogCap:   15,
		PPSLogScale: 5,
		BPSPoints:   8,
		BPSLogCap:   12,
		BPSLogScale: 4,

		ZScoreTiers: []SignalTier{
			{Min: 6, Points: 22},
			{Min: 4, Points: 18},
			{Min: 3, Points: 14},
			{Min: 2, Points: 8},
			{Min: 1.5, Points: 4},
		},
		BaselineRatioTiers: []SignalTier{
			{Min: 20, Points: 10},
			{Min: 8, Points: 6},
		},
		BaselineAlpha:                0.04,
		BaselineSkipFloorMultiple:    4,
		BaselineSkipBaselineMultiple: 8,

		SmallPacketTiers: []SignalTier{
			{Min: 80, Points: 10},
			{Min: 120, Points: 6},
			{Min: 200, Points: 3},
		},
		SignalVolumeGate: 0.5,
		MalformedShareTiers: []SignalTier{
			{Min: 0.6, Points: 12},
			{Min: 0.3, Points: 7},
			{Min: 0.15, Points: 3},
		},

		SynShareTiers: []SignalTier{
			{Min: 0.8, Points: 18},
			{Min: 0.6, Points: 12},
			{Min: 0.4, Points: 6},
		},
		SynACKCountMin:    100,
		SynACKCountRatio:  4,
		SynACKCountPoints: 6,
		SrcSynMin:         100,
		SrcSynACKRatio:    10,
		SrcSynShareMin:    0.5,
		SrcSynACKPoints:   10,

		PshAckMin:    100,
		PshAckRatio:  8,
		PshAckPoints: 8,

		UDPShareTiers: []SignalTier{
			{Min: 0.8, Points: 10},
			{Min: 0.6, Points: 6},
		},
		ICMPShareMin: 0.5,
		ICMPPoints:   5,

		TTLDistinctMin:    8,
		TTLDistinctPoints: 6,

		DistributedSourcesMin:    1000,
		DistributedSourcesPoints: 8,
		SourceOverflowPoints:     4,
		TopShareTiers: []SignalTier{
			{Min: 0.8, Points: 6},
			{Min: 0.6, Points: 4},
		},

		LowTrustTiers: []SignalTier{
			{Min: 20, Points: 8},
			{Min: 40, Points: 4},
		},
		HighTrustMin:      80,
		HighTrustDiscount: 8,
		TrustedDiscount:   12,

		WarmupScoreCap:   45,
		SmoothingHistory: 0.6,
		ArmGateFactor:    0.25,
		CalmFactor:       0.5,
		CalmWindows:      5,

		WarmupVolumeMultiple:  2,
		WarmupExtremeMultiple: 4,
		WarmupSynShare:        0.6,

		RepSynTopShare:     0.5,
		RepSynMin:          100,
		RepSynACKRatio:     10,
		RepSynShareMin:     0.6,
		RepSynMinPPS:       200,
		RepDiscardMultiple: 2,

		PreciseSourceShare:      0.6,
		StrongScoreBonus:        15,
		StrongSynShare:          0.5,
		StrongTrustBelow:        40,
		DominantPortShare:       0.8,
		TrustedStrongSynShare:   0.85,
		TrustedStrongPPSMultiple: 20,
		TrustedStrongSynPPSMultiple: 5,
		TrustedStrongScoreBonus:  25,

		RTBHSynShare:    0.5,
		RTBHTopShare:    0.9,
		RTBHSynMin:      1000,
		RTBHSynACKRatio: 20,
		RTBHScoreBonus:  20,
		RTBHPPSMultiple: 200,
		RTBHMinPPS:      1_000_000,
		RTBHBPSMultiple: 50,
		RTBHMinBPS:      1_000_000_000,
	}
}

// LowTrustTierFloor returns the trust score below which a source counts as
// plainly untrusted: the least extreme low-trust tier, or a sane fallback when
// the operator removed the tiers entirely.
func (s SignalsConfig) LowTrustTierFloor() float64 {
	if len(s.LowTrustTiers) == 0 {
		return 20
	}
	return s.LowTrustTiers[len(s.LowTrustTiers)-1].Min
}

// DefaultSweep returns the default carpet-bomb detection tuning.
func DefaultSweep() SweepConfig {
	return SweepConfig{
		Enabled:         true,
		MinDestinations: 16,
		PrefixBits:      24,
		MinPackets:      200,
		Action:          "rate-limit",
		TTLMinPackets:   100,
	}
}

// NormalizeDetection fills safe defaults for any unset field so a partial
// configuration (or a dashboard payload) still yields a fully specified
// detector. It never overrides a field the operator set explicitly.
func NormalizeDetection(d DetectionConfig) DetectionConfig {
	if d.Threshold <= 0 {
		d.Threshold = DefaultThreatThreshold
	}
	if d.Persistence < 1 {
		d.Persistence = DefaultPersistence
	}
	if d.PPSFloor <= 0 {
		d.PPSFloor = DefaultPPSFloor
	}
	if d.BPSFloor <= 0 {
		d.BPSFloor = DefaultBPSFloor
	}
	if d.WarmupWindows < 1 {
		d.WarmupWindows = 30
	}
	if d.TrustExemptionScore <= 0 {
		d.TrustExemptionScore = 70
	}
	if len(d.Signals.ZScoreTiers) == 0 && d.Signals.PPSPoints <= 0 {
		d.Signals = DefaultSignals()
	}
	if d.Sweep.MinDestinations < 1 {
		d.Sweep = DefaultSweep()
	}
	if d.Sweep.PrefixBits < 8 || d.Sweep.PrefixBits > 128 {
		d.Sweep.PrefixBits = 24
	}
	switch d.Sweep.Action {
	case "none", "rate-limit", "discard":
	default:
		d.Sweep.Action = "rate-limit"
	}
	return d
}

// ValidateDetection checks one detection configuration. It is used both at
// load time and when the dashboard applies live tuning.
func ValidateDetection(d DetectionConfig) error {
	var errs []error
	if d.EvaluationInterval <= 0 {
		errs = append(errs, errors.New("detection.evaluation_interval must be positive"))
	}
	if d.RateWindowSeconds < 1 || d.RateWindowSeconds > 60 {
		errs = append(errs, errors.New("detection.rate_window_seconds must be between 1 and 60"))
	}
	if d.Cooldown < 0 {
		errs = append(errs, errors.New("detection.cooldown must not be negative"))
	}
	if d.WarmupWindows < 1 {
		errs = append(errs, errors.New("detection.warmup_windows must be at least 1"))
	}
	if d.TrustExemptionScore < 0 || d.TrustExemptionScore > 100 {
		errs = append(errs, errors.New("detection.trust_exemption_score must be between 0 and 100"))
	}
	if d.Threshold < 1 || d.Threshold > 100 {
		errs = append(errs, errors.New("detection.threshold must be between 1 and 100"))
	}
	if d.Persistence < 1 {
		errs = append(errs, errors.New("detection.persistence must be at least 1"))
	}
	if d.PPSFloor <= 0 {
		errs = append(errs, errors.New("detection.pps_floor must be positive"))
	}
	if d.BPSFloor <= 0 {
		errs = append(errs, errors.New("detection.bps_floor must be positive"))
	}
	s := d.Signals
	tierLists := map[string][]SignalTier{
		"detection.signals.z_score_tiers":        s.ZScoreTiers,
		"detection.signals.baseline_ratio_tiers": s.BaselineRatioTiers,
		"detection.signals.small_packet_tiers":   s.SmallPacketTiers,
		"detection.signals.malformed_share_tiers": s.MalformedShareTiers,
		"detection.signals.syn_share_tiers":      s.SynShareTiers,
		"detection.signals.udp_share_tiers":      s.UDPShareTiers,
		"detection.signals.top_share_tiers":      s.TopShareTiers,
		"detection.signals.low_trust_tiers":      s.LowTrustTiers,
	}
	shareLists := map[string]bool{
		"detection.signals.malformed_share_tiers": true,
		"detection.signals.syn_share_tiers":       true,
		"detection.signals.udp_share_tiers":       true,
		"detection.signals.top_share_tiers":       true,
	}
	// Inverted ladders fire when the value falls below the threshold, so their
	// most extreme rung is the smallest threshold.
	invertedLists := map[string]bool{
		"detection.signals.small_packet_tiers": true,
		"detection.signals.low_trust_tiers":    true,
	}
	for name, tiers := range tierLists {
		if len(tiers) > 8 {
			errs = append(errs, errors.New(name+" must not have more than 8 tiers"))
		}
		for i, tier := range tiers {
			if tier.Points < 0 {
				errs = append(errs, fmt.Errorf("%s tier %d must not have negative points", name, i+1))
			}
			if shareLists[name] && (tier.Min <= 0 || tier.Min > 1) {
				errs = append(errs, fmt.Errorf("%s tier %d must use a share between 0 and 1", name, i+1))
			}
			if tier.Min < 0 {
				errs = append(errs, fmt.Errorf("%s tier %d must not use a negative threshold", name, i+1))
			}
			if i > 0 {
				previous := tiers[i-1].Min
				ordered := previous > tier.Min
				if invertedLists[name] {
					ordered = previous < tier.Min
				}
				if !ordered {
					errs = append(errs, fmt.Errorf("%s must be ordered from most to least extreme", name))
				}
			}
		}
	}
	if s.BaselineAlpha <= 0 || s.BaselineAlpha > 1 {
		errs = append(errs, errors.New("detection.signals.baseline_alpha must be between 0 (exclusive) and 1"))
	}
	if s.SmoothingHistory < 0 || s.SmoothingHistory >= 1 {
		errs = append(errs, errors.New("detection.signals.smoothing_history must be between 0 and 1 (exclusive)"))
	}
	if s.CalmWindows < 1 {
		errs = append(errs, errors.New("detection.signals.calm_windows must be at least 1"))
	}
	for field, value := range map[string]float64{
		"syn_ack_count_ratio": s.SynACKCountRatio,
		"src_syn_ack_ratio":   s.SrcSynACKRatio,
		"psh_ack_ratio":       s.PshAckRatio,
		"rep_syn_ack_ratio":   s.RepSynACKRatio,
		"rtbh_syn_ack_ratio":  s.RTBHSynACKRatio,
	} {
		if value <= 0 {
			errs = append(errs, fmt.Errorf("detection.signals.%s must be positive", field))
		}
	}
	for field, value := range map[string]float64{
		"signal_volume_gate": s.SignalVolumeGate,
		"arm_gate_factor":    s.ArmGateFactor,
		"calm_factor":        s.CalmFactor,
		"src_syn_share_min":  s.SrcSynShareMin,
		"rep_syn_top_share":  s.RepSynTopShare,
		"rep_syn_share_min":  s.RepSynShareMin,
		"precise_source_share": s.PreciseSourceShare,
		"strong_syn_share":     s.StrongSynShare,
		"dominant_port_share":  s.DominantPortShare,
		"trusted_strong_syn_share": s.TrustedStrongSynShare,
		"rtbh_syn_share":      s.RTBHSynShare,
		"rtbh_top_share":      s.RTBHTopShare,
		"warmup_syn_share":    s.WarmupSynShare,
		"icmp_share_min":      s.ICMPShareMin,
	} {
		if value < 0 || value > 1 {
			errs = append(errs, fmt.Errorf("detection.signals.%s must be between 0 and 1", field))
		}
	}
	if d.Sweep.PrefixBits < 8 || d.Sweep.PrefixBits > 128 {
		errs = append(errs, errors.New("detection.sweep.prefix_bits must be between 8 and 128"))
	}
	switch d.Sweep.Action {
	case "none", "rate-limit", "discard":
	default:
		errs = append(errs, errors.New("detection.sweep.action must be none, rate-limit, or discard"))
	}
	return errors.Join(errs...)
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

// Application-specific detection no longer lives in code or configuration.
// Protocol knowledge (FTP, SSH, HTTP, ...) is expressed as .dly rule packs
// imported into the rules engine, so a "protocols" config section no longer
// exists and old files that set one fail loudly with an unknown-field error.

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
	MaxProfiles         int      `json:"max_profiles"`
	TrustDecayInterval  Duration `json:"trust_decay_interval"`
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
			EvaluationInterval:  Duration(time.Second),
			RateWindowSeconds:   5,
			Cooldown:            Duration(10 * time.Minute),
			WarmupWindows:       30,
			TrustExemptionScore: 70,
			Threshold:           DefaultThreatThreshold,
			Persistence:         DefaultPersistence,
			PPSFloor:            DefaultPPSFloor,
			BPSFloor:            DefaultBPSFloor,
			Signals:             DefaultSignals(),
			Sweep:               DefaultSweep(),
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
			MaxProfiles:         10000,
			TrustDecayInterval:  Duration(15 * time.Minute),
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
	if err := ValidateDetection(c.Detection); err != nil {
		errs = append(errs, err)
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
	if c.Memory.MaxProfiles < 1 {
		errs = append(errs, errors.New("memory.max_profiles must be at least 1"))
	}
	if c.Memory.TrustDecayInterval <= 0 {
		errs = append(errs, errors.New("memory.trust_decay_interval must be positive"))
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
