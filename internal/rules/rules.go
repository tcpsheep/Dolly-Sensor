// Package rules owns operator-defined standing and conditional mitigation
// policies. It validates policy independently of the detector and evaluates
// those policies against sampled sFlow observations.
//
// The enforcement boundary is deliberately explicit: sFlow is sampled and the
// actions Dolly can announce are BGP Flowspec header matches. Payload and
// first-N conditions are evaluated on the sampled stream and then enforced as
// header-based Flowspec. They are not inline packet inspection.
package rules

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"dollysensor/internal/model"
	"dollysensor/internal/netutil"
)

const (
	ModeStanding    = "standing"
	ModeConditional = "conditional"

	ActionAllow     = "allow"
	ActionDiscard   = "discard"
	ActionRateLimit = "rate-limit"

	ScopeRule   = "rule"
	ScopeFlow   = "flow"
	ScopeSource = "source"

	// DestinationWildcard is the special destination value that makes a rule
	// apply to every protected prefix. Only conditional rules may use it,
	// because a wildcard has no concrete prefix to announce: enforcement must
	// be flow- or source-scoped, where the destination comes from the
	// triggering observation. Rule packs use it so one definition covers any
	// protected destination.
	DestinationWildcard = "@protected"

	PayloadNone     = "none"
	PayloadContains = "contains"
	PayloadAbsentN  = "absent_first_n"
	PayloadPresentN = "present_first_n"

	PayloadText = "text"
	PayloadHex  = "hex"

	PayloadKindContains = "contains"
	PayloadKindPrefix   = "prefix"
	PayloadKindSuffix   = "suffix"
	PayloadKindRegex    = "regex"

	DirectionAny      = ""
	DirectionInbound  = "inbound"
	DirectionInternal = "internal"

	maxPatternBytes   = 256
	maxOffsetBytes    = 512
	maxPackNameLength = 60
)

var (
	ErrNotFound = errors.New("rule not found")
	ErrCapacity = errors.New("maximum number of rules reached")
	ErrInvalid  = errors.New("invalid rule")
	ErrDisabled = errors.New("rule engine is disabled")
)

// Rule is one persisted operator policy. Stats are a snapshot of runtime
// counters and are persisted on save, but transient state is rebuilt on load.
type Rule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	Mode        string    `json:"mode"`
	Pack        string    `json:"pack,omitempty"`
	Match       Match     `json:"match"`
	Condition   Condition `json:"condition"`
	Action      Action    `json:"action"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Stats       Stats     `json:"stats"`

	compiled *compiledRule
}

// Match selects the traffic a rule evaluates and the Flowspec header fields
// Dolly can enforce. Destination is required: either a concrete prefix inside
// the protected network, or the wildcard "@protected" (conditional rules
// only), which matches any protected destination. Source is optional for
// rate-limit rules and for flow-scoped payload rules; discard rules need an
// explicit source unless the operator opted into destination-only discards.
//
// Port, packet-length, and payload-length fields support either an exact
// value or an inclusive min/max range; setting both an exact value and a
// range on the same field is rejected. Port and packet-length ranges are
// enforced with Flowspec GE/LE comparison operators; payload length is
// evaluated on the sampled stream only (routers cannot match payload
// lengths), so it behaves like a payload condition.
type Match struct {
	Destination        string `json:"destination"`
	Source             string `json:"source,omitempty"`
	Protocol           uint8  `json:"protocol,omitempty"`
	SrcPort            uint16 `json:"src_port,omitempty"`
	DstPort            uint16 `json:"dst_port,omitempty"`
	SrcPortMin         uint16 `json:"src_port_min,omitempty"`
	SrcPortMax         uint16 `json:"src_port_max,omitempty"`
	DstPortMin         uint16 `json:"dst_port_min,omitempty"`
	DstPortMax         uint16 `json:"dst_port_max,omitempty"`
	TCPFlags           uint16 `json:"tcp_flags,omitempty"`
	PacketLength       uint16 `json:"packet_length,omitempty"`
	PacketLengthMin    uint16 `json:"packet_length_min,omitempty"`
	PacketLengthMax    uint16 `json:"packet_length_max,omitempty"`
	PayloadLength      uint16 `json:"payload_length,omitempty"`
	PayloadLengthMin   uint16 `json:"payload_length_min,omitempty"`
	PayloadLengthMax   uint16 `json:"payload_length_max,omitempty"`
	Fragment           bool   `json:"fragment,omitempty"`
	Direction          string `json:"direction,omitempty"`
}

// normalizeRange canonicalizes an inclusive range: a single bound implies the
// field maximum. It returns the effective min and max (0,0 means unset).
func normalizeRange(minValue, maxValue uint16, impliedMax uint16) (uint16, uint16) {
	if minValue > 0 && maxValue == 0 {
		maxValue = impliedMax
	}
	if maxValue > 0 && minValue == 0 {
		minValue = 1
	}
	if minValue > maxValue {
		return maxValue, minValue
	}
	return minValue, maxValue
}

// Condition defines when a conditional rule triggers. Volume thresholds are
// evaluated over a sliding window of sampled observations. Payload conditions
// inspect up to the captured payload limit (512 bytes) of sampled packets.
// MinSources requires distinct sampled source addresses inside the window; it
// is a distributed-attack guard and is bounded by sampling.
//
// PerSource evaluates the volume thresholds per source address instead of
// across all matching traffic: it answers "is any single source exceeding
// this?" rather than "is the aggregate exceeding this?". Each tracked source
// has its own window, persistence counter, and cooldown, so one abusive
// client can be mitigated precisely while the rest of the service keeps
// working. Per-source rules enforce with the "source" scope by default: the
// rule's header match pinned to the triggering source address.
type Condition struct {
	WindowSeconds   int              `json:"window_seconds,omitempty"`
	MinPPS          float64          `json:"min_pps,omitempty"`
	MinBPS          float64          `json:"min_bps,omitempty"`
	MinPackets      uint64           `json:"min_packets,omitempty"`
	MinBytes        uint64           `json:"min_bytes,omitempty"`
	MinSources      int              `json:"min_sources,omitempty"`
	PerSource       bool             `json:"per_source,omitempty"`
	Consecutive     int              `json:"consecutive,omitempty"`
	CooldownSeconds int              `json:"cooldown_seconds,omitempty"`
	Payload         PayloadCondition `json:"payload"`
}

// PayloadCondition is a sampled-payload predicate. FirstN counts sampled
// observations, not all packets on the wire.
type PayloadCondition struct {
	Mode            string `json:"mode,omitempty"`
	Pattern         string `json:"pattern,omitempty"`
	Encoding        string `json:"encoding,omitempty"`
	Kind            string `json:"kind,omitempty"`
	CaseInsensitive bool   `json:"case_insensitive,omitempty"`
	Offset          int    `json:"offset,omitempty"`
	FirstN          int    `json:"first_n,omitempty"`
}

// Action describes the enforcement. Allow is a local bypass of Dolly's
// automatic mitigation, not a BGP permit. Flow scope narrows a conditional
// trigger to the exact observed conversation; source scope announces the
// rule's header match pinned to the triggering source address (the default
// for per-source rules); rule scope announces the rule's header match.
type Action struct {
	Type            string `json:"type"`
	RateLimitBPS    uint64 `json:"rate_limit_bps,omitempty"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
	Scope           string `json:"scope,omitempty"`
}

// Stats is the operator-facing runtime summary for a rule.
type Stats struct {
	Hits           uint64    `json:"hits"`
	MatchedPackets uint64    `json:"matched_packets"`
	MatchedBytes   uint64    `json:"matched_bytes"`
	Triggers       uint64    `json:"triggers"`
	Suppressed     uint64    `json:"suppressed"`
	LastHit        time.Time `json:"last_hit,omitempty"`
	LastTrigger    time.Time `json:"last_trigger,omitempty"`
	State          string    `json:"state,omitempty"`
	ActionID       string    `json:"action_id,omitempty"`
	ActionStatus   string    `json:"action_status,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
}

// Trigger is a conditional rule activation. Observation is the most recent
// matching sample (payload cleared) used to build a flow-scoped action.
type Trigger struct {
	Rule        Rule
	At          time.Time
	Observation model.Observation
	Reason      string
}

// Summary is a dashboard-friendly aggregate.
type Summary struct {
	Total               int    `json:"total"`
	Enabled             int    `json:"enabled"`
	Standing            int    `json:"standing"`
	Conditional         int    `json:"conditional"`
	Allow               int    `json:"allow"`
	Errors              int    `json:"errors"`
	Hits                uint64 `json:"hits"`
	Triggers            uint64 `json:"triggers"`
	Suppressed          uint64 `json:"suppressed"`
	DroppedObservations uint64 `json:"dropped_observations"`
}

// Limits describes hard bounds.
type Limits struct {
	MaxRules                int  `json:"max_rules"`
	MaxFlowsPerRule         int  `json:"max_flows_per_rule"`
	AllowDestinationDiscard bool `json:"allow_destination_discard"`
}

// Defaults describes effective fallback values used when an action leaves a
// field at zero.
type Defaults struct {
	RateLimitBPS    uint64 `json:"rate_limit_bps"`
	DurationSeconds int    `json:"duration_seconds"`
	FlowTTLSeconds  int    `json:"flow_ttl_seconds"`
}

// PreviewResult describes a draft rule against the recent sample ring.
type PreviewResult struct {
	Matched           int                 `json:"matched"`
	Flows             int                 `json:"flows"`
	PotentialTriggers int                 `json:"potential_triggers"`
	EstimatedPackets  uint64              `json:"estimated_packets"`
	EstimatedBytes    uint64              `json:"estimated_bytes"`
	EquivalentPPS     float64             `json:"equivalent_pps"`
	EquivalentBPS     float64             `json:"equivalent_bps"`
	Samples           []model.Observation `json:"samples"`
	Warning           string              `json:"warning,omitempty"`
}

type compiledRule struct {
	destination netip.Prefix
	source      netip.Prefix
	hasSource   bool
	wildcard    bool
	protected   *netutil.PrefixSet
	payload     *compiledPayload
}

type compiledPayload struct {
	mode     string
	kind     string
	encoding string
	pattern  []byte
	text     string
	display  string
	re       *regexp.Regexp
	ci       bool
	offset   int
	firstN   int
}

var idSeq atomic.Uint64

func newID(now time.Time) string {
	var random [5]byte
	if _, err := rand.Read(random[:]); err == nil {
		return "rule-" + now.UTC().Format("20060102T150405") + "-" + hex.EncodeToString(random[:])
	}
	return fmt.Sprintf("rule-%d-%06d", now.Unix(), idSeq.Add(1))
}

func normalizeAndValidate(rule *Rule, opts Options) error {
	if rule == nil {
		return fmt.Errorf("%w: empty rule", ErrInvalid)
	}
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Description = strings.TrimSpace(rule.Description)
	rule.Mode = strings.ToLower(strings.TrimSpace(rule.Mode))
	rule.Pack = strings.TrimSpace(rule.Pack)
	rule.Match.Direction = strings.ToLower(strings.TrimSpace(rule.Match.Direction))
	rule.Action.Type = strings.ToLower(strings.TrimSpace(rule.Action.Type))
	rule.Action.Scope = strings.ToLower(strings.TrimSpace(rule.Action.Scope))
	rule.Condition.Payload.Mode = strings.ToLower(strings.TrimSpace(rule.Condition.Payload.Mode))
	rule.Condition.Payload.Encoding = strings.ToLower(strings.TrimSpace(rule.Condition.Payload.Encoding))
	rule.Condition.Payload.Kind = strings.ToLower(strings.TrimSpace(rule.Condition.Payload.Kind))

	if rule.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if len(rule.Name) > 100 {
		return fmt.Errorf("%w: name must be 100 characters or fewer", ErrInvalid)
	}
	if len(rule.Description) > 1000 {
		return fmt.Errorf("%w: description must be 1000 characters or fewer", ErrInvalid)
	}
	if len(rule.Pack) > maxPackNameLength {
		return fmt.Errorf("%w: pack name must be %d characters or fewer", ErrInvalid, maxPackNameLength)
	}
	switch rule.Mode {
	case ModeStanding, ModeConditional:
	default:
		return fmt.Errorf("%w: mode must be standing or conditional", ErrInvalid)
	}

	if opts.Protected == nil || opts.Protected.Len() == 0 {
		return fmt.Errorf("%w: no protected prefixes configured", ErrInvalid)
	}
	wildcard := strings.TrimSpace(rule.Match.Destination) == DestinationWildcard
	var dst netip.Prefix
	if wildcard {
		if rule.Mode != ModeConditional {
			return fmt.Errorf("%w: destination %s is only valid for conditional rules: a wildcard has no concrete prefix to announce", ErrInvalid, DestinationWildcard)
		}
		rule.Match.Destination = DestinationWildcard
	} else {
		var err error
		dst, err = parsePolicyPrefix(rule.Match.Destination)
		if err != nil {
			return fmt.Errorf("%w: destination: %v", ErrInvalid, err)
		}
		if dst.Bits() == 0 {
			return fmt.Errorf("%w: destination must not be a default route", ErrInvalid)
		}
		if !opts.Protected.ContainsPrefix(dst) {
			return fmt.Errorf("%w: destination %s is not fully inside the protected network", ErrInvalid, dst)
		}
		rule.Match.Destination = dst.String()
	}

	var src netip.Prefix
	hasSource := strings.TrimSpace(rule.Match.Source) != ""
	if hasSource {
		parsed, err := parsePolicyPrefix(rule.Match.Source)
		if err != nil {
			return fmt.Errorf("%w: source: %v", ErrInvalid, err)
		}
		src = parsed
		if src.Bits() == 0 {
			return fmt.Errorf("%w: source must not be a default route", ErrInvalid)
		}
		if opts.Protected.Overlaps(src) {
			return fmt.Errorf("%w: source %s overlaps the protected network", ErrInvalid, src)
		}
		rule.Match.Source = src.String()
	} else {
		rule.Match.Source = ""
	}

	switch rule.Match.Direction {
	case DirectionAny, DirectionInbound, DirectionInternal:
	default:
		return fmt.Errorf("%w: direction must be any, inbound, or internal", ErrInvalid)
	}
	if rule.Match.TCPFlags > 0xFF {
		return fmt.Errorf("%w: TCP flags must fit in one byte", ErrInvalid)
	}
	if rule.Match.Protocol != 6 && rule.Match.TCPFlags != 0 {
		return fmt.Errorf("%w: TCP flags require protocol TCP (6)", ErrInvalid)
	}

	rule.Match.SrcPortMin, rule.Match.SrcPortMax = normalizeRange(rule.Match.SrcPortMin, rule.Match.SrcPortMax, 65535)
	rule.Match.DstPortMin, rule.Match.DstPortMax = normalizeRange(rule.Match.DstPortMin, rule.Match.DstPortMax, 65535)
	rule.Match.PacketLengthMin, rule.Match.PacketLengthMax = normalizeRange(rule.Match.PacketLengthMin, rule.Match.PacketLengthMax, 65535)
	rule.Match.PayloadLengthMin, rule.Match.PayloadLengthMax = normalizeRange(rule.Match.PayloadLengthMin, rule.Match.PayloadLengthMax, 65535)
	if rule.Match.SrcPort != 0 && rule.Match.SrcPortMin != 0 {
		return fmt.Errorf("%w: source port cannot be both an exact value and a range", ErrInvalid)
	}
	if rule.Match.DstPort != 0 && rule.Match.DstPortMin != 0 {
		return fmt.Errorf("%w: destination port cannot be both an exact value and a range", ErrInvalid)
	}
	if rule.Match.PacketLength != 0 && rule.Match.PacketLengthMin != 0 {
		return fmt.Errorf("%w: packet length cannot be both an exact value and a range", ErrInvalid)
	}
	if rule.Match.PayloadLength != 0 && rule.Match.PayloadLengthMin != 0 {
		return fmt.Errorf("%w: payload length cannot be both an exact value and a range", ErrInvalid)
	}
	portFields := [][2]uint16{
		{rule.Match.SrcPortMin, rule.Match.SrcPortMax},
		{rule.Match.DstPortMin, rule.Match.DstPortMax},
		{rule.Match.PacketLengthMin, rule.Match.PacketLengthMax},
	}
	for i, pair := range portFields {
		if pair[0] != 0 && pair[1] == 0 {
			portFields[i][1] = 65535
		}
	}
	if (rule.Match.SrcPortMin != 0 || rule.Match.DstPortMin != 0) && rule.Match.Protocol != 6 && rule.Match.Protocol != 17 {
		return fmt.Errorf("%w: port ranges are only meaningful for TCP or UDP", ErrInvalid)
	}
	if rule.Match.Protocol != 0 && rule.Match.Protocol != 6 && rule.Match.Protocol != 17 &&
		(rule.Match.SrcPort != 0 || rule.Match.DstPort != 0) {
		return fmt.Errorf("%w: ports are only meaningful for TCP or UDP", ErrInvalid)
	}

	switch rule.Action.Type {
	case ActionAllow, ActionDiscard, ActionRateLimit:
	default:
		return fmt.Errorf("%w: action must be allow, discard, or rate-limit", ErrInvalid)
	}
	if rule.Action.Type == ActionRateLimit {
		if rule.Action.RateLimitBPS > 1_000_000_000_000_000 {
			return fmt.Errorf("%w: rate limit is unreasonably large", ErrInvalid)
		}
	} else {
		rule.Action.RateLimitBPS = 0
	}
	if rule.Action.DurationSeconds < 0 || rule.Action.DurationSeconds > 86_400 {
		return fmt.Errorf("%w: duration_seconds must be between 0 and 86400", ErrInvalid)
	}

	switch rule.Action.Scope {
	case "":
		switch {
		case rule.Mode == ModeConditional && rule.Condition.PerSource:
			rule.Action.Scope = ScopeSource
		case rule.Mode == ModeConditional && rule.Condition.Payload.Mode != PayloadNone:
			rule.Action.Scope = ScopeFlow
		default:
			rule.Action.Scope = ScopeRule
		}
	case ScopeRule, ScopeFlow, ScopeSource:
	default:
		return fmt.Errorf("%w: enforcement scope must be rule, flow, or source", ErrInvalid)
	}
	if rule.Mode == ModeStanding && rule.Action.Scope != ScopeRule {
		return fmt.Errorf("%w: standing rules can only enforce their rule header", ErrInvalid)
	}
	if rule.Action.Scope == ScopeSource && rule.Mode != ModeConditional {
		return fmt.Errorf("%w: source-scoped enforcement is only available for conditional rules; the source address comes from the triggering observation", ErrInvalid)
	}
	if wildcard && rule.Action.Scope == ScopeRule {
		return fmt.Errorf("%w: destination %s has no concrete prefix to announce; use flow or source enforcement scope", ErrInvalid, DestinationWildcard)
	}
	if rule.Action.Type == ActionAllow {
		if rule.Mode != ModeStanding {
			return fmt.Errorf("%w: allow/bypass rules must be standing; conditional allow has no meaningful enforcement", ErrInvalid)
		}
		if rule.Action.Scope != ScopeRule || rule.Action.DurationSeconds != 0 || rule.Action.RateLimitBPS != 0 {
			return fmt.Errorf("%w: allow/bypass rules cannot carry an enforcement scope, duration, or rate", ErrInvalid)
		}
	}
	if rule.Action.Type == ActionDiscard && !hasSource && rule.Action.Scope != ScopeFlow && rule.Action.Scope != ScopeSource && !opts.AllowDestinationDiscard {
		return fmt.Errorf("%w: a rule-scoped discard needs a source prefix; use flow or source scope, or set rules.allow_destination_discard only if you intend to discard all traffic to the destination", ErrInvalid)
	}

	if err := normalizeCondition(rule); err != nil {
		return err
	}
	if rule.Mode == ModeStanding {
		if rule.Condition.Payload.Mode != PayloadNone ||
			rule.Condition.MinPPS != 0 || rule.Condition.MinBPS != 0 ||
			rule.Condition.MinPackets != 0 || rule.Condition.MinBytes != 0 ||
			rule.Condition.MinSources != 0 || rule.Condition.PerSource {
			return fmt.Errorf("%w: standing rules cannot carry rate, per-source, or payload conditions; use conditional mode", ErrInvalid)
		}
		rule.Condition.WindowSeconds = 0
		rule.Condition.Consecutive = 0
		rule.Condition.CooldownSeconds = 0
	}

	compiled := &compiledRule{
		destination: dst,
		source:      src,
		hasSource:   hasSource,
		wildcard:    wildcard,
		protected:   opts.Protected,
	}
	payload, err := compilePayload(rule.Condition.Payload)
	if err != nil {
		return err
	}
	compiled.payload = payload
	rule.compiled = compiled
	return nil
}

func normalizeCondition(rule *Rule) error {
	cond := &rule.Condition
	payload := &cond.Payload
	switch payload.Mode {
	case "":
		payload.Mode = PayloadNone
	case PayloadNone, PayloadContains, PayloadAbsentN, PayloadPresentN:
	default:
		return fmt.Errorf("%w: payload mode must be none, contains, absent_first_n, or present_first_n", ErrInvalid)
	}
	if payload.Encoding == "" {
		payload.Encoding = PayloadText
	}
	if payload.Kind == "" {
		payload.Kind = PayloadKindContains
	}
	switch payload.Encoding {
	case PayloadText, PayloadHex:
	default:
		return fmt.Errorf("%w: payload encoding must be text or hex", ErrInvalid)
	}
	switch payload.Kind {
	case PayloadKindContains, PayloadKindPrefix, PayloadKindSuffix, PayloadKindRegex:
	default:
		return fmt.Errorf("%w: payload match kind must be contains, prefix, suffix, or regex", ErrInvalid)
	}
	if payload.Offset < 0 || payload.Offset > maxOffsetBytes {
		return fmt.Errorf("%w: payload offset must be between 0 and %d", ErrInvalid, maxOffsetBytes)
	}
	if payload.Mode == PayloadNone {
		if payload.Pattern != "" {
			return fmt.Errorf("%w: a payload pattern requires a payload mode", ErrInvalid)
		}
	} else {
		if strings.TrimSpace(payload.Pattern) == "" {
			return fmt.Errorf("%w: payload pattern is required", ErrInvalid)
		}
		if len(payload.Pattern) > maxPatternBytes {
			return fmt.Errorf("%w: payload pattern must be at most %d bytes", ErrInvalid, maxPatternBytes)
		}
		if payload.Encoding == PayloadHex && payload.CaseInsensitive {
			return fmt.Errorf("%w: case-insensitive matching is only available for text payloads", ErrInvalid)
		}
		if payload.Kind == PayloadKindRegex && payload.Encoding != PayloadText {
			return fmt.Errorf("%w: regular expressions require text payload encoding", ErrInvalid)
		}
		switch payload.Mode {
		case PayloadContains:
			payload.FirstN = 0
		case PayloadAbsentN, PayloadPresentN:
			if payload.FirstN < 1 || payload.FirstN > 1000 {
				return fmt.Errorf("%w: first_n must be between 1 and 1000 sampled packets", ErrInvalid)
			}
			if cond.MinPPS != 0 || cond.MinBPS != 0 || cond.MinPackets != 0 || cond.MinBytes != 0 || cond.MinSources != 0 {
				return fmt.Errorf("%w: first-N payload rules cannot also use volume or distinct-source thresholds", ErrInvalid)
			}
		}
	}
	if rule.Mode == ModeConditional {
		if cond.WindowSeconds == 0 {
			cond.WindowSeconds = 5
		}
		if cond.WindowSeconds < 1 || cond.WindowSeconds > 60 {
			return fmt.Errorf("%w: window_seconds must be between 1 and 60", ErrInvalid)
		}
		if cond.Consecutive == 0 {
			cond.Consecutive = 1
		}
		if cond.Consecutive < 1 || cond.Consecutive > 60 {
			return fmt.Errorf("%w: consecutive must be between 1 and 60", ErrInvalid)
		}
		if cond.CooldownSeconds < 0 || cond.CooldownSeconds > 86_400 {
			return fmt.Errorf("%w: cooldown_seconds must be between 0 and 86400", ErrInvalid)
		}
		if cond.MinSources < 0 || cond.MinSources > 65_535 {
			return fmt.Errorf("%w: min_sources must be between 0 and 65535", ErrInvalid)
		}
		if math.IsNaN(cond.MinPPS) || math.IsInf(cond.MinPPS, 0) || cond.MinPPS < 0 {
			return fmt.Errorf("%w: min_pps must be a finite non-negative number", ErrInvalid)
		}
		if math.IsNaN(cond.MinBPS) || math.IsInf(cond.MinBPS, 0) || cond.MinBPS < 0 {
			return fmt.Errorf("%w: min_bps must be a finite non-negative number", ErrInvalid)
		}
		hasRate := cond.MinPPS > 0 || cond.MinBPS > 0 || cond.MinPackets > 0 || cond.MinBytes > 0 || cond.MinSources > 0
		if payload.Mode == PayloadNone && !hasRate {
			return fmt.Errorf("%w: a conditional rule needs a volume, distinct-source, or payload condition", ErrInvalid)
		}
		if cond.MinSources > 0 && strings.TrimSpace(rule.Match.Source) != "" {
			return fmt.Errorf("%w: min_sources counts distinct sources, so the rule header must not pin a single source prefix", ErrInvalid)
		}
		if cond.PerSource {
			perSourceRate := cond.MinPPS > 0 || cond.MinBPS > 0 || cond.MinPackets > 0 || cond.MinBytes > 0
			if !perSourceRate {
				return fmt.Errorf("%w: per_source needs at least one volume threshold (min_pps, min_bps, min_packets, or min_bytes)", ErrInvalid)
			}
			if cond.MinSources > 0 {
				return fmt.Errorf("%w: per_source and min_sources are contradictory: per_source judges each source individually while min_sources counts them", ErrInvalid)
			}
			if strings.TrimSpace(rule.Match.Source) != "" {
				return fmt.Errorf("%w: per_source judges each source separately, so the rule header must not pin a source prefix", ErrInvalid)
			}
			switch payload.Mode {
			case PayloadAbsentN, PayloadPresentN:
				return fmt.Errorf("%w: per_source cannot be combined with first-N payload conditions, which are per-conversation", ErrInvalid)
			}
		}
	}
	if rule.Action.Type == ActionAllow && payload.Mode != PayloadNone {
		return fmt.Errorf("%w: allow/bypass rules cannot be conditional on payload", ErrInvalid)
	}
	return nil
}

func compilePayload(condition PayloadCondition) (*compiledPayload, error) {
	if condition.Mode == PayloadNone || condition.Mode == "" {
		return nil, nil
	}
	out := &compiledPayload{
		mode:     condition.Mode,
		kind:     condition.Kind,
		encoding: condition.Encoding,
		offset:   condition.Offset,
		firstN:   condition.FirstN,
		ci:       condition.CaseInsensitive,
		display:  condition.Pattern,
	}
	switch condition.Encoding {
	case PayloadHex:
		decoded, err := hex.DecodeString(strings.ReplaceAll(condition.Pattern, " ", ""))
		if err != nil || len(decoded) == 0 {
			return nil, fmt.Errorf("%w: payload pattern is not valid hexadecimal", ErrInvalid)
		}
		out.pattern = decoded
	case PayloadText:
		text := condition.Pattern
		if condition.CaseInsensitive {
			text = strings.ToLower(text)
		}
		out.text = text
		out.pattern = []byte(text)
		if condition.Kind == PayloadKindRegex {
			expression := condition.Pattern
			if condition.CaseInsensitive {
				expression = "(?i:" + expression + ")"
			}
			re, err := regexp.Compile(expression)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid payload regular expression: %v", ErrInvalid, err)
			}
			out.re = re
		}
	default:
		return nil, fmt.Errorf("%w: unsupported payload encoding", ErrInvalid)
	}
	return out, nil
}

func parsePolicyPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, errors.New("prefix is required")
	}
	prefix, err := netutil.ParseIPOrPrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, errors.New("IPv6 rules are not supported yet")
	}
	return prefix, nil
}

func (m Match) matches(obs model.Observation, compiled *compiledRule) bool {
	if compiled == nil {
		return false
	}
	if compiled.wildcard {
		// A wildcard rule applies to any address inside the protected
		// network; the traffic still has to be inbound toward it.
		if compiled.protected == nil || !compiled.protected.Contains(obs.DstIP.Unmap()) {
			return false
		}
	} else if !compiled.destination.Contains(obs.DstIP.Unmap()) {
		return false
	}
	if compiled.hasSource && !compiled.source.Contains(obs.SrcIP.Unmap()) {
		return false
	}
	if m.Direction != "" && string(obs.Direction) != m.Direction {
		return false
	}
	if m.Protocol != 0 && obs.Protocol != m.Protocol {
		return false
	}
	if !matchU16(m.SrcPort, m.SrcPortMin, m.SrcPortMax, obs.SrcPort) {
		return false
	}
	if !matchU16(m.DstPort, m.DstPortMin, m.DstPortMax, obs.DstPort) {
		return false
	}
	if m.TCPFlags != 0 && (uint16(obs.TCPFlags)&m.TCPFlags) != m.TCPFlags {
		return false
	}
	if !matchU16(m.PacketLength, m.PacketLengthMin, m.PacketLengthMax, obs.PacketSize) {
		return false
	}
	// Payload length is a sampled-stream condition: it inspects the captured
	// payload of the observation, which may be truncated by the sampler.
	if !matchU16(m.PayloadLength, m.PayloadLengthMin, m.PayloadLengthMax, uint16(len(obs.Payload))) {
		return false
	}
	if m.Fragment && !obs.Fragmented {
		return false
	}
	return true
}

// matchU16 compares an observation field against either an exact value or an
// inclusive range. An unset field (all zero) matches anything.
func matchU16(exact, minValue, maxValue, value uint16) bool {
	if exact != 0 {
		return value == exact
	}
	if minValue != 0 || maxValue != 0 {
		if minValue != 0 && value < minValue {
			return false
		}
		if maxValue != 0 && value > maxValue {
			return false
		}
	}
	return true
}

func (p *compiledPayload) matches(payload []byte) bool {
	if p == nil {
		return true
	}
	if p.offset > len(payload) {
		return false
	}
	data := payload[p.offset:]
	switch p.kind {
	case PayloadKindRegex:
		if p.re == nil {
			return false
		}
		return p.re.MatchString(string(data))
	case PayloadKindPrefix, PayloadKindSuffix:
		if p.encoding == PayloadHex {
			if p.kind == PayloadKindPrefix {
				return bytes.HasPrefix(data, p.pattern)
			}
			return bytes.HasSuffix(data, p.pattern)
		}
		if p.ci {
			data = bytes.ToLower(data)
		}
		if p.kind == PayloadKindPrefix {
			return bytes.HasPrefix(data, p.pattern)
		}
		return bytes.HasSuffix(data, p.pattern)
	default:
		if p.encoding == PayloadHex {
			return bytes.Contains(data, p.pattern)
		}
		if p.ci {
			data = bytes.ToLower(data)
		}
		return bytes.Contains(data, p.pattern)
	}
}

func cloneObservation(obs model.Observation) model.Observation {
	copy := obs
	copy.Payload = nil
	copy.PayloadPreview = ""
	copy.PayloadHex = ""
	return copy
}

func flowKey(obs model.Observation) string {
	return fmt.Sprintf("%s|%d|%s|%d|%d",
		obs.SrcIP.Unmap().String(), obs.SrcPort,
		obs.DstIP.Unmap().String(), obs.DstPort, obs.Protocol)
}

func prefixFromRequestString(value string) (netip.Prefix, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, false
	}
	prefix, err := netutil.ParseIPOrPrefix(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

func prefixCovers(outer, inner netip.Prefix) bool {
	if !outer.IsValid() || !inner.IsValid() {
		return false
	}
	outer = outer.Masked()
	inner = inner.Masked()
	if outer.Addr().BitLen() != inner.Addr().BitLen() {
		return false
	}
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func stateForRule(rule Rule, stats Stats, now time.Time, nextEligible time.Time, hasRecentFlow bool) string {
	if !rule.Enabled {
		return "disabled"
	}
	if stats.LastError != "" || stats.ActionStatus == "failed" {
		return "error"
	}
	if rule.Action.Type == ActionAllow {
		return "bypassing"
	}
	if rule.Mode == ModeStanding {
		switch stats.ActionStatus {
		case "simulated":
			return "simulated"
		case "active":
			return "enforcing"
		case "announcing", "withdrawing":
			return "pending"
		default:
			return "pending"
		}
	}
	if !stats.LastTrigger.IsZero() && now.Before(nextEligible) {
		return "cooldown"
	}
	if hasRecentFlow {
		return "watching"
	}
	return "idle"
}
