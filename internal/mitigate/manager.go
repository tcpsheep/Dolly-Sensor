// Package mitigate owns the mitigation state machine: validation, dedup,
// duration, automatic withdrawal, failure recording, and shutdown cleanup.
package mitigate

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dollysensor/internal/config"
	"dollysensor/internal/netutil"
)

// Kind is the type of network action.
type Kind string

const (
	KindRTBH     Kind = "rtbh"
	KindFlowspec Kind = "flowspec"
)

// Status is the lifecycle state of an action.
type Status string

const (
	StatusAnnouncing  Status = "announcing"
	StatusSimulated   Status = "simulated"
	StatusActive      Status = "active"
	StatusWithdrawing Status = "withdrawing"
	StatusWithdrawn   Status = "withdrawn"
	StatusExpired     Status = "expired"
	StatusFailed      Status = "failed"
)

// ErrDuplicate is returned when an equivalent action is already live or in its
// deduplication window.
var (
	ErrDuplicate    = errors.New("equivalent mitigation is already active or deduplicated")
	ErrCapacity     = errors.New("maximum number of active mitigations reached")
	ErrInvalid      = errors.New("invalid mitigation")
	ErrProtected    = errors.New("mitigation would target the protected network")
	ErrShuttingDown = errors.New("mitigation manager is shutting down")
)

// Match describes the traffic matched by a Flowspec rule. RTBH uses Source as
// the host to blackhole. Port and packet-length fields support either an exact
// value or an inclusive min/max range; ranges are encoded with Flowspec GE/LE
// comparison operators.
type Match struct {
	Source          string `json:"source,omitempty"`
	Destination     string `json:"destination,omitempty"`
	Protocol        uint8  `json:"protocol,omitempty"`
	SrcPort         uint16 `json:"src_port,omitempty"`
	DstPort         uint16 `json:"dst_port,omitempty"`
	SrcPortMin      uint16 `json:"src_port_min,omitempty"`
	SrcPortMax      uint16 `json:"src_port_max,omitempty"`
	DstPortMin      uint16 `json:"dst_port_min,omitempty"`
	DstPortMax      uint16 `json:"dst_port_max,omitempty"`
	TCPFlags        uint16 `json:"tcp_flags,omitempty"`
	PacketLength    uint16 `json:"packet_length,omitempty"`
	PacketLengthMin uint16 `json:"packet_length_min,omitempty"`
	PacketLengthMax uint16 `json:"packet_length_max,omitempty"`
	Fragment        bool   `json:"fragment,omitempty"`
}

// Request asks the manager to create an action. SourcePrefix and
// DestinationPrefix are used by operator rules for CIDR matches; Source and
// Destination remain the host-oriented automatic detector path.
type Request struct {
	Kind              Kind
	Source            netip.Addr
	Destination       netip.Addr
	SourcePrefix      netip.Prefix
	DestinationPrefix netip.Prefix
	Protocol          uint8
	SrcPort           uint16
	DstPort           uint16
	SrcPortMin        uint16
	SrcPortMax        uint16
	DstPortMin        uint16
	DstPortMax        uint16
	TCPFlags          uint16
	PacketLength      uint16
	PacketLengthMin   uint16
	PacketLengthMax   uint16
	Fragment          bool
	Action            string // discard or rate-limit
	RateLimitBPS      uint64 // bits per second; the BGP encoder converts to bytes
	Reason            string
	Owner             string
	AlertID           string
	RuleID            string
	DedupKey          string
	Duration          time.Duration
	Permanent         bool
}

// Action is an announced or simulated network action.
type Action struct {
	ID           string    `json:"id"`
	Kind         Kind      `json:"kind"`
	Match        Match     `json:"match"`
	Action       string    `json:"action"`
	RateLimitBPS uint64    `json:"rate_limit_bps,omitempty"` // bits per second
	Target       string    `json:"target"`
	Community    string    `json:"community,omitempty"`
	NextHop      string    `json:"next_hop,omitempty"`
	Reason       string    `json:"reason"`
	Owner        string    `json:"owner"`
	AlertID      string    `json:"alert_id,omitempty"`
	RuleID       string    `json:"rule_id,omitempty"`
	Permanent    bool      `json:"permanent,omitempty"`
	Status       Status    `json:"status"`
	Simulated    bool      `json:"simulated"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	WithdrawnAt  time.Time `json:"withdrawn_at,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
	Error        string    `json:"error,omitempty"`
	DedupKey     string    `json:"-"`
}

// Announcer is implemented by the BGP speaker. Calls are synchronous and may
// block on the network, so the manager invokes them outside its lock.
type Announcer interface {
	Announce(ctx context.Context, action Action) error
	Withdraw(ctx context.Context, action Action) error
}

// Options configures the manager.
type Options struct {
	Protected               *netutil.PrefixSet
	Announcer               Announcer
	Simulated               bool
	Duration                time.Duration
	DedupWindow             time.Duration
	MaxActive               int
	MaxAutomatic            int
	MaxRules                int
	HistoryLimit            int
	Community               string
	NextHop                 string
	RateLimitBPS            uint64
	OpTimeout               time.Duration
	AllowDestinationDiscard bool
}

type dedupEntry struct {
	actionID string
	until    time.Time
}

// Manager is safe for concurrent use.
type Manager struct {
	mu       sync.Mutex
	clockMu  sync.RWMutex
	opts     Options
	actions  map[string]*Action
	order    []string
	dedup    map[string]dedupEntry
	shutting bool
	opWG     sync.WaitGroup
	seq      atomic.Uint64
	now      func() time.Time
}

// New creates a mitigation manager.
func New(opts Options) *Manager {
	if opts.Duration <= 0 {
		opts.Duration = time.Minute
	}
	if opts.MaxActive < 1 {
		opts.MaxActive = 64
	}
	if opts.MaxAutomatic < 1 {
		opts.MaxAutomatic = opts.MaxActive
	}
	if opts.MaxRules < 1 {
		opts.MaxRules = opts.MaxActive
	}
	if opts.HistoryLimit < 1 {
		opts.HistoryLimit = 500
	}
	if opts.OpTimeout <= 0 {
		opts.OpTimeout = 10 * time.Second
	}
	return &Manager{
		opts:    opts,
		actions: map[string]*Action{},
		dedup:   map[string]dedupEntry{},
		now:     time.Now,
	}
}

// SetClock is used by tests.
func (m *Manager) SetClock(now func() time.Time) {
	if now == nil {
		return
	}
	m.clockMu.Lock()
	m.now = now
	m.clockMu.Unlock()
}

func (m *Manager) clock() time.Time {
	m.clockMu.RLock()
	now := m.now
	m.clockMu.RUnlock()
	return now()
}

// Propose validates and creates one mitigation. It returns the recorded action
// even when announcement fails; the failure is part of the action's story.
func (m *Manager) Propose(ctx context.Context, req Request) (*Action, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := m.clock()
	if strings.TrimSpace(req.Reason) == "" {
		req.Reason = "unspecified"
	}
	if req.Owner == "" {
		req.Owner = "detector"
	}
	kind := Kind(strings.ToLower(string(req.Kind)))
	req.Kind = kind
	actionType := strings.ToLower(strings.TrimSpace(req.Action))
	if actionType == "" && kind == KindRTBH {
		actionType = "discard"
	}
	req.Action = actionType
	if err := m.validate(&req); err != nil {
		return nil, err
	}
	duration := req.Duration
	if req.Permanent {
		duration = 0
	} else if duration <= 0 {
		duration = m.opts.Duration
	}
	expiresAt := now.Add(duration)
	if req.Permanent {
		expiresAt = time.Time{}
	}
	dedupKey := req.DedupKey
	if dedupKey == "" {
		dedupKey = deriveDedupKey(req)
	}
	m.mu.Lock()
	if m.shutting {
		m.mu.Unlock()
		return nil, ErrShuttingDown
	}
	if entry, ok := m.dedup[dedupKey]; ok && now.Before(entry.until) {
		// A withdrawing action is already on its way out. Let fresh evidence
		// establish a replacement instead of reporting a duplicate for a rule
		// that will not protect the flow for much longer.
		existing := m.actions[entry.actionID]
		if existing == nil || existing.Status != StatusWithdrawing {
			m.mu.Unlock()
			return nil, fmt.Errorf("%w (until %s)", ErrDuplicate, entry.until.Format(time.RFC3339))
		}
		delete(m.dedup, dedupKey)
	}
	live, automatic, ruleActions := 0, 0, 0
	for _, action := range m.actions {
		switch action.Status {
		case StatusAnnouncing, StatusActive, StatusSimulated, StatusWithdrawing:
			live++
			if action.RuleID == "" {
				automatic++
			} else {
				ruleActions++
			}
		}
	}
	if live >= m.opts.MaxActive {
		m.mu.Unlock()
		return nil, ErrCapacity
	}
	if req.RuleID != "" && ruleActions >= m.opts.MaxRules {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: rule action capacity is %d", ErrCapacity, m.opts.MaxRules)
	}
	if req.RuleID == "" && automatic >= m.opts.MaxAutomatic {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: automatic mitigation capacity is %d", ErrCapacity, m.opts.MaxAutomatic)
	}
	id := fmt.Sprintf("mit-%d-%06d", now.Unix(), m.seq.Add(1))
	status := StatusSimulated
	if !m.opts.Simulated {
		status = StatusAnnouncing
	}
	action := &Action{
		ID:           id,
		Kind:         kind,
		Match:        matchFromRequest(req),
		Action:       actionType,
		RateLimitBPS: req.RateLimitBPS,
		Reason:       req.Reason,
		Owner:        req.Owner,
		AlertID:      req.AlertID,
		RuleID:       req.RuleID,
		Permanent:    req.Permanent,
		Status:       status,
		Simulated:    m.opts.Simulated,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
		UpdatedAt:    now,
		DedupKey:     dedupKey,
	}
	if kind == KindRTBH {
		action.Target = netutil.ClampHost(req.Source).String()
		action.Community = m.opts.Community
		action.NextHop = m.opts.NextHop
	} else if req.DestinationPrefix.IsValid() {
		action.Target = req.DestinationPrefix.Masked().String()
	} else {
		action.Target = netutil.ClampHost(req.Destination).String()
	}
	m.actions[id] = action
	m.order = append(m.order, id)
	m.dedup[dedupKey] = dedupEntry{actionID: id, until: dedupUntil(action, now, m.opts.DedupWindow)}
	if m.opts.Simulated {
		// Clone while holding the lock: Tick or WithdrawNow may mutate the
		// shared action immediately after creation.
		snapshot := cloneAction(action)
		m.mu.Unlock()
		return snapshot, nil
	}
	m.opWG.Add(1)
	m.mu.Unlock()
	defer m.opWG.Done()
	announceCtx, cancel := context.WithTimeout(ctx, m.opts.OpTimeout)
	defer cancel()
	if err := m.announce(announceCtx, *action); err != nil {
		m.mu.Lock()
		action.Status = StatusFailed
		action.Error = err.Error()
		action.UpdatedAt = m.clock()
		// Keep failed actions deduplicated for the configured window so a
		// failing BGP peer does not produce a tight retry loop.
		until := m.clock().Add(m.opts.DedupWindow)
		if !action.Permanent && until.Before(action.ExpiresAt) {
			until = action.ExpiresAt
		}
		m.dedup[dedupKey] = dedupEntry{actionID: id, until: until}
		snapshot := cloneAction(action)
		m.mu.Unlock()
		return snapshot, err
	}
	m.mu.Lock()
	action.Status = StatusActive
	action.UpdatedAt = m.clock()
	m.dedup[dedupKey] = dedupEntry{actionID: id, until: dedupUntil(action, m.clock(), m.opts.DedupWindow)}
	snapshot := cloneAction(action)
	m.mu.Unlock()
	return snapshot, nil
}

func dedupUntil(action *Action, now time.Time, _ time.Duration) time.Time {
	if action == nil {
		return now
	}
	if action.Permanent {
		return now.AddDate(100, 0, 0)
	}
	return action.ExpiresAt
}

func cloneAction(action *Action) *Action {
	copy := *action
	return &copy
}

func matchFromRequest(req Request) Match {
	match := Match{
		Protocol:        req.Protocol,
		SrcPort:         req.SrcPort,
		DstPort:         req.DstPort,
		SrcPortMin:      req.SrcPortMin,
		SrcPortMax:      req.SrcPortMax,
		DstPortMin:      req.DstPortMin,
		DstPortMax:      req.DstPortMax,
		TCPFlags:        req.TCPFlags,
		PacketLength:    req.PacketLength,
		PacketLengthMin: req.PacketLengthMin,
		PacketLengthMax: req.PacketLengthMax,
		Fragment:        req.Fragment,
	}
	if req.SourcePrefix.IsValid() {
		match.Source = req.SourcePrefix.Masked().String()
	} else if req.Source.IsValid() {
		match.Source = netutil.ClampHost(req.Source).String()
	}
	if req.DestinationPrefix.IsValid() {
		match.Destination = req.DestinationPrefix.Masked().String()
	} else if req.Destination.IsValid() {
		match.Destination = netutil.ClampHost(req.Destination).String()
	}
	return match
}

func deriveDedupKey(req Request) string {
	src := netutil.AddrString(req.Source)
	if req.SourcePrefix.IsValid() {
		src = req.SourcePrefix.Masked().String()
	}
	dst := netutil.AddrString(req.Destination)
	if req.DestinationPrefix.IsValid() {
		dst = req.DestinationPrefix.Masked().String()
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%t|%s",
		req.Owner, req.Kind, req.RuleID, src, dst, req.Protocol,
		req.SrcPort, req.DstPort, req.SrcPortMin, req.SrcPortMax, req.DstPortMin, req.DstPortMax,
		req.TCPFlags, req.PacketLength, req.PacketLengthMin, req.PacketLengthMax, req.Fragment, req.Action)
}

func (m *Manager) validate(req *Request) error {
	if m.opts.Protected == nil {
		return fmt.Errorf("%w: no protected set configured", ErrInvalid)
	}
	if req.SourcePrefix.IsValid() {
		if req.Source.IsValid() {
			return fmt.Errorf("%w: specify either a source host or source prefix, not both", ErrInvalid)
		}
		prefix, err := normalizeIPv4Prefix(req.SourcePrefix)
		if err != nil {
			return fmt.Errorf("%w: source prefix: %v", ErrInvalid, err)
		}
		if prefix.Bits() == 0 {
			return fmt.Errorf("%w: source prefix must not be a default route", ErrInvalid)
		}
		if m.opts.Protected.Overlaps(prefix) {
			return fmt.Errorf("%w: source prefix %s overlaps the protected network", ErrProtected, prefix)
		}
		req.SourcePrefix = prefix
	}
	if req.Source.IsValid() {
		req.Source = req.Source.Unmap()
		if !req.Source.Is4() {
			return fmt.Errorf("%w: IPv6 mitigation is not supported yet", ErrInvalid)
		}
		if m.opts.Protected.Contains(req.Source) {
			return fmt.Errorf("%w: source %s is inside the protected network", ErrProtected, req.Source)
		}
	}
	if req.DestinationPrefix.IsValid() {
		if req.Destination.IsValid() {
			return fmt.Errorf("%w: specify either a destination host or destination prefix, not both", ErrInvalid)
		}
		prefix, err := normalizeIPv4Prefix(req.DestinationPrefix)
		if err != nil {
			return fmt.Errorf("%w: destination prefix: %v", ErrInvalid, err)
		}
		if prefix.Bits() == 0 {
			return fmt.Errorf("%w: destination prefix must not be a default route", ErrInvalid)
		}
		if !m.opts.Protected.ContainsPrefix(prefix) {
			return fmt.Errorf("%w: destination prefix %s is not fully inside the protected network", ErrProtected, prefix)
		}
		req.DestinationPrefix = prefix
	}
	if req.Destination.IsValid() {
		req.Destination = req.Destination.Unmap()
		if !req.Destination.Is4() {
			return fmt.Errorf("%w: IPv6 mitigation is not supported yet", ErrInvalid)
		}
		if !m.opts.Protected.Contains(req.Destination) {
			return fmt.Errorf("%w: destination %s is not protected", ErrProtected, req.Destination)
		}
	}
	hasSource := req.Source.IsValid() || req.SourcePrefix.IsValid()
	hasDestination := req.Destination.IsValid() || req.DestinationPrefix.IsValid()
	hasPortRange := req.SrcPortMin != 0 || req.SrcPortMax != 0 || req.DstPortMin != 0 || req.DstPortMax != 0
	hasLengthRange := req.PacketLengthMin != 0 || req.PacketLengthMax != 0
	switch req.Kind {
	case KindRTBH:
		if !req.Source.IsValid() {
			return fmt.Errorf("%w: RTBH requires a source host", ErrInvalid)
		}
		if req.SourcePrefix.IsValid() || req.Destination.IsValid() || req.DestinationPrefix.IsValid() || req.Protocol != 0 || req.SrcPort != 0 || req.DstPort != 0 || req.TCPFlags != 0 || req.PacketLength != 0 || hasPortRange || hasLengthRange || req.Fragment {
			return fmt.Errorf("%w: RTBH cannot carry Flowspec match fields", ErrInvalid)
		}
		req.Action = "discard"
		req.RateLimitBPS = 0
		return nil
	case KindFlowspec:
		if !hasDestination {
			return fmt.Errorf("%w: a destination match is required", ErrInvalid)
		}
		if req.SrcPort != 0 && req.SrcPortMin != 0 {
			return fmt.Errorf("%w: source port cannot be both an exact value and a range", ErrInvalid)
		}
		if req.DstPort != 0 && req.DstPortMin != 0 {
			return fmt.Errorf("%w: destination port cannot be both an exact value and a range", ErrInvalid)
		}
		if req.PacketLength != 0 && req.PacketLengthMin != 0 {
			return fmt.Errorf("%w: packet length cannot be both an exact value and a range", ErrInvalid)
		}
		if req.SrcPortMin > req.SrcPortMax && req.SrcPortMax != 0 || req.DstPortMin > req.DstPortMax && req.DstPortMax != 0 || req.PacketLengthMin > req.PacketLengthMax && req.PacketLengthMax != 0 {
			return fmt.Errorf("%w: range minimum must not exceed its maximum", ErrInvalid)
		}
		if req.Protocol == 0 && (req.SrcPort != 0 || req.DstPort != 0 || req.TCPFlags != 0 || hasPortRange) {
			return fmt.Errorf("%w: ports and TCP flags require a protocol match", ErrInvalid)
		}
		if req.Protocol != 6 && req.TCPFlags != 0 {
			return fmt.Errorf("%w: TCP flags require protocol TCP", ErrInvalid)
		}
		if req.Protocol != 6 && req.Protocol != 17 && (req.SrcPort != 0 || req.DstPort != 0 || hasPortRange) {
			return fmt.Errorf("%w: ports are only meaningful for TCP or UDP", ErrInvalid)
		}
		switch req.Action {
		case "discard":
			if !hasSource && !m.opts.AllowDestinationDiscard {
				return fmt.Errorf("%w: destination-only Flowspec may rate-limit but must not discard all traffic to a protected destination", ErrInvalid)
			}
		case "rate-limit":
			if req.RateLimitBPS == 0 {
				if m.opts.RateLimitBPS == 0 {
					return fmt.Errorf("%w: rate-limit action requires a rate", ErrInvalid)
				}
				req.RateLimitBPS = m.opts.RateLimitBPS
			}
		default:
			return fmt.Errorf("%w: action must be discard or rate-limit", ErrInvalid)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalid, req.Kind)
	}
}

func normalizeIPv4Prefix(prefix netip.Prefix) (netip.Prefix, error) {
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, errors.New("invalid IPv4-mapped prefix length")
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
	}
	if !prefix.Addr().Is4() {
		return netip.Prefix{}, errors.New("IPv6 mitigation is not supported yet")
	}
	return prefix, nil
}

func (m *Manager) announce(ctx context.Context, action Action) error {
	if m.opts.Announcer == nil {
		return errors.New("no BGP announcer configured")
	}
	return m.opts.Announcer.Announce(ctx, action)
}

// Tick expires actions and withdraws real announcements. It returns the actions
// whose state changed. The network calls happen outside the manager lock.
func (m *Manager) Tick(ctx context.Context) []Action {
	now := m.clock()
	var toWithdraw []Action
	var changed []Action
	m.mu.Lock()
	if m.shutting {
		m.mu.Unlock()
		return nil
	}
	for _, action := range m.actions {
		if action.Status != StatusActive && action.Status != StatusSimulated {
			continue
		}
		if action.Permanent {
			continue
		}
		if now.Before(action.ExpiresAt) {
			continue
		}
		if action.Simulated {
			action.Status = StatusExpired
			action.WithdrawnAt = now
			action.UpdatedAt = now
			m.clearDedupLocked(action)
			changed = append(changed, *action)
			continue
		}
		action.Status = StatusWithdrawing
		action.UpdatedAt = now
		toWithdraw = append(toWithdraw, *action)
		m.opWG.Add(1)
	}
	m.pruneDedupLocked(now)
	m.mu.Unlock()

	for _, snapshot := range toWithdraw {
		withdrawCtx, cancel := context.WithTimeout(ctx, m.opts.OpTimeout)
		err := m.withdraw(withdrawCtx, snapshot)
		cancel()
		m.mu.Lock()
		action := m.actions[snapshot.ID]
		if action != nil {
			action.UpdatedAt = m.clock()
			if err != nil {
				action.Status = StatusFailed
				action.Error = err.Error()
			} else {
				action.Status = StatusExpired
				action.WithdrawnAt = m.clock()
			}
			m.clearDedupLocked(action)
			changed = append(changed, *action)
		}
		m.mu.Unlock()
		m.opWG.Done()
	}
	m.mu.Lock()
	m.pruneHistoryLocked()
	m.mu.Unlock()
	return changed
}

func (m *Manager) withdraw(ctx context.Context, action Action) error {
	if m.opts.Simulated || action.Simulated {
		return nil
	}
	if m.opts.Announcer == nil {
		return errors.New("no BGP announcer configured")
	}
	return m.opts.Announcer.Withdraw(ctx, action)
}

// clearDedupLocked removes the dedup mapping only if it still belongs to
// action. An old withdrawal can complete after a replacement was created with
// the same dedup key; that completion must not erase the replacement's entry.
func (m *Manager) clearDedupLocked(action *Action) {
	if action == nil {
		return
	}
	if entry, ok := m.dedup[action.DedupKey]; ok && entry.actionID == action.ID {
		delete(m.dedup, action.DedupKey)
	}
}

func (m *Manager) pruneDedupLocked(now time.Time) {
	for key, entry := range m.dedup {
		if !now.Before(entry.until) {
			delete(m.dedup, key)
		}
	}
}

func (m *Manager) pruneHistoryLocked() {
	terminal := 0
	for _, id := range m.order {
		action := m.actions[id]
		if action == nil {
			continue
		}
		switch action.Status {
		case StatusWithdrawn, StatusExpired, StatusFailed:
			terminal++
		}
	}
	if terminal <= m.opts.HistoryLimit {
		return
	}
	remove := terminal - m.opts.HistoryLimit
	kept := m.order[:0]
	for _, id := range m.order {
		action := m.actions[id]
		if action == nil {
			continue
		}
		isTerminal := action.Status == StatusWithdrawn || action.Status == StatusExpired || action.Status == StatusFailed
		if isTerminal && remove > 0 {
			delete(m.actions, id)
			remove--
			continue
		}
		kept = append(kept, id)
	}
	m.order = kept
}

// WithdrawNow manually withdraws an action.
func (m *Manager) WithdrawNow(ctx context.Context, id, reason string) (*Action, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.shutting {
		m.mu.Unlock()
		return nil, ErrShuttingDown
	}
	action := m.actions[id]
	if action == nil {
		m.mu.Unlock()
		return nil, errors.New("mitigation not found")
	}
	switch action.Status {
	case StatusWithdrawn, StatusExpired, StatusFailed:
		copy := *action
		m.mu.Unlock()
		return &copy, nil
	case StatusWithdrawing, StatusAnnouncing:
		m.mu.Unlock()
		return nil, errors.New("mitigation is already changing state")
	}
	if !action.Simulated {
		action.Status = StatusWithdrawing
		m.opWG.Add(1)
	}
	action.UpdatedAt = m.clock()
	snapshot := *action
	m.mu.Unlock()
	if !snapshot.Simulated {
		defer m.opWG.Done()
	}

	if snapshot.Simulated {
		m.mu.Lock()
		action = m.actions[id]
		if action != nil && action.Status == StatusSimulated {
			action.Status = StatusWithdrawn
			action.WithdrawnAt = m.clock()
			action.UpdatedAt = action.WithdrawnAt
			m.clearDedupLocked(action)
		}
		if action != nil {
			snapshot = *action
		}
		m.mu.Unlock()
		return &snapshot, nil
	}

	withdrawCtx, cancel := context.WithTimeout(ctx, m.opts.OpTimeout)
	defer cancel()
	err := m.withdraw(withdrawCtx, snapshot)
	m.mu.Lock()
	defer m.mu.Unlock()
	action = m.actions[id]
	if action == nil {
		return nil, errors.New("mitigation disappeared")
	}
	action.UpdatedAt = m.clock()
	if err != nil {
		action.Status = StatusFailed
		action.Error = err.Error()
		m.clearDedupLocked(action)
		snapshot = *action
		return &snapshot, err
	}
	action.Status = StatusWithdrawn
	action.WithdrawnAt = m.clock()
	action.UpdatedAt = action.WithdrawnAt
	if reason != "" {
		action.Reason += " | withdrawn: " + reason
	}
	m.clearDedupLocked(action)
	snapshot = *action
	return &snapshot, nil
}

// Action returns one action by ID.
func (m *Manager) Action(id string) (*Action, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	action := m.actions[id]
	if action == nil {
		return nil, false
	}
	copy := *action
	return &copy, true
}

// Active returns live actions, newest first.
func (m *Manager) Active() []Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Action
	for _, action := range m.actions {
		switch action.Status {
		case StatusActive, StatusAnnouncing, StatusSimulated, StatusWithdrawing:
			out = append(out, *action)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// History returns recent actions, newest first.
func (m *Manager) History(limit int) []Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Action, 0, len(m.actions))
	for _, action := range m.actions {
		out = append(out, *action)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit <= 0 || limit > len(out) {
		limit = len(out)
	}
	return out[:limit]
}

// Counts summarises the manager.
type Counts struct {
	Live        int `json:"live"`
	Simulated   int `json:"simulated"`
	Active      int `json:"active"`
	Announcing  int `json:"announcing"`
	Failed      int `json:"failed"`
	Withdrawn   int `json:"withdrawn"`
	Expired     int `json:"expired"`
	History     int `json:"history"`
	RuleActions int `json:"rule_actions"`
	Permanent   int `json:"permanent"`
}

func (m *Manager) Counts() Counts {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := Counts{History: len(m.actions)}
	for _, action := range m.actions {
		switch action.Status {
		case StatusSimulated:
			counts.Live++
			counts.Simulated++
		case StatusAnnouncing:
			counts.Live++
			counts.Announcing++
		case StatusActive:
			counts.Live++
			counts.Active++
		case StatusWithdrawing:
			counts.Live++
		case StatusFailed:
			counts.Failed++
		case StatusWithdrawn:
			counts.Withdrawn++
		case StatusExpired:
			counts.Expired++
		}
		if action.RuleID != "" {
			counts.RuleActions++
		}
		if action.Permanent {
			counts.Permanent++
		}
	}
	return counts
}

// Shutdown stops new actions and withdraws active announcements. Simulated
// actions are simply expired.
func (m *Manager) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	m.shutting = true
	m.mu.Unlock()

	// Wait for an announcement or withdrawal that started before shutting was
	// set. Otherwise a shutdown could race an in-flight announce: withdraw the
	// rule first, then let the announce land afterward and leave it installed.
	m.opWG.Wait()

	m.mu.Lock()
	var pending []Action
	for _, action := range m.actions {
		switch action.Status {
		case StatusActive, StatusWithdrawing, StatusAnnouncing:
			action.Status = StatusWithdrawing
			action.UpdatedAt = m.clock()
			pending = append(pending, *action)
		case StatusSimulated:
			action.Status = StatusExpired
			action.WithdrawnAt = m.clock()
			action.UpdatedAt = action.WithdrawnAt
			m.clearDedupLocked(action)
		}
	}
	m.mu.Unlock()
	var errs []error
	for _, snapshot := range pending {
		withdrawCtx, cancel := context.WithTimeout(ctx, m.opts.OpTimeout)
		err := m.withdraw(withdrawCtx, snapshot)
		cancel()
		m.mu.Lock()
		if action := m.actions[snapshot.ID]; action != nil {
			action.UpdatedAt = m.clock()
			if err != nil {
				action.Status = StatusFailed
				action.Error = err.Error()
				errs = append(errs, fmt.Errorf("%s: %w", snapshot.ID, err))
			} else {
				action.Status = StatusWithdrawn
				action.WithdrawnAt = m.clock()
			}
			m.clearDedupLocked(action)
		}
		m.mu.Unlock()
	}
	return errors.Join(errs...)
}

// Snapshot converts config into manager options without exposing the config
// package to callers that already have values.
func OptionsFromConfig(cfg config.MitigationConfig, bgpEnabled bool, protected *netutil.PrefixSet, announcer Announcer, community, nextHop string) Options {
	return Options{
		Protected:    protected,
		Announcer:    announcer,
		Simulated:    !bgpEnabled,
		Duration:     cfg.DefaultDuration.Std(),
		DedupWindow:  cfg.DedupWindow.Std(),
		MaxActive:    cfg.MaxActive,
		HistoryLimit: cfg.HistoryLimit,
		Community:    community,
		NextHop:      nextHop,
		RateLimitBPS: uint64(cfg.RateLimitMbps * 1_000_000),
	}
}
