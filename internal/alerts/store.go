// Package alerts stores the operator's recent unit of work: deduplicated,
// explainable alert records.
package alerts

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity guides attention and, indirectly, action.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Alert is a recorded decision with a story.
type Alert struct {
	ID            string    `json:"id"`
	Time          time.Time `json:"time"`
	UpdatedAt     time.Time `json:"updated_at"`
	Severity      Severity  `json:"severity"`
	Type          string    `json:"type"`
	Layer         string    `json:"layer,omitempty"`
	Destination   string    `json:"destination,omitempty"`
	Source        string    `json:"source,omitempty"`
	Score         float64   `json:"score,omitempty"`
	Reason        string    `json:"reason"`
	Signals       []string  `json:"signals,omitempty"`
	Occurrences   int       `json:"occurrences"`
	ActionID      string    `json:"action_id,omitempty"`
	ActionStatus  string    `json:"action_status,omitempty"`
	ActionSummary string    `json:"action_summary,omitempty"`
}

// Candidate is a proposed alert before deduplication.
type Candidate struct {
	Key         string
	Severity    Severity
	Type        string
	Layer       string
	Destination string
	Source      string
	Score       float64
	Reason      string
	Signals     []string
}

// Stats summarises stored alerts.
type Stats struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
}

type dedupRef struct {
	alertID string
	until   time.Time
}

// Store holds a bounded alert history and deduplication state.
type Store struct {
	mu       sync.Mutex
	capacity int
	cooldown time.Duration
	alerts   map[string]*Alert
	order    []string
	dedup    map[string]dedupRef
	seq      uint64
}

// New creates an alert store. capacity is a hard bound on retained history.
func New(capacity int, cooldown time.Duration) *Store {
	if capacity < 1 {
		capacity = 500
	}
	if cooldown < 0 {
		cooldown = 0
	}
	return &Store{
		capacity: capacity,
		cooldown: cooldown,
		alerts:   make(map[string]*Alert),
		dedup:    make(map[string]dedupRef),
	}
}

// Record stores or coalesces an alert. It returns the resulting alert, whether
// a new record was created, and whether this observation upgraded the record to
// critical. Callers use the last flag to notify on severity escalation without
// notifying on every repeated occurrence.
func (s *Store) Record(c Candidate, now time.Time) (Alert, bool, bool) {
	if now.IsZero() {
		now = time.Now()
	}
	if c.Severity == "" {
		c.Severity = SeverityWarning
	}
	if c.Reason == "" {
		c.Reason = "unspecified"
	}
	key := c.Key
	if key == "" {
		key = strings.Join([]string{c.Type, c.Destination, c.Source}, "|")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ref, ok := s.dedup[key]; ok && now.Before(ref.until) {
		if alert := s.alerts[ref.alertID]; alert != nil {
			alert.UpdatedAt = now
			alert.Occurrences++
			if c.Score > alert.Score {
				alert.Score = c.Score
			}
			if c.Reason != "" {
				alert.Reason = c.Reason
			}
			// Keep the latest evidence rather than accumulating a new snapshot of
			// dynamic measurements on every re-observation. The latter would grow
			// without bound for the lifetime of the dedup window.
			previous := alert.Severity
			alert.Signals = dedupe(c.Signals)
			alert.Severity = maxSeverity(alert.Severity, c.Severity)
			upgraded := previous != SeverityCritical && alert.Severity == SeverityCritical
			copy := clone(*alert)
			return copy, false, upgraded
		}
	}
	s.seq++
	id := fmt.Sprintf("alert-%d-%06d", now.Unix(), s.seq)
	alert := &Alert{
		ID:          id,
		Time:        now,
		UpdatedAt:   now,
		Severity:    c.Severity,
		Type:        c.Type,
		Layer:       c.Layer,
		Destination: c.Destination,
		Source:      c.Source,
		Score:       c.Score,
		Reason:      c.Reason,
		Signals:     dedupe(c.Signals),
		Occurrences: 1,
	}
	s.alerts[id] = alert
	s.order = append(s.order, id)
	if s.cooldown > 0 {
		s.dedup[key] = dedupRef{alertID: id, until: now.Add(s.cooldown)}
	}
	for len(s.order) > s.capacity {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.alerts, oldest)
	}
	// Dedup entries for evicted alerts can never coalesce again. Drop them even
	// while their cooldown is live so a flood of unique keys cannot grow this map
	// without bound.
	s.pruneDedupLocked(now)
	return clone(*alert), true, false
}

// AttachAction links an alert to a mitigation outcome.
func (s *Store) AttachAction(id, actionID, status, summary string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert := s.alerts[id]
	if alert == nil {
		return
	}
	alert.ActionID = actionID
	alert.ActionStatus = status
	alert.ActionSummary = summary
	alert.UpdatedAt = time.Now()
}

// ActionFailed records a mitigation failure on the alert.
func (s *Store) ActionFailed(id, errText string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert := s.alerts[id]
	if alert == nil {
		return
	}
	alert.ActionStatus = "failed"
	alert.ActionSummary = errText
	alert.UpdatedAt = time.Now()
}

// Get returns one alert by ID.
func (s *Store) Get(id string) (Alert, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alert := s.alerts[id]
	if alert == nil {
		return Alert{}, false
	}
	return clone(*alert), true
}

// Snapshot returns alerts newest first. Empty severity means all severities.
func (s *Store) Snapshot(limit int, severity Severity) []Alert {
	if limit < 0 {
		limit = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	capacity := len(s.alerts)
	if limit > 0 && limit < capacity {
		capacity = limit
	}
	out := make([]Alert, 0, capacity)
	for index := len(s.order) - 1; index >= 0; index-- {
		alert := s.alerts[s.order[index]]
		if alert == nil {
			continue
		}
		if severity != "" && alert.Severity != severity {
			continue
		}
		out = append(out, clone(*alert))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// Stats returns counts of retained alerts.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := Stats{}
	for _, alert := range s.alerts {
		stats.Total++
		switch alert.Severity {
		case SeverityCritical:
			stats.Critical++
		case SeverityWarning:
			stats.Warning++
		default:
			stats.Info++
		}
	}
	return stats
}

func (s *Store) pruneDedupLocked(now time.Time) {
	for key, ref := range s.dedup {
		if !now.Before(ref.until) || s.alerts[ref.alertID] == nil {
			delete(s.dedup, key)
		}
	}
}

func clone(alert Alert) Alert {
	alert.Signals = append([]string(nil), alert.Signals...)
	return alert
}

func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func maxSeverity(a, b Severity) Severity {
	rank := func(value Severity) int {
		switch value {
		case SeverityCritical:
			return 3
		case SeverityWarning:
			return 2
		default:
			return 1
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}
