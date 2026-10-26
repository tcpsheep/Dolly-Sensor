package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dollysensor/internal/model"
	"dollysensor/internal/netutil"
)

const persistenceVersion = 1

// Options configures the rule store and evaluator.
type Options struct {
	Path                    string
	Protected               *netutil.PrefixSet
	MaxRules                int
	MaxFlowsPerRule         int
	AllowDestinationDiscard bool
	Disabled                bool
	DefaultRateLimitBPS     uint64
	DefaultDuration         time.Duration
	FlowTTL                 time.Duration
	Logger                  *slog.Logger
}

// Store is the persistent rule catalog and the sampled observation evaluator.
// It is safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	saveMu  sync.Mutex
	clockMu sync.RWMutex
	opts    Options
	rules   map[string]*Rule
	order   []string
	runtime map[string]*runtime
	now     func() time.Time

	lastSave time.Time
	saveErr  string
	dropped  atomic.Uint64
}

type persistenceFile struct {
	Version int       `json:"version"`
	SavedAt time.Time `json:"saved_at"`
	Rules   []Rule    `json:"rules"`
}

// Open loads the rule file. A missing file is an empty catalog. Corrupt or
// invalid definitions are rejected rather than silently ignored.
func Open(opts Options, logger *slog.Logger) (*Store, error) {
	if opts.MaxRules <= 0 {
		opts.MaxRules = 128
	}
	if opts.MaxFlowsPerRule <= 0 {
		opts.MaxFlowsPerRule = 8192
	}
	if opts.DefaultDuration <= 0 {
		opts.DefaultDuration = time.Minute
	}
	if opts.FlowTTL <= 0 {
		opts.FlowTTL = 10 * time.Minute
	}
	if logger == nil {
		logger = slog.Default()
	}
	opts.Logger = logger
	s := &Store{
		opts:    opts,
		rules:   map[string]*Rule{},
		runtime: map[string]*runtime{},
		now:     time.Now,
	}
	if strings.TrimSpace(opts.Path) == "" {
		return s, nil
	}
	data, err := os.ReadFile(opts.Path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var file persistenceFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", opts.Path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("rules file contains trailing JSON data")
		}
		return nil, fmt.Errorf("parse rules %s: %w", opts.Path, err)
	}
	if file.Version != persistenceVersion {
		return nil, fmt.Errorf("rules file version %d is not supported", file.Version)
	}
	if len(file.Rules) > opts.MaxRules {
		return nil, fmt.Errorf("rules file contains %d rules; maximum is %d", len(file.Rules), opts.MaxRules)
	}
	seen := map[string]bool{}
	for i := range file.Rules {
		rule := file.Rules[i]
		if strings.TrimSpace(rule.ID) == "" {
			return nil, fmt.Errorf("rules file entry %d has no id", i)
		}
		if seen[rule.ID] {
			return nil, fmt.Errorf("rules file contains duplicate id %q", rule.ID)
		}
		seen[rule.ID] = true
		storedStats := rule.Stats
		if err := normalizeAndValidate(&rule, opts); err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		if rule.CreatedAt.IsZero() {
			rule.CreatedAt = s.clock()
		}
		if rule.UpdatedAt.IsZero() {
			rule.UpdatedAt = rule.CreatedAt
		}
		storedStats.State = ""
		storedStats.ActionID = ""
		storedStats.ActionStatus = ""
		storedStats.LastError = ""
		rule.Stats = storedStats
		copy := rule
		s.rules[rule.ID] = &copy
		s.order = append(s.order, rule.ID)
		s.runtime[rule.ID] = newRuntime(rule.Stats)
	}
	return s, nil
}

// SetClock is used by tests.
func (s *Store) SetClock(now func() time.Time) {
	if now == nil {
		return
	}
	s.clockMu.Lock()
	s.now = now
	s.clockMu.Unlock()
}

func (s *Store) clock() time.Time {
	s.clockMu.RLock()
	now := s.now
	s.clockMu.RUnlock()
	if now == nil {
		return time.Now()
	}
	return now()
}

// Disabled reports whether evaluation and standing enforcement are disabled.
func (s *Store) Disabled() bool { return s.opts.Disabled }

// Options returns the effective options.
func (s *Store) Options() Options { return s.opts }

// Path returns the rule file path.
func (s *Store) Path() string { return s.opts.Path }

// Create adds one rule. The input ID, timestamps, and stats are ignored.
func (s *Store) Create(input Rule) (Rule, error) {
	input.ID = ""
	input.CreatedAt = time.Time{}
	input.UpdatedAt = time.Time{}
	input.Stats = Stats{}
	if err := normalizeAndValidate(&input, s.opts); err != nil {
		return Rule{}, err
	}
	now := s.clock()
	input.ID = newID(now)
	input.CreatedAt = now
	input.UpdatedAt = now
	copy := input

	s.mu.Lock()
	if len(s.rules) >= s.opts.MaxRules {
		s.mu.Unlock()
		return Rule{}, fmt.Errorf("%w: maximum is %d", ErrCapacity, s.opts.MaxRules)
	}
	for s.rules[copy.ID] != nil {
		copy.ID = newID(now)
	}
	s.rules[copy.ID] = &copy
	s.order = append(s.order, copy.ID)
	s.runtime[copy.ID] = newRuntime(Stats{})
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		s.remove(copy.ID)
		return Rule{}, err
	}
	return s.Get(copy.ID)
}

// Update replaces one rule while preserving its creation time and counters.
func (s *Store) Update(id string, input Rule) (Rule, error) {
	id = strings.TrimSpace(id)
	input.ID = ""
	input.CreatedAt = time.Time{}
	input.UpdatedAt = time.Time{}
	input.Stats = Stats{}
	if err := normalizeAndValidate(&input, s.opts); err != nil {
		return Rule{}, err
	}
	now := s.clock()

	s.mu.Lock()
	old := s.rules[id]
	if old == nil {
		s.mu.Unlock()
		return Rule{}, ErrNotFound
	}
	input.ID = id
	input.CreatedAt = old.CreatedAt
	input.UpdatedAt = now
	copy := input
	s.rules[id] = &copy
	if rt := s.runtime[id]; rt != nil {
		rt.resetForRuleChange(now)
	} else {
		s.runtime[id] = newRuntime(Stats{})
	}
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		s.mu.Lock()
		if current := s.rules[id]; current != nil {
			s.rules[id] = old
		}
		s.mu.Unlock()
		return Rule{}, err
	}
	return s.Get(id)
}

// SetEnabled toggles one rule.
func (s *Store) SetEnabled(id string, enabled bool) (Rule, error) {
	rule, ok := s.GetDefinition(id)
	if !ok {
		return Rule{}, ErrNotFound
	}
	rule.Enabled = enabled
	return s.Update(id, rule)
}

// Reorder applies a new absolute order for the full catalog. Every existing
// rule id must be present exactly once; the slice defines the new evaluation
// order from first (highest priority) to last.
func (s *Store) Reorder(ids []string) ([]Rule, error) {
	trimmed := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return nil, fmt.Errorf("%w: order contains an empty or duplicate id", ErrInvalid)
		}
		seen[id] = true
		trimmed = append(trimmed, id)
	}

	s.mu.Lock()
	if len(trimmed) != len(s.rules) {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: order must include every rule exactly once", ErrInvalid)
	}
	for _, id := range trimmed {
		if s.rules[id] == nil {
			s.mu.Unlock()
			return nil, fmt.Errorf("%w: unknown rule id %s", ErrInvalid, id)
		}
	}
	s.order = append([]string(nil), trimmed...)
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		return nil, err
	}
	return s.List(), nil
}

// MoveRule moves one rule to a new zero-based position in the evaluation
// order. Positions outside the catalog are clamped.
func (s *Store) MoveRule(id string, position int) ([]Rule, error) {
	s.mu.RLock()
	total := len(s.order)
	exists := s.rules[strings.TrimSpace(id)] != nil
	s.mu.RUnlock()
	if !exists {
		return nil, ErrNotFound
	}
	if position < 0 {
		position = 0
	}
	if position > total-1 {
		position = total - 1
	}
	order := make([]string, 0, total)
	for _, existing := range s.orderedIDs() {
		if existing == id {
			continue
		}
		order = append(order, existing)
	}
	next := make([]string, 0, total)
	next = append(next, order[:position]...)
	next = append(next, id)
	next = append(next, order[position:]...)
	return s.Reorder(next)
}

// orderedIDs returns a copy of the current evaluation order.
func (s *Store) orderedIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.order...)
}

// Delete removes a rule.
func (s *Store) Delete(id string) (Rule, error) {
	id = strings.TrimSpace(id)
	s.mu.Lock()
	rule := s.rules[id]
	if rule == nil {
		s.mu.Unlock()
		return Rule{}, ErrNotFound
	}
	index := -1
	for i, existing := range s.order {
		if existing == id {
			index = i
			break
		}
	}
	snapshot := s.viewLocked(rule)
	delete(s.rules, id)
	delete(s.runtime, id)
	if index >= 0 {
		s.order = append(s.order[:index], s.order[index+1:]...)
	}
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		s.mu.Lock()
		s.rules[id] = rule
		if index >= 0 {
			s.order = append(s.order, "")
			copy(s.order[index+1:], s.order[index:])
			s.order[index] = id
		} else {
			s.order = append(s.order, id)
		}
		s.runtime[id] = newRuntime(snapshot.Stats)
		s.mu.Unlock()
		return Rule{}, err
	}
	return snapshot, nil
}

func (s *Store) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rules, id)
	delete(s.runtime, id)
	for i, existing := range s.order {
		if existing == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// Get returns one rule with current runtime stats.
func (s *Store) Get(id string) (Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rule := s.rules[strings.TrimSpace(id)]
	if rule == nil {
		return Rule{}, ErrNotFound
	}
	return s.viewLocked(rule), nil
}

// GetDefinition returns the persisted rule definition without runtime stats.
func (s *Store) GetDefinition(id string) (Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rule := s.rules[strings.TrimSpace(id)]
	if rule == nil {
		return Rule{}, false
	}
	copy := *rule
	return copy, true
}

// Enabled reports whether a rule exists and is enabled.
func (s *Store) Enabled(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rule := s.rules[strings.TrimSpace(id)]
	return rule != nil && rule.Enabled
}

// List returns every rule in evaluation order (highest priority first).
func (s *Store) List() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, 0, len(s.order))
	for _, id := range s.order {
		if rule := s.rules[id]; rule != nil {
			out = append(out, s.viewLocked(rule))
		}
	}
	return out
}

// EnabledStandingRules returns enabled standing rules for enforcement.
func (s *Store) EnabledStandingRules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, 0)
	for _, id := range s.order {
		rule := s.rules[id]
		if rule == nil || !rule.Enabled || rule.Mode != ModeStanding {
			continue
		}
		out = append(out, s.viewLocked(rule))
	}
	return out
}

// Summary aggregates the catalog.
func (s *Store) Summary() Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := Summary{Total: len(s.rules), DroppedObservations: s.dropped.Load()}
	for _, rule := range s.rules {
		if rule.Enabled {
			out.Enabled++
		}
		switch rule.Mode {
		case ModeStanding:
			out.Standing++
		case ModeConditional:
			out.Conditional++
		}
		if rule.Action.Type == ActionAllow {
			out.Allow++
		}
		stats := Stats{}
		if rt := s.runtime[rule.ID]; rt != nil {
			stats = rt.snapshot(rule, s.clock())
		}
		if stats.LastError != "" || stats.ActionStatus == "failed" {
			out.Errors++
		}
		out.Hits += stats.Hits
		out.Triggers += stats.Triggers
		out.Suppressed += stats.Suppressed
	}
	return out
}

// Limits returns the configured hard bounds.
func (s *Store) Limits() Limits {
	return Limits{
		MaxRules:                s.opts.MaxRules,
		MaxFlowsPerRule:         s.opts.MaxFlowsPerRule,
		AllowDestinationDiscard: s.opts.AllowDestinationDiscard,
	}
}

// Defaults returns effective fallback values.
func (s *Store) Defaults() Defaults {
	return Defaults{
		RateLimitBPS:    s.opts.DefaultRateLimitBPS,
		DurationSeconds: int(s.opts.DefaultDuration / time.Second),
		FlowTTLSeconds:  int(s.opts.FlowTTL / time.Second),
	}
}

// NoteDroppedObservation records a sample that could not be evaluated because
// the bounded evaluator queue was full.
func (s *Store) NoteDroppedObservation() { s.dropped.Add(1) }

// viewLocked returns a copy with runtime stats. The caller must hold at least a
// read lock.
func (s *Store) viewLocked(rule *Rule) Rule {
	copy := *rule
	copy.Stats = Stats{}
	if rt := s.runtime[rule.ID]; rt != nil {
		copy.Stats = rt.snapshot(rule, s.clock())
	}
	return copy
}

// Save writes the catalog and stats atomically. Slow filesystem work happens
// outside the catalog lock.
func (s *Store) Save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if strings.TrimSpace(s.opts.Path) == "" {
		return nil
	}

	s.mu.RLock()
	file := persistenceFile{
		Version: persistenceVersion,
		SavedAt: time.Now().UTC(),
		Rules:   make([]Rule, 0, len(s.order)),
	}
	now := s.clock()
	for _, id := range s.order {
		rule := s.rules[id]
		if rule == nil {
			continue
		}
		copy := *rule
		copy.Stats = Stats{}
		if rt := s.runtime[id]; rt != nil {
			copy.Stats = rt.snapshot(rule, now)
		}
		// Transient state is reconstructed from live mitigations on startup.
		copy.Stats.State = ""
		copy.Stats.ActionID = ""
		copy.Stats.ActionStatus = ""
		copy.Stats.LastError = ""
		file.Rules = append(file.Rules, copy)
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		s.setSaveError(err)
		return fmt.Errorf("encode rules: %w", err)
	}
	dir := filepath.Dir(s.opts.Path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		s.setSaveError(err)
		return fmt.Errorf("create rules directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".rules-*.tmp")
	if err != nil {
		s.setSaveError(err)
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		s.setSaveError(err)
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		s.setSaveError(err)
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		s.setSaveError(err)
		return err
	}
	if err := temp.Close(); err != nil {
		s.setSaveError(err)
		return err
	}
	if err := os.Rename(tempName, s.opts.Path); err != nil {
		s.setSaveError(err)
		return err
	}
	s.mu.Lock()
	s.lastSave = time.Now()
	s.saveErr = ""
	s.mu.Unlock()
	return nil
}

func (s *Store) setSaveError(err error) {
	s.mu.Lock()
	s.saveErr = err.Error()
	s.mu.Unlock()
}

// SaveState describes persistence health.
type SaveState struct {
	LastSave time.Time `json:"last_save"`
	Error    string    `json:"error,omitempty"`
	Path     string    `json:"path"`
	Rules    int       `json:"rules"`
}

// SaveState returns the last persistence outcome.
func (s *Store) SaveState() SaveState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return SaveState{
		LastSave: s.lastSave,
		Error:    s.saveErr,
		Path:     s.opts.Path,
		Rules:    len(s.rules),
	}
}

// SortForDisplay is used by tests and callers that need a stable name order.
func SortForDisplay(rules []Rule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Name != rules[j].Name {
			return rules[i].Name < rules[j].Name
		}
		return rules[i].ID < rules[j].ID
	})
}

// Preview evaluates a draft policy against recent observations in
// chronological order. It never announces or mutates a live rule.
func (s *Store) Preview(input Rule, observations []model.Observation) (PreviewResult, error) {
	input.ID = "preview"
	input.CreatedAt = time.Time{}
	input.UpdatedAt = time.Time{}
	input.Stats = Stats{}
	if err := normalizeAndValidate(&input, s.opts); err != nil {
		return PreviewResult{}, err
	}
	result := PreviewResult{
		Samples: make([]model.Observation, 0, 10),
		Warning: "Preview uses sampled observations already in the bounded packet ring. It does not replay every packet on the wire and cannot prove first-N behaviour.",
	}
	flows := map[string]*previewFlow{}
	var first, last time.Time
	for _, obs := range observations {
		if !input.Match.matches(obs, input.compiled) {
			continue
		}
		if input.Condition.Payload.Mode == PayloadAbsentN || input.Condition.Payload.Mode == PayloadPresentN {
			key := flowKey(obs)
			flow := flows[key]
			if flow == nil {
				flow = &previewFlow{}
				flows[key] = flow
			}
			flow.seen++
			found := input.compiled.payload != nil && input.compiled.payload.matches(obs.Payload)
			if found {
				flow.found = true
			}
			switch input.Condition.Payload.Mode {
			case PayloadAbsentN:
				if flow.seen >= input.Condition.Payload.FirstN && !flow.found && !flow.resolved {
					flow.resolved = true
					flow.wouldTrigger = true
				}
				if flow.found {
					flow.resolved = true
				}
			case PayloadPresentN:
				if found && flow.seen <= input.Condition.Payload.FirstN && !flow.resolved {
					flow.resolved = true
					flow.wouldTrigger = true
				}
				if flow.seen >= input.Condition.Payload.FirstN {
					flow.resolved = true
				}
			}
			result.Matched++
			result.EstimatedPackets += obs.EstimatedPackets
			result.EstimatedBytes += obs.EstimatedBytes
			if first.IsZero() || obs.ReceivedAt.Before(first) {
				first = obs.ReceivedAt
			}
			if obs.ReceivedAt.After(last) {
				last = obs.ReceivedAt
			}
			if len(result.Samples) < 10 {
				result.Samples = append(result.Samples, obs.Clone())
			}
			continue
		}
		if input.Condition.Payload.Mode == PayloadContains {
			if input.compiled.payload == nil || !input.compiled.payload.matches(obs.Payload) {
				continue
			}
		}
		result.Matched++
		result.EstimatedPackets += obs.EstimatedPackets
		result.EstimatedBytes += obs.EstimatedBytes
		if first.IsZero() || obs.ReceivedAt.Before(first) {
			first = obs.ReceivedAt
		}
		if obs.ReceivedAt.After(last) {
			last = obs.ReceivedAt
		}
		if len(result.Samples) < 10 {
			result.Samples = append(result.Samples, obs.Clone())
		}
	}
	result.Flows = len(flows)
	for _, flow := range flows {
		if flow.wouldTrigger {
			result.PotentialTriggers++
		}
	}
	if !first.IsZero() && !last.IsZero() && last.After(first) {
		seconds := last.Sub(first).Seconds()
		if seconds < 1 {
			seconds = 1
		}
		result.EquivalentPPS = float64(result.EstimatedPackets) / seconds
		result.EquivalentBPS = float64(result.EstimatedBytes) * 8 / seconds
	}
	return result, nil
}

type previewFlow struct {
	seen         int
	found        bool
	resolved     bool
	wouldTrigger bool
}
