// Package intel is Dolly Sensor's institutional memory: durable destination
// profiles and per-destination source reputations (TrustScore). It owns no
// detection logic; it accumulates evidence for detectors and operators.
package intel

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"dollysensor/internal/model"
)

const (
	persistenceVersion = 1

	initialTrustCredit = 3.0
	activeDayCredit    = 1.0
	activeDayCreditMax = 20.0
	earnedTrustCeiling = 95.0
	decayPerDay        = 2.0
	defaultForgetAfter = 30 * 24 * time.Hour
	trustHistoryLimit  = 40
)

var (
	// ErrCorruptProfile is returned when the profile file cannot be trusted.
	ErrCorruptProfile = errors.New("corrupt profile file")
)

// Count is a named counter for JSON-friendly snapshots.
type Count struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// PortCount is a port counter for snapshots.
type PortCount struct {
	Port  uint16 `json:"port"`
	Count uint64 `json:"count"`
}

// TTLCount is a TTL counter for snapshots.
type TTLCount struct {
	TTL   uint8  `json:"ttl"`
	Count uint64 `json:"count"`
}

// TrustEvent records one change in a source's trust score.
type TrustEvent struct {
	At     time.Time `json:"at"`
	Delta  float64   `json:"delta"`
	Score  float64   `json:"score"`
	Reason string    `json:"reason"`
	Manual bool      `json:"manual,omitempty"`
}

// Reputation is the durable behaviour of one source toward one destination.
// Detection is stateless: trust is earned from sampled traffic shapes (active
// days, ACK/PSH milestones) rather than from reconstructed connections.
type Reputation struct {
	Source           string            `json:"source"`
	FirstSeen        time.Time         `json:"first_seen"`
	LastSeen         time.Time         `json:"last_seen"`
	ActiveDays       []string          `json:"active_days"`
	LastActiveDay    string            `json:"last_active_day"`
	Protocols        map[string]uint64 `json:"protocols"`
	DstPorts         map[uint16]uint64 `json:"dst_ports"`
	SYN              uint64            `json:"syn"`
	ACK              uint64            `json:"ack"`
	PSHACK           uint64            `json:"psh_ack"`
	PureACK          uint64            `json:"pure_ack"`
	PSH              uint64            `json:"psh"`
	RST              uint64            `json:"rst"`
	FIN              uint64            `json:"fin"`
	Earned           float64           `json:"earned"`
	Manual           bool              `json:"manual"`
	History          []TrustEvent      `json:"history,omitempty"`
	Milestones       map[string]bool   `json:"milestones,omitempty"`
	LastDecayDay     string            `json:"last_decay_day,omitempty"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// Trust returns the effective score: manual trust is always 100, otherwise the
// earned score clamped to a valid range.
func (r *Reputation) Trust() float64 {
	if r == nil {
		return 0
	}
	if r.Manual {
		return 100
	}
	return clamp(r.Earned, 0, 100)
}

// DestinationProfile is the lifetime view of a protected destination.
type DestinationProfile struct {
	Destination    string                 `json:"destination"`
	FirstSeen      time.Time              `json:"first_seen"`
	LastUpdated    time.Time              `json:"last_updated"`
	MaxPPS         float64                `json:"max_pps"`
	MaxBPS         float64                `json:"max_bps"`
	TotalPackets   uint64                 `json:"total_packets"`
	TotalBytes     uint64                 `json:"total_bytes"`
	Protocols      map[string]uint64      `json:"protocols"`
	DestPorts      map[uint16]uint64      `json:"dest_ports"`
	SrcPorts       map[uint16]uint64      `json:"src_ports"`
	TCPFlags       map[string]uint64      `json:"tcp_flags"`
	TTLs           map[uint8]uint64       `json:"ttls"`
	PacketSizeSum  uint64                 `json:"packet_size_sum"`
	PacketSamples  uint64                 `json:"packet_samples"`
	Sources        map[string]*Reputation `json:"sources"`
	SourceOverflow uint64                 `json:"source_overflow,omitempty"`
}

func newProfile(dst netip.Addr, now time.Time) *DestinationProfile {
	return &DestinationProfile{
		Destination: dst.Unmap().String(),
		FirstSeen:   now,
		LastUpdated: now,
		Protocols:   map[string]uint64{},
		DestPorts:   map[uint16]uint64{},
		SrcPorts:    map[uint16]uint64{},
		TCPFlags:    map[string]uint64{},
		TTLs:        map[uint8]uint64{},
		Sources:     map[string]*Reputation{},
	}
}

func (s *Store) addProfileLocked(dst netip.Addr, now time.Time) *DestinationProfile {
	if len(s.profiles) >= s.opts.MaxProfiles {
		evicted := false
		for len(s.profileOrder) > 0 {
			candidate := s.profileOrder[0]
			s.profileOrder = s.profileOrder[1:]
			if _, ok := s.profiles[candidate]; ok {
				delete(s.profiles, candidate)
				evicted = true
				break
			}
		}
		if !evicted {
			for candidate := range s.profiles {
				if candidate != dst {
					delete(s.profiles, candidate)
					break
				}
			}
		}
		s.dirty = true
	}
	profile := newProfile(dst, now)
	s.profiles[dst] = profile
	s.profileOrder = append(s.profileOrder, dst)
	if len(s.profileOrder) > 2*s.opts.MaxProfiles+1024 {
		s.rebuildProfileOrderLocked()
	}
	return profile
}

func (s *Store) rebuildProfileOrderLocked() {
	s.profileOrder = s.profileOrder[:0]
	for dst := range s.profiles {
		s.profileOrder = append(s.profileOrder, dst)
	}
	sort.Slice(s.profileOrder, func(i, j int) bool {
		left := s.profiles[s.profileOrder[i]]
		right := s.profiles[s.profileOrder[j]]
		if left.LastUpdated.Equal(right.LastUpdated) {
			return left.Destination < right.Destination
		}
		return left.LastUpdated.Before(right.LastUpdated)
	})
}

func (s *Store) trimProfilesLocked() {
	s.rebuildProfileOrderLocked()
	for len(s.profiles) > s.opts.MaxProfiles && len(s.profileOrder) > 0 {
		oldest := s.profileOrder[0]
		s.profileOrder = s.profileOrder[1:]
		delete(s.profiles, oldest)
	}
}

// Options bounds retained memory and controls decay.
type Options struct {
	MaxProfiles              int
	MaxSourcesPerDestination int
	MaxPortEntries           int
	ForgetAfter              time.Duration
	HistoryLimit             int
}

func defaultOptions() Options {
	return Options{
		MaxProfiles:              10000,
		MaxSourcesPerDestination: 10000,
		MaxPortEntries:           4096,
		ForgetAfter:              defaultForgetAfter,
		HistoryLimit:             trustHistoryLimit,
	}
}

// Store is the concurrent profile and reputation store.
type Store struct {
	mu           sync.Mutex
	saveMu       sync.Mutex
	path         string
	profiles     map[netip.Addr]*DestinationProfile
	profileOrder []netip.Addr
	opts         Options
	dirty        bool
	lastSave     time.Time
	saveErr      string
}

type persistenceFile struct {
	Version  int                            `json:"version"`
	SavedAt  time.Time                      `json:"saved_at"`
	Profiles map[string]*DestinationProfile `json:"profiles"`
}

// Open loads (or creates) a profile store. A missing file is not an error.
func Open(path string, opts Options) (*Store, error) {
	defaults := defaultOptions()
	if opts.MaxProfiles <= 0 {
		opts.MaxProfiles = defaults.MaxProfiles
	}
	if opts.MaxSourcesPerDestination <= 0 {
		opts.MaxSourcesPerDestination = defaults.MaxSourcesPerDestination
	}
	if opts.MaxPortEntries <= 0 {
		opts.MaxPortEntries = defaults.MaxPortEntries
	}
	if opts.ForgetAfter <= 0 {
		opts.ForgetAfter = defaults.ForgetAfter
	}
	if opts.HistoryLimit <= 0 {
		opts.HistoryLimit = defaults.HistoryLimit
	}
	s := &Store{
		path:     path,
		profiles: make(map[netip.Addr]*DestinationProfile),
		opts:     opts,
	}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read profiles: %w", err)
	}
	var file persistenceFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptProfile, err)
	}
	if file.Version != persistenceVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrCorruptProfile, file.Version)
	}
	for key, profile := range file.Profiles {
		addr, err := netip.ParseAddr(key)
		if err != nil || profile == nil {
			continue
		}
		normaliseProfile(profile, addr, opts)
		s.profiles[addr.Unmap()] = profile
	}
	s.trimProfilesLocked()
	return s, nil
}

func normaliseProfile(profile *DestinationProfile, addr netip.Addr, opts Options) {
	if profile.Destination == "" {
		profile.Destination = addr.Unmap().String()
	}
	if profile.Protocols == nil {
		profile.Protocols = map[string]uint64{}
	}
	if profile.DestPorts == nil {
		profile.DestPorts = map[uint16]uint64{}
	}
	if profile.SrcPorts == nil {
		profile.SrcPorts = map[uint16]uint64{}
	}
	if profile.TCPFlags == nil {
		profile.TCPFlags = map[string]uint64{}
	}
	if profile.TTLs == nil {
		profile.TTLs = map[uint8]uint64{}
	}
	if profile.Sources == nil {
		profile.Sources = map[string]*Reputation{}
	}
	for key, rep := range profile.Sources {
		if rep == nil {
			delete(profile.Sources, key)
			continue
		}
		if rep.Source == "" {
			rep.Source = key
		}
		if rep.Protocols == nil {
			rep.Protocols = map[string]uint64{}
		}
		if rep.DstPorts == nil {
			rep.DstPorts = map[uint16]uint64{}
		}
		if rep.Milestones == nil {
			rep.Milestones = map[string]bool{}
		}
		if rep.Earned < 0 {
			rep.Earned = 0
		}
		if rep.Earned > earnedTrustCeiling {
			rep.Earned = earnedTrustCeiling
		}
		if len(rep.History) > opts.HistoryLimit {
			rep.History = rep.History[len(rep.History)-opts.HistoryLimit:]
		}
	}
	if len(profile.Sources) > opts.MaxSourcesPerDestination {
		// Keep the most recently active sources when loading an oversized file.
		type pair struct {
			key string
			at  time.Time
		}
		pairs := make([]pair, 0, len(profile.Sources))
		for key, rep := range profile.Sources {
			pairs = append(pairs, pair{key, rep.LastSeen})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].at.After(pairs[j].at) })
		for index := opts.MaxSourcesPerDestination; index < len(pairs); index++ {
			delete(profile.Sources, pairs[index].key)
		}
	}
}

// Observe adds one observation to the destination profile and its source
// reputation. It should be called exactly once per accepted observation.
func (s *Store) Observe(obs model.Observation) {
	if !obs.DstProtected || !obs.DstIP.IsValid() {
		return
	}
	dst := obs.DstIP.Unmap()
	now := obs.ReceivedAt
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile := s.profiles[dst]
	if profile == nil {
		profile = s.addProfileLocked(dst, now)
		s.dirty = true
	}
	profile.LastUpdated = now
	profile.TotalPackets += obs.EstimatedPackets
	profile.TotalBytes += obs.EstimatedBytes
	if size := uint64(obs.PacketSize); size > 0 {
		profile.PacketSizeSum += size
		profile.PacketSamples++
	}
	protocol := strings.ToUpper(obs.ProtocolName)
	if protocol == "" {
		protocol = model.ProtocolName(obs.Protocol)
	}
	increment(profile.Protocols, protocol, 0)
	if obs.DstPort != 0 {
		increment(profile.DestPorts, obs.DstPort, s.opts.MaxPortEntries)
	}
	if obs.SrcPort != 0 {
		increment(profile.SrcPorts, obs.SrcPort, s.opts.MaxPortEntries)
	}
	if obs.Protocol == 6 {
		increment(profile.TCPFlags, obs.TCPFlags.String(), 0)
	}
	if obs.TTL > 0 {
		increment(profile.TTLs, obs.TTL, 0)
	}

	source := obs.SrcIP.Unmap().String()
	rep := profile.Sources[source]
	if rep == nil {
		if len(profile.Sources) >= s.opts.MaxSourcesPerDestination {
			profile.SourceOverflow++
			s.dirty = true
			return
		}
		rep = newReputation(source, now)
		rep.ActiveDays = append(rep.ActiveDays, dayString(now))
		rep.LastActiveDay = dayString(now)
		rep.Earned = clamp(rep.Earned+initialTrustCredit, 0, earnedTrustCeiling)
		profile.Sources[source] = rep
		s.addHistoryLocked(rep, now, initialTrustCredit, "first observed")
	}
	if rep.LastSeen.IsZero() || now.After(rep.LastSeen) {
		rep.LastSeen = now
	}
	rep.UpdatedAt = now
	rep.SYN += boolToUint(obs.TCPFlags.Has(model.TCPSYN))
	rep.ACK += boolToUint(obs.TCPFlags.Has(model.TCPACK))
	// PSH-ACK vs pure-ACK: the receiver-vs-sender rhythm of a healthy
	// conversation. A source that only ever pushes data (PSH-ACK) and never
	// acknowledges (pure ACK) is a one-way blast, not a conversation.
	rep.PSHACK += boolToUint(obs.TCPFlags.Has(model.TCPPSH) && obs.TCPFlags.Has(model.TCPACK))
	rep.PureACK += boolToUint(obs.TCPFlags.Has(model.TCPACK) && !obs.TCPFlags.Has(model.TCPPSH))
	rep.PSH += boolToUint(obs.TCPFlags.Has(model.TCPPSH))
	rep.RST += boolToUint(obs.TCPFlags.Has(model.TCPRST))
	rep.FIN += boolToUint(obs.TCPFlags.Has(model.TCPFIN))
	increment(rep.Protocols, protocol, 0)
	if obs.DstPort != 0 {
		increment(rep.DstPorts, obs.DstPort, s.opts.MaxPortEntries)
	}
	today := dayString(now)
	if today != rep.LastActiveDay {
		rep.LastActiveDay = today
		rep.ActiveDays = append(rep.ActiveDays, today)
		if len(rep.ActiveDays) > 60 {
			rep.ActiveDays = rep.ActiveDays[len(rep.ActiveDays)-60:]
		}
		activeCredits := float64(len(rep.ActiveDays))
		if activeCredits <= activeDayCreditMax/activeDayCredit {
			s.creditLocked(rep, now, activeDayCredit, "active on a new day")
		}
	}
	s.applyMilestonesLocked(rep, now)
	s.dirty = true
}

func newReputation(source string, now time.Time) *Reputation {
	return &Reputation{
		Source:     source,
		FirstSeen:  now,
		LastSeen:   now,
		ActiveDays: nil,
		Protocols:  map[string]uint64{},
		DstPorts:   map[uint16]uint64{},
		Milestones: map[string]bool{},
		UpdatedAt:  now,
	}
}

func (s *Store) applyMilestonesLocked(rep *Reputation, now time.Time) {
	type milestone struct {
		key    string
		value  uint64
		delta  float64
		reason string
	}
	milestones := []milestone{
		{"ack:100", rep.ACK, 2, "100 sampled ACKs"},
		{"ack:1000", rep.ACK, 3, "1,000 sampled ACKs"},
		{"ack:10000", rep.ACK, 4, "10,000 sampled ACKs"},
		{"ack:100000", rep.ACK, 5, "100,000 sampled ACKs"},
		{"psh:100", rep.PSH, 2, "100 sampled PSH packets"},
		{"psh:1000", rep.PSH, 3, "1,000 sampled PSH packets"},
		{"psh:10000", rep.PSH, 4, "10,000 sampled PSH packets"},
	}
	for _, m := range milestones {
		if rep.Milestones[m.key] || m.value < thresholdFromKey(m.key) {
			continue
		}
		rep.Milestones[m.key] = true
		s.creditLocked(rep, now, m.delta, m.reason)
	}
}

func thresholdFromKey(key string) uint64 {
	switch key {
	case "ack:100", "psh:100":
		return 100
	case "ack:1000", "psh:1000":
		return 1000
	case "ack:10000", "psh:10000":
		return 10000
	case "ack:100000":
		return 100000
	default:
		return math.MaxUint64
	}
}

func (s *Store) ensureReputationLocked(dst, src netip.Addr, at time.Time) *Reputation {
	if !dst.IsValid() || !src.IsValid() {
		return nil
	}
	dst = dst.Unmap()
	profile := s.profiles[dst]
	if profile == nil {
		profile = newProfile(dst, at)
		s.profiles[dst] = profile
	}
	key := src.Unmap().String()
	rep := profile.Sources[key]
	if rep == nil {
		rep = newReputation(key, at)
		rep.ActiveDays = []string{dayString(at)}
		rep.LastActiveDay = dayString(at)
		rep.Earned = clamp(rep.Earned+initialTrustCredit, 0, earnedTrustCeiling)
		profile.Sources[key] = rep
		s.addHistoryLocked(rep, at, initialTrustCredit, "first observed")
	}
	if rep.LastSeen.IsZero() || at.After(rep.LastSeen) {
		rep.LastSeen = at
	}
	rep.UpdatedAt = at
	return rep
}

func (s *Store) creditLocked(rep *Reputation, at time.Time, delta float64, reason string) {
	if rep.Manual || delta == 0 {
		return
	}
	before := rep.Earned
	rep.Earned = clamp(rep.Earned+delta, 0, earnedTrustCeiling)
	actual := rep.Earned - before
	if actual == 0 {
		return
	}
	s.addHistoryLocked(rep, at, actual, reason)
}

func (s *Store) addHistoryLocked(rep *Reputation, at time.Time, delta float64, reason string) {
	rep.History = append(rep.History, TrustEvent{
		At:     at,
		Delta:  delta,
		Score:  rep.Trust(),
		Reason: reason,
	})
	if len(rep.History) > s.opts.HistoryLimit {
		rep.History = rep.History[len(rep.History)-s.opts.HistoryLimit:]
	}
}

func (s *Store) addManualHistoryLocked(rep *Reputation, at time.Time, delta float64, reason string) {
	rep.History = append(rep.History, TrustEvent{
		At:     at,
		Delta:  delta,
		Score:  rep.Trust(),
		Reason: reason,
		Manual: true,
	})
	if len(rep.History) > s.opts.HistoryLimit {
		rep.History = rep.History[len(rep.History)-s.opts.HistoryLimit:]
	}
}

// SetTrust sets or revokes manual trust for a source toward one destination.
func (s *Store) SetTrust(dst, src netip.Addr, trusted bool, at time.Time) error {
	if !dst.IsValid() || !src.IsValid() {
		return errors.New("destination and source must be valid IP addresses")
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := s.ensureReputationLocked(dst, src, at)
	if rep == nil {
		return errors.New("could not create reputation")
	}
	if trusted {
		if rep.Manual {
			return nil
		}
		rep.Manual = true
		s.addManualHistoryLocked(rep, at, 100-rep.Trust(), "manual trust")
	} else {
		if !rep.Manual {
			return nil
		}
		rep.Manual = false
		s.addManualHistoryLocked(rep, at, rep.Trust()-100, "manual trust revoked")
	}
	rep.UpdatedAt = at
	s.dirty = true
	return nil
}

// Decay applies slow inactivity penalties, at most once per UTC day per source.
func (s *Store) Decay(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	today := dayString(now)
	removedProfile := false
	for dst, profile := range s.profiles {
		for key, rep := range profile.Sources {
			if rep.Manual {
				continue
			}
			if now.Sub(rep.LastSeen) < 24*time.Hour {
				continue
			}
			if rep.LastDecayDay == today {
				continue
			}
			rep.LastDecayDay = today
			before := rep.Earned
			rep.Earned = clamp(rep.Earned-decayPerDay, 0, earnedTrustCeiling)
			if rep.Earned != before {
				s.addHistoryLocked(rep, now, rep.Earned-before, "inactive for a day")
				s.dirty = true
			}
			if rep.Earned == 0 && now.Sub(rep.LastSeen) > s.opts.ForgetAfter {
				delete(profile.Sources, key)
				s.dirty = true
			}
		}
		if len(profile.Sources) == 0 && now.Sub(profile.LastUpdated) > s.opts.ForgetAfter {
			delete(s.profiles, dst)
			removedProfile = true
			s.dirty = true
		}
	}
	if removedProfile || len(s.profileOrder) > 2*s.opts.MaxProfiles+1024 {
		s.rebuildProfileOrderLocked()
	}
}

// RecordRates updates lifetime maxima for a destination.
func (s *Store) RecordRates(dst netip.Addr, pps, bps float64) {
	if !dst.IsValid() {
		return
	}
	dst = dst.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	profile := s.profiles[dst]
	if profile == nil {
		return
	}
	if pps > profile.MaxPPS {
		profile.MaxPPS = pps
		s.dirty = true
	}
	if bps > profile.MaxBPS {
		profile.MaxBPS = bps
		s.dirty = true
	}
}

// TrustScore returns the effective trust for dst/src.
func (s *Store) TrustScore(dst, src netip.Addr) float64 {
	if !dst.IsValid() || !src.IsValid() {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile := s.profiles[dst.Unmap()]
	if profile == nil {
		return 0
	}
	rep := profile.Sources[src.Unmap().String()]
	return rep.Trust()
}

// SourceSummary returns the sampled counters used by detection.
func (s *Store) SourceSummary(dst, src netip.Addr) (syn, ack, pshAck, pureAck uint64, trust float64, manual bool) {
	if !dst.IsValid() || !src.IsValid() {
		return 0, 0, 0, 0, 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile := s.profiles[dst.Unmap()]
	if profile == nil {
		return
	}
	rep := profile.Sources[src.Unmap().String()]
	if rep == nil {
		return
	}
	return rep.SYN, rep.ACK, rep.PSHACK, rep.PureACK, rep.Trust(), rep.Manual
}

func increment[K comparable](m map[K]uint64, key K, max int) {
	if _, exists := m[key]; !exists && max > 0 && len(m) >= max {
		return
	}
	m[key]++
}

func boolToUint(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func clamp(value, low, high float64) float64 {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

func dayString(t time.Time) string {
	return t.UTC().Format("2006-01-02")
}

// Save writes the profile store atomically. Snapshot encoding happens under the
// state lock, but the potentially slow filesystem work does not. Observations
// that arrive during a save stay dirty and are written by the next round.
func (s *Store) Save(force bool) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.Lock()
	if !force && !s.dirty {
		s.mu.Unlock()
		return nil
	}
	if s.path == "" {
		s.mu.Unlock()
		return nil
	}
	file := persistenceFile{
		Version:  persistenceVersion,
		SavedAt:  time.Now().UTC(),
		Profiles: make(map[string]*DestinationProfile, len(s.profiles)),
	}
	for addr, profile := range s.profiles {
		file.Profiles[addr.String()] = profile
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		s.saveErr = err.Error()
		s.mu.Unlock()
		return fmt.Errorf("encode profiles: %w", err)
	}
	s.dirty = false
	s.mu.Unlock()

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return s.failSave(fmt.Errorf("create profile directory: %w", err))
	}
	temp, err := os.CreateTemp(dir, ".profiles-*.tmp")
	if err != nil {
		return s.failSave(err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return s.failSave(err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return s.failSave(err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return s.failSave(err)
	}
	if err := temp.Close(); err != nil {
		return s.failSave(err)
	}
	if err := os.Rename(tempName, s.path); err != nil {
		return s.failSave(err)
	}
	s.mu.Lock()
	s.lastSave = time.Now()
	s.saveErr = ""
	s.mu.Unlock()
	return nil
}

func (s *Store) failSave(err error) error {
	s.mu.Lock()
	s.dirty = true
	s.saveErr = err.Error()
	s.mu.Unlock()
	return err
}

// SaveState reports the outcome of the last persistence attempt.
type SaveState struct {
	LastSave time.Time `json:"last_save"`
	Error    string    `json:"error,omitempty"`
	Path     string    `json:"path"`
	Profiles int       `json:"profiles"`
}

func (s *Store) SaveState() SaveState {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(s.profiles)
	return SaveState{LastSave: s.lastSave, Error: s.saveErr, Path: s.path, Profiles: count}
}
