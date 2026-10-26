package intel

import (
	"net/netip"
	"sort"
	"time"
)

// DestinationSummary is the table-row view of a destination profile.
type DestinationSummary struct {
	Destination   string      `json:"destination"`
	FirstSeen     time.Time   `json:"first_seen"`
	LastUpdated   time.Time   `json:"last_updated"`
	MaxPPS        float64     `json:"max_pps"`
	MaxBPS        float64     `json:"max_bps"`
	TotalPackets  uint64      `json:"total_packets"`
	TotalBytes    uint64      `json:"total_bytes"`
	AvgPacketSize float64     `json:"avg_packet_size"`
	SourceCount   int         `json:"source_count"`
	TrustedCount  int         `json:"trusted_count"`
	TopProtocols  []Count     `json:"top_protocols"`
	TopPorts      []PortCount `json:"top_ports"`
	DominantTTL   uint8       `json:"dominant_ttl"`
}

// DestinationDetail is the deep view of one destination.
type DestinationDetail struct {
	DestinationSummary
	Protocols      []Count          `json:"protocols"`
	DestPorts      []PortCount      `json:"dest_ports"`
	SrcPorts       []PortCount      `json:"src_ports"`
	TCPFlags       []Count          `json:"tcp_flags"`
	TTLs           []TTLCount       `json:"ttls"`
	Sources        []SourceSnapshot `json:"sources"`
	SourceOverflow uint64           `json:"source_overflow"`
}

// SourceSnapshot is a read-only reputation record.
type SourceSnapshot struct {
	Source     string       `json:"source"`
	Trust      float64      `json:"trust"`
	Manual     bool         `json:"manual"`
	FirstSeen  time.Time    `json:"first_seen"`
	LastSeen   time.Time    `json:"last_seen"`
	ActiveDays int          `json:"active_days"`
	Handshakes uint64       `json:"handshakes"`
	SYN        uint64       `json:"syn"`
	ACK        uint64       `json:"ack"`
	PSH        uint64       `json:"psh"`
	Protocols  []Count      `json:"protocols"`
	Ports      []PortCount  `json:"ports"`
	History    []TrustEvent `json:"history"`
}

// TrustedSource is one manual trust decision, for the operator's whitelist
// view. It always carries its destination: trust is contextual.
type TrustedSource struct {
	Destination string       `json:"destination"`
	Source      string       `json:"source"`
	Trust       float64      `json:"trust"`
	Manual      bool         `json:"manual"`
	FirstSeen   time.Time    `json:"first_seen"`
	LastSeen    time.Time    `json:"last_seen"`
	ActiveDays  int          `json:"active_days"`
	Handshakes  uint64       `json:"handshakes"`
	History     []TrustEvent `json:"history"`
}

// ReputationSummary is a flattened reputation for the intelligence view.
type ReputationSummary struct {
	Destination string    `json:"destination"`
	Source      string    `json:"source"`
	Trust       float64   `json:"trust"`
	Manual      bool      `json:"manual"`
	LastSeen    time.Time `json:"last_seen"`
	Handshakes  uint64    `json:"handshakes"`
	SYN         uint64    `json:"syn"`
	ACK         uint64    `json:"ack"`
}

// Summary returns the table-row summary of dst.
func (s *Store) Summary(dst netip.Addr) (DestinationSummary, bool) {
	if !dst.IsValid() {
		return DestinationSummary{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile := s.profiles[dst.Unmap()]
	if profile == nil {
		return DestinationSummary{}, false
	}
	return summaryLocked(profile), true
}

// Summaries returns every destination profile summary.
func (s *Store) Summaries() []DestinationSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]DestinationSummary, 0, len(s.profiles))
	for _, profile := range s.profiles {
		out = append(out, summaryLocked(profile))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastUpdated.Equal(out[j].LastUpdated) {
			return out[i].Destination < out[j].Destination
		}
		return out[i].LastUpdated.After(out[j].LastUpdated)
	})
	return out
}

func summaryLocked(profile *DestinationProfile) DestinationSummary {
	summary := DestinationSummary{
		Destination:  profile.Destination,
		FirstSeen:    profile.FirstSeen,
		LastUpdated:  profile.LastUpdated,
		MaxPPS:       profile.MaxPPS,
		MaxBPS:       profile.MaxBPS,
		TotalPackets: profile.TotalPackets,
		TotalBytes:   profile.TotalBytes,
		SourceCount:  len(profile.Sources),
		TopProtocols: topCounts(profile.Protocols, 3),
		TopPorts:     topPorts(profile.DestPorts, 3),
		DominantTTL:  dominantTTL(profile.TTLs),
	}
	if profile.PacketSamples > 0 {
		summary.AvgPacketSize = float64(profile.PacketSizeSum) / float64(profile.PacketSamples)
	}
	for _, rep := range profile.Sources {
		if rep.Manual {
			summary.TrustedCount++
		}
	}
	return summary
}

// Detail returns a deep copy of one destination profile.
func (s *Store) Detail(dst netip.Addr, sourceLimit int) (DestinationDetail, bool) {
	if !dst.IsValid() {
		return DestinationDetail{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile := s.profiles[dst.Unmap()]
	if profile == nil {
		return DestinationDetail{}, false
	}
	detail := DestinationDetail{
		DestinationSummary: summaryLocked(profile),
		Protocols:          topCounts(profile.Protocols, 0),
		DestPorts:          topPorts(profile.DestPorts, 0),
		SrcPorts:           topPorts(profile.SrcPorts, 0),
		TCPFlags:           topCounts(profile.TCPFlags, 0),
		TTLs:               ttlCounts(profile.TTLs),
		Sources:            sourceSnapshots(profile.Sources, sourceLimit),
		SourceOverflow:     profile.SourceOverflow,
	}
	if sourceLimit <= 0 || sourceLimit > len(detail.Sources) {
		sourceLimit = len(detail.Sources)
	}
	return detail, true
}

func sourceSnapshots(sources map[string]*Reputation, limit int) []SourceSnapshot {
	out := make([]SourceSnapshot, 0, len(sources))
	for _, rep := range sources {
		history := append([]TrustEvent(nil), rep.History...)
		if len(history) > 12 {
			history = history[len(history)-12:]
		}
		out = append(out, SourceSnapshot{
			Source:     rep.Source,
			Trust:      rep.Trust(),
			Manual:     rep.Manual,
			FirstSeen:  rep.FirstSeen,
			LastSeen:   rep.LastSeen,
			ActiveDays: len(rep.ActiveDays),
			Handshakes: rep.Handshakes,
			SYN:        rep.SYN,
			ACK:        rep.ACK,
			PSH:        rep.PSH,
			Protocols:  topCounts(rep.Protocols, 3),
			Ports:      topPorts(rep.DstPorts, 3),
			History:    history,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].Source < out[j].Source
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ManualTrust returns every manually trusted source.
func (s *Store) ManualTrust() []TrustedSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []TrustedSource
	for _, profile := range s.profiles {
		for _, rep := range profile.Sources {
			if !rep.Manual {
				continue
			}
			out = append(out, TrustedSource{
				Destination: profile.Destination,
				Source:      rep.Source,
				Trust:       rep.Trust(),
				Manual:      true,
				FirstSeen:   rep.FirstSeen,
				LastSeen:    rep.LastSeen,
				ActiveDays:  len(rep.ActiveDays),
				Handshakes:  rep.Handshakes,
				History:     append([]TrustEvent(nil), rep.History...),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Destination == out[j].Destination {
			return out[i].Source < out[j].Source
		}
		return out[i].Destination < out[j].Destination
	})
	return out
}

// Reputations returns source reputations, highest trust first.
func (s *Store) Reputations(limit int) []ReputationSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ReputationSummary, 0)
	for _, profile := range s.profiles {
		for _, rep := range profile.Sources {
			out = append(out, ReputationSummary{
				Destination: profile.Destination,
				Source:      rep.Source,
				Trust:       rep.Trust(),
				Manual:      rep.Manual,
				LastSeen:    rep.LastSeen,
				Handshakes:  rep.Handshakes,
				SYN:         rep.SYN,
				ACK:         rep.ACK,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Trust == out[j].Trust {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Trust > out[j].Trust
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Count returns the number of durable destination profiles.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.profiles)
}

// DestinationIPs returns the destinations currently present in the store.
func (s *Store) DestinationIPs() []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]netip.Addr, 0, len(s.profiles))
	for addr := range s.profiles {
		out = append(out, addr)
	}
	return out
}

func topCounts(values map[string]uint64, limit int) []Count {
	out := make([]Count, 0, len(values))
	for name, count := range values {
		out = append(out, Count{Name: name, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func topPorts(values map[uint16]uint64, limit int) []PortCount {
	out := make([]PortCount, 0, len(values))
	for port, count := range values {
		out = append(out, PortCount{Port: port, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Port < out[j].Port
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func ttlCounts(values map[uint8]uint64) []TTLCount {
	out := make([]TTLCount, 0, len(values))
	for ttl, count := range values {
		out = append(out, TTLCount{TTL: ttl, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].TTL < out[j].TTL
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func dominantTTL(values map[uint8]uint64) uint8 {
	var best uint8
	var bestCount uint64
	for ttl, count := range values {
		if count > bestCount {
			bestCount = count
			best = ttl
		}
	}
	return best
}
