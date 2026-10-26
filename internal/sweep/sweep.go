// Package sweep tracks cross-destination behaviour that per-destination
// scoring cannot see: one external source touching many protected IPs
// (carpet bombing, subnet scanning) and per-source TTL entropy. Like the rest
// of the sensor it is stateless evidence over a short rolling window, not a
// connection table.
package sweep

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"dollysensor/internal/model"
)

const (
	rotateEvery    = 15 * time.Second
	maxSources     = 4096
	maxDestsPerSrc = 512
	maxTTLDistinct = 256
	snapshotRows   = 100
)

// SourceSweep is the merged recent view of one source's cross-destination
// behaviour.
type SourceSweep struct {
	Source            string     `json:"source"`
	SourceAddr        netip.Addr `json:"-"`
	Packets           uint64     `json:"packets"`
	Distinct          int        `json:"distinct_destinations"`
	DestOverflow      uint64     `json:"dest_overflow,omitempty"`
	DistinctTTLs      int        `json:"distinct_ttls"`
	LowTTLs           uint64     `json:"low_ttls,omitempty"` // packets with TTL <= 1
	TargetPrefix      string     `json:"target_prefix,omitempty"`
	TargetPrefixHits  int        `json:"target_prefix_hits,omitempty"`
	TopDestinations   []string   `json:"top_destinations,omitempty"`
}

type sourceState struct {
	packets      uint64
	dests        map[netip.Addr]uint64
	destOverflow uint64
	ttls         map[uint8]uint64
	lowTTLs      uint64
}

// Tracker is safe for concurrent use.
type Tracker struct {
	mu         sync.Mutex
	prefixBits int
	sources    map[netip.Addr]*sourceState
	previous   map[netip.Addr]*sourceState
	lastRotate time.Time
	untracked  uint64
}

// New creates a sweep tracker. prefixBits is the aggregation prefix used to
// report a source's most-sprayed subnet (24 means IPv4 /24).
func New(prefixBits int) *Tracker {
	if prefixBits < 8 || prefixBits > 128 {
		prefixBits = 24
	}
	return &Tracker{
		prefixBits: prefixBits,
		sources:    map[netip.Addr]*sourceState{},
		previous:   map[netip.Addr]*sourceState{},
	}
}

// SetPrefixBits changes the aggregation prefix used for target reporting.
func (t *Tracker) SetPrefixBits(bits int) {
	if bits < 8 || bits > 128 {
		return
	}
	t.mu.Lock()
	t.prefixBits = bits
	t.mu.Unlock()
}

// Observe records one inbound observation toward a protected destination.
func (t *Tracker) Observe(obs model.Observation, now time.Time) {
	if !obs.DstProtected || !obs.SrcIP.IsValid() || !obs.DstIP.IsValid() {
		return
	}
	src := obs.SrcIP.Unmap()
	dst := obs.DstIP.Unmap()
	packets := obs.EstimatedPackets
	if packets == 0 {
		packets = 1
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rotateLocked(now)
	state := t.sources[src]
	if state == nil {
		if len(t.sources) >= maxSources {
			// A flood with more distinct sources than the cap cannot be a
			// single-source carpet bomb; the per-destination detector owns it.
			t.untracked += packets
			return
		}
		state = &sourceState{
			dests: map[netip.Addr]uint64{},
			ttls:  map[uint8]uint64{},
		}
		t.sources[src] = state
	}
	state.packets += packets
	if _, exists := state.dests[dst]; exists || len(state.dests) < maxDestsPerSrc {
		state.dests[dst] += packets
	} else {
		state.destOverflow += packets
	}
	if obs.Protocol == 6 || obs.Protocol == 17 || obs.Protocol == 1 {
		if obs.TTL > 0 {
			if len(state.ttls) < maxTTLDistinct {
				state.ttls[obs.TTL] += packets
			} else if _, exists := state.ttls[obs.TTL]; exists {
				state.ttls[obs.TTL] += packets
			}
		} else if obs.TTL == 0 {
			state.lowTTLs += packets
		}
		if obs.TTL == 1 {
			state.lowTTLs += packets
		}
	}
}

func (t *Tracker) rotateLocked(now time.Time) {
	if now.Sub(t.lastRotate) < rotateEvery {
		return
	}
	// Keep the previous generation so the merged view covers ~30 seconds,
	// matching the aggregate package's recent-window semantics.
	t.previous = t.sources
	t.sources = map[netip.Addr]*sourceState{}
	t.lastRotate = now
}

// Snapshot returns the merged cross-destination view of every source that
// touched at least two destinations, most spread first. Untracked volume is
// reported separately.
func (t *Tracker) Snapshot(now time.Time) ([]SourceSweep, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rotateLocked(now)
	merged := t.mergeLocked()
	out := make([]SourceSweep, 0, 64)
	for src, state := range merged {
		if len(state.dests) < 2 {
			continue
		}
		out = append(out, t.buildRow(src, state))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Distinct != out[j].Distinct {
			return out[i].Distinct > out[j].Distinct
		}
		if out[i].Packets != out[j].Packets {
			return out[i].Packets > out[j].Packets
		}
		return out[i].Source < out[j].Source
	})
	if len(out) > snapshotRows {
		out = out[:snapshotRows]
	}
	return out, t.untracked
}

// TTLRows returns sources whose recent packets carried at least minDistinct
// distinct TTL values with at least minPackets packets, regardless of how many
// destinations they touched. Single-destination floods randomise TTLs too.
func (t *Tracker) TTLRows(now time.Time, minDistinct int, minPackets uint64) []SourceSweep {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rotateLocked(now)
	merged := t.mergeLocked()
	out := make([]SourceSweep, 0, 16)
	for src, state := range merged {
		if len(state.ttls) < minDistinct || state.packets < minPackets {
			continue
		}
		out = append(out, t.buildRow(src, state))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DistinctTTLs != out[j].DistinctTTLs {
			return out[i].DistinctTTLs > out[j].DistinctTTLs
		}
		if out[i].Packets != out[j].Packets {
			return out[i].Packets > out[j].Packets
		}
		return out[i].Source < out[j].Source
	})
	if len(out) > snapshotRows {
		out = out[:snapshotRows]
	}
	return out
}

func (t *Tracker) mergeLocked() map[netip.Addr]*sourceState {
	merged := make(map[netip.Addr]*sourceState, len(t.sources))
	for _, generation := range []map[netip.Addr]*sourceState{t.previous, t.sources} {
		for src, state := range generation {
			out := merged[src]
			if out == nil {
				clone := *state
				clone.dests = make(map[netip.Addr]uint64, len(state.dests))
				clone.ttls = make(map[uint8]uint64, len(state.ttls))
				for k, v := range state.dests {
					clone.dests[k] = v
				}
				for k, v := range state.ttls {
					clone.ttls[k] = v
				}
				merged[src] = &clone
				continue
			}
			out.packets += state.packets
			out.destOverflow += state.destOverflow
			out.lowTTLs += state.lowTTLs
			for dst, count := range state.dests {
				if _, exists := out.dests[dst]; exists || len(out.dests) < maxDestsPerSrc {
					out.dests[dst] += count
				} else {
					out.destOverflow += count
				}
			}
			for ttl, count := range state.ttls {
				out.ttls[ttl] += count
			}
		}
	}
	return merged
}

func (t *Tracker) buildRow(src netip.Addr, state *sourceState) SourceSweep {
	row := SourceSweep{
		Source:       src.String(),
		SourceAddr:   src,
		Packets:      state.packets,
		Distinct:     len(state.dests),
		DestOverflow: state.destOverflow,
		DistinctTTLs: len(state.ttls),
		LowTTLs:      state.lowTTLs,
	}
	if state.destOverflow > 0 {
		// The map is capped, so the real count is unknown but larger.
		row.Distinct = maxDestsPerSrc
	}
	row.TargetPrefix, row.TargetPrefixHits = t.topPrefix(state.dests)
	row.TopDestinations = topDestinations(state.dests, 5)
	return row
}

func (t *Tracker) topPrefix(dests map[netip.Addr]uint64) (string, int) {
	counts := map[string]int{}
	var best string
	bestHits := 0
	for dst := range dests {
		bits := t.prefixBits
		if bits > dst.BitLen() {
			bits = dst.BitLen()
		}
		prefix := netip.PrefixFrom(dst, bits).Masked()
		key := prefix.String()
		counts[key]++
		if counts[key] > bestHits {
			bestHits = counts[key]
			best = key
		}
	}
	return best, bestHits
}

func topDestinations(dests map[netip.Addr]uint64, limit int) []string {
	type pair struct {
		dst   netip.Addr
		count uint64
	}
	pairs := make([]pair, 0, len(dests))
	for dst, count := range dests {
		pairs = append(pairs, pair{dst: dst, count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].dst.String() < pairs[j].dst.String()
	})
	if len(pairs) > limit {
		pairs = pairs[:limit]
	}
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.dst.String())
	}
	return out
}

