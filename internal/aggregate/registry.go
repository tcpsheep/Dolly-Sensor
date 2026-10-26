// Package aggregate keeps bounded hot state for protected destinations:
// sampling-corrected rates, recent source/port/protocol distributions, and a
// short history for the dashboard. Durable facts live in package intel.
package aggregate

import (
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"

	"dollysensor/internal/model"
)

const (
	shardCount   = 32
	rateSlots    = 64
	historySlots = 180
	rotateEvery  = 15 * time.Second

	maxSources   = 512
	maxProtocols = 64
	maxPorts     = 512
	maxFlags     = 32
)

// Count is a named counter.
type Count struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

// PortCount is a port counter.
type PortCount struct {
	Port  uint16 `json:"port"`
	Count uint64 `json:"count"`
}

// TTLCount is a TTL counter.
type TTLCount struct {
	TTL   uint8  `json:"ttl"`
	Count uint64 `json:"count"`
}

// SourceCount is a source address and its estimated packet count.
type SourceCount struct {
	Source     string     `json:"source"`
	SourceAddr netip.Addr `json:"-"`
	Count      uint64     `json:"count"`
}

// SizeBucket counts packets by size.
type SizeBucket struct {
	Label string `json:"label"`
	Count uint64 `json:"count"`
}

// Recent is the merged distribution for the last 15-30 seconds.
type Recent struct {
	Packets        uint64        `json:"packets"`
	Bytes          uint64        `json:"bytes"`
	Samples        uint64        `json:"samples"`
	AvgPacketSize  float64       `json:"avg_packet_size"`
	Malformed      uint64        `json:"malformed"`
	Sources        []SourceCount `json:"sources"`
	SourceCount    int           `json:"source_count"`
	SourceOverflow uint64        `json:"source_overflow"`
	Protocols      []Count       `json:"protocols"`
	DestPorts      []PortCount   `json:"dest_ports"`
	SrcPorts       []PortCount   `json:"src_ports"`
	TCPFlags       []Count       `json:"tcp_flags"`
	TTLs           []TTLCount    `json:"ttls"`
	SizeBuckets    []SizeBucket  `json:"size_buckets"`
}

// HistoryPoint is one evaluation sample for the destination chart.
type HistoryPoint struct {
	At     time.Time `json:"at"`
	PPS    float64   `json:"pps"`
	BPS    float64   `json:"bps"`
	Threat float64   `json:"threat"`
}

// DestSnapshot is a consistent read-only view of one destination.
type DestSnapshot struct {
	Destination string         `json:"destination"`
	Addr        netip.Addr     `json:"-"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	PPS         float64        `json:"pps"`
	BPS         float64        `json:"bps"`
	CurrentPPS  float64        `json:"current_pps"`
	CurrentBPS  float64        `json:"current_bps"`
	Recent      Recent         `json:"recent"`
	History     []HistoryPoint `json:"history"`
}

// Point is one second of global protected traffic.
type Point struct {
	At  time.Time `json:"at"`
	PPS float64   `json:"pps"`
	BPS float64   `json:"bps"`
}

// GlobalStats summarises all protected traffic.
type GlobalStats struct {
	PPS          float64 `json:"pps"`
	BPS          float64 `json:"bps"`
	TotalPackets uint64  `json:"total_packets"`
	TotalBytes   uint64  `json:"total_bytes"`
	Series       []Point `json:"series"`
	Destinations int     `json:"destinations"`
}

type shard struct {
	mu    sync.Mutex
	dests map[netip.Addr]*destState
}

// Registry is the sharded hot-state registry.
type Registry struct {
	shards [shardCount]shard

	globalMu     sync.Mutex
	global       [300]globalBucket
	totalPackets uint64
	totalBytes   uint64
	started      time.Time
}

type globalBucket struct {
	second  int64
	packets uint64
	bytes   uint64
}

type rateBucket struct {
	second  int64
	packets uint64
	bytes   uint64
}

type window struct {
	packets        uint64
	bytes          uint64
	samples        uint64
	sizeSum        uint64
	malformed      uint64
	sources        map[netip.Addr]uint64
	protocols      map[string]uint64
	destPorts      map[uint16]uint64
	srcPorts       map[uint16]uint64
	flags          map[string]uint64
	ttls           map[uint8]uint64
	sizes          [6]uint64
	sourceOverflow uint64
}

type destState struct {
	firstSeen  time.Time
	lastSeen   time.Time
	rates      [rateSlots]rateBucket
	recent     window
	previous   window
	lastRotate time.Time
	history    [historySlots]HistoryPoint
	historyAt  int
	historyN   int
}

// New creates an empty registry.
func New() *Registry {
	r := &Registry{started: time.Now()}
	for i := range r.shards {
		r.shards[i].dests = make(map[netip.Addr]*destState)
	}
	return r
}

// Observe records protected-destination traffic.
func (r *Registry) Observe(obs model.Observation, now time.Time) {
	if !obs.DstIP.IsValid() || !obs.DstProtected {
		return
	}
	dst := obs.DstIP.Unmap()
	packets := obs.EstimatedPackets
	if packets == 0 {
		packets = 1
	}
	bytes := obs.EstimatedBytes
	if bytes == 0 {
		bytes = uint64(obs.PacketSize) * packets
	}
	r.globalMu.Lock()
	r.totalPackets += packets
	r.totalBytes += bytes
	second := now.Unix()
	index := int(second % int64(len(r.global)))
	if r.global[index].second != second {
		r.global[index] = globalBucket{second: second}
	}
	r.global[index].packets += packets
	r.global[index].bytes += bytes
	r.globalMu.Unlock()

	sh := &r.shards[shardIndex(dst)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	state := sh.dests[dst]
	if state == nil {
		state = &destState{firstSeen: now, lastRotate: now, recent: allocateWindow()}
		sh.dests[dst] = state
	}
	state.lastSeen = now
	idx := int(second % int64(len(state.rates)))
	if state.rates[idx].second != second {
		state.rates[idx] = rateBucket{second: second}
	}
	state.rates[idx].packets += packets
	state.rates[idx].bytes += bytes
	if now.Sub(state.lastRotate) >= rotateEvery {
		state.previous = state.recent
		state.recent = allocateWindow()
		state.lastRotate = now
	}
	addToWindow(&state.recent, obs, packets, bytes)
}

func shardIndex(addr netip.Addr) int {
	// FNV-1a over the address bytes is overkill; taking low bytes is stable and
	// adequately distributed for a fixed 32-way shard count.
	bytes := addr.As16()
	var value uint32
	for i := 12; i < 16; i++ {
		value = value*31 + uint32(bytes[i])
	}
	return int(value % shardCount)
}

func addToWindow(w *window, obs model.Observation, packets, bytes uint64) {
	w.packets += packets
	w.bytes += bytes
	w.samples++
	size := uint64(obs.PacketSize)
	w.sizeSum += size * packets
	w.sizes[sizeBucket(size)] += packets
	if obs.Malformed() {
		w.malformed += packets
	}
	protocol := obs.ProtocolName
	if protocol == "" {
		protocol = model.ProtocolName(obs.Protocol)
	}
	addCap(w.protocols, protocol, packets, maxProtocols)
	if obs.DstPort != 0 {
		addCap(w.destPorts, obs.DstPort, packets, maxPorts)
	}
	if obs.SrcPort != 0 {
		addCap(w.srcPorts, obs.SrcPort, packets, maxPorts)
	}
	if obs.Protocol == 6 {
		addCap(w.flags, obs.TCPFlags.String(), packets, maxFlags)
	}
	if obs.TTL > 0 {
		addCap(w.ttls, obs.TTL, packets, 0)
	}
	if obs.SrcIP.IsValid() {
		src := obs.SrcIP.Unmap()
		if _, exists := w.sources[src]; exists || len(w.sources) < maxSources {
			w.sources[src] += packets
		} else {
			w.sourceOverflow += packets
		}
	}
}

func addCap[K comparable](m map[K]uint64, key K, value uint64, cap int) {
	if m == nil {
		return
	}
	if _, exists := m[key]; exists || cap <= 0 || len(m) < cap {
		m[key] += value
	}
}

func allocateWindow() window {
	return window{
		sources:   map[netip.Addr]uint64{},
		protocols: map[string]uint64{},
		destPorts: map[uint16]uint64{},
		srcPorts:  map[uint16]uint64{},
		flags:     map[string]uint64{},
		ttls:      map[uint8]uint64{},
	}
}

func mergeWindows(target *window, source window) {
	target.packets += source.packets
	target.bytes += source.bytes
	target.samples += source.samples
	target.sizeSum += source.sizeSum
	target.malformed += source.malformed
	target.sourceOverflow += source.sourceOverflow
	for i := range target.sizes {
		target.sizes[i] += source.sizes[i]
	}
	for key, value := range source.sources {
		if _, exists := target.sources[key]; exists || len(target.sources) < maxSources {
			target.sources[key] += value
		} else {
			target.sourceOverflow += value
		}
	}
	for key, value := range source.protocols {
		addBoundedMap(target.protocols, key, value, maxProtocols)
	}
	for key, value := range source.destPorts {
		addBoundedMap(target.destPorts, key, value, maxPorts)
	}
	for key, value := range source.srcPorts {
		addBoundedMap(target.srcPorts, key, value, maxPorts)
	}
	for key, value := range source.flags {
		addBoundedMap(target.flags, key, value, maxFlags)
	}
	for key, value := range source.ttls {
		target.ttls[key] += value
	}
}

func addBoundedMap[K comparable](m map[K]uint64, key K, value uint64, cap int) {
	if _, exists := m[key]; exists || cap <= 0 || len(m) < cap {
		m[key] += value
	}
}

// Snapshot returns a consistent view of one destination.
func (r *Registry) Snapshot(dst netip.Addr, now time.Time, windowSeconds int) (DestSnapshot, bool) {
	if !dst.IsValid() {
		return DestSnapshot{}, false
	}
	sh := &r.shards[shardIndex(dst.Unmap())]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	state := sh.dests[dst.Unmap()]
	if state == nil {
		return DestSnapshot{}, false
	}
	rotateLocked(state, now)
	return snapshotLocked(dst.Unmap(), state, now, windowSeconds), true
}

// SnapshotAll returns every tracked destination, most recently active first.
func (r *Registry) SnapshotAll(now time.Time, windowSeconds int) []DestSnapshot {
	out := make([]DestSnapshot, 0, 64)
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		for dst, state := range sh.dests {
			rotateLocked(state, now)
			out = append(out, snapshotLocked(dst, state, now, windowSeconds))
		}
		sh.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].Destination < out[j].Destination
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

func rotateLocked(state *destState, now time.Time) {
	if now.Sub(state.lastRotate) < rotateEvery {
		return
	}
	if state.recent.sources == nil {
		state.lastRotate = now
		return
	}
	state.previous = state.recent
	state.recent = allocateWindow()
	state.lastRotate = now
}

func snapshotLocked(dst netip.Addr, state *destState, now time.Time, windowSeconds int) DestSnapshot {
	if windowSeconds < 1 {
		windowSeconds = 1
	}
	if windowSeconds > rateSlots {
		windowSeconds = rateSlots
	}
	var packets, bytes, currentPackets, currentBytes uint64
	// Include the bucket exactly windowSeconds behind the current second. A
	// strict comparison made a one-second window empty as soon as the wall
	// clock crossed a second boundary, which could drop a short burst before
	// detection had satisfied its persistence requirement. Buckets are
	// one-second granular, so the inclusive boundary can over-cover by at most
	// one bucket; the denominator remains the configured window.
	cutoff := now.Unix() - int64(windowSeconds)
	for _, bucket := range state.rates {
		if bucket.second >= cutoff && bucket.second <= now.Unix() {
			packets += bucket.packets
			bytes += bucket.bytes
			if bucket.second == now.Unix() {
				currentPackets += bucket.packets
				currentBytes += bucket.bytes
			}
		}
	}
	denom := float64(windowSeconds)
	if state.firstSeen.After(now.Add(-time.Duration(windowSeconds) * time.Second)) {
		denom = math.Max(1, math.Floor(now.Sub(state.firstSeen).Seconds())+1)
	}
	merged := allocateWindow()
	mergeWindows(&merged, state.previous)
	mergeWindows(&merged, state.recent)
	recent := buildRecent(merged)
	history := make([]HistoryPoint, 0, state.historyN)
	start := state.historyAt - state.historyN
	if start < 0 {
		start += len(state.history)
	}
	for i := 0; i < state.historyN; i++ {
		history = append(history, state.history[(start+i)%len(state.history)])
	}
	return DestSnapshot{
		Destination: dst.String(),
		Addr:        dst,
		FirstSeen:   state.firstSeen,
		LastSeen:    state.lastSeen,
		PPS:         float64(packets) / denom,
		BPS:         float64(bytes) * 8 / denom,
		CurrentPPS:  float64(currentPackets),
		CurrentBPS:  float64(currentBytes) * 8,
		Recent:      recent,
		History:     history,
	}
}

func buildRecent(w window) Recent {
	recent := Recent{
		Packets:        w.packets,
		Bytes:          w.bytes,
		Samples:        w.samples,
		Malformed:      w.malformed,
		SourceOverflow: w.sourceOverflow,
		SourceCount:    len(w.sources),
		Sources:        make([]SourceCount, 0, min(len(w.sources), 24)),
		Protocols:      countsFromMap(w.protocols, 8),
		DestPorts:      portsFromMap(w.destPorts, 10),
		SrcPorts:       portsFromMap(w.srcPorts, 10),
		TCPFlags:       countsFromMap(w.flags, 8),
		TTLs:           ttlsFromMap(w.ttls),
	}
	if w.sizeSum > 0 && w.packets > 0 {
		recent.AvgPacketSize = float64(w.sizeSum) / float64(w.packets)
	}
	for src, count := range w.sources {
		recent.Sources = append(recent.Sources, SourceCount{Source: src.String(), SourceAddr: src, Count: count})
	}
	sort.Slice(recent.Sources, func(i, j int) bool {
		if recent.Sources[i].Count == recent.Sources[j].Count {
			return recent.Sources[i].Source < recent.Sources[j].Source
		}
		return recent.Sources[i].Count > recent.Sources[j].Count
	})
	if len(recent.Sources) > 24 {
		recent.Sources = recent.Sources[:24]
	}
	sizeLabels := []string{"0-64", "65-128", "129-256", "257-512", "513-1024", "1025+"}
	for i, label := range sizeLabels {
		recent.SizeBuckets = append(recent.SizeBuckets, SizeBucket{Label: label, Count: w.sizes[i]})
	}
	return recent
}

func countsFromMap(values map[string]uint64, limit int) []Count {
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

func portsFromMap(values map[uint16]uint64, limit int) []PortCount {
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

func ttlsFromMap(values map[uint8]uint64) []TTLCount {
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
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func sizeBucket(size uint64) int {
	switch {
	case size <= 64:
		return 0
	case size <= 128:
		return 1
	case size <= 256:
		return 2
	case size <= 512:
		return 3
	case size <= 1024:
		return 4
	default:
		return 5
	}
}

// RecordEvaluation appends one point to the destination history.
func (r *Registry) RecordEvaluation(dst netip.Addr, at time.Time, pps, bps, threat float64) {
	if !dst.IsValid() {
		return
	}
	sh := &r.shards[shardIndex(dst.Unmap())]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	state := sh.dests[dst.Unmap()]
	if state == nil {
		return
	}
	state.history[state.historyAt] = HistoryPoint{At: at, PPS: pps, BPS: bps, Threat: threat}
	state.historyAt = (state.historyAt + 1) % len(state.history)
	if state.historyN < len(state.history) {
		state.historyN++
	}
}

// Global returns global traffic stats and a per-second series.
func (r *Registry) Global(now time.Time, windowSeconds int, seriesSeconds int) GlobalStats {
	if windowSeconds < 1 {
		windowSeconds = 1
	}
	if seriesSeconds < 1 {
		seriesSeconds = 1
	}
	if seriesSeconds > 300 {
		seriesSeconds = 300
	}
	r.globalMu.Lock()
	defer r.globalMu.Unlock()
	var packets, bytes uint64
	cutoff := now.Unix() - int64(windowSeconds)
	for _, bucket := range r.global {
		if bucket.second > cutoff && bucket.second <= now.Unix() {
			packets += bucket.packets
			bytes += bucket.bytes
		}
	}
	points := make([]Point, 0, seriesSeconds)
	for offset := seriesSeconds - 1; offset >= 0; offset-- {
		at := now.Add(-time.Duration(offset) * time.Second)
		second := at.Unix()
		index := int(second % int64(len(r.global)))
		bucket := r.global[index]
		point := Point{At: at.Truncate(time.Second)}
		if bucket.second == second {
			point.PPS = float64(bucket.packets)
			point.BPS = float64(bucket.bytes) * 8
		}
		points = append(points, point)
	}
	return GlobalStats{
		PPS:          float64(packets) / float64(windowSeconds),
		BPS:          float64(bytes) * 8 / float64(windowSeconds),
		Destinations: r.DestinationCount(),
		TotalPackets: r.totalPackets,
		TotalBytes:   r.totalBytes,
		Series:       points,
	}
}

// Cleanup removes destinations that have been idle beyond ttl.
func (r *Registry) Cleanup(now time.Time, ttl time.Duration) int {
	removed := 0
	for i := range r.shards {
		sh := &r.shards[i]
		sh.mu.Lock()
		for dst, state := range sh.dests {
			if now.Sub(state.lastSeen) > ttl {
				delete(sh.dests, dst)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	return removed
}

// SetDestinationCount is used only to keep GlobalStats cheap to construct.
func (r *Registry) DestinationCount() int {
	count := 0
	for i := range r.shards {
		r.shards[i].mu.Lock()
		count += len(r.shards[i].dests)
		r.shards[i].mu.Unlock()
	}
	return count
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
