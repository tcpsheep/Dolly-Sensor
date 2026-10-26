// Package tcpstate tracks just enough TCP state to tell whether observed
// packets belong to a plausible conversation. It is not a TCP stack: sampled
// traffic regularly misses handshakes, so out-of-state evidence is only
// meaningful when the rate is high or other signals agree.
package tcpstate

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"dollysensor/internal/model"
)

// Event kinds emitted by the tracker.
const (
	EventHandshake   = "handshake"
	EventLongSession = "long_session"
)

// Event describes a notable TCP lifecycle moment, used to grant trust.
type Event struct {
	Kind        string        `json:"kind"`
	Source      netip.Addr    `json:"source"`
	Destination netip.Addr    `json:"destination"`
	At          time.Time     `json:"at"`
	Duration    time.Duration `json:"duration,omitempty"`
}

// Options controls bounds and expiry.
type Options struct {
	PendingTTL  time.Duration
	SessionTTL  time.Duration
	MaxSessions int
	ClosedTTL   time.Duration
}

// Connection is a read-only view of an established session.
type Connection struct {
	Source        string    `json:"source"`
	Destination   string    `json:"destination"`
	SourcePort    uint16    `json:"source_port"`
	DestPort      uint16    `json:"dest_port"`
	State         string    `json:"state"`
	StartedAt     time.Time `json:"started_at"`
	EstablishedAt time.Time `json:"established_at"`
	LastSeen      time.Time `json:"last_seen"`
	DurationSec   float64   `json:"duration_seconds"`
	Packets       uint64    `json:"packets"`
	Bytes         uint64    `json:"bytes"`
}

// Stats is a point-in-time summary of the tracker.
type Stats struct {
	Active      int    `json:"active"`
	Pending     int    `json:"pending"`
	Established int    `json:"established"`
	TotalSeen   uint64 `json:"total_seen"`
	OutOfState  uint64 `json:"out_of_state"`
	Evicted     uint64 `json:"evicted"`
	Tracked     int    `json:"tracked"`
}

// OOSStat is the recent out-of-state volume for one destination.
type OOSStat struct {
	OutOfState uint64  `json:"out_of_state"`
	Total      uint64  `json:"total"`
	Rate       float64 `json:"rate"`
}

type endpoint struct {
	addr netip.Addr
	port uint16
}

func (e endpoint) compare(other endpoint) int {
	if e.addr != other.addr {
		if e.addr.Less(other.addr) {
			return -1
		}
		return 1
	}
	switch {
	case e.port < other.port:
		return -1
	case e.port > other.port:
		return 1
	default:
		return 0
	}
}

type flowKey struct {
	a endpoint
	b endpoint
}

func makeKey(a, b endpoint) flowKey {
	if a.compare(b) <= 0 {
		return flowKey{a: a, b: b}
	}
	return flowKey{a: b, b: a}
}

type session struct {
	client        endpoint
	server        endpoint
	state         string
	clientISN     uint32
	serverISN     uint32
	clientISNSeen bool
	serverISNSeen bool
	synackSeen    bool
	started       time.Time
	established   time.Time
	lastSeen      time.Time
	packets       uint64
	bytes         uint64
	long15        bool
	long30        bool
	closed        time.Time
}

type bucket struct {
	second int64
	oos    uint64
	total  uint64
}

type destCounter struct {
	lastSeen time.Time
	buckets  [12]bucket
}

// Tracker is safe for concurrent use.
type Tracker struct {
	mu          sync.Mutex
	sessions    map[flowKey]*session
	oos         map[netip.Addr]*destCounter
	pendingTTL  time.Duration
	sessionTTL  time.Duration
	closedTTL   time.Duration
	maxSessions int
	totalSeen   uint64
	oosTotal    uint64
	evicted     uint64
}

// New builds a tracker with sane minimums.
func New(opts Options) *Tracker {
	if opts.PendingTTL <= 0 {
		opts.PendingTTL = 10 * time.Second
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 5 * time.Minute
	}
	if opts.ClosedTTL <= 0 {
		opts.ClosedTTL = 10 * time.Second
	}
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = 100000
	}
	return &Tracker{
		sessions:    make(map[flowKey]*session),
		oos:         make(map[netip.Addr]*destCounter),
		pendingTTL:  opts.PendingTTL,
		sessionTTL:  opts.SessionTTL,
		closedTTL:   opts.ClosedTTL,
		maxSessions: opts.MaxSessions,
	}
}

// Process enriches obs with session state and returns lifecycle events. It must
// be called before the observation is stored or judged.
func (t *Tracker) Process(obs *model.Observation) []Event {
	if obs.Protocol != 6 || !obs.SrcIP.IsValid() || !obs.DstIP.IsValid() {
		return nil
	}
	if obs.SrcPort == 0 || obs.DstPort == 0 {
		// A TCP header with a zero port is malformed enough that session memory
		// would be meaningless.
		return nil
	}
	now := obs.ReceivedAt
	if now.IsZero() {
		now = time.Now()
	}
	src := endpoint{addr: obs.SrcIP.Unmap(), port: obs.SrcPort}
	dst := endpoint{addr: obs.DstIP.Unmap(), port: obs.DstPort}
	key := makeKey(src, dst)
	flags := obs.TCPFlags
	packets := obs.EstimatedPackets
	if packets == 0 {
		packets = 1
	}

	t.mu.Lock()
	oos := false
	defer func() {
		t.updateOOSStatsLocked(obs.DstIP, packets, oos, now)
		t.mu.Unlock()
	}()
	t.totalSeen++

	sess := t.sessions[key]
	if flags.IsSYN() && !flags.Has(model.TCPACK) {
		if sess != nil && sess.state == "established" {
			// A bare SYN on an established tuple is usually a retransmission.
			sess.lastSeen = now
			sess.packets += obs.EstimatedPackets
			sess.bytes += obs.EstimatedBytes
			obs.SessionKey = sessionKey(sess)
			obs.SessionState = sess.state
			return nil
		}
		if sess == nil {
			if !t.makeRoomLocked(now) {
				return nil
			}
			sess = &session{
				client:        src,
				server:        dst,
				state:         "pending",
				clientISN:     obs.Seq,
				clientISNSeen: true,
				started:       now,
				lastSeen:      now,
			}
			t.sessions[key] = sess
		} else {
			sess.client = src
			sess.server = dst
			sess.lastSeen = now
			if sess.state == "closed" {
				// A fresh SYN on an old tuple starts a new conversation.
				sess.state = "pending"
				sess.clientISN = obs.Seq
				sess.clientISNSeen = true
				sess.serverISN = 0
				sess.serverISNSeen = false
				sess.synackSeen = false
				sess.started = now
				sess.established = time.Time{}
				sess.closed = time.Time{}
				sess.packets = 0
				sess.bytes = 0
				sess.long15 = false
				sess.long30 = false
			} else if !sess.clientISNSeen {
				sess.clientISN = obs.Seq
				sess.clientISNSeen = true
			}
		}
		sess.packets += obs.EstimatedPackets
		sess.bytes += obs.EstimatedBytes
		obs.SessionKey = sessionKey(sess)
		obs.SessionState = sess.state
		if sess.state == "closed" {
			sess.state = "pending"
		}
		return nil
	}

	if sess == nil && flags.IsSYNACK() {
		// The handshake began on a sample we did not see. Remember the server's
		// half so a later client ACK can complete the conversation.
		if !t.makeRoomLocked(now) {
			return nil
		}
		sess = &session{
			client:        dst,
			server:        src,
			state:         "pending",
			serverISN:     obs.Seq,
			serverISNSeen: true,
			synackSeen:    true,
			started:       now,
			lastSeen:      now,
			packets:       obs.EstimatedPackets,
			bytes:         obs.EstimatedBytes,
		}
		t.sessions[key] = sess
		obs.SessionKey = sessionKey(sess)
		obs.SessionState = "pending"
		return nil
	}

	if sess == nil {
		obs.SessionState = "out-of-state"
		obs.OutOfState = true
		obs.SessionKey = fmt.Sprintf("%s:%d->%s:%d", src.addr, src.port, dst.addr, dst.port)
		t.oosTotal++
		oos = true
		return nil
	}

	sess.lastSeen = now
	sess.packets += obs.EstimatedPackets
	sess.bytes += obs.EstimatedBytes
	obs.SessionKey = sessionKey(sess)

	if sess.state == "closed" {
		obs.SessionState = "closed"
		return nil
	}

	fromClient := src == sess.client
	if flags.IsSYNACK() {
		sess.serverISN = obs.Seq
		sess.serverISNSeen = true
		sess.synackSeen = true
		if sess.clientISNSeen && sess.serverISNSeen {
			// Not established yet: the final ACK is what completes the handshake.
			sess.state = "pending"
		}
		obs.SessionState = sess.state
		return nil
	}

	if sess.state == "pending" {
		if fromClient && flags.Has(model.TCPACK) {
			plausible := true
			if sess.clientISNSeen {
				plausible = obs.Seq == sess.clientISN+1 || (sess.serverISNSeen && obs.Ack == sess.serverISN+1)
			}
			if plausible {
				sess.state = "established"
				sess.established = now
				obs.SessionState = "established"
				obs.HandshakeCompleted = true
				return []Event{{
					Kind:        EventHandshake,
					Source:      sess.client.addr,
					Destination: sess.server.addr,
					At:          now,
				}}
			}
		}
		obs.SessionState = "pending"
		return nil
	}

	obs.SessionState = sess.state
	if flags.Has(model.TCPRST) || flags.Has(model.TCPFIN) {
		sess.state = "closed"
		sess.closed = now
		obs.SessionState = "closed"
	}
	return nil
}

func sessionKey(sess *session) string {
	return fmt.Sprintf("%s:%d->%s:%d", sess.client.addr, sess.client.port, sess.server.addr, sess.server.port)
}

func (t *Tracker) updateOOSStatsLocked(dst netip.Addr, packets uint64, oos bool, now time.Time) {
	if !dst.IsValid() {
		return
	}
	dst = dst.Unmap()
	counter := t.oos[dst]
	if counter == nil {
		counter = &destCounter{}
		t.oos[dst] = counter
	}
	counter.lastSeen = now
	second := now.Unix()
	index := int(second % int64(len(counter.buckets)))
	if counter.buckets[index].second != second {
		counter.buckets[index] = bucket{second: second}
	}
	counter.buckets[index].total += packets
	if oos {
		counter.buckets[index].oos += packets
	}
}

// makeRoomLocked evicts the oldest session if the tracker is at capacity.
func (t *Tracker) makeRoomLocked(now time.Time) bool {
	if len(t.sessions) < t.maxSessions {
		return true
	}
	var oldestKey flowKey
	var oldest *session
	for key, sess := range t.sessions {
		if oldest == nil || sess.lastSeen.Before(oldest.lastSeen) {
			oldest = sess
			oldestKey = key
		}
	}
	if oldest == nil {
		return true
	}
	// Prefer evicting a pending or closed session over an active one.
	for key, sess := range t.sessions {
		if sess.state != "established" {
			oldestKey = key
			oldest = sess
			break
		}
	}
	delete(t.sessions, oldestKey)
	t.evicted++
	_ = now
	return true
}

// Sweep expires idle state and returns long-session events.
func (t *Tracker) Sweep(now time.Time) []Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	var events []Event
	for key, sess := range t.sessions {
		switch sess.state {
		case "pending":
			if now.Sub(sess.lastSeen) > t.pendingTTL {
				delete(t.sessions, key)
			}
		case "closed":
			if now.Sub(sess.closed) > t.closedTTL {
				delete(t.sessions, key)
			}
		case "established":
			if now.Sub(sess.lastSeen) > t.sessionTTL {
				delete(t.sessions, key)
				continue
			}
			age := now.Sub(sess.established)
			if !sess.long15 && age >= 15*time.Minute {
				sess.long15 = true
				events = append(events, Event{Kind: EventLongSession, Source: sess.client.addr, Destination: sess.server.addr, At: now, Duration: 15 * time.Minute})
			}
			if !sess.long30 && age >= 30*time.Minute {
				sess.long30 = true
				events = append(events, Event{Kind: EventLongSession, Source: sess.client.addr, Destination: sess.server.addr, At: now, Duration: 30 * time.Minute})
			}
		}
	}
	for dst, counter := range t.oos {
		if now.Sub(counter.lastSeen) > t.sessionTTL {
			delete(t.oos, dst)
		}
	}
	return events
}

// OutOfStateStats returns recent per-destination totals and rates.
func (t *Tracker) OutOfStateStats(now time.Time, seconds int) map[netip.Addr]OOSStat {
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 12 {
		seconds = 12
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[netip.Addr]OOSStat, len(t.oos))
	cutoff := now.Add(-time.Duration(seconds) * time.Second).Unix()
	for dst, counter := range t.oos {
		var stat OOSStat
		for _, b := range counter.buckets {
			if b.second > cutoff && b.second <= now.Unix() {
				stat.OutOfState += b.oos
				stat.Total += b.total
			}
		}
		if stat.Total == 0 && stat.OutOfState == 0 {
			continue
		}
		stat.Rate = float64(stat.OutOfState) / float64(seconds)
		out[dst] = stat
	}
	return out
}

// Established returns established connections, newest activity first.
func (t *Tracker) Established(limit int) []Connection {
	t.mu.Lock()
	defer t.mu.Unlock()
	if limit < 0 {
		limit = 0
	}
	out := make([]Connection, 0, min(limit, len(t.sessions)))
	for _, sess := range t.sessions {
		if sess.state != "established" {
			continue
		}
		established := sess.established
		duration := 0.0
		if !established.IsZero() {
			duration = sess.lastSeen.Sub(established).Seconds()
			if duration < 0 {
				duration = 0
			}
		}
		out = append(out, Connection{
			Source:        sess.client.addr.String(),
			Destination:   sess.server.addr.String(),
			SourcePort:    sess.client.port,
			DestPort:      sess.server.port,
			State:         sess.state,
			StartedAt:     sess.started,
			EstablishedAt: established,
			LastSeen:      sess.lastSeen,
			DurationSec:   duration,
			Packets:       sess.packets,
			Bytes:         sess.bytes,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if limit <= 0 || limit > len(out) {
		limit = len(out)
	}
	return out[:limit]
}

// Stats returns a summary of tracker state.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	stats := Stats{TotalSeen: t.totalSeen, OutOfState: t.oosTotal, Evicted: t.evicted, Tracked: len(t.sessions)}
	for _, sess := range t.sessions {
		switch sess.state {
		case "pending":
			stats.Pending++
		case "established":
			stats.Established++
			stats.Active++
		case "closed":
		}
	}
	return stats
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
