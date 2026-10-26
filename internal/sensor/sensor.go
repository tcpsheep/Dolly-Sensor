// Package sensor wires Dolly Sensor's subsystems into one service: UDP
// collection, decoding, trust and profiles, aggregation, detection, alerts,
// mitigation, persistence, and live updates.
package sensor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dollysensor/internal/aggregate"
	"dollysensor/internal/alerts"
	"dollysensor/internal/bgp"
	"dollysensor/internal/blocklist"
	"dollysensor/internal/buffer"
	"dollysensor/internal/config"
	"dollysensor/internal/detect"
	"dollysensor/internal/events"
	"dollysensor/internal/intel"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/model"
	"dollysensor/internal/netutil"
	"dollysensor/internal/notify"
	"dollysensor/internal/rules"
	"dollysensor/internal/sflow"
	"dollysensor/internal/sweep"
	"dollysensor/internal/version"
)

type runtimeCounters struct {
	datagrams        atomic.Uint64
	decodeErrors     atomic.Uint64
	observations     atomic.Uint64
	accepted         atomic.Uint64
	outbound         atomic.Uint64
	internal         atomic.Uint64
	ignored          atomic.Uint64
	droppedDatagrams atomic.Uint64
	droppedFindings  atomic.Uint64
	droppedRules     atomic.Uint64
	blocklistHits    atomic.Uint64
	evaluations      atomic.Uint64
}

type lastTimes struct {
	packet  atomic.Int64
	decoded atomic.Int64
}

// Sensor is the complete Dolly Sensor service, minus the HTTP listener.
type Sensor struct {
	cfg      config.Config
	warnings []string
	logger   *slog.Logger
	// cfgMu guards runtime mutation of s.cfg (dashboard detection tuning).
	// Cold-path readers of the whole struct take the lock; hot paths read
	// immutable sections that tuning never touches.
	cfgMu sync.RWMutex

	startedAt time.Time
	protected *netutil.PrefixSet
	trusted   *netutil.PrefixSet

	blocklist *blocklist.List
	intel     *intel.Store
	aggregate *aggregate.Registry
	detector  *detect.Detector
	sweeper   *sweep.Tracker
	alerts    *alerts.Store
	hub       *events.Hub
	notifier  *notify.Notifier
	bgp       *bgp.Speaker
	mitigator *mitigate.Manager
	ring      *buffer.Ring
	ruleStore *rules.Store

	datagrams        chan []byte
	findings         chan detect.Finding
	ruleObservations chan model.Observation
	ruleOpsMu        sync.Mutex

	conn     *net.UDPConn
	readDone chan struct{}

	runCtx      context.Context
	cancel      context.CancelFunc
	started     bool
	closed      atomic.Bool
	lifecycleMu sync.Mutex
	readWG      sync.WaitGroup
	ingestWG    sync.WaitGroup
	loopWG      sync.WaitGroup
	controlWG   sync.WaitGroup
	closeOnce   sync.Once

	nextID     atomic.Uint64
	counters   runtimeCounters
	last       lastTimes
	lastEval   atomic.Int64
	lastLog    atomic.Int64
	gate       *findingGate
	lastReload atomic.Int64
	running    atomic.Bool
	sweepOn    atomic.Bool
}

// New constructs a Sensor and loads durable state. No sockets are opened and no
// goroutines are started until Start.
func New(cfg config.Config, loadedWarnings []string, logger *slog.Logger) (*Sensor, error) {
	if logger == nil {
		logger = slog.Default()
	}
	warnings, err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	warnings = append(loadedWarnings, warnings...)
	warnings = dedupeStrings(warnings)
	protected := cfg.ProtectedSet()
	if protected.Len() == 0 {
		return nil, errors.New("protected CIDRs are required")
	}
	trusted := cfg.TrustedSet()

	lists := blocklist.New(cfg.Mitigation.BlocklistDir, cfg.Mitigation.ManualFile, protected)
	blockWarnings, err := lists.Reload()
	if err != nil {
		return nil, fmt.Errorf("load blocklist: %w", err)
	}
	warnings = append(warnings, blockWarnings...)

	profiles, err := intel.Open(cfg.Persistence.ProfileFile, intel.Options{
		MaxProfiles: cfg.Memory.MaxProfiles,
	})
	if err != nil {
		return nil, fmt.Errorf("load profiles: %w", err)
	}
	ruleStore, err := rules.Open(rules.Options{
		Path:                    cfg.Rules.File,
		Protected:               protected,
		MaxRules:                cfg.Rules.MaxRules,
		MaxFlowsPerRule:         cfg.Rules.MaxFlowsPerRule,
		AllowDestinationDiscard: cfg.Rules.AllowDestinationDiscard,
		Disabled:                !cfg.Rules.Enabled,
		DefaultRateLimitBPS:     uint64(cfg.Mitigation.RateLimitMbps * 1_000_000),
		DefaultDuration:         cfg.Mitigation.DefaultDuration.Std(),
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}

	s := &Sensor{
		cfg:       cfg,
		warnings:  warnings,
		logger:    logger,
		startedAt: time.Now(),
		protected: protected,
		trusted:   trusted,
		blocklist: lists,
		intel:     profiles,
		aggregate: aggregate.New(),
		sweeper:   sweep.New(cfg.Detection.Sweep.PrefixBits),
		alerts:    alerts.New(cfg.Memory.AlertHistory, cfg.Detection.Cooldown.Std()),
		hub:       events.New(),
		ruleStore: ruleStore,
		datagrams: make(chan []byte, cfg.Collector.Queue),
		findings:  make(chan detect.Finding, 2048),
		gate:      newFindingGate(2 * time.Second),
	}
	s.sweepOn.Store(cfg.Detection.Sweep.Enabled)
	s.ruleObservations = make(chan model.Observation, cfg.Rules.EvaluationQueue)
	s.notifier = notify.New(notify.Options{
		URL:     cfg.Alerting.WebhookURL,
		Format:  cfg.Alerting.Format,
		Timeout: cfg.Alerting.Timeout.Std(),
		Retries: cfg.Alerting.Retries,
		Logger:  logger,
	})
	s.detector = detect.New(detect.Options{
		Detection: cfg.Detection,
		Intel:     profiles,
		Protected: protected,
		Trusted:   trusted,
	})
	s.ring = buffer.New(cfg.Memory.PacketBuffer)

	var announcer mitigate.Announcer
	if cfg.BGP.Enabled {
		peerIP, err := netip.ParseAddr(cfg.BGP.PeerIP)
		if err != nil {
			return nil, fmt.Errorf("bgp peer ip: %w", err)
		}
		var localAddr netip.Addr
		if strings.TrimSpace(cfg.BGP.LocalAddr) != "" {
			localAddr, err = netip.ParseAddr(cfg.BGP.LocalAddr)
			if err != nil {
				return nil, fmt.Errorf("bgp local address: %w", err)
			}
		}
		routerID, _ := netip.ParseAddr(cfg.BGP.RouterID)
		nextHop, _ := netip.ParseAddr(cfg.BGP.NextHop)
		community, err := config.ParseCommunity(cfg.BGP.Community)
		if err != nil {
			return nil, fmt.Errorf("bgp community: %w", err)
		}
		speaker, err := bgp.New(bgp.Options{
			LocalAS:        cfg.BGP.LocalAS,
			PeerAS:         cfg.BGP.PeerAS,
			PeerIP:         peerIP,
			PeerPort:       cfg.BGP.PeerPort,
			LocalAddr:      localAddr,
			RouterID:       routerID,
			Community:      community,
			NextHop:        nextHop,
			HoldTime:       cfg.BGP.HoldTime.Std(),
			ConnectTimeout: cfg.BGP.ConnectTimeout.Std(),
			Logger:         logger,
			OnEstablished: func() {
				s.syncStandingRules(context.Background())
			},
		}, logger)
		if err != nil {
			return nil, fmt.Errorf("configure BGP: %w", err)
		}
		s.bgp = speaker
		announcer = speaker
	}
	ruleCapacity := 0
	if cfg.Rules.Enabled {
		ruleCapacity = cfg.Rules.MaxRules
	}
	s.mitigator = mitigate.New(mitigate.Options{
		Protected:               protected,
		Announcer:               announcer,
		Simulated:               !cfg.BGP.Enabled,
		Duration:                cfg.Mitigation.DefaultDuration.Std(),
		DedupWindow:             cfg.Mitigation.DedupWindow.Std(),
		MaxActive:               cfg.Mitigation.MaxActive + ruleCapacity,
		MaxAutomatic:            cfg.Mitigation.MaxActive,
		MaxRules:                cfg.Rules.MaxRules,
		HistoryLimit:            cfg.Mitigation.HistoryLimit,
		Community:               cfg.BGP.Community,
		NextHop:                 cfg.BGP.NextHop,
		RateLimitBPS:            uint64(cfg.Mitigation.RateLimitMbps * 1_000_000),
		OpTimeout:               12 * time.Second,
		AllowDestinationDiscard: cfg.Rules.Enabled && cfg.Rules.AllowDestinationDiscard,
	})
	return s, nil
}

// Start opens the UDP collector and starts all background loops.
func (s *Sensor) Start(parent context.Context) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.started {
		return errors.New("sensor is already started")
	}
	if s.closed.Load() {
		return errors.New("sensor is closed")
	}
	if parent == nil {
		parent = context.Background()
	}
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Collector.Listen)
	if err != nil {
		return fmt.Errorf("resolve collector address: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen for sFlow on %s: %w", s.cfg.Collector.Listen, err)
	}
	if err := conn.SetReadBuffer(s.cfg.Collector.ReadBufferBytes); err != nil {
		s.logger.Warn("could not set UDP read buffer", "error", err.Error())
	}
	s.conn = conn
	s.readDone = make(chan struct{})
	runCtx, cancel := context.WithCancel(parent)
	s.runCtx = runCtx
	s.cancel = cancel
	s.started = true
	s.notifier.Start(runCtx)

	for i := 0; i < s.cfg.Collector.Workers; i++ {
		s.ingestWG.Add(1)
		go s.decodeWorker(runCtx)
	}
	s.readWG.Add(1)
	go s.readLoop(conn, s.readDone)
	s.controlWG.Add(2)
	for i := 0; i < 2; i++ {
		go s.controlWorker(runCtx)
	}
	s.loopWG.Add(1)
	go s.ruleEvaluationLoop(runCtx)
	s.loopWG.Add(1)
	go s.evaluationLoop(runCtx)
	s.loopWG.Add(1)
	go s.maintenanceLoop(runCtx)
	s.loopWG.Add(1)
	go s.trustDecayLoop(runCtx)
	s.loopWG.Add(1)
	go s.mitigationLoop(runCtx)
	s.loopWG.Add(1)
	go s.saveLoop(runCtx)
	if s.bgp != nil {
		s.loopWG.Add(1)
		go func() {
			defer s.loopWG.Done()
			s.bgp.Run(runCtx)
		}()
	}
	s.loopWG.Add(1)
	go func() {
		defer s.loopWG.Done()
		select {
		case <-runCtx.Done():
			return
		case <-time.After(1500 * time.Millisecond):
		}
		s.syncStandingRules(runCtx)
	}()

	s.lastReload.Store(time.Now().UnixNano())
	s.running.Store(true)
	s.logger.Info("collector listening", "address", conn.LocalAddr().String())
	if s.cfg.BGP.Enabled {
		s.logger.Info("mitigation armed", "bgp_peer", s.cfg.BGP.PeerIP, "simulation", false)
	} else {
		s.logger.Info("mitigation simulation mode; no BGP announcements will be sent")
	}
	for _, warning := range s.warnings {
		s.logger.Warn("configuration warning", "warning", warning)
	}
	return nil
}

func (s *Sensor) readLoop(conn *net.UDPConn, done chan struct{}) {
	defer s.readWG.Done()
	defer close(done)
	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			s.logThrottled("collector read error", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		s.counters.datagrams.Add(1)
		datagram := make([]byte, n)
		copy(datagram, buf[:n])
		select {
		case s.datagrams <- datagram:
		default:
			s.counters.droppedDatagrams.Add(1)
		}
	}
}

func (s *Sensor) decodeWorker(ctx context.Context) {
	defer s.ingestWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case datagram, ok := <-s.datagrams:
			if !ok {
				return
			}
			s.ProcessDatagram(datagram, time.Now())
		}
	}
}

// ProcessDatagram decodes and ingests one datagram. It is exported so tools and
// tests can replay captured sFlow without opening a socket.
func (s *Sensor) ProcessDatagram(datagram []byte, receivedAt time.Time) int {
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	observations, err := sflow.Decode(datagram, receivedAt)
	if err != nil {
		s.counters.decodeErrors.Add(1)
		s.logThrottled("sFlow decode error", err)
	}
	for i := range observations {
		s.counters.observations.Add(1)
		s.processObservation(observations[i], receivedAt)
	}
	return len(observations)
}

func (s *Sensor) processObservation(obs model.Observation, now time.Time) {
	if !obs.SrcIP.IsValid() || !obs.DstIP.IsValid() {
		s.counters.ignored.Add(1)
		return
	}
	obs.ID = s.nextID.Add(1)
	if obs.ReceivedAt.IsZero() {
		obs.ReceivedAt = now
	}
	obs.SrcProtected = s.protected.Contains(obs.SrcIP)
	obs.DstProtected = s.protected.Contains(obs.DstIP)
	switch {
	case obs.DstProtected && obs.SrcProtected:
		obs.Direction = model.DirectionInternal
		s.counters.internal.Add(1)
	case obs.DstProtected:
		obs.Direction = model.DirectionInbound
	case obs.SrcProtected:
		obs.Direction = model.DirectionOutbound
		s.counters.outbound.Add(1)
		return
	default:
		obs.Direction = model.DirectionOther
		s.counters.ignored.Add(1)
		return
	}
	s.counters.accepted.Add(1)
	s.last.packet.Store(now.UnixNano())

	var matched netip.Prefix
	blocked := false
	if obs.DstProtected && !obs.SrcProtected {
		if prefix, ok := s.blocklist.Lookup(obs.SrcIP); ok {
			matched = prefix
			blocked = true
			s.counters.blocklistHits.Add(1)
		}
	}

	obs.Finalize()

	if obs.DstProtected {
		s.intel.Observe(obs)
		s.aggregate.Observe(obs, now)
	}
	if obs.DstProtected && !obs.SrcProtected && s.sweepOn.Load() {
		s.sweeper.Observe(obs, now)
	}
	s.ring.Add(obs)
	if obs.DstProtected && s.ruleStore != nil {
		select {
		case s.ruleObservations <- obs:
		default:
			s.counters.droppedRules.Add(1)
			s.ruleStore.NoteDroppedObservation()
		}
	}
	s.maybePublishPacket(obs, now)

	if blocked {
		finding := blocklistFinding(obs, matched, s.cfg.Mitigation.AutoBlock)
		if finding != nil {
			s.enqueueFinding(*finding, now)
		}
	}
}

func blocklistFinding(obs model.Observation, matched netip.Prefix, autoBlock bool) *detect.Finding {
	reason := fmt.Sprintf("Source %s matches blocklist entry %s. Traffic to protected destination %s is subject to automatic blocking.", obs.SrcIP, matched, obs.DstIP)
	signals := []string{
		fmt.Sprintf("blocklist match: %s", matched),
		fmt.Sprintf("direction: %s", obs.Direction),
	}
	finding := &detect.Finding{Alert: alerts.Candidate{
		Key:         fmt.Sprintf("blocklist|%s|%s", obs.DstIP, obs.SrcIP),
		Severity:    alerts.SeverityCritical,
		Type:        "blocklist",
		Layer:       "blocklist",
		Destination: obs.DstIP.String(),
		Source:      obs.SrcIP.String(),
		Reason:      reason,
		Signals:     signals,
	}}
	if !autoBlock || obs.Protocol == 0 {
		return finding
	}
	request := &mitigate.Request{
		Kind:        mitigate.KindFlowspec,
		Source:      obs.SrcIP,
		Destination: obs.DstIP,
		Protocol:    obs.Protocol,
		Action:      "discard",
		Reason:      fmt.Sprintf("blocklist match %s toward %s", matched, obs.DstIP),
		Owner:       "blocklist",
		AlertID:     "",
	}
	if obs.Protocol == 6 || obs.Protocol == 17 {
		// Deliberately omit the port: a blocklisted source should not reach the
		// destination through a different service port.
		request.DstPort = 0
	}
	finding.Action = request
	return finding
}

func (s *Sensor) maybePublishPacket(obs model.Observation, now time.Time) {
	const minInterval = 100 * time.Millisecond
	last := s.last.decoded.Load()
	current := now.UnixNano()
	if last != 0 && current-last < int64(minInterval) {
		return
	}
	if !s.last.decoded.CompareAndSwap(last, current) {
		return
	}
	s.hub.Publish(events.Event{Type: "packet", Data: obs})
}

func (s *Sensor) enqueueFinding(finding detect.Finding, now time.Time) {
	key := finding.Alert.Key
	if key == "" {
		key = finding.Alert.Type + "|" + finding.Alert.Destination + "|" + finding.Alert.Source
	}
	if !s.gate.allow(key, now) {
		return
	}
	select {
	case s.findings <- finding:
	default:
		s.counters.droppedFindings.Add(1)
	}
}

func (s *Sensor) logThrottled(message string, err error) {
	if err == nil {
		return
	}
	now := time.Now().UnixNano()
	last := s.lastLog.Load()
	if last != 0 && now-last < int64(10*time.Second) {
		return
	}
	if !s.lastLog.CompareAndSwap(last, now) {
		return
	}
	s.logger.Warn(message, "error", err.Error())
}

// StartTime returns process start time.
func (s *Sensor) StartTime() time.Time { return s.startedAt }

// Version returns the service version.
func (s *Sensor) Version() string { return version.Version }

// Config returns the effective configuration. Callers rendering it for the
// dashboard must redact secrets.
func (s *Sensor) Config() config.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// detection returns the live detection tuning.
func (s *Sensor) detection() config.DetectionConfig {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg.Detection
}

// Warnings returns startup warnings.
func (s *Sensor) Warnings() []string { return append([]string(nil), s.warnings...) }

// ProtectedSet returns protected prefixes.
func (s *Sensor) ProtectedSet() *netutil.PrefixSet { return s.protected }

// TrustedSet returns globally trusted prefixes.
func (s *Sensor) TrustedSet() *netutil.PrefixSet { return s.trusted }

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
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

// findingGate suppresses duplicate finding enqueues for a short interval.
type findingGate struct {
	mu       sync.Mutex
	interval time.Duration
	seen     map[string]time.Time
}

func newFindingGate(interval time.Duration) *findingGate {
	return &findingGate{interval: interval, seen: map[string]time.Time{}}
}

func (g *findingGate) allow(key string, now time.Time) bool {
	const maxSeen = 16384
	g.mu.Lock()
	defer g.mu.Unlock()
	if at, ok := g.seen[key]; ok && now.Sub(at) < g.interval {
		return false
	}
	if _, exists := g.seen[key]; !exists && len(g.seen) >= maxSeen {
		for existing, at := range g.seen {
			if now.Sub(at) > g.interval*2 {
				delete(g.seen, existing)
			}
		}
		if len(g.seen) >= maxSeen {
			// A flood of ever-changing keys must not turn this gate into an
			// unbounded allocation. Dropping a new finding is safe: the
			// downstream finding queue is bounded for the same reason.
			return false
		}
	}
	g.seen[key] = now
	return true
}

func (g *findingGate) cleanup(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for key, at := range g.seen {
		if now.Sub(at) > g.interval*2 {
			delete(g.seen, key)
		}
	}
}
