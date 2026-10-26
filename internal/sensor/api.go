package sensor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"dollysensor/internal/aggregate"
	"dollysensor/internal/alerts"
	"dollysensor/internal/bgp"
	"dollysensor/internal/blocklist"
	"dollysensor/internal/config"
	"dollysensor/internal/detect"
	"dollysensor/internal/events"
	"dollysensor/internal/intel"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/model"
	"dollysensor/internal/notify"
	"dollysensor/internal/tcpstate"
	"dollysensor/internal/version"
)

// CollectorStatus is the ingestion side of the health view.
type CollectorStatus struct {
	Listen           string    `json:"listen"`
	Running          bool      `json:"running"`
	Workers          int       `json:"workers"`
	QueueDepth       int       `json:"queue_depth"`
	QueueCapacity    int       `json:"queue_capacity"`
	FindingQueue     int       `json:"finding_queue"`
	Datagrams        uint64    `json:"datagrams"`
	DecodeErrors     uint64    `json:"decode_errors"`
	Observations     uint64    `json:"observations"`
	Accepted         uint64    `json:"accepted"`
	Internal         uint64    `json:"internal"`
	Outbound         uint64    `json:"outbound"`
	Ignored          uint64    `json:"ignored"`
	DroppedDatagrams uint64    `json:"dropped_datagrams"`
	DroppedFindings  uint64    `json:"dropped_findings"`
	BlocklistHits    uint64    `json:"blocklist_hits"`
	FTPFindings      uint64    `json:"ftp_findings"`
	Evaluations      uint64    `json:"evaluations"`
	LastPacket       time.Time `json:"last_packet,omitempty"`
	LastEvaluation   time.Time `json:"last_evaluation,omitempty"`
	PacketBuffer     int       `json:"packet_buffer"`
	PacketBufferCap  int       `json:"packet_buffer_capacity"`
}

// EventStatus describes live dashboard fanout.
type EventStatus struct {
	Clients int    `json:"clients"`
	Dropped uint64 `json:"dropped"`
}

// StatusData is the operational health and safety view.
type StatusData struct {
	Version         string            `json:"version"`
	StartedAt       time.Time         `json:"started_at"`
	UptimeSeconds   float64           `json:"uptime_seconds"`
	Running         bool              `json:"running"`
	Simulated       bool              `json:"simulated"`
	ProtectedCIDRs  []string          `json:"protected_cidrs"`
	TrustedSources  []string          `json:"trusted_sources"`
	Collector       CollectorStatus   `json:"collector"`
	TCP             tcpstate.Stats    `json:"tcp"`
	DestinationLive int               `json:"destination_live"`
	Profiles        int               `json:"profiles"`
	Alerts          alerts.Stats      `json:"alerts"`
	Mitigation      mitigate.Counts   `json:"mitigation"`
	BGP             *bgp.Status       `json:"bgp,omitempty"`
	Notifier        notify.Stats      `json:"notifier"`
	Events          EventStatus       `json:"events"`
	Persistence     intel.SaveState   `json:"persistence"`
	Detection       detect.Parameters `json:"detection"`
	Config          config.Config     `json:"-"`
	Warnings        []string          `json:"warnings"`
	DashboardListen string            `json:"dashboard_listen"`
	CollectorListen string            `json:"collector_listen"`
}

// DestinationRow is one row of the overview/destinations table.
type DestinationRow struct {
	Destination    string            `json:"destination"`
	Threat         string            `json:"threat"`
	Score          float64           `json:"score"`
	SmoothedScore  float64           `json:"smoothed_score"`
	Threshold      float64           `json:"threshold"`
	Warmup         bool              `json:"warmup"`
	Attack         bool              `json:"attack"`
	PPS            float64           `json:"pps"`
	BPS            float64           `json:"bps"`
	CurrentPPS     float64           `json:"current_pps"`
	CurrentBPS     float64           `json:"current_bps"`
	BaselinePPS    float64           `json:"baseline_pps"`
	BaselineBPS    float64           `json:"baseline_bps"`
	OutOfStatePPS  float64           `json:"out_of_state_pps"`
	Sources        int               `json:"sources"`
	TrustedSources int               `json:"trusted_sources"`
	TotalPackets   uint64            `json:"total_packets"`
	TotalBytes     uint64            `json:"total_bytes"`
	MaxPPS         float64           `json:"max_pps"`
	MaxBPS         float64           `json:"max_bps"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	TopProtocols   []intel.Count     `json:"top_protocols"`
	TopPorts       []intel.PortCount `json:"top_ports"`
}

// OverviewData is the landing view in one request.
type OverviewData struct {
	Status            StatusData            `json:"status"`
	Global            aggregate.GlobalStats `json:"global"`
	Detection         detect.Parameters     `json:"detection"`
	Destinations      []DestinationRow      `json:"destinations"`
	RecentAlerts      []alerts.Alert        `json:"recent_alerts"`
	RecentPackets     []model.Observation   `json:"recent_packets"`
	ActiveMitigations []mitigate.Action     `json:"active_mitigations"`
}

// DestinationDetailData is the deep destination investigation view.
type DestinationDetailData struct {
	Destination string                   `json:"destination"`
	Profile     *intel.DestinationDetail `json:"profile,omitempty"`
	Live        *aggregate.DestSnapshot  `json:"live,omitempty"`
	Detection   *detect.State            `json:"detection,omitempty"`
	Recent      []model.Observation      `json:"recent"`
	Alerts      []alerts.Alert           `json:"alerts"`
	Actions     []mitigate.Action        `json:"actions"`
	Trusted     []intel.TrustedSource    `json:"trusted"`
}

// IntelligenceData holds reputation and learning evidence.
type IntelligenceData struct {
	Reputations  []intel.ReputationSummary  `json:"reputations"`
	Destinations []intel.DestinationSummary `json:"destinations"`
	ManualTrust  []intel.TrustedSource      `json:"manual_trust"`
	Detection    detect.Parameters          `json:"detection"`
	Profiles     int                        `json:"profiles"`
}

// PacketFilter narrows recent observation searches.
type PacketFilter struct {
	Destination string
	Source      string
	Port        uint16
	Protocol    string
	Direction   string
	Query       string
	Limit       int
}

// ConnectionsData is the TCP session view.
type ConnectionsData struct {
	Stateful    bool                  `json:"stateful"`
	Stats       tcpstate.Stats        `json:"stats"`
	Connections []tcpstate.Connection `json:"connections"`
}

// SettingsData exposes effective settings with secrets removed.
type SettingsData struct {
	Config            config.Config `json:"config"`
	WebhookConfigured bool          `json:"webhook_configured"`
	Version           string        `json:"version"`
	Warnings          []string      `json:"warnings"`
}

// DestinationRows merges live rates, durable profiles, and detection state.
func (s *Sensor) DestinationRows(limit int) []DestinationRow {
	now := time.Now()
	snapshots := s.aggregate.SnapshotAll(now, s.cfg.Detection.RateWindowSeconds)
	profiles := s.intel.Summaries()
	states := map[string]detect.State{}
	for _, state := range s.detector.States() {
		states[state.Destination] = state
	}
	rows := map[string]*DestinationRow{}
	for _, summary := range profiles {
		row := &DestinationRow{
			Destination:    summary.Destination,
			Threat:         "idle",
			Sources:        summary.SourceCount,
			TrustedSources: summary.TrustedCount,
			TotalPackets:   summary.TotalPackets,
			TotalBytes:     summary.TotalBytes,
			MaxPPS:         summary.MaxPPS,
			MaxBPS:         summary.MaxBPS,
			FirstSeen:      summary.FirstSeen,
			LastSeen:       summary.LastUpdated,
			TopProtocols:   summary.TopProtocols,
			TopPorts:       summary.TopPorts,
		}
		rows[summary.Destination] = row
	}
	for _, snapshot := range snapshots {
		row := rows[snapshot.Destination]
		if row == nil {
			row = &DestinationRow{Destination: snapshot.Destination, Threat: "learning"}
			rows[snapshot.Destination] = row
		}
		row.PPS = snapshot.PPS
		row.BPS = snapshot.BPS
		row.CurrentPPS = snapshot.CurrentPPS
		row.CurrentBPS = snapshot.CurrentBPS
		row.FirstSeen = snapshot.FirstSeen
		row.LastSeen = snapshot.LastSeen
		if state, ok := states[snapshot.Destination]; ok {
			row.Threat = state.Threat
			row.Score = state.Score
			row.SmoothedScore = state.SmoothedScore
			row.Threshold = state.Threshold
			row.Warmup = state.Warmup
			row.Attack = state.Attack
			row.BaselinePPS = state.BaselinePPS
			row.BaselineBPS = state.BaselineBPS
			row.OutOfStatePPS = state.OutOfStatePPS
		} else if row.Warmup {
			row.Threat = "learning"
		}
	}
	for destination, state := range states {
		row := rows[destination]
		if row == nil {
			row = &DestinationRow{Destination: destination}
			rows[destination] = row
		}
		row.Threat = state.Threat
		row.Score = state.Score
		row.SmoothedScore = state.SmoothedScore
		row.Threshold = state.Threshold
		row.Warmup = state.Warmup
		row.Attack = state.Attack
		row.BaselinePPS = state.BaselinePPS
		row.BaselineBPS = state.BaselineBPS
		row.OutOfStatePPS = state.OutOfStatePPS
	}
	out := make([]DestinationRow, 0, len(rows))
	for _, row := range rows {
		if row.Threat == "" {
			row.Threat = "idle"
		}
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Attack != out[j].Attack {
			return out[i].Attack
		}
		if out[i].Threat != out[j].Threat {
			rank := func(threat string) int {
				switch threat {
				case "under_attack":
					return 4
				case "anomalous":
					return 3
				case "learning":
					return 2
				case "idle":
					return 0
				default:
					return 1
				}
			}
			if rank(out[i].Threat) != rank(out[j].Threat) {
				return rank(out[i].Threat) > rank(out[j].Threat)
			}
		}
		if out[i].PPS != out[j].PPS {
			return out[i].PPS > out[j].PPS
		}
		return out[i].Destination < out[j].Destination
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// DestinationDetail assembles the investigation view for one protected IP.
func (s *Sensor) DestinationDetail(destination string) (DestinationDetailData, error) {
	dst, err := parseAddr(destination)
	if err != nil {
		return DestinationDetailData{}, err
	}
	data := DestinationDetailData{Destination: dst.String()}
	if detail, ok := s.intel.Detail(dst, 200); ok {
		data.Profile = &detail
	}
	if live, ok := s.aggregate.Snapshot(dst, time.Now(), s.cfg.Detection.RateWindowSeconds); ok {
		data.Live = &live
	}
	if state, ok := s.detector.State(dst); ok {
		data.Detection = &state
	}
	data.Recent = s.Observations(PacketFilter{Destination: dst.String(), Limit: 50})
	data.Trusted = s.manualTrustFor(dst)
	allAlerts := s.alerts.Snapshot(500, "")
	for _, alert := range allAlerts {
		if alert.Destination == dst.String() {
			data.Alerts = append(data.Alerts, alert)
			if len(data.Alerts) >= 50 {
				break
			}
		}
	}
	alertIDs := map[string]bool{}
	for _, alert := range data.Alerts {
		alertIDs[alert.ID] = true
	}
	for _, action := range s.mitigator.History(500) {
		if action.Match.Destination == dst.String() || alertIDs[action.AlertID] {
			data.Actions = append(data.Actions, action)
		}
	}
	return data, nil
}

// Observations searches the bounded packet ring. It never blocks ingestion.
func (s *Sensor) Observations(filter PacketFilter) []model.Observation {
	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	items := s.ring.Latest(s.cfg.Memory.PacketBuffer)
	destination := strings.ToLower(strings.TrimSpace(filter.Destination))
	source := strings.ToLower(strings.TrimSpace(filter.Source))
	protocol := strings.ToLower(strings.TrimSpace(filter.Protocol))
	direction := strings.ToLower(strings.TrimSpace(filter.Direction))
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	out := make([]model.Observation, 0, minInt(limit, len(items)))
	for _, obs := range items {
		if destination != "" && !strings.Contains(strings.ToLower(obs.DstIP.String()), destination) {
			continue
		}
		if source != "" && !strings.Contains(strings.ToLower(obs.SrcIP.String()), source) {
			continue
		}
		if filter.Port != 0 && obs.SrcPort != filter.Port && obs.DstPort != filter.Port {
			continue
		}
		if protocol != "" && strings.ToLower(obs.ProtocolName) != protocol && fmt.Sprint(obs.Protocol) != protocol {
			continue
		}
		if direction != "" && string(obs.Direction) != direction {
			continue
		}
		if query != "" {
			haystack := strings.ToLower(strings.Join([]string{
				obs.Summary, obs.SrcIP.String(), obs.DstIP.String(), obs.ProtocolName,
				obs.App.Protocol, obs.App.Detail, obs.App.HTTPHost, obs.App.DNSQuery,
			}, " "))
			if !strings.Contains(haystack, query) {
				continue
			}
		}
		out = append(out, obs)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// Observation returns one packet by ID.
func (s *Sensor) Observation(id uint64) (model.Observation, bool) {
	if id == 0 {
		return model.Observation{}, false
	}
	for _, obs := range s.ring.Latest(s.cfg.Memory.PacketBuffer) {
		if obs.ID == id {
			return obs, true
		}
	}
	return model.Observation{}, false
}

// Alerts returns recent alerts.
func (s *Sensor) Alerts(limit int, severity string) []alerts.Alert {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	return s.alerts.Snapshot(limit, alerts.Severity(strings.ToLower(strings.TrimSpace(severity))))
}

// Alert returns one alert record.
func (s *Sensor) Alert(id string) (alerts.Alert, bool) {
	return s.alerts.Get(id)
}

// BlocklistInfo returns the active list metadata.
func (s *Sensor) BlocklistInfo() blocklist.Info {
	return s.blocklist.Info()
}

// AddBlocklistEntry validates, persists, and atomically applies an entry.
func (s *Sensor) AddBlocklistEntry(value string) error {
	if err := s.blocklist.AddManual(value); err != nil {
		return err
	}
	s.hub.Publish(events.Event{Type: "blocklist", Data: s.blocklist.Info()})
	return nil
}

// RemoveBlocklistEntry removes one manual entry and reloads.
func (s *Sensor) RemoveBlocklistEntry(value string) error {
	if err := s.blocklist.RemoveManual(value); err != nil {
		return err
	}
	s.hub.Publish(events.Event{Type: "blocklist", Data: s.blocklist.Info()})
	return nil
}

// ReloadBlocklist re-reads files from disk.
func (s *Sensor) ReloadBlocklist() ([]string, error) {
	warnings, err := s.blocklist.Reload()
	if err == nil {
		s.hub.Publish(events.Event{Type: "blocklist", Data: s.blocklist.Info()})
	}
	return warnings, err
}

// ManualTrust returns every manual trust decision.
func (s *Sensor) ManualTrust() []intel.TrustedSource {
	return s.intel.ManualTrust()
}

// SetTrust changes contextual manual trust for one source/destination pair.
func (s *Sensor) SetTrust(destination, source string, trusted bool) error {
	dst, err := parseAddr(destination)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	src, err := parseAddr(source)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if !s.protected.Contains(dst) {
		return errors.New("destination is not inside the protected network")
	}
	if s.protected.Contains(src) {
		return errors.New("source is inside the protected network; internal sources are never blocked or trusted as external clients")
	}
	if err := s.intel.SetTrust(dst, src, trusted, time.Now()); err != nil {
		return err
	}
	s.hub.Publish(events.Event{Type: "trust", Data: map[string]any{
		"destination": dst.String(),
		"source":      src.String(),
		"trusted":     trusted,
	}})
	return nil
}

func (s *Sensor) manualTrustFor(dst netip.Addr) []intel.TrustedSource {
	out := make([]intel.TrustedSource, 0)
	for _, trusted := range s.intel.ManualTrust() {
		if trusted.Destination == dst.String() {
			out = append(out, trusted)
		}
	}
	return out
}

// Connections returns live established TCP sessions.
func (s *Sensor) Connections(limit int) ConnectionsData {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	data := ConnectionsData{Stateful: s.cfg.Detection.Stateful}
	if s.tcp != nil {
		data.Stats = s.tcp.Stats()
		data.Connections = s.tcp.Established(limit)
	}
	return data
}

func (s *Sensor) tcpStats() tcpstate.Stats {
	if s.tcp == nil {
		return tcpstate.Stats{}
	}
	return s.tcp.Stats()
}

// MitigationHistory returns recent mitigations, newest first.
func (s *Sensor) MitigationHistory(limit int) []mitigate.Action {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	return s.mitigator.History(limit)
}

// ActiveMitigations returns mitigations that are currently simulated or live.
func (s *Sensor) ActiveMitigations() []mitigate.Action {
	return s.mitigator.Active()
}

// Subscribe attaches a non-blocking live event subscriber.
func (s *Sensor) Subscribe(buffer int) *events.Subscriber {
	return s.hub.Subscribe(buffer)
}

// Unsubscribe detaches a live event subscriber.
func (s *Sensor) Unsubscribe(sub *events.Subscriber) {
	s.hub.Unsubscribe(sub)
}

// WithdrawMitigation manually withdraws one action.
func (s *Sensor) WithdrawMitigation(id, reason string) (*mitigate.Action, error) {
	action, err := s.mitigator.WithdrawNow(context.Background(), id, reason)
	if action != nil {
		s.publishAction(*action)
		if action.AlertID != "" {
			s.alerts.AttachAction(action.AlertID, action.ID, string(action.Status), summarizeAction(action))
			if alert, ok := s.alerts.Get(action.AlertID); ok {
				s.hub.Publish(events.Event{Type: "alert", Data: alert})
			}
		}
	}
	return action, err
}

// Intelligence returns reputation and destination learning facts.
func (s *Sensor) Intelligence() IntelligenceData {
	return IntelligenceData{
		Reputations:  s.intel.Reputations(500),
		Destinations: s.intel.Summaries(),
		ManualTrust:  s.intel.ManualTrust(),
		Detection:    s.detector.Parameters(),
		Profiles:     s.intel.Count(),
	}
}

// Settings returns effective configuration without the webhook URL.
func (s *Sensor) Settings() SettingsData {
	redacted := s.cfg
	redacted.Alerting.WebhookURL = ""
	return SettingsData{
		Config:            redacted,
		WebhookConfigured: s.cfg.Alerting.WebhookURL != "",
		Version:           version.Version,
		Warnings:          s.Warnings(),
	}
}

// SendTestAlert delivers a test notification synchronously and records it.
func (s *Sensor) SendTestAlert(ctx context.Context) error {
	if !s.notifier.Stats().Configured {
		return errors.New("webhook is not configured; set alerting.webhook_url and restart")
	}
	now := time.Now()
	alert, _, _ := s.alerts.Record(alerts.Candidate{
		Key:      fmt.Sprintf("test|%d", now.UnixNano()),
		Severity: alerts.SeverityInfo,
		Type:     "test",
		Layer:    "settings",
		Reason:   "Operator requested a test notification from the dashboard.",
		Signals:  []string{"delivery test only; no mitigation requested"},
	}, now)
	value := notify.Notification{
		Title:    "Dolly Sensor test notification",
		Severity: "info",
		Type:     "test",
		Reason:   "This is a test notification requested from the Dolly Sensor dashboard. No attack was detected and no mitigation was requested.",
		Signals:  []string{"delivery test only"},
		At:       now,
		Test:     true,
	}
	err := s.notifier.SendNow(ctx, value)
	if err != nil {
		last := s.notifier.Stats().LastError
		if last == "" {
			last = "delivery failed"
		}
		s.alerts.AttachAction(alert.ID, "", "failed", "Webhook delivery failed: "+last)
		if updated, ok := s.alerts.Get(alert.ID); ok {
			s.hub.Publish(events.Event{Type: "alert", Data: updated})
		}
		// Never surface the raw transport error: it can include the webhook URL
		// or an upstream response body. Stats.LastError is already redacted.
		return fmt.Errorf("webhook delivery failed: %s", last)
	}
	s.alerts.AttachAction(alert.ID, "", "delivered", "Test notification delivered.")
	if updated, ok := s.alerts.Get(alert.ID); ok {
		s.hub.Publish(events.Event{Type: "alert", Data: updated})
	}
	return nil
}

// Status returns a snapshot of counters and subsystem health.
func (s *Sensor) Status() StatusData {
	now := time.Now()
	status := StatusData{
		Version:        version.Version,
		StartedAt:      s.startedAt,
		UptimeSeconds:  now.Sub(s.startedAt).Seconds(),
		Running:        s.running.Load(),
		Simulated:      !s.cfg.BGP.Enabled,
		ProtectedCIDRs: s.protected.Strings(),
		TrustedSources: s.trusted.Strings(),
		Collector: CollectorStatus{
			Listen:           s.cfg.Collector.Listen,
			Running:          s.running.Load(),
			Workers:          s.cfg.Collector.Workers,
			QueueDepth:       len(s.datagrams),
			QueueCapacity:    cap(s.datagrams),
			FindingQueue:     len(s.findings),
			Datagrams:        s.counters.datagrams.Load(),
			DecodeErrors:     s.counters.decodeErrors.Load(),
			Observations:     s.counters.observations.Load(),
			Accepted:         s.counters.accepted.Load(),
			Internal:         s.counters.internal.Load(),
			Outbound:         s.counters.outbound.Load(),
			Ignored:          s.counters.ignored.Load(),
			DroppedDatagrams: s.counters.droppedDatagrams.Load(),
			DroppedFindings:  s.counters.droppedFindings.Load(),
			BlocklistHits:    s.counters.blocklistHits.Load(),
			FTPFindings:      s.counters.ftpFindings.Load(),
			Evaluations:      s.counters.evaluations.Load(),
			LastPacket:       timeFromUnixNano(s.last.packet.Load()),
			LastEvaluation:   timeFromUnixNano(s.lastEval.Load()),
			PacketBuffer:     s.ring.Len(),
			PacketBufferCap:  s.cfg.Memory.PacketBuffer,
		},
		TCP:             s.tcpStats(),
		DestinationLive: s.aggregate.DestinationCount(),
		Profiles:        s.intel.Count(),
		Alerts:          s.alerts.Stats(),
		Mitigation:      s.mitigator.Counts(),
		Notifier:        s.notifier.Stats(),
		Events: EventStatus{
			Clients: s.hub.Clients(),
			Dropped: s.hub.Dropped(),
		},
		Persistence:     s.intel.SaveState(),
		Detection:       s.detector.Parameters(),
		Warnings:        s.Warnings(),
		DashboardListen: s.cfg.Dashboard.Listen,
		CollectorListen: s.cfg.Collector.Listen,
	}
	if s.bgp != nil {
		bgpStatus := s.bgp.Status()
		status.BGP = &bgpStatus
	}
	return status
}

// Overview returns the landing page's complete initial state.
func (s *Sensor) Overview() OverviewData {
	now := time.Now()
	return OverviewData{
		Status:            s.Status(),
		Global:            s.aggregate.Global(now, s.cfg.Detection.RateWindowSeconds, 300),
		Detection:         s.detector.Parameters(),
		Destinations:      s.DestinationRows(200),
		RecentAlerts:      s.alerts.Snapshot(20, ""),
		RecentPackets:     s.ring.Latest(12),
		ActiveMitigations: s.mitigator.Active(),
	}
}

func parseAddr(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q", value)
	}
	return addr.Unmap(), nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
