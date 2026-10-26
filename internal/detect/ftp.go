package detect

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"dollysensor/internal/alerts"
	"dollysensor/internal/config"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/model"
	"dollysensor/internal/netutil"
)

const ftpWindowSeconds = 5

type ftpKey struct {
	destination netip.Addr
	source      netip.Addr
	port        uint16
}

type ftpBucket struct {
	second  int64
	packets uint64
}

type ftpState struct {
	firstSeen     time.Time
	lastSeen      time.Time
	buckets       [8]ftpBucket
	lastRateAlert time.Time
	lastCmdAlert  time.Time
}

type ftpTracker struct {
	mu        sync.Mutex
	cfg       config.FTPConfig
	ttl       time.Duration
	protected *netutil.PrefixSet
	trusted   *netutil.PrefixSet
	intel     Intel
	states    map[ftpKey]*ftpState
}

func newFTPTracker(cfg config.FTPConfig, ttl time.Duration, protected, trusted *netutil.PrefixSet, intel Intel) *ftpTracker {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &ftpTracker{
		cfg:       cfg,
		ttl:       ttl,
		protected: protected,
		trusted:   trusted,
		intel:     intel,
		states:    map[ftpKey]*ftpState{},
	}
}

func (f *ftpTracker) check(obs *model.Observation, now time.Time) []Finding {
	if !f.cfg.Enabled || obs == nil || !obs.DstProtected || !obs.DstIP.IsValid() || !obs.SrcIP.IsValid() {
		return nil
	}
	if now.IsZero() {
		now = obs.ReceivedAt
	}
	src := obs.SrcIP.Unmap()
	dst := obs.DstIP.Unmap()
	if f.protected != nil && f.protected.Contains(src) {
		return nil
	}
	if f.isTrusted(dst, src) {
		return nil
	}
	// This tracker only receives traffic whose protected destination is the FTP
	// service port. In that direction the source is the client; a privileged
	// source port is suspicious, not a legitimate server reply. Server-to-client
	// replies have an ephemeral destination and do not reach this check.
	if obs.DstPort != 21 && obs.DstPort != 20 {
		return nil
	}

	if obs.Protocol != 6 {
		protocol := obs.Protocol
		finding := Finding{Alert: alerts.Candidate{
			Key:         fmt.Sprintf("ftp-protocol|%s|%s", dst, src),
			Severity:    alerts.SeverityCritical,
			Type:        "ftp_protocol",
			Layer:       "application",
			Destination: dst.String(),
			Source:      src.String(),
			Reason:      fmt.Sprintf("Non-TCP %s traffic from %s to FTP service port %d on %s. FTP control and data channels are TCP-only.", obs.ProtocolName, src, obs.DstPort, dst),
			Signals:     []string{"direction: client to server", "protocol mismatch on FTP service port"},
		}}
		if protocol != 0 {
			request := &mitigate.Request{
				Kind:        mitigate.KindFlowspec,
				Source:      src,
				Destination: dst,
				Protocol:    protocol,
				Reason:      fmt.Sprintf("non-TCP traffic to FTP service port %d on %s", obs.DstPort, dst),
				Owner:       "ftp",
				Action:      "discard",
			}
			if protocol == 6 || protocol == 17 {
				request.DstPort = obs.DstPort
			}
			finding.Action = request
		}
		return []Finding{finding}
	}

	var findings []Finding
	if obs.SrcPort < 1024 {
		findings = append(findings, Finding{Alert: alerts.Candidate{
			Key:         fmt.Sprintf("ftp-privileged|%s|%s", dst, src),
			Severity:    alerts.SeverityWarning,
			Type:        "ftp_privileged_port",
			Layer:       "application",
			Destination: dst.String(),
			Source:      src.String(),
			Reason:      fmt.Sprintf("Client %s used privileged source port %d toward FTP service port %d on %s. Normal clients use ephemeral source ports.", src, obs.SrcPort, obs.DstPort, dst),
			Signals:     []string{"direction: client to server", fmt.Sprintf("source port %d < 1024", obs.SrcPort)},
		}})
	}

	key := ftpKey{destination: dst, source: src, port: obs.DstPort}
	f.mu.Lock()
	state := f.states[key]
	if state == nil {
		state = &ftpState{firstSeen: now}
		f.states[key] = state
	}
	state.lastSeen = now
	second := now.Unix()
	index := int(second % int64(len(state.buckets)))
	if state.buckets[index].second != second {
		state.buckets[index] = ftpBucket{second: second}
	}
	packets := obs.EstimatedPackets
	if packets == 0 {
		packets = 1
	}
	state.buckets[index].packets += packets
	var windowPackets uint64
	cutoff := second - ftpWindowSeconds
	for _, bucket := range state.buckets {
		if bucket.second > cutoff && bucket.second <= second {
			windowPackets += bucket.packets
		}
	}
	seconds := float64(ftpWindowSeconds)
	if now.Sub(state.firstSeen) < ftpWindowSeconds*time.Second {
		seconds = now.Sub(state.firstSeen).Seconds() + 1
		if seconds < 1 {
			seconds = 1
		}
	}
	rate := float64(windowPackets) / seconds
	limit := f.cfg.ControlRateLimitPPS
	channel := "control"
	if obs.DstPort == 20 {
		limit = f.cfg.DataRateLimitPPS
		channel = "data"
	}
	rateAlert := false
	if limit > 0 && rate > limit && now.Sub(state.lastRateAlert) >= 5*time.Second {
		state.lastRateAlert = now
		rateAlert = true
	}
	f.mu.Unlock()

	if rateAlert {
		severity := alerts.SeverityCritical
		reason := fmt.Sprintf("FTP %s flood: %s sent %s toward %s:%d over the last %d seconds (limit %.0f pps).", channel, src, formatPPS(rate), dst, obs.DstPort, ftpWindowSeconds, limit)
		request := &mitigate.Request{
			Kind:        mitigate.KindFlowspec,
			Source:      src,
			Destination: dst,
			Protocol:    6,
			DstPort:     obs.DstPort,
			Action:      "rate-limit",
			Reason:      fmt.Sprintf("FTP %s flood from %s", channel, src),
			Owner:       "ftp",
			Duration:    f.cfg.BlockDuration.Std(),
		}
		if rate > limit*4 {
			request.Action = "discard"
		}
		findings = append(findings, Finding{
			Alert: alerts.Candidate{
				Key:         fmt.Sprintf("ftp-%s|%s|%s", channel, dst, src),
				Severity:    severity,
				Type:        "ftp_" + channel,
				Layer:       "application",
				Destination: dst.String(),
				Source:      src.String(),
				Reason:      reason,
				Signals:     []string{"direction: client to server", fmt.Sprintf("%.0f%% above the configured %.0f pps limit", (rate/limit-1)*100, limit), "trust below exemption threshold"},
			},
			Action: request,
		})
	}

	if obs.DstPort == 21 && len(obs.Payload) > 0 {
		malformed := ""
		if f.cfg.MaxCommandBytes > 0 && len(obs.Payload) > f.cfg.MaxCommandBytes {
			malformed = fmt.Sprintf("oversized FTP command (%d captured bytes, limit %d)", len(obs.Payload), f.cfg.MaxCommandBytes)
		} else if hasControlBytes(obs.Payload) {
			malformed = "FTP control payload contains unexpected control bytes"
		}
		if malformed != "" && (obs.SessionState == "established" || obs.SessionState == "") {
			f.mu.Lock()
			state := f.states[key]
			allowed := state == nil || now.Sub(state.lastCmdAlert) >= 5*time.Second
			if state != nil && allowed {
				state.lastCmdAlert = now
			}
			f.mu.Unlock()
			if allowed {
				findings = append(findings, Finding{Alert: alerts.Candidate{
					Key:         fmt.Sprintf("ftp-command|%s|%s", dst, src),
					Severity:    alerts.SeverityWarning,
					Type:        "ftp_command",
					Layer:       "application",
					Destination: dst.String(),
					Source:      src.String(),
					Reason:      fmt.Sprintf("%s from %s toward %s:21. %s", strings.ToUpper(malformed[:1])+malformed[1:], src, dst, preview(obs.Payload, 80)),
					Signals:     []string{"direction: client to server", "established or sampled control channel"},
				}})
			}
		}
	}
	return findings
}

func (f *ftpTracker) isTrusted(dst, src netip.Addr) bool {
	if f.trusted != nil && f.trusted.Contains(src) {
		return true
	}
	if f.intel == nil || f.cfg.ExemptTrustScore <= 0 {
		return false
	}
	return f.intel.TrustScore(dst, src) >= f.cfg.ExemptTrustScore
}

func (f *ftpTracker) cleanup(now time.Time) {
	ttl := f.ttl
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, state := range f.states {
		if now.Sub(state.lastSeen) > ttl {
			delete(f.states, key)
		}
	}
}

func hasControlBytes(payload []byte) bool {
	for _, c := range payload {
		if c == '\r' || c == '\n' || c == '\t' {
			continue
		}
		if c < 32 || c == 127 {
			return true
		}
	}
	return false
}

func preview(payload []byte, limit int) string {
	if limit <= 0 || limit > len(payload) {
		limit = len(payload)
	}
	var b strings.Builder
	for _, c := range payload[:limit] {
		if c >= 32 && c <= 126 {
			b.WriteByte(c)
		} else if c == '\r' {
			continue
		} else if c == '\n' {
			b.WriteByte(' ')
		} else {
			b.WriteByte('.')
		}
	}
	return strings.TrimSpace(b.String())
}
