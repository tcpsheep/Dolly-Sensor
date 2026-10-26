package sensor

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"dollysensor/internal/alerts"
	"dollysensor/internal/config"
	"dollysensor/internal/detect"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/sweep"
)

// evaluateSweeps turns the cross-destination sweep tracker into findings: one
// external source spraying many protected IPs (carpet bombing) and per-source
// TTL entropy. It runs on the same evaluation cadence as the per-destination
// detector but is independent of its state machine: a slow, quiet scan that
// never trips volumetric scoring is still caught here.
func (s *Sensor) evaluateSweeps(now time.Time) []detect.Finding {
	det := s.detection()
	cfg := det.Sweep
	if !cfg.Enabled {
		return nil
	}
	ttlMin := det.Signals.TTLDistinctMin
	rows, _ := s.sweeper.Snapshot(now)
	var out []detect.Finding
	for _, row := range rows {
		internal := s.protected.Contains(row.SourceAddr)
		trusted := s.trusted.Contains(row.SourceAddr) || s.intel.TrustScore(mostHitDest(row), row.SourceAddr) >= det.TrustExemptionScore
		if row.Distinct >= cfg.MinDestinations && row.Packets >= cfg.MinPackets {
			out = append(out, s.sweepFinding(row, cfg, internal, trusted))
		}
	}
	if ttlMin > 0 {
		for _, row := range s.sweeper.TTLRows(now, ttlMin, cfg.TTLMinPackets) {
			// Sources already reported as carpet bombs carry their TTL evidence
			// in that alert; this pass is for single-destination entropy.
			already := false
			for _, prior := range out {
				if prior.Alert.Source == row.Source {
					already = true
					break
				}
			}
			if !already {
				out = append(out, s.ttlFinding(row, s.protected.Contains(row.SourceAddr)))
			}
		}
	}
	return out
}

func mostHitDest(row sweep.SourceSweep) netip.Addr {
	if len(row.TopDestinations) > 0 {
		if addr, err := netip.ParseAddr(row.TopDestinations[0]); err == nil {
			return addr
		}
	}
	return netip.Addr{}
}

func (s *Sensor) sweepFinding(row sweep.SourceSweep, cfg config.SweepConfig, internal, trusted bool) detect.Finding {
	target := ""
	if row.TargetPrefix != "" {
		target = " concentrated on " + row.TargetPrefix + " (" + fmtInt(row.TargetPrefixHits) + " destinations)"
	}
	reason := fmt.Sprintf("Source %s sent %s packets to %d distinct protected destinations in the last ~30s%s.", row.Source, formatCount(row.Packets), row.Distinct, target)
	if row.DestOverflow > 0 {
		reason += fmt.Sprintf(" Destination tracking overflowed; the spread is at least %d IPs.", row.Distinct)
	}
	signals := []string{
		fmt.Sprintf("carpet bomb: %d distinct protected destinations", row.Distinct),
		fmt.Sprintf("packets: %s", formatCount(row.Packets)),
	}
	if row.DistinctTTLs > 1 {
		signals = append(signals, fmt.Sprintf("%d distinct TTL values from one source", row.DistinctTTLs))
	}
	if row.LowTTLs > 0 {
		signals = append(signals, fmt.Sprintf("%s packets arrived with TTL <= 1", formatCount(row.LowTTLs)))
	}
	severity := alerts.SeverityCritical
	if internal {
		severity = alerts.SeverityWarning
		reason += " The source is inside the protected network; external mitigation is intentionally suppressed."
	} else if trusted {
		severity = alerts.SeverityWarning
		reason += " The source is trusted; observe before blocking."
	}
	finding := detect.Finding{Alert: alerts.Candidate{
		Key:         "sweep|" + row.Source + "|" + row.TargetPrefix,
		Severity:    severity,
		Type:        "sweep",
		Layer:       "sweep",
		Destination: row.TargetPrefix,
		Source:      row.Source,
		Reason:      reason,
		Signals:     signals,
	}}
	if cfg.Action == "none" || internal || trusted || !row.SourceAddr.IsValid() {
		return finding
	}
	request := &mitigate.Request{
		Kind:   mitigate.KindFlowspec,
		Source: row.SourceAddr,
		Reason: fmt.Sprintf("carpet bomb from %s across %d protected destinations", row.Source, row.Distinct),
		Owner:  "sweep",
		Action: cfg.Action,
	}
	// Prefer a prefix-scoped rule: it protects the whole sprayed subnet at
	// once. Fall back to the single most-hit host when the aggregated prefix
	// is not fully inside a protected range (or is IPv6, which the BGP
	// encoder cannot announce yet).
	if prefix, err := netip.ParsePrefix(row.TargetPrefix); err == nil && prefix.Addr().Is4() && s.protected.ContainsPrefix(prefix) {
		request.DestinationPrefix = prefix.Masked()
	} else if len(row.TopDestinations) > 0 {
		if dst, err := netip.ParseAddr(row.TopDestinations[0]); err == nil {
			request.Destination = dst
		}
	}
	if !request.DestinationPrefix.IsValid() && !request.Destination.IsValid() {
		// Nowhere to anchor the rule; alert only.
		return finding
	}
	finding.Action = request
	return finding
}

func (s *Sensor) ttlFinding(row sweep.SourceSweep, internal bool) detect.Finding {
	reason := fmt.Sprintf("Source %s sent %s packets carrying %d distinct TTL values in the last ~30s. A single real TCP/IP stack emits an almost constant TTL; randomised values indicate forged or scripted packets.", row.Source, formatCount(row.Packets), row.DistinctTTLs)
	signals := []string{
		fmt.Sprintf("TTL entropy: %d distinct values", row.DistinctTTLs),
		fmt.Sprintf("packets: %s", formatCount(row.Packets)),
	}
	if row.LowTTLs > 0 {
		reason += fmt.Sprintf(" %s packets arrived with TTL <= 1, which a legitimate router should have dropped.", formatCount(row.LowTTLs))
		signals = append(signals, fmt.Sprintf("%s packets with TTL <= 1", formatCount(row.LowTTLs)))
	}
	if internal {
		reason += " The source is inside the protected network."
	}
	return detect.Finding{Alert: alerts.Candidate{
		Key:         "ttl|" + row.Source,
		Severity:    alerts.SeverityWarning,
		Type:        "ttl_anomaly",
		Layer:       "sweep",
		Destination: strings.Join(row.TopDestinations, ", "),
		Source:      row.Source,
		Reason:      reason,
		Signals:     signals,
	}}
}

func fmtInt(value int) string {
	return fmt.Sprintf("%d", value)
}

func formatCount(value uint64) string {
	switch {
	case value >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(value)/1_000_000)
	case value >= 1_000:
		return fmt.Sprintf("%.1fk", float64(value)/1_000)
	default:
		return fmt.Sprintf("%d", value)
	}
}
