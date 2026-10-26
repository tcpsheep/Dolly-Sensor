// Package detect implements Dolly Sensor's layered detection funnel and
// decision logic. It turns observations and hot aggregates into explainable
// findings: which signals fired, what the threat score is, and which mitigation
// (if any) is appropriate.
package detect

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"

	"dollysensor/internal/aggregate"
	"dollysensor/internal/alerts"
	"dollysensor/internal/config"
	"dollysensor/internal/mitigate"
	"dollysensor/internal/model"
	"dollysensor/internal/netutil"
	"dollysensor/internal/tcpstate"
)

// Intel supplies reputation facts without coupling detection to persistence.
type Intel interface {
	TrustScore(dst, src netip.Addr) float64
	SourceSummary(dst, src netip.Addr) (syn, ack, handshakes uint64, trust float64, manual bool)
}

// Options configures the detector.
type Options struct {
	Detection   config.DetectionConfig
	FTP         config.FTPConfig
	FTPStateTTL time.Duration
	Intel       Intel
	Protected   *netutil.PrefixSet
	Trusted     *netutil.PrefixSet
}

// Parameters is the effective tuning exposed in the status view.
type Parameters struct {
	Stateful        bool    `json:"stateful"`
	Threshold       float64 `json:"threshold"`
	Persistence     int     `json:"persistence"`
	PPSFloor        float64 `json:"pps_floor"`
	BPSFloor        float64 `json:"bps_floor"`
	WarmupWindows   int     `json:"warmup_windows"`
	CooldownSeconds float64 `json:"cooldown_seconds"`
	RateWindowSec   int     `json:"rate_window_seconds"`
	FTPEnabled      bool    `json:"ftp_enabled"`
}

// Finding is one explainable detection result and its proposed action.
type Finding struct {
	Alert  alerts.Candidate
	Action *mitigate.Request
}

// State is the current detection view of one destination.
type State struct {
	Destination    string    `json:"destination"`
	Threat         string    `json:"threat"`
	Score          float64   `json:"score"`
	SmoothedScore  float64   `json:"smoothed_score"`
	Threshold      float64   `json:"threshold"`
	PPS            float64   `json:"pps"`
	BPS            float64   `json:"bps"`
	BaselinePPS    float64   `json:"baseline_pps"`
	BaselineBPS    float64   `json:"baseline_bps"`
	ZPPS           float64   `json:"z_pps"`
	ZBPS           float64   `json:"z_bps"`
	Samples        int       `json:"samples"`
	Warmup         bool      `json:"warmup"`
	Attack         bool      `json:"attack"`
	Consecutive    int       `json:"consecutive"`
	OutOfStatePPS  float64   `json:"out_of_state_pps"`
	Signals        []string  `json:"signals"`
	LastEvaluation time.Time `json:"last_evaluation"`
}

// Result bundles the state update for one destination with any findings.
type Result struct {
	State    State
	Findings []Finding
}

type baseline struct {
	firstSeen   time.Time
	samples     int
	meanPPS     float64
	meanBPS     float64
	varPPS      float64
	varBPS      float64
	smoothed    float64
	consecutive int
	attack      bool
	calm        int
	lastEval    time.Time
	lastPPS     float64
	lastBPS     float64
	lastScore   float64
	signals     []string
	oosRate     float64
}

// Detector is safe for concurrent evaluation and state reads.
type Detector struct {
	mu        sync.Mutex
	cfg       config.DetectionConfig
	ftpCfg    config.FTPConfig
	intel     Intel
	protected *netutil.PrefixSet
	trusted   *netutil.PrefixSet

	threshold    float64
	persistence  int
	ppsFloor     float64
	bpsFloor     float64
	trustExempt  float64
	destinations map[netip.Addr]*baseline
	ftp          *ftpTracker
}

// New builds a detector from configuration.
func New(opts Options) *Detector {
	threshold := opts.Detection.Threshold
	if threshold <= 0 {
		threshold = config.DefaultThreatThreshold
	}
	persistence := opts.Detection.Persistence
	if persistence < 1 {
		persistence = config.DefaultPersistence
	}
	ppsFloor := opts.Detection.PPSFloor
	if ppsFloor <= 0 {
		ppsFloor = config.DefaultPPSFloor
	}
	bpsFloor := opts.Detection.BPSFloor
	if bpsFloor <= 0 {
		bpsFloor = config.DefaultBPSFloor
	}
	opts.Detection.Threshold = threshold
	opts.Detection.Persistence = persistence
	opts.Detection.PPSFloor = ppsFloor
	opts.Detection.BPSFloor = bpsFloor
	d := &Detector{
		cfg:          opts.Detection,
		ftpCfg:       opts.FTP,
		intel:        opts.Intel,
		protected:    opts.Protected,
		trusted:      opts.Trusted,
		threshold:    threshold,
		persistence:  persistence,
		ppsFloor:     ppsFloor,
		bpsFloor:     bpsFloor,
		trustExempt:  opts.Detection.TrustExemptionScore,
		destinations: map[netip.Addr]*baseline{},
	}
	if d.trustExempt <= 0 {
		d.trustExempt = 70
	}
	if opts.FTP.Enabled {
		d.ftp = newFTPTracker(opts.FTP, opts.FTPStateTTL, opts.Protected, opts.Trusted, opts.Intel)
	}
	return d
}

// Parameters returns effective tuning.
func (d *Detector) Parameters() Parameters {
	return Parameters{
		Stateful:        d.cfg.Stateful,
		Threshold:       d.threshold,
		Persistence:     d.persistence,
		PPSFloor:        d.ppsFloor,
		BPSFloor:        d.bpsFloor,
		WarmupWindows:   d.warmupWindows(),
		CooldownSeconds: d.cfg.Cooldown.Std().Seconds(),
		RateWindowSec:   d.cfg.RateWindowSeconds,
		FTPEnabled:      d.ftpCfg.Enabled,
	}
}

func (d *Detector) warmupWindows() int {
	if d.cfg.WarmupWindows < 1 {
		return 30
	}
	return d.cfg.WarmupWindows
}

// Evaluate processes one round of destination snapshots.
func (d *Detector) Evaluate(now time.Time, snapshots []aggregate.DestSnapshot, oos map[netip.Addr]tcpstate.OOSStat) []Result {
	d.mu.Lock()
	defer d.mu.Unlock()
	results := make([]Result, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if !snapshot.Addr.IsValid() {
			if addr, err := netip.ParseAddr(snapshot.Destination); err == nil {
				snapshot.Addr = addr
			} else {
				continue
			}
		}
		if now.Sub(snapshot.LastSeen) > 10*time.Second {
			// Traffic has stopped, but a destination that was under attack still
			// needs to leave attack state. Otherwise the dashboard would show an
			// alarm forever and the last score/signals would remain frozen.
			dst := snapshot.Addr.Unmap()
			if d.destinations[dst] == nil {
				continue
			}
			results = append(results, d.evaluateIdle(now, dst))
			continue
		}
		result := d.evaluateOne(now, snapshot, oos[snapshot.Addr.Unmap()])
		results = append(results, result)
	}
	return results
}

func (d *Detector) evaluateOne(now time.Time, snap aggregate.DestSnapshot, oos tcpstate.OOSStat) Result {
	dst := snap.Addr.Unmap()
	if !d.cfg.Stateful {
		oos = tcpstate.OOSStat{}
	}
	base := d.destinations[dst]
	if base == nil {
		base = &baseline{firstSeen: snap.FirstSeen}
		d.destinations[dst] = base
	}
	pps := snap.PPS
	bps := snap.BPS
	if pps < 0 {
		pps = 0
	}
	if bps < 0 {
		bps = 0
	}
	base.lastEval = now
	base.lastPPS = pps
	base.lastBPS = bps
	base.oosRate = oos.Rate

	zPPS, zBPS := 0.0, 0.0
	if base.samples >= 2 {
		zPPS = zScore(pps, base.meanPPS, base.varPPS, base.meanPPS*0.05)
		zBPS = zScore(bps, base.meanBPS, base.varBPS, base.meanBPS*0.05)
	}

	recent := snap.Recent
	total := recent.Packets
	top := topSource(recent)
	topShare := 0.0
	if total > 0 && top.Source != "" {
		topShare = float64(top.Count) / float64(total)
	}
	protocolShares := shareMap(recent.Protocols, total)
	synCount := flagCount(recent.TCPFlags, "SYN")
	ackCount := flagCount(recent.TCPFlags, "ACK")
	synShare := ratio(synCount, total)
	udpShare := protocolShares["UDP"]
	icmpShare := protocolShares["ICMP"] + protocolShares["ICMPv6"]
	dominantPort, dominantPortShare := topPort(recent.DestPorts, total)

	var topSyn, topHandshakes uint64
	var topTrust float64
	var topManual bool
	if top.SourceAddr.IsValid() && d.intel != nil {
		topSyn, _, topHandshakes, topTrust, topManual = d.intel.SourceSummary(dst, top.SourceAddr)
	}
	topGloballyTrusted := d.trusted != nil && top.SourceAddr.IsValid() && d.trusted.Contains(top.SourceAddr)
	topSourceInternal := d.protected != nil && top.SourceAddr.IsValid() && d.protected.Contains(top.SourceAddr)
	trustedTop := topManual || topGloballyTrusted || (topTrust >= d.trustExempt && topTrust > 0)

	score := 0.0
	signals := make([]string, 0, 10)
	add := func(points float64, signal string) {
		score += points
		if signal != "" && points > 0 {
			signals = append(signals, signal)
		}
	}

	ppsRatio := safeRatio(pps, d.ppsFloor)
	bpsRatio := safeRatio(bps, d.bpsFloor)
	if pps >= d.ppsFloor {
		add(10+math.Min(15, 5*math.Log2(math.Max(1, ppsRatio))), fmt.Sprintf("%s is %.1fx the configured PPS floor", formatPPS(pps), ppsRatio))
	}
	if bps >= d.bpsFloor {
		add(8+math.Min(12, 4*math.Log2(math.Max(1, bpsRatio))), fmt.Sprintf("%s is %.1fx the configured bandwidth floor", formatBPS(bps), bpsRatio))
	}
	mature := base.samples >= 3
	if mature {
		z := math.Max(zPPS, zBPS*0.8)
		switch {
		case z >= 6:
			add(22, fmt.Sprintf("rate is %.1f standard deviations above baseline", z))
		case z >= 4:
			add(18, fmt.Sprintf("rate is %.1f standard deviations above baseline", z))
		case z >= 3:
			add(14, fmt.Sprintf("rate is %.1f standard deviations above baseline", z))
		case z >= 2:
			add(8, fmt.Sprintf("rate is %.1f standard deviations above baseline", z))
		case z >= 1.5:
			add(4, fmt.Sprintf("rate is %.1f standard deviations above baseline", z))
		}
		if base.meanPPS > 0 && ppsRatio >= 1 {
			ratioToBaseline := pps / base.meanPPS
			switch {
			case ratioToBaseline >= 20:
				add(10, fmt.Sprintf("%.0fx its learned baseline", ratioToBaseline))
			case ratioToBaseline >= 8:
				add(6, fmt.Sprintf("%.0fx its learned baseline", ratioToBaseline))
			}
		}
	}
	if recent.AvgPacketSize > 0 && (pps >= d.ppsFloor*0.5 || bps >= d.bpsFloor*0.5) {
		switch {
		case recent.AvgPacketSize <= 80:
			add(10, fmt.Sprintf("tiny packets averaging %.0f bytes", recent.AvgPacketSize))
		case recent.AvgPacketSize <= 120:
			add(6, fmt.Sprintf("small packets averaging %.0f bytes", recent.AvgPacketSize))
		case recent.AvgPacketSize <= 200:
			add(3, fmt.Sprintf("smallish packets averaging %.0f bytes", recent.AvgPacketSize))
		}
	}
	if total > 0 {
		if synShare >= 0.8 {
			add(18, fmt.Sprintf("%.0f%% of packets are pure TCP SYN", synShare*100))
		} else if synShare >= 0.6 {
			add(12, fmt.Sprintf("%.0f%% of packets are pure TCP SYN", synShare*100))
		} else if synShare >= 0.4 {
			add(6, fmt.Sprintf("%.0f%% of packets are pure TCP SYN", synShare*100))
		}
		if synCount > 100 && ackCount > 0 && synCount > ackCount*4 {
			add(6, fmt.Sprintf("pure SYNs outnumber pure ACKs %.1fx", float64(synCount)/float64(ackCount)))
		}
		if udpShare >= 0.8 {
			add(10, fmt.Sprintf("%.0f%% of packets are UDP", udpShare*100))
		} else if udpShare >= 0.6 {
			add(6, fmt.Sprintf("%.0f%% of packets are UDP", udpShare*100))
		}
		if icmpShare >= 0.5 {
			add(5, fmt.Sprintf("%.0f%% of packets are ICMP", icmpShare*100))
		}
		if recent.SourceCount >= 1000 {
			add(8, fmt.Sprintf("%d distinct sources in the recent window (distributed)", recent.SourceCount))
		}
		if recent.SourceOverflow > 0 {
			add(4, fmt.Sprintf("source cardinality exceeded the tracking cap (%d packets untracked)", recent.SourceOverflow))
		}
		if topShare >= 0.8 {
			add(6, fmt.Sprintf("top source contributes %.0f%% of traffic", topShare*100))
		} else if topShare >= 0.6 {
			add(4, fmt.Sprintf("top source contributes %.0f%% of traffic", topShare*100))
		}
		if topSyn >= 100 && topHandshakes == 0 && synShare >= 0.5 {
			add(10, fmt.Sprintf("top source has %s sampled SYNs and no completed handshake", formatCount(topSyn)))
		}
	}
	if oos.Rate >= d.outOfStateFloor() {
		add(12, fmt.Sprintf("%s out-of-state TCP packets/s", formatPPS(oos.Rate)))
	}
	switch {
	case trustedTop:
		add(-12, "")
	case topTrust < 20 && top.Source != "":
		add(8, fmt.Sprintf("top source trust is %.0f/100", topTrust))
	case topTrust < 40 && top.Source != "":
		add(4, fmt.Sprintf("top source trust is %.0f/100", topTrust))
	case topTrust >= 80:
		add(-8, "")
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	warmup := base.samples < d.warmupWindows()
	if warmup && score > 45 {
		score = 45
	}
	base.smoothed = base.smoothed*0.6 + score*0.4
	if base.samples == 0 {
		base.smoothed = score
	}
	gate := pps >= d.ppsFloor*0.25 || bps >= d.bpsFloor*0.25
	if !warmup && gate && base.smoothed >= d.threshold {
		base.consecutive++
	} else {
		base.consecutive = 0
	}
	if !base.attack && base.consecutive >= d.persistence {
		base.attack = true
		base.calm = 0
	}
	if base.attack {
		if base.smoothed < d.threshold*0.5 {
			base.calm++
			if base.calm >= 5 {
				base.attack = false
				base.consecutive = 0
			}
		} else {
			base.calm = 0
		}
	}
	base.lastScore = score
	base.signals = append([]string(nil), signals...)

	state := State{
		Destination:    dst.String(),
		Score:          round(score, 1),
		SmoothedScore:  round(base.smoothed, 1),
		Threshold:      d.threshold,
		PPS:            pps,
		BPS:            bps,
		BaselinePPS:    base.meanPPS,
		BaselineBPS:    base.meanBPS,
		ZPPS:           round(zPPS, 2),
		ZBPS:           round(zBPS, 2),
		Samples:        base.samples,
		Warmup:         warmup,
		Attack:         base.attack,
		Consecutive:    base.consecutive,
		OutOfStatePPS:  oos.Rate,
		Signals:        append([]string(nil), signals...),
		LastEvaluation: now,
	}
	switch {
	case base.attack:
		state.Threat = "under_attack"
	case warmup:
		state.Threat = "learning"
	case base.smoothed >= d.threshold:
		state.Threat = "anomalous"
	default:
		state.Threat = "clean"
	}

	result := Result{State: state}
	haveFinding := false
	if base.attack && gate {
		finding, action := d.volumetricFinding(now, dst, snap, state, top, topShare, topTrust, trustedTop, topSourceInternal, protocolShares, synShare, dominantPort, dominantPortShare, oos)
		result.Findings = append(result.Findings, finding)
		haveFinding = action != nil
	} else if warmup && gate && (pps >= d.ppsFloor*2 || bps >= d.bpsFloor*2) && (synShare >= 0.6 || pps >= d.ppsFloor*4) {
		reason := fmt.Sprintf("Baseline is still learning (%d/%d samples): traffic to %s is %s / %s. This is an observation, not a confirmed attack, and no statistical mitigation is applied during warm-up.", base.samples, d.warmupWindows(), dst, formatPPS(pps), formatBPS(bps))
		if synShare >= 0.6 {
			reason += fmt.Sprintf(" %.0f%% of packets are pure TCP SYN.", synShare*100)
		}
		result.Findings = append(result.Findings, Finding{Alert: alerts.Candidate{
			Key:         "warmup|" + dst.String(),
			Severity:    alerts.SeverityWarning,
			Type:        "warmup",
			Layer:       "volumetric",
			Destination: dst.String(),
			Source:      top.Source,
			Score:       state.SmoothedScore,
			Reason:      reason,
			Signals:     signals,
		}})
	}

	// Layer 2: behavioural reputation. This can fire before the statistical
	// layer has enough persistence, when the source's own history is damning.
	if !haveFinding && base.samples >= 2 && !warmup && gate && top.SourceAddr.IsValid() && topShare >= 0.5 && topSyn >= 100 && topHandshakes == 0 && synShare >= 0.6 && pps >= math.Max(200, d.ppsFloor*0.25) && !trustedTop && !topSourceInternal {
		reason := fmt.Sprintf("Probable SYN flood toward %s: top source %s has %s sampled SYNs and 0 completed handshakes; the destination saw %s (%s) with %.0f%% pure SYN.", dst, top.Source, formatCount(topSyn), formatPPS(pps), formatBPS(bps), synShare*100)
		action := &mitigate.Request{
			Kind:        mitigate.KindFlowspec,
			Source:      top.SourceAddr,
			Destination: dst,
			Protocol:    6,
			DstPort:     dominantPort,
			TCPFlags:    0x02,
			Action:      "rate-limit",
			Reason:      "reputation: probable SYN flood from " + top.Source,
			Owner:       "reputation",
		}
		if pps >= d.ppsFloor*2 {
			action.Action = "discard"
		}
		result.Findings = append(result.Findings, Finding{
			Alert: alerts.Candidate{
				Key:         "syn-flood|" + dst.String() + "|" + top.Source,
				Severity:    alerts.SeverityCritical,
				Type:        "syn_flood",
				Layer:       "reputation",
				Destination: dst.String(),
				Source:      top.Source,
				Score:       state.SmoothedScore,
				Reason:      reason,
				Signals:     append(signals, "behavioural reputation: no handshake evidence"),
			},
			Action: action,
		})
		haveFinding = true
	}

	// Layer 3: out-of-state TCP at meaningful rate.
	if !haveFinding && oos.Rate >= d.outOfStateFloor() {
		severity := alerts.SeverityWarning
		if oos.Rate >= math.Max(d.outOfStateFloor()*5, 500) {
			severity = alerts.SeverityCritical
		}
		share := ratio(oos.OutOfState, oos.Total)
		reason := fmt.Sprintf("%s out-of-state TCP packets/s toward %s (%.0f%% of recent TCP), with no plausible session. Sampled traffic can miss handshakes, so this is corroborating evidence rather than proof.", formatPPS(oos.Rate), dst, share*100)
		if trustedTop {
			severity = alerts.SeverityWarning
			reason += " The dominant source is trusted; out-of-state evidence alone is not enough to mitigate it."
		} else if topSourceInternal {
			reason += " The dominant source is inside the protected network; external mitigation is intentionally suppressed."
		}
		finding := Finding{Alert: alerts.Candidate{
			Key:         "tcp-state|" + dst.String(),
			Severity:    severity,
			Type:        "tcp_out_of_state",
			Layer:       "tcp",
			Destination: dst.String(),
			Source:      top.Source,
			Score:       state.SmoothedScore,
			Reason:      reason,
			Signals:     []string{fmt.Sprintf("%s of %s recent TCP packets had no tracked session", formatCount(oos.OutOfState), formatCount(oos.Total))},
		}}
		if severity == alerts.SeverityCritical && !trustedTop && !topSourceInternal {
			request := &mitigate.Request{
				Kind:        mitigate.KindFlowspec,
				Destination: dst,
				Protocol:    6,
				Action:      "rate-limit",
				Reason:      "out-of-state TCP toward " + dst.String(),
				Owner:       "tcp-state",
			}
			// Name the source when it clearly dominates. Otherwise keep the
			// rule destination-oriented rather than blaming an arbitrary top
			// source in a distributed out-of-state flood.
			if top.SourceAddr.IsValid() && topShare >= 0.6 {
				request.Source = top.SourceAddr
			}
			finding.Action = request
		}
		result.Findings = append(result.Findings, finding)
	}

	d.updateBaseline(base, pps, bps, warmup)
	return result
}

// evaluateIdle advances a destination with no recent traffic. It decays the
// smoothed score without teaching the baseline night-time zeroes, clears
// attack state after the usual calm window, and drops stale evidence.
func (d *Detector) evaluateIdle(now time.Time, dst netip.Addr) Result {
	base := d.destinations[dst]
	base.lastEval = now
	base.lastPPS = 0
	base.lastBPS = 0
	base.oosRate = 0
	base.lastScore = 0
	base.signals = nil
	base.consecutive = 0
	base.smoothed *= 0.6
	if base.attack {
		if base.smoothed < d.threshold*0.5 {
			base.calm++
			if base.calm >= 5 {
				base.attack = false
				base.calm = 0
			}
		} else {
			base.calm = 0
		}
	}
	return Result{State: stateFromBaseline(dst, base, d.threshold, d.warmupWindows(), d.outOfStateFloor())}
}

func (d *Detector) volumetricFinding(now time.Time, dst netip.Addr, snap aggregate.DestSnapshot, state State, top aggregate.SourceCount, topShare, topTrust float64, trusted, internal bool, protocols map[string]float64, synShare float64, dominantPort uint16, dominantPortShare float64, oos tcpstate.OOSStat) (Finding, *mitigate.Request) {
	severity := alerts.SeverityCritical
	qualified := true
	if internal {
		severity = alerts.SeverityCritical
		qualified = false
	}
	if trusted && !internal {
		strong := state.PPS >= d.ppsFloor*20 || (synShare >= 0.85 && state.PPS >= d.ppsFloor*5) || state.SmoothedScore >= d.threshold+25
		if !strong {
			severity = alerts.SeverityWarning
			qualified = false
		}
	}
	reason := fmt.Sprintf("Traffic to %s rose to %s / %s", dst, formatPPS(state.PPS), formatBPS(state.BPS))
	if state.BaselinePPS > 0 {
		reason += fmt.Sprintf(" (%.0fx its learned baseline of %s)", safeRatio(state.PPS, state.BaselinePPS), formatPPS(state.BaselinePPS))
	}
	if snap.Recent.AvgPacketSize > 0 {
		reason += fmt.Sprintf(", averaging %.0f B", snap.Recent.AvgPacketSize)
	}
	if synShare >= 0.3 {
		reason += fmt.Sprintf(", %.0f%% pure TCP SYN", synShare*100)
	} else if protocols["UDP"] >= 0.3 {
		reason += fmt.Sprintf(", %.0f%% UDP", protocols["UDP"]*100)
	}
	if top.Source != "" {
		reason += fmt.Sprintf("; top source %s contributes %.0f%% (trust %.0f)", top.Source, topShare*100, topTrust)
	}
	reason += "."
	if synShare < 0.3 {
		if topSyn, _, handshakes, _, _ := d.sourceStats(dst, top.SourceAddr); topSyn >= 100 && handshakes == 0 {
			reason += fmt.Sprintf(" The top source has %s sampled SYNs and 0 completed handshakes.", formatCount(topSyn))
		}
	}
	if internal {
		reason += " The dominant source is inside the protected network; external mitigation is intentionally suppressed."
	} else if trusted && severity == alerts.SeverityWarning {
		reason += " The dominant source is trusted and the evidence is not strong enough to justify mitigation."
	} else if trusted && severity == alerts.SeverityCritical {
		reason += " The dominant source is trusted, but the volume is extreme; only a rate-limit is considered."
	}
	if oos.Rate > 0 {
		reason += fmt.Sprintf(" Out-of-state TCP is running at %s.", formatPPS(oos.Rate))
	}
	signals := append([]string(nil), state.Signals...)
	if top.Source != "" {
		signals = append(signals, fmt.Sprintf("top source %s at %.0f%% share, trust %.0f", top.Source, topShare*100, topTrust))
	}
	finding := Finding{Alert: alerts.Candidate{
		Key:         "volumetric|" + dst.String(),
		Severity:    severity,
		Type:        "volumetric",
		Layer:       "volumetric",
		Destination: dst.String(),
		Source:      top.Source,
		Score:       state.SmoothedScore,
		Reason:      reason,
		Signals:     signals,
	}}
	if !qualified {
		return finding, nil
	}
	protocol := chooseProtocol(protocols)
	if protocol == 0 {
		return finding, nil
	}
	precise := top.SourceAddr.IsValid() && topShare >= 0.6 && !d.protected.Contains(top.SourceAddr)
	topSyn, _, handshakes, _, _ := d.sourceStats(dst, top.SourceAddr)
	// RTBH is deliberately rare. It is only for a confirmed, extreme SYN flood
	// from one external source that has never completed a handshake. Everything
	// else gets a precise Flowspec rule. This keeps a blunt blackhole out of
	// ambiguous or distributed incidents.
	severeRTBH := precise && !trusted && protocol == 6 && synShare >= 0.5 &&
		topShare >= 0.9 && topTrust < 20 && topSyn >= 1_000 && handshakes == 0 &&
		state.SmoothedScore >= d.threshold+20 &&
		(state.PPS >= math.Max(d.ppsFloor*200, 1_000_000) ||
			state.BPS >= math.Max(d.bpsFloor*50, 1_000_000_000))
	if severeRTBH {
		finding.Alert.Reason += " A single external source dominates this extreme SYN flood; a host-route RTBH is proposed."
		finding.Action = &mitigate.Request{
			Kind:   mitigate.KindRTBH,
			Source: top.SourceAddr,
			Reason: fmt.Sprintf("severe single-source SYN flood toward %s: %s / %s", dst, formatPPS(state.PPS), formatBPS(state.BPS)),
			Owner:  "volumetric",
			Action: "discard",
		}
		return finding, finding.Action
	}
	request := &mitigate.Request{
		Kind:        mitigate.KindFlowspec,
		Destination: dst,
		Protocol:    protocol,
		Reason:      fmt.Sprintf("volumetric attack toward %s: %s / %s", dst, formatPPS(state.PPS), formatBPS(state.BPS)),
		Owner:       "volumetric",
		Action:      "rate-limit",
	}
	if protocol == 6 || protocol == 17 {
		if dominantPort != 0 && dominantPortShare >= 0.8 {
			request.DstPort = dominantPort
		}
	}
	if protocol == 6 && synShare >= 0.5 {
		request.TCPFlags = 0x02
	}
	strong := state.SmoothedScore >= d.threshold+15 && (synShare >= 0.5 || topTrust < 40)
	if precise {
		request.Source = top.SourceAddr
		if strong && !trusted {
			request.Action = "discard"
		}
	} else {
		// Distributed attacks get a destination-oriented rate-limit. A
		// destination-only discard would be a blackhole of a protected service.
		request.Action = "rate-limit"
		request.Source = netip.Addr{}
	}
	if trusted {
		request.Action = "rate-limit"
	}
	if oos.Rate >= d.outOfStateFloor() {
		request.Protocol = 6
		request.DstPort = 0
		request.TCPFlags = 0
		if request.Source.IsValid() {
			request.Action = "rate-limit"
		}
	}
	finding.Action = request
	_ = now
	return finding, request
}

func (d *Detector) sourceStats(dst, src netip.Addr) (uint64, uint64, uint64, float64, bool) {
	if d.intel == nil || !src.IsValid() {
		return 0, 0, 0, 0, false
	}
	return d.intel.SourceSummary(dst, src)
}

func (d *Detector) updateBaseline(base *baseline, pps, bps float64, warmup bool) {
	if base.attack || warmup && base.samples == 0 {
		if base.samples == 0 {
			base.meanPPS = pps
			base.meanBPS = bps
			base.samples = 1
		}
		return
	}
	obvious := pps > math.Max(d.ppsFloor*4, base.meanPPS*8) || bps > math.Max(d.bpsFloor*4, base.meanBPS*8)
	if base.attack || obvious {
		return
	}
	const alpha = 0.04
	if base.samples == 0 {
		base.meanPPS = pps
		base.meanBPS = bps
		base.samples = 1
		return
	}
	deltaPPS := pps - base.meanPPS
	base.meanPPS += alpha * deltaPPS
	base.varPPS = (1 - alpha) * (base.varPPS + alpha*deltaPPS*deltaPPS)
	deltaBPS := bps - base.meanBPS
	base.meanBPS += alpha * deltaBPS
	base.varBPS = (1 - alpha) * (base.varBPS + alpha*deltaBPS*deltaBPS)
	base.samples++
}

func (d *Detector) outOfStateFloor() float64 {
	if d.cfg.OutOfStateMinPPS > 0 {
		return d.cfg.OutOfStateMinPPS
	}
	return 100
}

// CheckFTP runs the application filter for one observation. It returns zero or
// more findings.
func (d *Detector) CheckFTP(obs *model.Observation, now time.Time) []Finding {
	if d.ftp == nil {
		return nil
	}
	return d.ftp.check(obs, now)
}

// State returns the last detection state for a destination.
func (d *Detector) State(dst netip.Addr) (State, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	base := d.destinations[dst.Unmap()]
	if base == nil || base.lastEval.IsZero() {
		return State{}, false
	}
	return stateFromBaseline(dst, base, d.threshold, d.warmupWindows(), d.outOfStateFloor()), true
}

// States returns every recent detection state.
func (d *Detector) States() []State {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]State, 0, len(d.destinations))
	for dst, base := range d.destinations {
		if base.lastEval.IsZero() {
			continue
		}
		out = append(out, stateFromBaseline(dst, base, d.threshold, d.warmupWindows(), d.outOfStateFloor()))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Destination < out[j].Destination })
	return out
}

func stateFromBaseline(dst netip.Addr, base *baseline, threshold float64, warmup int, oosFloor float64) State {
	state := State{
		Destination:    dst.String(),
		Score:          round(base.lastScore, 1),
		SmoothedScore:  round(base.smoothed, 1),
		Threshold:      threshold,
		PPS:            base.lastPPS,
		BPS:            base.lastBPS,
		BaselinePPS:    base.meanPPS,
		BaselineBPS:    base.meanBPS,
		Samples:        base.samples,
		Warmup:         base.samples < warmup,
		Attack:         base.attack,
		Consecutive:    base.consecutive,
		OutOfStatePPS:  base.oosRate,
		Signals:        append([]string(nil), base.signals...),
		LastEvaluation: base.lastEval,
	}
	switch {
	case base.attack:
		state.Threat = "under_attack"
	case state.Warmup:
		state.Threat = "learning"
	case base.smoothed >= threshold:
		state.Threat = "anomalous"
	default:
		state.Threat = "clean"
	}
	return state
}

// Cleanup forgets idle baseline state and FTP counters.
func (d *Detector) Cleanup(now time.Time, ttl time.Duration) {
	d.mu.Lock()
	for dst, base := range d.destinations {
		if base.lastEval.IsZero() || now.Sub(base.lastEval) > ttl {
			delete(d.destinations, dst)
		}
	}
	d.mu.Unlock()
	if d.ftp != nil {
		d.ftp.cleanup(now)
	}
}

func topSource(recent aggregate.Recent) aggregate.SourceCount {
	if len(recent.Sources) == 0 {
		return aggregate.SourceCount{}
	}
	return recent.Sources[0]
}

func topPort(ports []aggregate.PortCount, total uint64) (uint16, float64) {
	if len(ports) == 0 || total == 0 {
		return 0, 0
	}
	return ports[0].Port, float64(ports[0].Count) / float64(total)
}

func shareMap(counts []aggregate.Count, total uint64) map[string]float64 {
	out := map[string]float64{}
	if total == 0 {
		return out
	}
	for _, count := range counts {
		out[count.Name] = float64(count.Count) / float64(total)
	}
	return out
}

func flagCount(counts []aggregate.Count, name string) uint64 {
	for _, count := range counts {
		if count.Name == name {
			return count.Count
		}
	}
	return 0
}

func chooseProtocol(shares map[string]float64) uint8 {
	best := ""
	bestShare := 0.0
	for name, share := range shares {
		if share > bestShare {
			best = name
			bestShare = share
		}
	}
	switch best {
	case "TCP":
		return 6
	case "UDP":
		return 17
	case "ICMP":
		return 1
	case "ICMPv6":
		return 58
	default:
		return 0
	}
}

func zScore(value, mean, variance, minStd float64) float64 {
	std := math.Sqrt(math.Max(0, variance))
	if std < minStd {
		std = minStd
	}
	if std == 0 {
		return 0
	}
	return (value - mean) / std
}

func ratio(part, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total)
}

func safeRatio(value, reference float64) float64 {
	if reference <= 0 {
		return 0
	}
	return value / reference
}

func round(value float64, places int) float64 {
	factor := math.Pow(10, float64(places))
	return math.Round(value*factor) / factor
}

func formatPPS(value float64) string {
	switch {
	case value >= 1_000_000:
		return fmt.Sprintf("%.2fM pps", value/1_000_000)
	case value >= 1_000:
		return fmt.Sprintf("%.1fk pps", value/1_000)
	default:
		return fmt.Sprintf("%.0f pps", value)
	}
}

func formatBPS(value float64) string {
	switch {
	case value >= 1_000_000_000:
		return fmt.Sprintf("%.2f Gbps", value/1_000_000_000)
	case value >= 1_000_000:
		return fmt.Sprintf("%.1f Mbps", value/1_000_000)
	case value >= 1_000:
		return fmt.Sprintf("%.1f kbps", value/1_000)
	default:
		return fmt.Sprintf("%.0f bps", value)
	}
}

func formatCount(value uint64) string {
	if value >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(value)/1_000_000)
	}
	if value >= 1_000 {
		return fmt.Sprintf("%.1fk", float64(value)/1_000)
	}
	return fmt.Sprintf("%d", value)
}
