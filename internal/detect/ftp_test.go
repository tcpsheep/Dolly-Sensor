package detect

import (
	"net/netip"
	"testing"
	"time"

	"dollysensor/internal/config"
	"dollysensor/internal/model"
	"dollysensor/internal/netutil"
)

func TestPrivilegedSourcePortOnFTPControlIsNotAServerReply(t *testing.T) {
	protected, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	tracker := newFTPTracker(config.Default().Protocols.FTP, time.Minute, protected, nil, nil)
	now := time.Now()
	obs := &model.Observation{
		ReceivedAt:       now,
		SrcIP:            netip.MustParseAddr("198.51.100.7"),
		DstIP:            netip.MustParseAddr("203.0.113.10"),
		DstProtected:     true,
		SrcPort:          21,
		DstPort:          21,
		Protocol:         6,
		ProtocolName:     "TCP",
		EstimatedPackets: 1,
	}
	findings := tracker.check(obs, now)
	for _, finding := range findings {
		if finding.Alert.Type == "ftp_privileged_port" {
			return
		}
	}
	t.Fatalf("missing privileged-source finding: %+v", findings)
}

func TestServerReplyToEphemeralPortIsNotFTPClientAbuse(t *testing.T) {
	protected, err := netutil.ParsePrefixes([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	tracker := newFTPTracker(config.Default().Protocols.FTP, time.Minute, protected, nil, nil)
	now := time.Now()
	obs := &model.Observation{
		ReceivedAt:       now,
		SrcIP:            netip.MustParseAddr("198.51.100.7"),
		DstIP:            netip.MustParseAddr("203.0.113.10"),
		DstProtected:     true,
		SrcPort:          21,
		DstPort:          50000,
		Protocol:         6,
		ProtocolName:     "TCP",
		EstimatedPackets: 100,
	}
	if findings := tracker.check(obs, now); len(findings) != 0 {
		t.Fatalf("server reply was penalised: %+v", findings)
	}
}
