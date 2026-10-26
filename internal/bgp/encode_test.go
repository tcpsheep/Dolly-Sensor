package bgp

import (
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"dollysensor/internal/mitigate"
)

func TestFlowspecAnnouncementUsesBytesPerSecondAndEmptyNextHop(t *testing.T) {
	action := mitigate.Action{
		Kind: mitigate.KindFlowspec,
		Match: mitigate.Match{
			Source:      "198.51.100.23/32",
			Destination: "203.0.113.50/32",
			Protocol:    6,
			DstPort:     443,
			TCPFlags:    0x02,
		},
		Action:       "rate-limit",
		RateLimitBPS: 10_000_000, // 10 Mbps in bits/s.
	}
	opts := Options{
		LocalAS:  65000,
		RouterID: netip.MustParseAddr("192.0.2.2"),
		NextHop:  netip.MustParseAddr("192.0.2.2"),
	}
	message, err := buildFlowspecAnnouncement(action, opts, true)
	if err != nil {
		t.Fatal(err)
	}
	body := bgpBody(t, message)
	attrs := body[4:]
	mpReach := findAttribute(t, attrs, attrMPReach)
	if len(mpReach) < 5 {
		t.Fatalf("MP_REACH too short: %x", mpReach)
	}
	if afi := binary.BigEndian.Uint16(mpReach[0:2]); afi != afiIPv4 {
		t.Fatalf("AFI = %d, want IPv4", afi)
	}
	if mpReach[2] != safiFlowspec {
		t.Fatalf("SAFI = %d, want Flowspec", mpReach[2])
	}
	if mpReach[3] != 0 {
		t.Fatalf("next-hop length = %d, want 0 for IPv4 Flowspec", mpReach[3])
	}
	if mpReach[4] != 0 {
		t.Fatalf("reserved byte = %d, want 0", mpReach[4])
	}
	types := flowspecComponentTypes(t, mpReach[5:])
	want := []byte{flowspecDestPrefix, flowspecSourcePrefix, flowspecProtocol, flowspecDestPort, flowspecTCPFlags}
	if len(types) != len(want) {
		t.Fatalf("component types = %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("component types = %v, want %v", types, want)
		}
	}

	ext := findAttribute(t, attrs, attrExtCommunity)
	if len(ext) != 8 {
		t.Fatalf("extended community length = %d", len(ext))
	}
	if community := binary.BigEndian.Uint16(ext[0:2]); community != extCommunityTrafficRate {
		t.Fatalf("community type = 0x%x", community)
	}
	rate := math.Float32frombits(binary.BigEndian.Uint32(ext[4:8]))
	if rate != 1_250_000 {
		t.Fatalf("wire rate = %v bytes/s, want 1,250,000 for 10 Mbps", rate)
	}
}

func TestFlowspecComponentsAreInAscendingTypeOrder(t *testing.T) {
	action := mitigate.Action{
		Kind: mitigate.KindFlowspec,
		Match: mitigate.Match{
			Destination: "203.0.113.50/32",
			Protocol:    6,
			SrcPort:     40000,
			DstPort:     443,
		},
	}
	nlri, err := buildFlowspecNLRI(action)
	if err != nil {
		t.Fatal(err)
	}
	types := flowspecComponentTypes(t, nlri)
	want := []byte{flowspecDestPrefix, flowspecProtocol, flowspecDestPort, flowspecSourcePort}
	if len(types) != len(want) {
		t.Fatalf("component types = %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("component types = %v, want %v", types, want)
		}
	}
}

func TestFlowspecDiscardUsesZeroRate(t *testing.T) {
	action := mitigate.Action{
		Kind: mitigate.KindFlowspec,
		Match: mitigate.Match{
			Source:      "198.51.100.23/32",
			Destination: "203.0.113.50/32",
			Protocol:    17,
		},
		Action: "discard",
	}
	message, err := buildFlowspecAnnouncement(action, Options{
		LocalAS:  65000,
		RouterID: netip.MustParseAddr("192.0.2.2"),
		NextHop:  netip.MustParseAddr("192.0.2.2"),
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	ext := findAttribute(t, bgpBody(t, message)[4:], attrExtCommunity)
	if rate := math.Float32frombits(binary.BigEndian.Uint32(ext[4:8])); rate != 0 {
		t.Fatalf("discard rate = %v, want 0", rate)
	}
}

func bgpBody(t *testing.T, message []byte) []byte {
	t.Helper()
	if len(message) < 19 {
		t.Fatalf("short BGP message: %d", len(message))
	}
	if length := int(binary.BigEndian.Uint16(message[16:18])); length != len(message) {
		t.Fatalf("BGP length = %d, actual %d", length, len(message))
	}
	if message[18] != msgUpdate {
		t.Fatalf("message type = %d, want UPDATE", message[18])
	}
	body := message[19:]
	if len(body) < 4 {
		t.Fatalf("short UPDATE body: %d", len(body))
	}
	if withdrawn := binary.BigEndian.Uint16(body[0:2]); withdrawn != 0 {
		t.Fatalf("withdrawn routes length = %d, want 0", withdrawn)
	}
	attrLength := int(binary.BigEndian.Uint16(body[2:4]))
	if 4+attrLength > len(body) {
		t.Fatalf("attribute length %d exceeds body %d", attrLength, len(body))
	}
	return body
}

func findAttribute(t *testing.T, attrs []byte, want byte) []byte {
	t.Helper()
	for len(attrs) > 0 {
		if len(attrs) < 3 {
			t.Fatalf("truncated path attribute")
		}
		flags := attrs[0]
		code := attrs[1]
		length := int(attrs[2])
		header := 3
		if flags&0x10 != 0 {
			if len(attrs) < 4 {
				t.Fatalf("truncated extended path attribute")
			}
			length = int(binary.BigEndian.Uint16(attrs[2:4]))
			header = 4
		}
		if header+length > len(attrs) {
			t.Fatalf("path attribute %d length exceeds buffer", code)
		}
		if code == want {
			return attrs[header : header+length]
		}
		attrs = attrs[header+length:]
	}
	t.Fatalf("attribute %d not found", want)
	return nil
}

func flowspecComponentTypes(t *testing.T, nlri []byte) []byte {
	t.Helper()
	if len(nlri) < 1 {
		t.Fatalf("empty NLRI")
	}
	count := int(nlri[0])
	offset := 1
	if count >= 240 {
		if len(nlri) < 2 {
			t.Fatalf("truncated extended-length NLRI")
		}
		count = (count&0x0f)<<8 | int(nlri[1])
		offset = 2
	}
	var types []byte
	for i := 0; i < count; i++ {
		if offset >= len(nlri) {
			t.Fatalf("component %d exceeds NLRI", i)
		}
		componentType := nlri[offset]
		offset++
		switch componentType {
		case flowspecDestPrefix, flowspecSourcePrefix:
			if offset >= len(nlri) {
				t.Fatalf("truncated prefix component")
			}
			bits := int(nlri[offset])
			offset += 1 + (bits+7)/8
		case flowspecProtocol:
			if offset >= len(nlri) {
				t.Fatalf("truncated protocol component")
			}
			offset++ // operator
			offset++ // one-byte value
		case flowspecDestPort, flowspecSourcePort, flowspecTCPFlags, flowspecPacketLength:
			// Range components chain up to two {operator, value} pairs; keep
			// consuming until an operator carries the end-of-list bit.
			for {
				if offset >= len(nlri) {
					t.Fatalf("truncated numeric component")
				}
				op := nlri[offset]
				offset++ // operator
				offset += 2
				if op&0x80 != 0 {
					break
				}
			}
		case flowspecFragment:
			if offset >= len(nlri) {
				t.Fatalf("truncated fragment component")
			}
			offset++ // operator
			offset++ // one-byte mask
		default:
			t.Fatalf("unexpected component type %d", componentType)
		}
		if offset > len(nlri) {
			t.Fatalf("component %d overran NLRI", componentType)
		}
		types = append(types, componentType)
	}
	if offset != len(nlri) {
		t.Fatalf("parsed %d of %d NLRI bytes", offset, len(nlri))
	}
	return types
}

func TestFlowspecRangeComponents(t *testing.T) {
	action := mitigate.Action{
		Kind: mitigate.KindFlowspec,
		Match: mitigate.Match{
			Destination:     "203.0.113.50/32",
			Protocol:        6,
			DstPortMin:      1024,
			DstPortMax:      65535,
			PacketLengthMin: 64,
			PacketLengthMax: 128,
		},
	}
	nlri, err := buildFlowspecNLRI(action)
	if err != nil {
		t.Fatal(err)
	}
	// destination prefix (type 1), protocol (type 3), dest-port range (type 5),
	// packet-length range (type 10).
	want := []byte{flowspecDestPrefix, flowspecProtocol, flowspecDestPort, flowspecPacketLength}
	got := flowspecComponentTypes(t, nlri)
	if len(got) != len(want) {
		t.Fatalf("component types = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("component types = %v, want %v", got, want)
		}
	}

	// Walk the NLRI to find the dest-port range component and verify the
	// chained GE/LE operator bytes: AND|GE, AND|LE|EOL.
	idx := indexOfComponent(nlri, flowspecDestPort)
	if idx < 0 {
		t.Fatal("dest-port component not found")
	}
	// Prefix component: type(1) + bits(1) + 4 address bytes = 6 bytes; protocol: 3 bytes.
	portStart := idx + 1
	if portStart+2+3 > len(nlri) {
		t.Fatalf("dest-port range truncated: %v", nlri)
	}
	geOperator := nlri[portStart]
	leOperator := nlri[portStart+3]
	geValue := binary.BigEndian.Uint16(nlri[portStart+1 : portStart+3])
	leValue := binary.BigEndian.Uint16(nlri[portStart+4 : portStart+6])
	if geOperator != operatorAnd|operatorGE {
		t.Fatalf("GE operator = 0x%02x, want 0x%02x", geOperator, operatorAnd|operatorGE)
	}
	if leOperator != operatorEOL|operatorAnd|operatorLE {
		t.Fatalf("LE operator = 0x%02x, want 0x%02x", leOperator, operatorEOL|operatorAnd|operatorLE)
	}
	if geValue != 1024 || leValue != 65535 {
		t.Fatalf("range values = %d-%d, want 1024-65535", geValue, leValue)
	}

	lenIdx := indexOfComponent(nlri, flowspecPacketLength)
	if lenIdx < 0 {
		t.Fatal("packet-length component not found")
	}
	lenStart := lenIdx + 1
	lenGe := nlri[lenStart]
	lenLe := nlri[lenStart+3]
	lenGeValue := binary.BigEndian.Uint16(nlri[lenStart+1 : lenStart+3])
	lenLeValue := binary.BigEndian.Uint16(nlri[lenStart+4 : lenStart+6])
	if lenGe != operatorAnd|operatorGE || lenLe != operatorEOL|operatorAnd|operatorLE {
		t.Fatalf("length operators = 0x%02x 0x%02x", lenGe, lenLe)
	}
	if lenGeValue != 64 || lenLeValue != 128 {
		t.Fatalf("length range = %d-%d, want 64-128", lenGeValue, lenLeValue)
	}
}

func TestFlowspecFragmentComponent(t *testing.T) {
	action := mitigate.Action{
		Kind: mitigate.KindFlowspec,
		Match: mitigate.Match{
			Destination: "203.0.113.50/32",
			Fragment:    true,
		},
	}
	nlri, err := buildFlowspecNLRI(action)
	if err != nil {
		t.Fatal(err)
	}
	idx := indexOfComponent(nlri, flowspecFragment)
	if idx < 0 {
		t.Fatalf("fragment component not found in %v", nlri)
	}
	operator := nlri[idx+1]
	mask := nlri[idx+2]
	if operator != operatorEOL|operatorEqual {
		t.Fatalf("fragment operator = 0x%02x, want 0x%02x", operator, operatorEOL|operatorEqual)
	}
	if mask != fragmentIsFragment {
		t.Fatalf("fragment mask = 0x%02x, want 0x%02x", mask, fragmentIsFragment)
	}
}

func TestFlowspecOpenEndedRangeOmitsSide(t *testing.T) {
	action := mitigate.Action{
		Kind: mitigate.KindFlowspec,
		Match: mitigate.Match{
			Destination:     "203.0.113.50/32",
			Protocol:        6,
			PacketLengthMin: 500,
		},
	}
	nlri, err := buildFlowspecNLRI(action)
	if err != nil {
		t.Fatal(err)
	}
	idx := indexOfComponent(nlri, flowspecPacketLength)
	if idx < 0 {
		t.Fatal("packet-length component not found")
	}
	// Only the GE side should be present, and it must carry EOL.
	operator := nlri[idx+1]
	value := binary.BigEndian.Uint16(nlri[idx+2 : idx+4])
	if operator != operatorEOL|operatorAnd|operatorGE {
		t.Fatalf("operator = 0x%02x, want GE|AND|EOL", operator)
	}
	if value != 500 {
		t.Fatalf("value = %d, want 500", value)
	}
	// The component after the operator is exactly 2 bytes of value; a second
	// operand would imply a max side.
	if idx+1+1+2+1 <= len(nlri) && nlri[idx+1+1+2] == byte(operatorAnd|operatorLE) {
		t.Fatal("open-ended range unexpectedly encoded a max side")
	}
}

func indexOfComponent(nlri []byte, componentType byte) int {
	count := int(nlri[0])
	offset := 1
	if count >= 240 {
		return -1
	}
	for i := 0; i < count; i++ {
		if offset >= len(nlri) {
			return -1
		}
		current := nlri[offset]
		if current == componentType {
			return offset
		}
		switch current {
		case flowspecDestPrefix, flowspecSourcePrefix:
			bits := int(nlri[offset+1])
			offset += 2 + (bits+7)/8
		case flowspecProtocol:
			offset += 3
		case flowspecDestPort, flowspecSourcePort, flowspecTCPFlags, flowspecPacketLength:
			// Range components carry up to two operands; walk by reading the
			// operator's EOL bit.
			opOffset := offset + 1
			for {
				if opOffset >= len(nlri) {
					return -1
				}
				op := nlri[opOffset]
				opOffset += 3
				if op&operatorEOL != 0 {
					break
				}
			}
			offset = opOffset
		default:
			return -1
		}
	}
	return -1
}
