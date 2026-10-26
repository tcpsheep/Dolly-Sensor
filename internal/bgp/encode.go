package bgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"

	"dollysensor/internal/mitigate"
)

const (
	msgOpen         = 1
	msgUpdate       = 2
	msgNotification = 3
	msgKeepalive    = 4

	asTrans = 23456

	attrOrigin       = 1
	attrASPath       = 2
	attrNextHop      = 3
	attrCommunity    = 8
	attrMPReach      = 14
	attrMPUnreach    = 15
	attrExtCommunity = 16
	attrAS4Path      = 17

	capMultiprotocol = 1
	capAS4           = 65

	afiIPv4      = 1
	safiUnicast  = 1
	safiFlowspec = 133

	flowspecDestPrefix   = 1
	flowspecSourcePrefix = 2
	flowspecProtocol     = 3
	flowspecDestPort     = 5
	flowspecSourcePort   = 6
	flowspecTCPFlags     = 9
	flowspecPacketLength = 10
	flowspecFragment     = 12

	// Numeric operator bits per RFC 8955 section 4.2.1.1. The low three bits
	// carry lt/gt/eq; 0x40 is the AND bit chaining comparisons in one
	// component; 0x80 is end-of-list.
	operatorEOL   = 0x80
	operatorAnd   = 0x40
	operatorEqual = 0x01
	operatorGT    = 0x02
	operatorGE    = 0x04
	operatorLT    = 0x08
	operatorLE    = 0x10

	// Fragment bitmask per RFC 8955: bit 0 (LSB) is "is a fragment other than
	// the first", bit 1 is "is a first fragment", bit 2 "is a last fragment",
	// bit 3 "is not a fragment". We only need "is a fragment".
	fragmentIsFragment = 0x01

	extCommunityTrafficRate = 0x8006
)

// buildOpen creates a BGP OPEN message.
func buildOpen(opts Options) ([]byte, error) {
	routerID, err := routerIDUint32(opts.RouterID)
	if err != nil {
		return nil, err
	}
	myAS := opts.LocalAS
	if myAS > 65535 {
		myAS = asTrans
	}
	hold := uint16(opts.HoldTime.Seconds())
	if hold < 3 {
		hold = 3
	}

	var capabilities []byte
	appendCapability := func(code byte, data []byte) {
		capabilities = append(capabilities, code, byte(len(data)))
		capabilities = append(capabilities, data...)
	}
	// Four-octet AS capability.
	as4 := make([]byte, 4)
	binary.BigEndian.PutUint32(as4, opts.LocalAS)
	appendCapability(capAS4, as4)
	// Multiprotocol: IPv4 unicast and IPv4 Flowspec.
	for _, safi := range []uint8{safiUnicast, safiFlowspec} {
		mp := make([]byte, 4)
		binary.BigEndian.PutUint16(mp[0:2], afiIPv4)
		mp[2] = 0
		mp[3] = safi
		appendCapability(capMultiprotocol, mp)
	}
	if len(capabilities) > 255 {
		return nil, errors.New("BGP capabilities too large")
	}

	body := make([]byte, 10)
	body[0] = 4
	binary.BigEndian.PutUint16(body[1:3], uint16(myAS))
	binary.BigEndian.PutUint16(body[3:5], hold)
	binary.BigEndian.PutUint32(body[5:9], routerID)
	body[9] = byte(len(capabilities) + 2)
	body = append(body, 2, byte(len(capabilities)))
	body = append(body, capabilities...)
	return bgpMessage(msgOpen, body), nil
}

// buildAnnouncement builds the UPDATE for an action. as4 indicates that the
// peer advertised four-octet AS support.
func buildAnnouncement(action mitigate.Action, opts Options, as4 bool) ([]byte, error) {
	switch action.Kind {
	case mitigate.KindRTBH:
		return buildRTBHAnnouncement(action, opts, as4)
	case mitigate.KindFlowspec:
		return buildFlowspecAnnouncement(action, opts, as4)
	default:
		return nil, fmt.Errorf("unsupported action kind %q", action.Kind)
	}
}

func buildWithdrawal(action mitigate.Action, opts Options, as4 bool) ([]byte, error) {
	switch action.Kind {
	case mitigate.KindRTBH:
		prefix, err := parseIPv4Prefix(action.Match.Source)
		if err != nil {
			return nil, err
		}
		if prefix.Bits() != 32 {
			return nil, errors.New("RTBH withdrawal target must be a /32")
		}
		withdrawn := encodeNLRI(prefix)
		body := make([]byte, 2+len(withdrawn))
		binary.BigEndian.PutUint16(body[0:2], uint16(len(withdrawn)))
		copy(body[2:], withdrawn)
		return bgpMessage(msgUpdate, body), nil
	case mitigate.KindFlowspec:
		nlri, err := buildFlowspecNLRI(action)
		if err != nil {
			return nil, err
		}
		mp := make([]byte, 3+len(nlri))
		binary.BigEndian.PutUint16(mp[0:2], afiIPv4)
		mp[2] = safiFlowspec
		copy(mp[3:], nlri)
		attr := pathAttribute(0x80, attrMPUnreach, mp)
		attrs := attr
		body := make([]byte, 4+len(attrs))
		copy(body[2:4], encodeUint16(uint16(len(attrs))))
		copy(body[4:], attrs)
		return bgpMessage(msgUpdate, body), nil
	default:
		return nil, fmt.Errorf("unsupported action kind %q", action.Kind)
	}
}

func buildRTBHAnnouncement(action mitigate.Action, opts Options, as4 bool) ([]byte, error) {
	prefix, err := parseIPv4Prefix(action.Match.Source)
	if err != nil {
		return nil, err
	}
	if prefix.Bits() != 32 {
		return nil, errors.New("RTBH target must be a /32")
	}
	if prefix.Addr().IsUnspecified() {
		return nil, errors.New("refusing to announce RTBH for an unspecified address")
	}
	var attrs []byte
	attrs = append(attrs, pathAttribute(0x40, attrOrigin, []byte{0})...)
	asPath, as4Path, err := encodedASPath(opts.LocalAS, as4)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, pathAttribute(0x40, attrASPath, asPath)...)
	if as4Path != nil {
		attrs = append(attrs, pathAttribute(0xC0, attrAS4Path, as4Path)...)
	}
	nextHop, err := ipv4Bytes(opts.NextHop)
	if err != nil {
		return nil, fmt.Errorf("BGP next hop: %w", err)
	}
	attrs = append(attrs, pathAttribute(0x40, attrNextHop, nextHop)...)
	if opts.Community != 0 {
		community := make([]byte, 4)
		binary.BigEndian.PutUint32(community, opts.Community)
		attrs = append(attrs, pathAttribute(0xC0, attrCommunity, community)...)
	}
	if len(attrs) > 65535 {
		return nil, errors.New("path attributes exceed BGP limit")
	}
	nlri := encodeNLRI(prefix)
	body := make([]byte, 4+len(attrs)+len(nlri))
	binary.BigEndian.PutUint16(body[0:2], 0)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(attrs)))
	copy(body[4:], attrs)
	copy(body[4+len(attrs):], nlri)
	return bgpMessage(msgUpdate, body), nil
}

func buildFlowspecAnnouncement(action mitigate.Action, opts Options, as4 bool) ([]byte, error) {
	nlri, err := buildFlowspecNLRI(action)
	if err != nil {
		return nil, err
	}
	var attrs []byte
	attrs = append(attrs, pathAttribute(0x40, attrOrigin, []byte{0})...)
	asPath, as4Path, err := encodedASPath(opts.LocalAS, as4)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, pathAttribute(0x40, attrASPath, asPath)...)
	if as4Path != nil {
		attrs = append(attrs, pathAttribute(0xC0, attrAS4Path, as4Path)...)
	}

	// MP_REACH_NLRI for IPv4 Flowspec: AFI, SAFI, next-hop length of zero
	// (RFC 8955 does not use a next hop for this AFI/SAFI), reserved, NLRI.
	mp := make([]byte, 3+1+1+len(nlri))
	binary.BigEndian.PutUint16(mp[0:2], afiIPv4)
	mp[2] = safiFlowspec
	mp[3] = 0
	mp[4] = 0
	copy(mp[5:], nlri)
	attrs = append(attrs, pathAttribute(0x80, attrMPReach, mp)...)

	// Traffic-rate extended community. A rate of zero means discard.
	rate := float32(0)
	if action.Action == "rate-limit" {
		if action.RateLimitBPS == 0 {
			return nil, errors.New("rate-limit action has no rate")
		}
		// RFC 8955 traffic-rate is expressed in bytes per second; the action
		// stores bits per second.
		rate = float32(action.RateLimitBPS / 8)
		if rate <= 0 {
			return nil, errors.New("rate-limit is too small to encode")
		}
	}
	ext := make([]byte, 8)
	binary.BigEndian.PutUint16(ext[0:2], extCommunityTrafficRate)
	asn := uint16(opts.LocalAS)
	if opts.LocalAS > 65535 {
		asn = asTrans
	}
	binary.BigEndian.PutUint16(ext[2:4], asn)
	binary.BigEndian.PutUint32(ext[4:8], math.Float32bits(rate))
	attrs = append(attrs, pathAttribute(0xC0, attrExtCommunity, ext)...)

	if len(attrs) > 65535 {
		return nil, errors.New("path attributes exceed BGP limit")
	}
	body := make([]byte, 4+len(attrs))
	binary.BigEndian.PutUint16(body[0:2], 0)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(attrs)))
	copy(body[4:], attrs)
	return bgpMessage(msgUpdate, body), nil
}

func buildFlowspecNLRI(action mitigate.Action) ([]byte, error) {
	match := action.Match
	var components []byte
	if match.Destination == "" {
		return nil, errors.New("Flowspec requires a destination prefix")
	}
	dst, err := parseIPv4Prefix(match.Destination)
	if err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	if dst.Bits() == 0 {
		return nil, errors.New("refusing to encode a default-route Flowspec match")
	}
	if dst.Addr().IsUnspecified() {
		return nil, errors.New("destination is unspecified")
	}
	componentCount := 1
	components = append(components, flowspecPrefixComponent(flowspecDestPrefix, dst)...)
	if match.Source != "" {
		src, err := parseIPv4Prefix(match.Source)
		if err != nil {
			return nil, fmt.Errorf("source: %w", err)
		}
		if src.Bits() == 0 || src.Addr().IsUnspecified() {
			return nil, errors.New("refusing to encode an unspecified or default source")
		}
		components = append(components, flowspecPrefixComponent(flowspecSourcePrefix, src)...)
		componentCount++
	}
	if match.Protocol != 0 {
		components = append(components, flowspecNumericComponent(flowspecProtocol, []byte{match.Protocol}, 1)...)
		componentCount++
	}
	// Flowspec components must be encoded in ascending component-type order.
	if match.DstPort != 0 || match.DstPortMin != 0 {
		components = append(components, flowspecNumericOrRangeComponent(flowspecDestPort, match.DstPort, match.DstPortMin, match.DstPortMax)...)
		componentCount++
	}
	if match.SrcPort != 0 || match.SrcPortMin != 0 {
		components = append(components, flowspecNumericOrRangeComponent(flowspecSourcePort, match.SrcPort, match.SrcPortMin, match.SrcPortMax)...)
		componentCount++
	}
	if match.TCPFlags != 0 {
		components = append(components, flowspecNumericComponent(flowspecTCPFlags, encodeUint16(match.TCPFlags), 2)...)
		componentCount++
	}
	if match.PacketLength != 0 || match.PacketLengthMin != 0 {
		components = append(components, flowspecNumericOrRangeComponent(flowspecPacketLength, match.PacketLength, match.PacketLengthMin, match.PacketLengthMax)...)
		componentCount++
	}
	if match.Fragment {
		components = append(components, flowspecFragmentComponent(fragmentIsFragment)...)
		componentCount++
	}
	if componentCount < 1 {
		return nil, errors.New("Flowspec match is empty")
	}
	var nlri []byte
	if componentCount < 240 {
		nlri = append(nlri, byte(componentCount))
	} else {
		nlri = append(nlri, 0xF0|byte(componentCount>>8), byte(componentCount))
	}
	nlri = append(nlri, components...)
	return nlri, nil
}

func flowspecPrefixComponent(componentType byte, prefix netip.Prefix) []byte {
	addr := prefix.Masked().Addr().As4()
	bits := prefix.Bits()
	byteCount := (bits + 7) / 8
	out := make([]byte, 2+byteCount)
	out[0] = componentType
	out[1] = byte(bits)
	copy(out[2:], addr[:byteCount])
	return out
}

func flowspecNumericComponent(componentType byte, value []byte, width int) []byte {
	// End-of-list, equality, and length: len is the base-2 logarithm of the
	// value width (1, 2, 4, or 8 bytes).
	var operator byte
	switch width {
	case 1:
		operator = 0x81
	case 2:
		operator = 0x91
	case 4:
		operator = 0xA1
	default:
		operator = 0xB1
	}
	out := make([]byte, 1+1+len(value))
	out[0] = componentType
	out[1] = operator
	copy(out[2:], value)
	return out
}

// flowspecNumericOrRangeComponent encodes either an equality match or an
// inclusive [min,max] range. Ranges use two chained comparisons (GE then LE)
// joined with the AND bit per RFC 8955 section 4.2.1.1. An open-ended side is
// simply omitted, so "min only" means ">= min".
func flowspecNumericOrRangeComponent(componentType byte, exact, minValue, maxValue uint16) []byte {
	if exact != 0 {
		return flowspecNumericComponent(componentType, encodeUint16(exact), 2)
	}
	var out []byte
	out = append(out, componentType)
	if minValue != 0 {
		out = append(out, operatorAnd|operatorGE, byte(minValue>>8), byte(minValue))
	}
	if maxValue != 0 {
		maxOperator := byte(operatorAnd | operatorLE)
		if minValue == 0 {
			maxOperator = byte(operatorLE)
		}
		out = append(out, maxOperator, byte(maxValue>>8), byte(maxValue))
	}
	// Mark only the final comparison as end-of-list; earlier chained
	// comparisons keep the AND bit without EOL.
	if len(out) > 1 {
		out[len(out)-3] |= operatorEOL
	}
	return out
}

// flowspecFragmentComponent matches the IPv4 fragment bitmask. Only the "is a
// fragment" bit is used; the value is encoded as a 1-octet bitmask match
// (bitwise AND against the stored mask equals the mask).
func flowspecFragmentComponent(mask byte) []byte {
	return []byte{flowspecFragment, operatorEOL | operatorEqual, mask}
}

func encodedASPath(localAS uint32, as4 bool) ([]byte, []byte, error) {
	if localAS == 0 {
		return nil, nil, errors.New("local AS is zero")
	}
	if as4 {
		value := make([]byte, 6)
		value[0] = 2 // AS_SEQUENCE
		value[1] = 1
		binary.BigEndian.PutUint32(value[2:6], localAS)
		return value, nil, nil
	}
	if localAS > 65535 {
		value := make([]byte, 4)
		value[0] = 2
		value[1] = 1
		binary.BigEndian.PutUint16(value[2:4], asTrans)
		as4Path := make([]byte, 6)
		as4Path[0] = 2
		as4Path[1] = 1
		binary.BigEndian.PutUint32(as4Path[2:6], localAS)
		return value, as4Path, nil
	}
	value := make([]byte, 4)
	value[0] = 2
	value[1] = 1
	binary.BigEndian.PutUint16(value[2:4], uint16(localAS))
	return value, nil, nil
}

func pathAttribute(flags, code byte, value []byte) []byte {
	if len(value) > 255 {
		flags |= 0x10
		out := make([]byte, 4+len(value))
		out[0] = flags
		out[1] = code
		binary.BigEndian.PutUint16(out[2:4], uint16(len(value)))
		copy(out[4:], value)
		return out
	}
	out := make([]byte, 3+len(value))
	out[0] = flags
	out[1] = code
	out[2] = byte(len(value))
	copy(out[3:], value)
	return out
}

func bgpMessage(messageType byte, body []byte) []byte {
	length := 19 + len(body)
	out := make([]byte, length)
	for i := 0; i < 16; i++ {
		out[i] = 0xff
	}
	binary.BigEndian.PutUint16(out[16:18], uint16(length))
	out[18] = messageType
	copy(out[19:], body)
	return out
}

func encodeNLRI(prefix netip.Prefix) []byte {
	addr := prefix.Masked().Addr().As4()
	bits := prefix.Bits()
	byteCount := (bits + 7) / 8
	out := make([]byte, 1+byteCount)
	out[0] = byte(bits)
	copy(out[1:], addr[:byteCount])
	return out
}

func parseIPv4Prefix(value string) (netip.Prefix, error) {
	if value == "" {
		return netip.Prefix{}, errors.New("empty prefix")
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		addr := prefix.Addr().Unmap()
		if !addr.Is4() {
			return netip.Prefix{}, errors.New("only IPv4 prefixes are supported")
		}
		return netip.PrefixFrom(addr, prefix.Bits()).Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return netip.Prefix{}, errors.New("only IPv4 is supported")
	}
	return netip.PrefixFrom(addr, 32), nil
}

func ipv4Bytes(addr netip.Addr) ([]byte, error) {
	addr = addr.Unmap()
	if !addr.Is4() {
		return nil, errors.New("not an IPv4 address")
	}
	value := addr.As4()
	return value[:], nil
}

func routerIDUint32(addr netip.Addr) (uint32, error) {
	addr = addr.Unmap()
	if !addr.Is4() || addr.IsUnspecified() {
		return 0, errors.New("BGP router ID must be a non-zero IPv4 address")
	}
	value := addr.As4()
	return binary.BigEndian.Uint32(value[:]), nil
}

func encodeUint16(value uint16) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, value)
	return out
}
