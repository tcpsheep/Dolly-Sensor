// Package packet decodes sampled packet headers into model observations.
//
// The decoder is deliberately forgiving. sFlow exporters can capture only the
// first bytes of a frame, can carry raw IP headers instead of Ethernet, and can
// emit unusual encapsulations. A malformed sample must never take ingestion
// down, so every length is checked and partial headers degrade to a usable
// observation or a clear error.
package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"dollysensor/internal/model"
)

var (
	ErrTruncated   = errors.New("truncated packet")
	ErrUnsupported = errors.New("unsupported packet format")
)

const (
	etherTypeIPv4     = 0x0800
	etherTypeIPv6     = 0x86DD
	etherTypeARP      = 0x0806
	etherTypeVLAN     = 0x8100
	etherTypeQinQ     = 0x88A8
	etherTypeVLAN9100 = 0x9100
	etherTypeMPLS     = 0x8847
)

// Ethernet decodes an Ethernet frame. VLAN and MPLS headers are traversed.
func Ethernet(frame []byte) (*model.Observation, error) {
	if len(frame) < 14 {
		return nil, ErrTruncated
	}
	obs := &model.Observation{
		SrcMAC: net.HardwareAddr(frame[0:6]).String(),
		DstMAC: net.HardwareAddr(frame[6:12]).String(),
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	offset := 14
	for depth := 0; depth < 3; depth++ {
		switch etherType {
		case etherTypeVLAN, etherTypeQinQ, etherTypeVLAN9100:
			if len(frame) < offset+4 {
				return nil, ErrTruncated
			}
			etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
			offset += 4
		default:
			goto decoded
		}
	}
decoded:
	if len(frame) < offset {
		return nil, ErrTruncated
	}
	switch etherType {
	case etherTypeIPv4, etherTypeIPv6:
		ip, err := RawIP(frame[offset:])
		if err != nil {
			return nil, err
		}
		ip.SrcMAC = obs.SrcMAC
		ip.DstMAC = obs.DstMAC
		return ip, nil
	case etherTypeARP:
		arp, err := decodeARP(frame[offset:])
		if err != nil {
			return nil, err
		}
		arp.SrcMAC = obs.SrcMAC
		arp.DstMAC = obs.DstMAC
		return arp, nil
	case etherTypeMPLS:
		return mpls(frame[offset:])
	default:
		return nil, fmt.Errorf("%w: ethertype 0x%04x", ErrUnsupported, etherType)
	}
}

// MPLS decodes an MPLS label stack followed by an IP packet.
func MPLS(data []byte) (*model.Observation, error) { return mpls(data) }

func mpls(data []byte) (*model.Observation, error) {
	offset := 0
	for depth := 0; depth < 8; depth++ {
		if len(data) < offset+4 {
			return nil, ErrTruncated
		}
		entry := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		if entry&0x100 != 0 { // bottom-of-stack bit
			if len(data) < offset+1 {
				return nil, ErrTruncated
			}
			return RawIP(data[offset:])
		}
	}
	return nil, fmt.Errorf("%w: mpls stack too deep", ErrUnsupported)
}

// RawIP decodes a raw IPv4 or IPv6 header, as carried by some sFlow samples.
func RawIP(data []byte) (*model.Observation, error) {
	if len(data) < 1 {
		return nil, ErrTruncated
	}
	switch data[0] >> 4 {
	case 4:
		return ipv4(data)
	case 6:
		return ipv6(data)
	default:
		return nil, fmt.Errorf("%w: IP version %d", ErrUnsupported, data[0]>>4)
	}
}

func ipv4(data []byte) (*model.Observation, error) {
	if len(data) < 20 {
		return nil, ErrTruncated
	}
	if data[0]>>4 != 4 {
		return nil, fmt.Errorf("%w: not IPv4", ErrUnsupported)
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || ihl > len(data) {
		return nil, fmt.Errorf("%w: bad IPv4 header length", ErrTruncated)
	}
	totalLength := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLength < ihl {
		return nil, fmt.Errorf("%w: IPv4 total length smaller than header", ErrTruncated)
	}
	captured := len(data)
	if totalLength < captured {
		captured = totalLength
	}
	frag := binary.BigEndian.Uint16(data[6:8])
	fragOffset := int(frag&0x1fff) * 8
	moreFragments := frag&0x2000 != 0
	obs := &model.Observation{
		IPVersion:      4,
		Protocol:       data[9],
		ProtocolName:   model.ProtocolName(data[9]),
		TTL:            data[8],
		IPLength:       uint16(totalLength),
		Fragmented:     fragOffset > 0 || moreFragments,
		NonInitialFrag: fragOffset > 0,
		SrcIP:          netip.AddrFrom4([4]byte(data[12:16])),
		DstIP:          netip.AddrFrom4([4]byte(data[16:20])),
	}
	if fragOffset == 0 {
		if err := decodeTransport(obs, data[ihl:captured]); err != nil {
			// A truncated transport header still leaves useful IP facts. Keep the
			// observation but mark it as captured short.
			obs.PayloadPreview = ""
		}
	}
	return obs, nil
}

func ipv6(data []byte) (*model.Observation, error) {
	if len(data) < 40 {
		return nil, ErrTruncated
	}
	if data[0]>>4 != 6 {
		return nil, fmt.Errorf("%w: not IPv6", ErrUnsupported)
	}
	payloadLength := int(binary.BigEndian.Uint16(data[4:6]))
	captured := len(data)
	if 40+payloadLength < captured {
		captured = 40 + payloadLength
	}
	if captured < 40 {
		return nil, ErrTruncated
	}
	obs := &model.Observation{
		IPVersion: 6,
		TTL:       data[7],
		SrcIP:     netip.AddrFrom16([16]byte(data[8:24])),
		DstIP:     netip.AddrFrom16([16]byte(data[24:40])),
	}
	if payloadLength+40 <= 65535 {
		obs.IPLength = uint16(payloadLength + 40)
	}
	next := data[6]
	offset := 40
	for depth := 0; depth < 8; depth++ {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if captured < offset+2 {
				obs.Protocol = next
				obs.ProtocolName = model.ProtocolName(next)
				return obs, nil
			}
			length := (int(data[offset+1]) + 1) * 8
			if length < 8 || captured < offset+length {
				obs.Protocol = next
				obs.ProtocolName = model.ProtocolName(next)
				return obs, nil
			}
			next = data[offset]
			offset += length
		case 51: // authentication header
			if captured < offset+2 {
				obs.Protocol = next
				obs.ProtocolName = model.ProtocolName(next)
				return obs, nil
			}
			length := (int(data[offset+1]) + 2) * 4
			if length < 8 || captured < offset+length {
				obs.Protocol = next
				obs.ProtocolName = model.ProtocolName(next)
				return obs, nil
			}
			next = data[offset]
			offset += length
		case 44: // fragment header
			if captured < offset+8 {
				obs.Protocol = next
				obs.ProtocolName = model.ProtocolName(next)
				return obs, nil
			}
			fragOffset := binary.BigEndian.Uint16(data[offset+2:offset+4]) >> 3
			obs.Fragmented = true
			obs.NonInitialFrag = fragOffset > 0
			next = data[offset]
			offset += 8
			if obs.NonInitialFrag {
				obs.Protocol = next
				obs.ProtocolName = model.ProtocolName(next)
				return obs, nil
			}
		case 50, 59: // ESP is opaque; no-next-header means nothing follows
			obs.Protocol = next
			obs.ProtocolName = model.ProtocolName(next)
			return obs, nil
		default:
			obs.Protocol = next
			obs.ProtocolName = model.ProtocolName(next)
			if captured > offset {
				_ = decodeTransport(obs, data[offset:captured])
			}
			return obs, nil
		}
	}
	obs.Protocol = next
	obs.ProtocolName = model.ProtocolName(next)
	return obs, nil
}

func decodeARP(data []byte) (*model.Observation, error) {
	if len(data) < 8 {
		return nil, ErrTruncated
	}
	hardwareLen := int(data[4])
	protocolLen := int(data[5])
	op := binary.BigEndian.Uint16(data[6:8])
	required := 8 + 2*hardwareLen + 2*protocolLen
	if len(data) < required || hardwareLen != 6 || protocolLen != 4 {
		return nil, fmt.Errorf("%w: unsupported ARP layout", ErrUnsupported)
	}
	sender := netip.AddrFrom4([4]byte(data[8+hardwareLen : 8+hardwareLen+4]))
	target := netip.AddrFrom4([4]byte(data[8+hardwareLen+4+hardwareLen : 8+hardwareLen+4+hardwareLen+4]))
	obs := &model.Observation{
		ProtocolName: "ARP",
		ARP: &model.ARPInfo{
			Operation: op,
			SenderIP:  sender,
			TargetIP:  target,
		},
		SrcIP: sender,
		DstIP: target,
	}
	return obs, nil
}

func decodeTransport(obs *model.Observation, payload []byte) error {
	switch obs.Protocol {
	case 6:
		return decodeTCP(obs, payload)
	case 17:
		return decodeUDP(obs, payload)
	case 1, 58:
		if len(payload) > 0 {
			obs.Payload = append([]byte(nil), payload...)
			if len(obs.Payload) > 512 {
				obs.Payload = obs.Payload[:512]
			}
		}
		return nil
	case 132:
		if len(payload) >= 4 {
			obs.SrcPort = binary.BigEndian.Uint16(payload[0:2])
			obs.DstPort = binary.BigEndian.Uint16(payload[2:4])
		}
		return nil
	default:
		return nil
	}
}

func decodeTCP(obs *model.Observation, payload []byte) error {
	if len(payload) < 20 {
		return ErrTruncated
	}
	obs.SrcPort = binary.BigEndian.Uint16(payload[0:2])
	obs.DstPort = binary.BigEndian.Uint16(payload[2:4])
	obs.Seq = binary.BigEndian.Uint32(payload[4:8])
	obs.Ack = binary.BigEndian.Uint32(payload[8:12])
	dataOffset := int(payload[12]>>4) * 4
	obs.TCPFlags = model.TCPFlags(payload[13])
	if dataOffset < 20 || dataOffset > len(payload) {
		dataOffset = len(payload)
	}
	if len(payload) > dataOffset {
		limit := len(payload) - dataOffset
		if limit > 2048 {
			limit = 2048
		}
		obs.Payload = append([]byte(nil), payload[dataOffset:dataOffset+limit]...)
	}
	classifyApp(obs)
	return nil
}

func decodeUDP(obs *model.Observation, payload []byte) error {
	if len(payload) < 8 {
		return ErrTruncated
	}
	obs.SrcPort = binary.BigEndian.Uint16(payload[0:2])
	obs.DstPort = binary.BigEndian.Uint16(payload[2:4])
	length := int(binary.BigEndian.Uint16(payload[4:6]))
	end := len(payload)
	if length >= 8 && length <= len(payload) {
		end = length
	}
	if end > 8 {
		limit := end - 8
		if limit > 2048 {
			limit = 2048
		}
		obs.Payload = append([]byte(nil), payload[8:8+limit]...)
	}
	classifyApp(obs)
	return nil
}
