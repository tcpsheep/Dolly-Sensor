// Package sflowgen builds small, standards-shaped sFlow v5 datagrams carrying
// Ethernet/IPv4 packets. It exists so the sensor can be demonstrated and tested
// without access to a physical switch.
package sflowgen

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// PacketSpec describes one packet inside a flow sample.
type PacketSpec struct {
	SrcIP       netip.Addr
	DstIP       netip.Addr
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	TCPFlags    uint8
	TTL         uint8
	Payload     []byte
	FrameLength int
	ICMPType    uint8
}

// DatagramSpec controls one sFlow datagram.
type DatagramSpec struct {
	Agent        netip.Addr
	SubAgentID   uint32
	Sequence     uint32
	UptimeMillis uint32
	SamplingRate uint32
	Packets      []PacketSpec
}

// Frame builds the Ethernet frame for one packet spec.
func Frame(spec PacketSpec) ([]byte, error) {
	src, dst, err := ipv4Pair(spec)
	if err != nil {
		return nil, err
	}
	payload := spec.Payload
	protocol := spec.Protocol
	if protocol == 0 {
		protocol = 17
	}
	var transport []byte
	switch protocol {
	case 6:
		transport = make([]byte, 20+len(payload))
		binary.BigEndian.PutUint16(transport[0:2], spec.SrcPort)
		binary.BigEndian.PutUint16(transport[2:4], spec.DstPort)
		binary.BigEndian.PutUint32(transport[4:8], 1)
		transport[12] = 5 << 4
		transport[13] = spec.TCPFlags
		binary.BigEndian.PutUint16(transport[14:16], 64240)
		copy(transport[20:], payload)
		binary.BigEndian.PutUint16(transport[16:18], checksum(transportPseudo(src, dst, 6, len(transport)), transport))
	case 17:
		transport = make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(transport[0:2], spec.SrcPort)
		binary.BigEndian.PutUint16(transport[2:4], spec.DstPort)
		binary.BigEndian.PutUint16(transport[4:6], uint16(8+len(payload)))
		copy(transport[8:], payload)
		checksumValue := checksum(transportPseudo(src, dst, 17, len(transport)), transport)
		if checksumValue == 0 {
			checksumValue = 0xffff
		}
		binary.BigEndian.PutUint16(transport[6:8], checksumValue)
	case 1:
		transport = make([]byte, 8+len(payload))
		icmpType := spec.ICMPType
		if icmpType == 0 {
			icmpType = 8
		}
		transport[0] = icmpType
		binary.BigEndian.PutUint16(transport[4:6], 1)
		binary.BigEndian.PutUint16(transport[6:8], 1)
		copy(transport[8:], payload)
		binary.BigEndian.PutUint16(transport[2:4], checksum(transport[0:], nil))
	default:
		transport = append([]byte(nil), payload...)
	}

	totalLength := 20 + len(transport)
	if totalLength > 65535 {
		return nil, fmt.Errorf("frame too large")
	}
	ip := make([]byte, totalLength)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLength))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	ip[8] = spec.TTL
	if ip[8] == 0 {
		ip[8] = 64
	}
	ip[9] = protocol
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[0:20], nil))
	copy(ip[20:], transport)

	frame := make([]byte, 14+len(ip))
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], ip)
	if len(frame) < 60 {
		frame = append(frame, make([]byte, 60-len(frame))...)
	}
	if spec.FrameLength > 0 {
		if spec.FrameLength < len(frame) {
			frame = frame[:spec.FrameLength]
		} else if spec.FrameLength > len(frame) {
			frame = append(frame, make([]byte, spec.FrameLength-len(frame))...)
		}
	}
	return frame, nil
}

// Datagram builds one sFlow v5 datagram with one flow sample per packet.
func Datagram(spec DatagramSpec) ([]byte, error) {
	if !spec.Agent.IsValid() || !spec.Agent.Unmap().Is4() {
		return nil, fmt.Errorf("agent must be an IPv4 address")
	}
	if len(spec.Packets) == 0 {
		return nil, fmt.Errorf("at least one packet is required")
	}
	if len(spec.Packets) > 64 {
		return nil, fmt.Errorf("at most 64 packets per datagram")
	}
	rate := spec.SamplingRate
	if rate == 0 {
		rate = 1
	}
	sequence := spec.Sequence
	subAgent := spec.SubAgentID
	agent := spec.Agent.Unmap().As4()

	out := make([]byte, 0, 512)
	out = binary.BigEndian.AppendUint32(out, 5)
	out = binary.BigEndian.AppendUint32(out, 1)
	out = append(out, agent[:]...)
	out = binary.BigEndian.AppendUint32(out, subAgent)
	out = binary.BigEndian.AppendUint32(out, sequence)
	out = binary.BigEndian.AppendUint32(out, spec.UptimeMillis)
	out = binary.BigEndian.AppendUint32(out, uint32(len(spec.Packets)))
	pool := rate
	for index, packet := range spec.Packets {
		frame, err := Frame(packet)
		if err != nil {
			return nil, fmt.Errorf("packet %d: %w", index, err)
		}
		recordBody := make([]byte, 16)
		binary.BigEndian.PutUint32(recordBody[0:4], 1) // Ethernet
		binary.BigEndian.PutUint32(recordBody[4:8], uint32(len(frame)))
		binary.BigEndian.PutUint32(recordBody[8:12], 4)
		binary.BigEndian.PutUint32(recordBody[12:16], uint32(len(frame)))
		recordBody = append(recordBody, frame...)
		for len(recordBody)%4 != 0 {
			recordBody = append(recordBody, 0)
		}
		record := make([]byte, 8, 8+len(recordBody))
		binary.BigEndian.PutUint32(record[0:4], 1) // raw packet header
		binary.BigEndian.PutUint32(record[4:8], uint32(len(recordBody)))
		record = append(record, recordBody...)

		sample := make([]byte, 32)
		binary.BigEndian.PutUint32(sample[0:4], sequence+uint32(index))
		binary.BigEndian.PutUint32(sample[4:8], 0) // source id 0:0
		binary.BigEndian.PutUint32(sample[8:12], rate)
		binary.BigEndian.PutUint32(sample[12:16], pool)
		binary.BigEndian.PutUint32(sample[20:24], 1) // input
		binary.BigEndian.PutUint32(sample[28:32], 1) // one flow record
		sample = append(sample, record...)
		pool += rate
		out = binary.BigEndian.AppendUint32(out, 1) // flow sample
		out = binary.BigEndian.AppendUint32(out, uint32(len(sample)))
		out = append(out, sample...)
	}
	return out, nil
}

func ipv4Pair(spec PacketSpec) ([4]byte, [4]byte, error) {
	var src, dst [4]byte
	if !spec.SrcIP.IsValid() || !spec.SrcIP.Unmap().Is4() {
		return src, dst, fmt.Errorf("source must be IPv4")
	}
	if !spec.DstIP.IsValid() || !spec.DstIP.Unmap().Is4() {
		return src, dst, fmt.Errorf("destination must be IPv4")
	}
	src = spec.SrcIP.Unmap().As4()
	dst = spec.DstIP.Unmap().As4()
	return src, dst, nil
}

func transportPseudo(src, dst [4]byte, protocol uint8, length int) []byte {
	pseudo := make([]byte, 12, 12+length)
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(length))
	return pseudo
}

func checksum(prefix, data []byte) uint16 {
	var sum uint32
	all := prefix
	if data != nil {
		all = make([]byte, 0, len(prefix)+len(data))
		all = append(all, prefix...)
		all = append(all, data...)
	}
	for i := 0; i+1 < len(all); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(all[i : i+2]))
	}
	if len(all)%2 == 1 {
		sum += uint32(all[len(all)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
