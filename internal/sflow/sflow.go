// Package sflow decodes sFlow version 5 datagrams into sampled packet
// observations.
package sflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"dollysensor/internal/model"
	"dollysensor/internal/packet"
)

const (
	flowSampleFormat         = 1
	expandedFlowSampleFormat = 3
	rawPacketHeaderFormat    = 1

	headerProtocolEthernet = 1
	headerProtocolIPv4     = 11
	headerProtocolIPv6     = 12
	headerProtocolMPLS     = 13
)

// Decode decodes one sFlow v5 datagram received at the supplied time.
//
// A malformed sample does not prevent other samples in the same datagram from
// being returned. When that happens the observations are returned together
// with an error describing the first malformed record, allowing the caller to
// ingest the good data and count the bad data.
func Decode(data []byte, receivedAt time.Time) ([]model.Observation, error) {
	r := &reader{data: data}
	version := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if version != 5 {
		return nil, fmt.Errorf("unsupported sFlow version %d", version)
	}
	agentType := r.u32()
	agent, err := readAddress(r, agentType)
	if err != nil {
		return nil, err
	}
	subAgentID := r.u32()
	_ = r.u32() // datagram sequence
	_ = r.u32() // uptime
	count := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if count > 100000 {
		return nil, fmt.Errorf("implausible sFlow sample count %d", count)
	}

	var observations []model.Observation
	var firstErr error
	for i := uint32(0); i < count; i++ {
		if r.remaining() < 8 {
			if firstErr == nil {
				firstErr = io.ErrUnexpectedEOF
			}
			break
		}
		format := r.u32()
		length := r.u32()
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			break
		}
		if int(length) > r.remaining() {
			if firstErr == nil {
				firstErr = fmt.Errorf("sample %d length %d exceeds datagram", i, length)
			}
			break
		}
		body := r.bytes(int(length))
		enterprise := format >> 12
		formatID := format & 0x0fff
		if enterprise != 0 {
			continue
		}
		switch formatID {
		case flowSampleFormat, expandedFlowSampleFormat:
			meta, err := parseFlowSample(body, formatID == expandedFlowSampleFormat)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("sample %d: %w", i, err)
				}
				continue
			}
			meta.Exporter = agent
			meta.SubAgentID = subAgentID
			meta.ReceivedAt = receivedAt
			for _, raw := range meta.records {
				obs, err := decodeRawHeader(raw, meta)
				if err != nil {
					if firstErr == nil {
						firstErr = fmt.Errorf("sample %d: %w", i, err)
					}
					continue
				}
				observations = append(observations, obs)
			}
		default:
			// Counter samples and vendor extensions are intentionally ignored.
		}
	}
	return observations, firstErr
}

type sampleMeta struct {
	Exporter     netip.Addr
	SubAgentID   uint32
	ReceivedAt   time.Time
	Sequence     uint32
	SourceID     string
	SamplingRate uint32
	SamplePool   uint32
	Drops        uint32
	Input        uint32
	Output       uint32
	records      []rawHeader
}

type rawHeader struct {
	Protocol     uint32
	FrameLength  uint32
	Stripped     uint32
	HeaderLength uint32
	Header       []byte
}

func parseFlowSample(data []byte, expanded bool) (*sampleMeta, error) {
	r := &reader{data: data}
	meta := &sampleMeta{}
	meta.Sequence = r.u32()
	if expanded {
		sourceType := r.u32()
		sourceIndex := r.u32()
		meta.SourceID = fmt.Sprintf("%d:%d", sourceType, sourceIndex)
	} else {
		sourceID := r.u32()
		meta.SourceID = fmt.Sprintf("%d:%d", sourceID>>24, sourceID&0x00ffffff)
	}
	meta.SamplingRate = r.u32()
	meta.SamplePool = r.u32()
	meta.Drops = r.u32()
	meta.Input = r.u32()
	meta.Output = r.u32()
	recordCount := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if recordCount > 10000 {
		return nil, fmt.Errorf("implausible flow record count %d", recordCount)
	}
	for i := uint32(0); i < recordCount; i++ {
		if r.remaining() < 8 {
			return nil, io.ErrUnexpectedEOF
		}
		format := r.u32()
		length := r.u32()
		if int(length) > r.remaining() {
			return nil, fmt.Errorf("flow record length %d exceeds sample", length)
		}
		body := r.bytes(int(length))
		enterprise := format >> 12
		formatID := format & 0x0fff
		if enterprise != 0 || formatID != rawPacketHeaderFormat {
			continue
		}
		raw, err := parseRawHeader(body)
		if err != nil {
			return nil, err
		}
		meta.records = append(meta.records, raw)
	}
	return meta, nil
}

func parseRawHeader(data []byte) (rawHeader, error) {
	r := &reader{data: data}
	raw := rawHeader{
		Protocol:     r.u32(),
		FrameLength:  r.u32(),
		Stripped:     r.u32(),
		HeaderLength: r.u32(),
	}
	if r.err != nil {
		return raw, r.err
	}
	if raw.HeaderLength > uint32(r.remaining()) {
		return raw, fmt.Errorf("raw header length %d exceeds record", raw.HeaderLength)
	}
	raw.Header = append([]byte(nil), r.bytes(int(raw.HeaderLength))...)
	padding := (4 - int(raw.HeaderLength%4)) % 4
	if r.remaining() >= padding {
		r.skip(padding)
	}
	return raw, nil
}

func decodeRawHeader(raw rawHeader, meta *sampleMeta) (model.Observation, error) {
	var (
		obs *model.Observation
		err error
	)
	switch raw.Protocol {
	case headerProtocolEthernet:
		obs, err = packet.Ethernet(raw.Header)
	case headerProtocolIPv4, headerProtocolIPv6:
		obs, err = packet.RawIP(raw.Header)
	case headerProtocolMPLS:
		obs, err = packet.MPLS(raw.Header)
	default:
		return model.Observation{}, fmt.Errorf("unsupported sFlow header protocol %d", raw.Protocol)
	}
	if err != nil {
		return model.Observation{}, err
	}
	if obs == nil {
		return model.Observation{}, errors.New("decoder returned no observation")
	}
	rate := meta.SamplingRate
	if rate == 0 {
		rate = 1
	}
	wireSize := raw.FrameLength
	if wireSize == 0 {
		wireSize = uint32(obs.IPLength)
	}
	if wireSize == 0 {
		wireSize = raw.HeaderLength
	}
	obs.Exporter = meta.Exporter
	obs.SubAgentID = meta.SubAgentID
	obs.ReceivedAt = meta.ReceivedAt
	obs.SampleSequence = meta.Sequence
	obs.SourceID = meta.SourceID
	obs.SamplingRate = int(rate)
	obs.FrameLength = raw.FrameLength
	obs.Stripped = raw.Stripped
	obs.Sampled = rate > 1
	obs.EstimatedPackets = uint64(rate)
	obs.EstimatedBytes = uint64(rate) * uint64(wireSize)
	obs.Finalize()
	if obs.PacketSize == 0 {
		obs.PacketSize = uint16(minU32(raw.FrameLength, 65535))
		obs.Summary = modelObservationSummary(*obs)
	}
	return *obs, nil
}

func modelObservationSummary(obs model.Observation) string {
	obs.Finalize()
	return obs.Summary
}

func readAddress(r *reader, addressType uint32) (netip.Addr, error) {
	switch addressType {
	case 1:
		b := r.bytes(4)
		if r.err != nil {
			return netip.Addr{}, r.err
		}
		return netip.AddrFrom4([4]byte(b)), nil
	case 2:
		b := r.bytes(16)
		if r.err != nil {
			return netip.Addr{}, r.err
		}
		return netip.AddrFrom16([16]byte(b)), nil
	default:
		return netip.Addr{}, fmt.Errorf("unsupported agent address type %d", addressType)
	}
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

type reader struct {
	data []byte
	off  int
	err  error
}

func (r *reader) remaining() int {
	if r.off >= len(r.data) {
		return 0
	}
	return len(r.data) - r.off
}

func (r *reader) u32() uint32 {
	if r.err != nil {
		return 0
	}
	if r.remaining() < 4 {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	value := binary.BigEndian.Uint32(r.data[r.off : r.off+4])
	r.off += 4
	return value
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.remaining() < n {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	value := r.data[r.off : r.off+n]
	r.off += n
	return value
}

func (r *reader) skip(n int) {
	if r.err != nil {
		return
	}
	if n < 0 || r.remaining() < n {
		r.err = io.ErrUnexpectedEOF
		return
	}
	r.off += n
}
