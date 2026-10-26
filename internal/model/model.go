// Package model holds the vocabulary of Dolly Sensor: packet observations,
// TCP flag helpers, and the small pieces of derived data shared by every
// subsystem. It intentionally has no dependencies beyond the standard library.
package model

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// PacketDirection describes an observation relative to the protected network.
type PacketDirection string

const (
	DirectionInbound  PacketDirection = "inbound"
	DirectionOutbound PacketDirection = "outbound"
	DirectionInternal PacketDirection = "internal"
	DirectionOther    PacketDirection = "other"
)

// TCPFlags is the raw TCP flags byte.
type TCPFlags uint8

const (
	TCPFIN TCPFlags = 0x01
	TCPSYN TCPFlags = 0x02
	TCPRST TCPFlags = 0x04
	TCPPSH TCPFlags = 0x08
	TCPACK TCPFlags = 0x10
	TCPURG TCPFlags = 0x20
	TCPECE TCPFlags = 0x40
	TCPCWR TCPFlags = 0x80
)

var tcpFlagNames = []struct {
	bit  TCPFlags
	name string
}{
	{TCPFIN, "FIN"},
	{TCPSYN, "SYN"},
	{TCPRST, "RST"},
	{TCPPSH, "PSH"},
	{TCPACK, "ACK"},
	{TCPURG, "URG"},
	{TCPECE, "ECE"},
	{TCPCWR, "CWR"},
}

// Has reports whether all bits in f are set.
func (f TCPFlags) Has(bits TCPFlags) bool { return f&bits == bits }

// IsSYN reports whether this is a pure SYN (no ACK).
func (f TCPFlags) IsSYN() bool { return f.Has(TCPSYN) && !f.Has(TCPACK) }

// IsSYNACK reports whether this is a SYN/ACK.
func (f TCPFlags) IsSYNACK() bool { return f.Has(TCPSYN) && f.Has(TCPACK) }

// String returns a stable, readable flag list, for example "SYN,ACK".
func (f TCPFlags) String() string {
	if f == 0 {
		return "-"
	}
	parts := make([]string, 0, 4)
	for _, item := range tcpFlagNames {
		if f.Has(item.bit) {
			parts = append(parts, item.name)
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
}

// AppInfo describes application-layer facts recovered from the sampled
// payload. It is deliberately shallow: enough to explain traffic, not to
// reconstruct sessions.
type AppInfo struct {
	Protocol     string `json:"protocol,omitempty"`
	Detail       string `json:"detail,omitempty"`
	DNSQuery     string `json:"dns_query,omitempty"`
	DNSRecord    string `json:"dns_record,omitempty"`
	HTTPMethod   string `json:"http_method,omitempty"`
	HTTPHost     string `json:"http_host,omitempty"`
	HTTPPath     string `json:"http_path,omitempty"`
	SSHBanner    string `json:"ssh_banner,omitempty"`
	FTPCommand   string `json:"ftp_command,omitempty"`
	FTPArgument  string `json:"ftp_argument,omitempty"`
	FTPReplyCode string `json:"ftp_reply_code,omitempty"`
}

// Observation is one sampled packet, decoded, enriched, and scaled to an
// estimate of the real traffic it represents. Payload is kept only in memory
// and is never serialised directly.
type Observation struct {
	ID         uint64    `json:"id"`
	ReceivedAt time.Time `json:"received_at"`

	Exporter       netip.Addr `json:"exporter"`
	SubAgentID     uint32     `json:"sub_agent_id"`
	SampleSequence uint32     `json:"sample_sequence"`
	SourceID       string     `json:"source_id"`
	SamplingRate   int        `json:"sampling_rate"`

	FrameLength uint32 `json:"frame_length"`
	Stripped    uint32 `json:"stripped"`
	Sampled     bool   `json:"sampled"`

	SrcMAC string `json:"src_mac,omitempty"`
	DstMAC string `json:"dst_mac,omitempty"`

	SrcIP netip.Addr `json:"src_ip"`
	DstIP netip.Addr `json:"dst_ip"`

	IPVersion    int    `json:"ip_version,omitempty"`
	Protocol     uint8  `json:"protocol"`
	ProtocolName string `json:"protocol_name"`

	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`

	TCPFlags     TCPFlags `json:"-"`
	TCPFlagsText string   `json:"tcp_flags,omitempty"`
	Seq          uint32   `json:"seq,omitempty"`
	Ack          uint32   `json:"ack,omitempty"`

	TTL            uint8  `json:"ttl,omitempty"`
	IPLength       uint16 `json:"ip_length,omitempty"`
	PacketSize     uint16 `json:"packet_size"`
	Fragmented     bool   `json:"fragmented,omitempty"`
	NonInitialFrag bool   `json:"non_initial_fragment,omitempty"`

	Payload        []byte  `json:"-"`
	PayloadPreview string  `json:"payload_preview,omitempty"`
	PayloadHex     string  `json:"payload_hex,omitempty"`
	App            AppInfo `json:"app"`

	ARP *ARPInfo `json:"arp,omitempty"`

	SessionState       string `json:"session_state,omitempty"`
	SessionKey         string `json:"session_key,omitempty"`
	HandshakeCompleted bool   `json:"handshake_completed,omitempty"`
	OutOfState         bool   `json:"out_of_state,omitempty"`

	DstProtected bool            `json:"dst_protected"`
	SrcProtected bool            `json:"src_protected"`
	Direction    PacketDirection `json:"direction"`

	EstimatedPackets uint64 `json:"estimated_packets"`
	EstimatedBytes   uint64 `json:"estimated_bytes"`
	Summary          string `json:"summary"`
}

// ARPInfo is the decoded body of an ARP packet.
type ARPInfo struct {
	Operation uint16     `json:"operation"`
	SenderIP  netip.Addr `json:"sender_ip"`
	TargetIP  netip.Addr `json:"target_ip"`
}

// Clone returns a deep copy safe to hand to another goroutine or store.
func (o Observation) Clone() Observation {
	c := o
	if len(o.Payload) > 0 {
		c.Payload = append([]byte(nil), o.Payload...)
	}
	return c
}

// Finalize computes derived text fields from the decoded values. It is called
// once, after sampling metadata and session enrichment have been attached.
func (o *Observation) Finalize() {
	o.SrcIP = o.SrcIP.Unmap()
	o.DstIP = o.DstIP.Unmap()
	o.TCPFlagsText = o.TCPFlags.String()
	if o.ProtocolName == "" {
		o.ProtocolName = ProtocolName(o.Protocol)
	}
	if o.PacketSize == 0 {
		switch {
		case o.IPLength > 0:
			o.PacketSize = o.IPLength
		case o.FrameLength > 100000:
			o.PacketSize = 0
		case o.FrameLength > 0:
			o.PacketSize = uint16(o.FrameLength)
		}
	}
	if o.SamplingRate <= 0 {
		o.SamplingRate = 1
	}
	if o.EstimatedPackets == 0 {
		o.EstimatedPackets = 1
	}
	o.PayloadPreview = previewPayload(o.Payload, 160)
	o.PayloadHex = hexPreview(o.Payload, 256)
	o.App = NormalizeApp(o.App)
	if o.Direction == "" {
		switch {
		case o.DstProtected && o.SrcProtected:
			o.Direction = DirectionInternal
		case o.DstProtected:
			o.Direction = DirectionInbound
		case o.SrcProtected:
			o.Direction = DirectionOutbound
		default:
			o.Direction = DirectionOther
		}
	}
	o.Summary = summarize(*o)
}

// ProtocolName returns a conventional name for an IP protocol number.
func ProtocolName(protocol uint8) string {
	switch protocol {
	case 0:
		return "HOPOPT"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IP-in-IP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 132:
		return "SCTP"
	default:
		return "IP/" + strconv.Itoa(int(protocol))
	}
}

// TransportName returns a lowercase transport description suitable for JSON.
func TransportName(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	default:
		return "ip"
	}
}

func summarize(o Observation) string {
	var b strings.Builder
	switch {
	case o.ARP != nil:
		verb := "request"
		if o.ARP.Operation == 2 {
			verb = "reply"
		}
		fmt.Fprintf(&b, "ARP %s %s -> %s", verb, addrOr(o.ARP.SenderIP, "?"), addrOr(o.ARP.TargetIP, "?"))
	case o.ProtocolName == "ICMP" || o.ProtocolName == "ICMPv6":
		b.WriteString(o.ProtocolName)
		if detail := icmpSummary(o.Payload); detail != "" {
			b.WriteString(" ")
			b.WriteString(detail)
		}
		if o.SrcIP.IsValid() && o.DstIP.IsValid() {
			fmt.Fprintf(&b, " %s -> %s", o.SrcIP, o.DstIP)
		}
	default:
		name := o.ProtocolName
		if name == "" {
			name = ProtocolName(o.Protocol)
		}
		b.WriteString(name)
		if o.SrcIP.IsValid() {
			b.WriteString(" ")
			b.WriteString(o.SrcIP.String())
			if o.SrcPort != 0 {
				fmt.Fprintf(&b, ":%d", o.SrcPort)
			}
		}
		if o.DstIP.IsValid() {
			b.WriteString(" -> ")
			b.WriteString(o.DstIP.String())
			if o.DstPort != 0 {
				fmt.Fprintf(&b, ":%d", o.DstPort)
			}
		}
		if o.TCPFlags != 0 {
			fmt.Fprintf(&b, " [%s]", o.TCPFlags.String())
		}
	}
	if o.PacketSize > 0 {
		fmt.Fprintf(&b, " %dB", o.PacketSize)
	}
	if o.TTL > 0 {
		fmt.Fprintf(&b, " ttl=%d", o.TTL)
	}
	if o.App.Protocol != "" {
		b.WriteString(" | ")
		if o.App.Detail != "" {
			b.WriteString(o.App.Detail)
		} else {
			b.WriteString(o.App.Protocol)
		}
	}
	if o.OutOfState {
		b.WriteString(" | out-of-state")
	}
	return b.String()
}

func addrOr(addr netip.Addr, fallback string) string {
	if addr.IsValid() {
		return addr.String()
	}
	return fallback
}

func icmpSummary(payload []byte) string {
	if len(payload) < 1 {
		return ""
	}
	switch payload[0] {
	case 0:
		return "echo reply"
	case 3:
		return "destination unreachable"
	case 8:
		return "echo request"
	case 11:
		return "time exceeded"
	case 128:
		return "echo request"
	case 129:
		return "echo reply"
	case 133:
		return "router solicitation"
	case 134:
		return "router advertisement"
	case 135:
		return "neighbor solicitation"
	case 136:
		return "neighbor advertisement"
	default:
		return "type " + strconv.Itoa(int(payload[0]))
	}
}

// NormalizeApp fills in a readable detail string when a parser has supplied
// structured fields but not a summary.
func NormalizeApp(app AppInfo) AppInfo {
	if app.Protocol == "" {
		return app
	}
	if app.Detail != "" {
		return app
	}
	switch app.Protocol {
	case "DNS":
		d := "DNS"
		if app.DNSRecord != "" {
			d += " " + app.DNSRecord
		}
		if app.DNSQuery != "" {
			d += " " + app.DNSQuery
		}
		app.Detail = d
	case "HTTP":
		d := "HTTP"
		if app.HTTPMethod != "" {
			d += " " + app.HTTPMethod
		}
		if app.HTTPPath != "" {
			d += " " + app.HTTPPath
		}
		if app.HTTPHost != "" {
			d += " " + app.HTTPHost
		}
		app.Detail = d
	case "SSH":
		app.Detail = "SSH " + app.SSHBanner
	case "FTP":
		if app.FTPReplyCode != "" {
			app.Detail = "FTP reply " + app.FTPReplyCode
		} else if app.FTPCommand != "" {
			app.Detail = strings.TrimSpace("FTP " + app.FTPCommand + " " + app.FTPArgument)
		} else {
			app.Detail = "FTP"
		}
	}
	return app
}

func previewPayload(payload []byte, limit int) string {
	if len(payload) == 0 {
		return ""
	}
	if limit <= 0 || limit > len(payload) {
		limit = len(payload)
	}
	var b strings.Builder
	b.Grow(limit)
	for _, c := range payload[:limit] {
		switch {
		case c == '\r':
			// Ignore carriage returns in the preview.
		case c == '\n':
			b.WriteString("⏎")
		case c == '\t':
			b.WriteString("\\t")
		case c >= 32 && c <= 126:
			b.WriteByte(c)
		default:
			b.WriteByte('.')
		}
	}
	if limit < len(payload) {
		b.WriteString("…")
	}
	return b.String()
}

func hexPreview(payload []byte, limit int) string {
	if len(payload) == 0 {
		return ""
	}
	if limit <= 0 || limit > len(payload) {
		limit = len(payload)
	}
	truncated := limit < len(payload)
	data := payload[:limit]
	var b strings.Builder
	for offset := 0; offset < len(data); offset += 16 {
		end := offset + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(&b, "%04x  ", offset)
		b.WriteString(hex.EncodeToString(data[offset:end]))
		if end < len(data) || truncated {
			b.WriteByte('\n')
		}
	}
	if truncated {
		fmt.Fprintf(&b, "… %d bytes captured\n", len(payload))
	}
	return strings.TrimRight(b.String(), "\n")
}
