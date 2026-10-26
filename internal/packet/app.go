package packet

import (
	"encoding/binary"
	"strconv"
	"strings"

	"dollysensor/internal/model"
)

// classifyApp performs light, bounded payload inspection. It never assumes
// the captured payload contains a complete message: sFlow samples are often
// truncated to the first 128 or 256 bytes.
func classifyApp(obs *model.Observation) {
	payload := obs.Payload
	if len(payload) == 0 {
		return
	}
	switch obs.Protocol {
	case 6:
		classifyTCPApp(obs)
	case 17:
		classifyUDPApp(obs)
	}
}

func classifyTCPApp(obs *model.Observation) {
	payload := obs.Payload
	// SSH is recognisable regardless of port and is commonly sent first.
	if len(payload) >= 4 && string(payload[:4]) == "SSH-" {
		line := firstLine(payload)
		obs.App.Protocol = "SSH"
		obs.App.SSHBanner = sanitizeText(line, 120)
		obs.App.Detail = "SSH " + obs.App.SSHBanner
		return
	}
	if obs.SrcPort == 21 || obs.DstPort == 21 || obs.SrcPort == 20 || obs.DstPort == 20 {
		parseFTP(obs)
		return
	}
	if isHTTPPayload(payload) {
		parseHTTP(obs)
		return
	}
	if isTLSHandshake(payload) {
		obs.App.Protocol = "TLS"
		obs.App.Detail = "TLS handshake"
		return
	}
	if len(payload) >= 2 && (obs.SrcPort == 53 || obs.DstPort == 53) {
		parseDNS(obs, true)
	}
}

func classifyUDPApp(obs *model.Observation) {
	if obs.SrcPort == 53 || obs.DstPort == 53 || obs.SrcPort == 5353 || obs.DstPort == 5353 {
		parseDNS(obs, false)
		return
	}
	if isHTTPPayload(obs.Payload) {
		parseHTTP(obs)
	}
}

func isHTTPPayload(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	if len(payload) >= 5 && string(payload[:5]) == "HTTP/" {
		return true
	}
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
	for _, method := range methods {
		if len(payload) >= len(method) && string(payload[:len(method)]) == method {
			return true
		}
	}
	return false
}

func parseHTTP(obs *model.Observation) {
	line := firstLine(obs.Payload)
	obs.App.Protocol = "HTTP"
	if strings.HasPrefix(line, "HTTP/") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			obs.App.Detail = "HTTP response " + parts[1]
		}
		return
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		obs.App.Detail = "HTTP"
		return
	}
	obs.App.HTTPMethod = sanitizeToken(parts[0], 16)
	obs.App.HTTPPath = sanitizeToken(parts[1], 160)
	if host := httpHeader(obs.Payload, "Host"); host != "" {
		obs.App.HTTPHost = sanitizeToken(host, 120)
	}
	obs.App.Detail = "HTTP " + obs.App.HTTPMethod + " " + obs.App.HTTPPath
	if obs.App.HTTPHost != "" {
		obs.App.Detail += " " + obs.App.HTTPHost
	}
}

func httpHeader(payload []byte, name string) string {
	text := string(payload)
	lower := strings.ToLower(text)
	needle := strings.ToLower(name) + ":"
	index := strings.Index(lower, "\n"+needle)
	if index < 0 {
		if !strings.HasPrefix(lower, needle) {
			return ""
		}
	} else {
		text = text[index+1:]
	}
	line := firstLine([]byte(text))
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func firstLine(payload []byte) string {
	if index := strings.IndexByte(string(payload), '\n'); index >= 0 {
		payload = payload[:index]
	}
	return strings.TrimRight(string(payload), "\r")
}

func sanitizeText(value string, max int) string {
	var b strings.Builder
	for _, r := range value {
		if r == '\t' {
			b.WriteRune(' ')
			continue
		}
		if r < 32 || r == 127 {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= max {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func sanitizeToken(value string, max int) string {
	value = sanitizeText(value, max)
	if len(value) > max {
		value = value[:max]
	}
	return value
}

func isTLSHandshake(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	if payload[0] != 0x16 {
		return false
	}
	if payload[1] != 0x03 {
		return false
	}
	return payload[2] >= 0x01 && payload[2] <= 0x04
}

func parseFTP(obs *model.Observation) {
	obs.App.Protocol = "FTP"
	payload := obs.Payload
	// Data channel: bulk transfer, never interpreted as commands.
	if obs.DstPort == 20 && obs.SrcPort >= 1024 {
		obs.App.Detail = "FTP data"
		return
	}
	if obs.SrcPort == 20 {
		obs.App.Detail = "FTP data reply"
		return
	}
	line := firstLine(payload)
	if len(line) >= 4 && isDigits(line[:3]) && (line[3] == ' ' || line[3] == '-') {
		obs.App.FTPReplyCode = line[:3]
		obs.App.Detail = "FTP reply " + line[:3]
		return
	}
	command, argument := parseFTPCommand(line)
	if command != "" {
		obs.App.FTPCommand = command
		obs.App.FTPArgument = argument
		obs.App.Detail = strings.TrimSpace("FTP " + command + " " + argument)
		return
	}
	obs.App.Detail = "FTP control"
}

func parseFTPCommand(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	end := 0
	for end < len(line) && end < 8 {
		c := line[end]
		if c >= 'A' && c <= 'Z' {
			end++
			continue
		}
		break
	}
	if end < 3 || end > 5 {
		return "", ""
	}
	command := line[:end]
	if end < len(line) {
		next := line[end]
		if next != ' ' && next != '\t' {
			return "", ""
		}
	}
	argument := ""
	if end < len(line) {
		argument = strings.TrimSpace(line[end:])
	}
	return command, sanitizeToken(argument, 120)
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func parseDNS(obs *model.Observation, tcp bool) {
	payload := obs.Payload
	if tcp {
		if len(payload) < 2 {
			obs.App.Protocol = "DNS"
			return
		}
		length := int(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
		if length < len(payload) {
			payload = payload[:length]
		}
	}
	dns := parseDNSMessage(payload)
	if dns.name == "" && dns.record == "" {
		return
	}
	obs.App.Protocol = "DNS"
	obs.App.DNSQuery = dns.name
	obs.App.DNSRecord = dns.record
	detail := "DNS"
	if dns.record != "" {
		detail += " " + dns.record
	}
	if dns.name != "" {
		detail += " " + dns.name
	}
	obs.App.Detail = detail
}

type dnsFacts struct {
	name   string
	record string
}

func parseDNSMessage(payload []byte) dnsFacts {
	if len(payload) < 12 {
		return dnsFacts{}
	}
	questions := int(binary.BigEndian.Uint16(payload[4:6]))
	if questions < 1 {
		return dnsFacts{}
	}
	offset := 12
	var labels []string
	for depth := 0; depth < 16 && offset < len(payload); depth++ {
		length := int(payload[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			// Compression pointer in a question is legal but uncommon. We do not
			// follow it; the visible part of the name is still useful.
			offset += 2
			break
		}
		if length > 63 || offset+1+length > len(payload) {
			return dnsFacts{}
		}
		label := payload[offset+1 : offset+1+length]
		labels = append(labels, sanitizeText(string(label), 63))
		offset += 1 + length
	}
	name := strings.Join(labels, ".")
	if offset+2 <= len(payload) {
		recordType := binary.BigEndian.Uint16(payload[offset : offset+2])
		return dnsFacts{name: sanitizeToken(name, 200), record: dnsRecordName(recordType)}
	}
	return dnsFacts{name: sanitizeToken(name, 200)}
}

func dnsRecordName(value uint16) string {
	switch value {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 43:
		return "DS"
	case 46:
		return "RRSIG"
	case 48:
		return "DNSKEY"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	default:
		return "TYPE" + strconv.Itoa(int(value))
	}
}
