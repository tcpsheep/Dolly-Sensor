// Command sflowgen sends synthetic sFlow v5 samples to Dolly Sensor.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dollysensor/internal/sflowgen"
)

func main() {
	target := flag.String("target", "127.0.0.1:6343", "sFlow collector UDP address")
	agent := flag.String("agent", "192.0.2.10", "sFlow agent IPv4 address")
	src := flag.String("src", "198.51.100.7", "packet source IPv4 address")
	dst := flag.String("dst", "203.0.113.10", "packet destination IPv4 address")
	srcPort := flag.Int("sport", 40000, "source port")
	dstPort := flag.Int("dport", 443, "destination port")
	protocol := flag.String("proto", "tcp", "tcp, udp, icmp, or an IP protocol number")
	flagsText := flag.String("flags", "syn", "TCP flags: syn,ack,fin,rst,psh,urg or none")
	rate := flag.Int("rate", 1, "sFlow sampling rate represented by each sample")
	count := flag.Int("count", 100, "number of datagrams to send (0 = forever)")
	interval := flag.Duration("interval", 100*time.Millisecond, "delay between datagrams")
	perDatagram := flag.Int("samples", 1, "packets/samples per datagram")
	size := flag.Int("size", 0, "frame length override (0 = natural size)")
	payloadText := flag.String("payload", "", "application payload (supports \\r, \\n, \\t, \\xNN)")
	varyPort := flag.Bool("vary-src-port", true, "increment source port for each sample")
	flag.Parse()

	targetAddr, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		log.Fatalf("target: %v", err)
	}
	agentAddr, err := netip.ParseAddr(*agent)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	sourceAddr, err := netip.ParseAddr(*src)
	if err != nil {
		log.Fatalf("src: %v", err)
	}
	destinationAddr, err := netip.ParseAddr(*dst)
	if err != nil {
		log.Fatalf("dst: %v", err)
	}
	proto, err := parseProtocol(*protocol)
	if err != nil {
		log.Fatal(err)
	}
	tcpFlags, err := parseFlags(*flagsText)
	if err != nil {
		log.Fatal(err)
	}
	payload, err := unescape(*payloadText)
	if err != nil {
		log.Fatalf("payload: %v", err)
	}
	if *srcPort < 1 || *srcPort > 65535 || *dstPort < 0 || *dstPort > 65535 {
		log.Fatal("ports must be between 0 and 65535")
	}
	if *perDatagram < 1 || *perDatagram > 64 {
		log.Fatal("samples per datagram must be between 1 and 64")
	}
	if *rate < 1 {
		log.Fatal("rate must be at least 1")
	}
	if *interval < 0 {
		log.Fatal("interval must not be negative")
	}

	conn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Fatalf("dial collector: %v", err)
	}
	defer conn.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	start := time.Now()
	sequence := uint32(0)
	sentDatagrams := uint64(0)
	sentSamples := uint64(0)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for *count == 0 || sentDatagrams < uint64(*count) {
		packets := make([]sflowgen.PacketSpec, 0, *perDatagram)
		for index := 0; index < *perDatagram; index++ {
			port := *srcPort
			if *varyPort {
				span := 65535 - *srcPort
				if span > 0 {
					port += int((sentSamples + uint64(index)) % uint64(span+1))
				}
			}
			packet := sflowgen.PacketSpec{
				SrcIP:       sourceAddr,
				DstIP:       destinationAddr,
				SrcPort:     uint16(port),
				DstPort:     uint16(*dstPort),
				Protocol:    proto,
				TCPFlags:    tcpFlags,
				TTL:         64,
				Payload:     payload,
				FrameLength: *size,
			}
			packets = append(packets, packet)
		}
		datagram, err := sflowgen.Datagram(sflowgen.DatagramSpec{
			Agent:        agentAddr,
			Sequence:     sequence,
			UptimeMillis: uint32(time.Since(start) / time.Millisecond),
			SamplingRate: uint32(*rate),
			Packets:      packets,
		})
		if err != nil {
			log.Fatalf("build datagram: %v", err)
		}
		if _, err := conn.Write(datagram); err != nil {
			log.Fatalf("send datagram: %v", err)
		}
		sentDatagrams++
		sentSamples += uint64(len(packets))
		sequence++
		select {
		case <-ctx.Done():
			goto done
		case <-ticker.C:
		}
	}
done:
	elapsed := time.Since(start).Seconds()
	fmt.Printf("sent %d datagrams, %d samples to %s in %.2fs (%.0f samples/s)\n",
		sentDatagrams, sentSamples, *target, elapsed, float64(sentSamples)/max(elapsed, 0.001))
}

func parseProtocol(value string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "icmp":
		return 1, nil
	case "icmpv6":
		return 58, nil
	default:
		number, err := strconv.Atoi(value)
		if err != nil || number < 0 || number > 255 {
			return 0, fmt.Errorf("protocol must be tcp, udp, icmp, or 0-255")
		}
		return uint8(number), nil
	}
}

func parseFlags(value string) (uint8, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "none" || value == "-" {
		return 0, nil
	}
	var flags uint8
	for _, part := range strings.Split(value, ",") {
		switch strings.TrimSpace(part) {
		case "fin":
			flags |= 0x01
		case "syn":
			flags |= 0x02
		case "rst":
			flags |= 0x04
		case "psh":
			flags |= 0x08
		case "ack":
			flags |= 0x10
		case "urg":
			flags |= 0x20
		case "ece":
			flags |= 0x40
		case "cwr":
			flags |= 0x80
		default:
			return 0, fmt.Errorf("unknown TCP flag %q", part)
		}
	}
	return flags, nil
}

func unescape(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			out = append(out, value[i])
			continue
		}
		if i+1 >= len(value) {
			return nil, fmt.Errorf("trailing backslash")
		}
		i++
		switch value[i] {
		case 'r':
			out = append(out, '\r')
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case '\\':
			out = append(out, '\\')
		case 'x':
			if i+2 >= len(value) {
				return nil, fmt.Errorf("incomplete \\x escape")
			}
			number, err := strconv.ParseUint(value[i+1:i+3], 16, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid \\x escape")
			}
			out = append(out, byte(number))
			i += 2
		default:
			out = append(out, value[i])
		}
	}
	return out, nil
}
