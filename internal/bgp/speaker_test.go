package bgp

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"dollysensor/internal/mitigate"
)

type fakeBGPPeer struct {
	listener    net.Listener
	flowspec    bool
	hold        uint16
	updates     chan []byte
	acceptDone  chan struct{}
	serveWG     sync.WaitGroup
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closeOnce   sync.Once
}

func startFakeBGPPeer(t *testing.T, flowspec bool, hold uint16) *fakeBGPPeer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := &fakeBGPPeer{
		listener:    listener,
		flowspec:    flowspec,
		hold:        hold,
		updates:     make(chan []byte, 32),
		acceptDone:  make(chan struct{}),
		connections: make(map[net.Conn]struct{}),
	}
	go peer.acceptLoop()
	return peer
}

func (p *fakeBGPPeer) acceptLoop() {
	defer close(p.acceptDone)
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.connections[conn] = struct{}{}
		p.mu.Unlock()
		p.serveWG.Add(1)
		go p.serve(conn)
	}
}

func (p *fakeBGPPeer) serve(conn net.Conn) {
	defer p.serveWG.Done()
	defer func() {
		p.mu.Lock()
		delete(p.connections, conn)
		p.mu.Unlock()
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := readBGPMessage(conn, 5*time.Second); err != nil {
		return
	}
	if err := writeBGPMessage(conn, fakeOpenMessage(p.flowspec, p.hold), time.Now().Add(5*time.Second)); err != nil {
		return
	}
	if err := writeBGPMessage(conn, bgpMessage(msgKeepalive, nil), time.Now().Add(5*time.Second)); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	for {
		messageType, body, err := readBGPMessage(conn, 0)
		if err != nil {
			return
		}
		if messageType == msgUpdate {
			p.updates <- append([]byte(nil), body...)
		}
	}
}

func (p *fakeBGPPeer) dropConnections() {
	p.mu.Lock()
	conns := make([]net.Conn, 0, len(p.connections))
	for conn := range p.connections {
		conns = append(conns, conn)
	}
	p.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (p *fakeBGPPeer) Close() {
	p.closeOnce.Do(func() {
		_ = p.listener.Close()
		<-p.acceptDone
		p.dropConnections()
		p.serveWG.Wait()
	})
}

func fakeOpenMessage(flowspec bool, hold uint16) []byte {
	var capabilities []byte
	appendCapability := func(code byte, data []byte) {
		capabilities = append(capabilities, code, byte(len(data)))
		capabilities = append(capabilities, data...)
	}
	unicast := make([]byte, 4)
	binary.BigEndian.PutUint16(unicast[0:2], afiIPv4)
	unicast[3] = safiUnicast
	appendCapability(capMultiprotocol, unicast)
	if flowspec {
		flow := make([]byte, 4)
		binary.BigEndian.PutUint16(flow[0:2], afiIPv4)
		flow[3] = safiFlowspec
		appendCapability(capMultiprotocol, flow)
	}
	options := append([]byte{2, byte(len(capabilities))}, capabilities...)
	body := make([]byte, 10)
	body[0] = 4
	binary.BigEndian.PutUint16(body[1:3], 65000)
	binary.BigEndian.PutUint16(body[3:5], hold)
	binary.BigEndian.PutUint32(body[5:9], 0xC0000201) // 192.0.2.1
	body[9] = byte(len(options))
	body = append(body, options...)
	return bgpMessage(msgOpen, body)
}

func testSpeaker(t *testing.T, peer *fakeBGPPeer) *Speaker {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	speaker, err := New(Options{
		LocalAS:        65001,
		PeerAS:         65000,
		PeerIP:         netip.MustParseAddr("127.0.0.1"),
		PeerPort:       peer.listener.Addr().(*net.TCPAddr).Port,
		RouterID:       netip.MustParseAddr("192.0.2.10"),
		Community:      0xFDE80000 | 666,
		NextHop:        netip.MustParseAddr("192.0.2.1"),
		HoldTime:       30 * time.Second,
		ConnectTimeout: 2 * time.Second,
	}, logger)
	if err != nil {
		t.Fatal(err)
	}
	return speaker
}

func testFlowAction(id, source string) mitigate.Action {
	return mitigate.Action{
		ID:   id,
		Kind: mitigate.KindFlowspec,
		Match: mitigate.Match{
			Source:      source + "/32",
			Destination: "203.0.113.10/32",
			Protocol:    6,
			DstPort:     443,
			TCPFlags:    2,
		},
		Action: "discard",
		Target: "203.0.113.10/32",
	}
}

func waitForUpdate(t *testing.T, updates <-chan []byte, want []byte) {
	t.Helper()
	select {
	case got := <-updates:
		if !bytes.Equal(got, want) {
			t.Fatalf("update body mismatch\n got: %x\nwant: %x", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for BGP UPDATE")
	}
}

func TestSpeakerRejectsFlowspecWithoutPeerCapability(t *testing.T) {
	peer := startFakeBGPPeer(t, false, 90)
	defer peer.Close()
	speaker := testSpeaker(t, peer)
	defer speaker.Close()

	err := speaker.Announce(context.Background(), testFlowAction("flow-1", "198.51.100.10"))
	if err == nil || !strings.Contains(err.Error(), "did not advertise IPv4 Flowspec") {
		t.Fatalf("Announce error = %v, want capability rejection", err)
	}
	status := speaker.Status()
	if status.Flowspec {
		t.Fatalf("peer Flowspec status = true, want false")
	}
}

func TestSpeakerReplaysDesiredActionsAndWithdrawsAfterReconnect(t *testing.T) {
	peer := startFakeBGPPeer(t, true, 90)
	defer peer.Close()
	speaker := testSpeaker(t, peer)
	defer speaker.Close()
	ctx := context.Background()

	first := testFlowAction("flow-1", "198.51.100.10")
	second := testFlowAction("flow-2", "198.51.100.11")
	if err := speaker.Announce(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := speaker.Announce(ctx, second); err != nil {
		t.Fatal(err)
	}
	firstMessage, err := buildAnnouncement(first, speaker.opts, false)
	if err != nil {
		t.Fatal(err)
	}
	secondMessage, err := buildAnnouncement(second, speaker.opts, false)
	if err != nil {
		t.Fatal(err)
	}
	waitForUpdate(t, peer.updates, firstMessage[19:])
	waitForUpdate(t, peer.updates, secondMessage[19:])

	// Drop the session. The next operation must establish a new session,
	// replay only the still-desired action, and then send the withdrawal.
	peer.dropConnections()
	deadline := time.Now().Add(3 * time.Second)
	for speaker.Status().State != "disconnected" {
		if time.Now().After(deadline) {
			t.Fatalf("speaker state = %q, want disconnected", speaker.Status().State)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := speaker.Withdraw(ctx, first); err != nil {
		t.Fatal(err)
	}
	withdrawal, err := buildWithdrawal(first, speaker.opts, false)
	if err != nil {
		t.Fatal(err)
	}
	waitForUpdate(t, peer.updates, secondMessage[19:])
	waitForUpdate(t, peer.updates, withdrawal[19:])
}

func TestSpeakerRunReconnectsAndReplays(t *testing.T) {
	peer := startFakeBGPPeer(t, true, 90)
	defer peer.Close()
	speaker := testSpeaker(t, peer)
	defer speaker.Close()
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		speaker.Run(ctx)
		close(runDone)
	}()
	defer func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(3 * time.Second):
			t.Fatal("Run did not stop")
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for speaker.Status().State != "established" {
		if time.Now().After(deadline) {
			t.Fatalf("speaker state = %q, want established", speaker.Status().State)
		}
		time.Sleep(10 * time.Millisecond)
	}
	action := testFlowAction("flow-run", "198.51.100.13")
	if err := speaker.Announce(ctx, action); err != nil {
		t.Fatal(err)
	}
	message, err := buildAnnouncement(action, speaker.opts, false)
	if err != nil {
		t.Fatal(err)
	}
	waitForUpdate(t, peer.updates, message[19:])

	// Run should notice the dropped session, wait for its bounded backoff, and
	// replay the still-desired action on the replacement session.
	peer.dropConnections()
	waitForUpdate(t, peer.updates, message[19:])
}

func TestSpeakerEnforcesNegotiatedHoldTime(t *testing.T) {
	peer := startFakeBGPPeer(t, true, 3)
	defer peer.Close()
	speaker := testSpeaker(t, peer)
	defer speaker.Close()

	if err := speaker.Announce(context.Background(), testFlowAction("flow-hold", "198.51.100.12")); err != nil {
		t.Fatal(err)
	}
	if got := speaker.Status().HoldSeconds; got != 3 {
		t.Fatalf("negotiated hold = %v, want 3", got)
	}
	deadline := time.Now().Add(7 * time.Second)
	for speaker.Status().State != "disconnected" {
		if time.Now().After(deadline) {
			t.Fatalf("speaker state = %q, want hold-time disconnect", speaker.Status().State)
		}
		time.Sleep(25 * time.Millisecond)
	}
}
