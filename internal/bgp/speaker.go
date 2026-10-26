// Package bgp implements the small, deliberate subset of BGP that Dolly Sensor
// needs: a single-session speaker that announces and withdraws IPv4 RTBH
// host routes and IPv4 Flowspec rules. It is not a routing daemon.
package bgp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"dollysensor/internal/mitigate"
)

const maxBGPMessage = 4096

// Options configures one BGP session.
type Options struct {
	LocalAS        uint32
	PeerAS         uint32
	PeerIP         netip.Addr
	PeerPort       int
	LocalAddr      netip.Addr
	RouterID       netip.Addr
	Community      uint32
	NextHop        netip.Addr
	HoldTime       time.Duration
	ConnectTimeout time.Duration
	Logger         *slog.Logger
	// OnEstablished runs asynchronously after a session is established and
	// replay has completed. It lets the sensor reconcile standing rules that
	// failed while the peer was down.
	OnEstablished func()
}

// Status is the operator-visible state of the speaker.
type Status struct {
	Enabled         bool      `json:"enabled"`
	State           string    `json:"state"`
	Peer            string    `json:"peer"`
	LocalAS         uint32    `json:"local_as"`
	PeerAS          uint32    `json:"peer_as"`
	As4             bool      `json:"four_byte_as"`
	Flowspec        bool      `json:"peer_flowspec"`
	ConnectedAt     time.Time `json:"connected_at,omitempty"`
	UptimeSeconds   float64   `json:"uptime_seconds"`
	LastError       string    `json:"last_error,omitempty"`
	LastErrorAt     time.Time `json:"last_error_at,omitempty"`
	UpdatesSent     uint64    `json:"updates_sent"`
	WithdrawalsSent uint64    `json:"withdrawals_sent"`
	HoldSeconds     float64   `json:"hold_seconds"`
}

// Speaker is a single-peer BGP speaker. Run keeps the session alive and
// replays desired announcements after a session flap.
type Speaker struct {
	opts   Options
	logger *slog.Logger

	opMu sync.Mutex // serializes connect and update writes

	mu           sync.Mutex
	conn         net.Conn
	closeCh      chan struct{}
	state        string
	established  bool
	closed       bool
	connectedAt  time.Time
	as4          bool
	peerFlowspec bool
	hold         time.Duration
	lastErr      string
	lastErrAt    time.Time
	desired      map[string]mitigate.Action

	updates     atomic.Uint64
	withdrawals atomic.Uint64
	wg          sync.WaitGroup
	closeOnce   sync.Once
}

// New validates options and creates a disconnected speaker.
func New(opts Options, logger *slog.Logger) (*Speaker, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if opts.PeerPort == 0 {
		opts.PeerPort = 179
	}
	if opts.PeerPort < 1 || opts.PeerPort > 65535 {
		return nil, errors.New("BGP peer port must be between 1 and 65535")
	}
	if !opts.PeerIP.IsValid() {
		return nil, errors.New("BGP peer IP is required")
	}
	opts.PeerIP = opts.PeerIP.Unmap()
	if opts.LocalAS == 0 {
		return nil, errors.New("BGP local AS is required")
	}
	if opts.PeerAS == 0 {
		return nil, errors.New("BGP peer AS is required")
	}
	if opts.HoldTime <= 0 {
		opts.HoldTime = 90 * time.Second
	}
	if opts.HoldTime > 65535*time.Second {
		return nil, errors.New("BGP hold time must not exceed 65535s")
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = 5 * time.Second
	}
	if opts.LocalAddr.IsValid() {
		opts.LocalAddr = opts.LocalAddr.Unmap()
	}
	if _, err := routerIDUint32(opts.RouterID); err != nil {
		return nil, err
	}
	if !opts.NextHop.IsValid() || !opts.NextHop.Unmap().Is4() {
		return nil, errors.New("BGP next hop must be an IPv4 address")
	}
	opts.NextHop = opts.NextHop.Unmap()
	if opts.Community == 0 {
		return nil, errors.New("BGP blackhole community is required for RTBH")
	}
	return &Speaker{
		opts:    opts,
		logger:  logger,
		state:   "disconnected",
		desired: make(map[string]mitigate.Action),
	}, nil
}

// Run maintains the BGP session until ctx is canceled. It reconnects with
// bounded backoff and replays still-desired announcements after a flap so a
// brief peer restart does not silently leave the edge unprotected.
func (s *Speaker) Run(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		s.opMu.Lock()
		err := s.ensure(ctx)
		s.opMu.Unlock()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Warn("BGP session unavailable", "error", err.Error(), "retry_in", backoff.String())
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if backoff < 30*time.Second {
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
			continue
		}
		backoff = 2 * time.Second
		s.mu.Lock()
		closeCh := s.closeCh
		s.mu.Unlock()
		if closeCh == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-closeCh:
			// Reconnect promptly, but avoid a tight loop if the peer keeps
			// accepting TCP and immediately closing the session.
			timer := time.NewTimer(time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

// Announce connects if needed and announces one action.
func (s *Speaker) Announce(ctx context.Context, action mitigate.Action) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.ensure(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	conn := s.conn
	as4 := s.as4
	peerFlowspec := s.peerFlowspec
	s.mu.Unlock()
	if conn == nil {
		return errors.New("BGP session is not established")
	}
	if action.Kind == mitigate.KindFlowspec && !peerFlowspec {
		return errors.New("peer did not advertise IPv4 Flowspec (AFI 1 / SAFI 133)")
	}
	message, err := buildAnnouncement(action, s.opts, as4)
	if err != nil {
		return err
	}
	deadline := writeDeadline(ctx, s.opts.ConnectTimeout)
	if err := writeBGPMessage(conn, message, deadline); err != nil {
		s.sessionEnded(conn, fmt.Errorf("announce %s: %w", action.ID, err))
		return err
	}
	s.updates.Add(1)
	s.mu.Lock()
	s.desired[action.ID] = action
	s.mu.Unlock()
	return nil
}

// Withdraw connects if needed and withdraws one action.
func (s *Speaker) Withdraw(ctx context.Context, action mitigate.Action) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	delete(s.desired, action.ID)
	s.mu.Unlock()
	// Re-establishing only to send this withdrawal must not silently leave
	// other active announcements absent from the new session.
	if err := s.ensure(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	conn := s.conn
	as4 := s.as4
	s.mu.Unlock()
	if conn == nil {
		return errors.New("BGP session is not established")
	}
	message, err := buildWithdrawal(action, s.opts, as4)
	if err != nil {
		return err
	}
	if err := writeBGPMessage(conn, message, writeDeadline(ctx, s.opts.ConnectTimeout)); err != nil {
		s.sessionEnded(conn, fmt.Errorf("withdraw %s: %w", action.ID, err))
		return err
	}
	s.withdrawals.Add(1)
	return nil
}

func writeDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctx != nil {
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
	}
	return deadline
}

func (s *Speaker) ensure(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("BGP speaker is closed")
	}
	if s.established && s.conn != nil {
		s.mu.Unlock()
		return nil
	}
	old := s.conn
	s.conn = nil
	s.established = false
	s.state = "connecting"
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	connectCtx := ctx
	cancel := func() {}
	if _, ok := ctx.Deadline(); !ok {
		connectCtx, cancel = context.WithTimeout(ctx, s.opts.ConnectTimeout)
	}
	defer cancel()

	address := net.JoinHostPort(s.opts.PeerIP.String(), strconv.Itoa(s.opts.PeerPort))
	dialer := net.Dialer{}
	if s.opts.LocalAddr.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: net.IP(s.opts.LocalAddr.AsSlice())}
	}
	conn, err := dialer.DialContext(connectCtx, "tcp", address)
	if err != nil {
		s.setError(err)
		return fmt.Errorf("connect to BGP peer %s: %w", address, err)
	}
	deadline := time.Now().Add(s.opts.ConnectTimeout)
	if ctxDeadline, ok := connectCtx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		s.setError(err)
		return err
	}
	peer, as4, hold, err := s.handshake(conn)
	if err != nil {
		conn.Close()
		s.setError(err)
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	closeCh := make(chan struct{})
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return errors.New("BGP speaker is closed")
	}
	s.conn = conn
	s.closeCh = closeCh
	s.established = true
	s.state = "established"
	s.connectedAt = time.Now()
	s.as4 = as4
	s.peerFlowspec = peer.flowspec
	s.hold = hold
	s.lastErr = ""
	// Register the session goroutines while still holding mu so Close cannot
	// start Wait before these Add calls. They are launched before replay: if
	// replay fails, closing the session channel makes them exit, and a
	// concurrent Close is never left waiting on unstarted goroutines.
	s.wg.Add(1)
	if hold > 0 {
		s.wg.Add(1)
	}
	s.mu.Unlock()
	s.logger.Info("BGP session established", "peer", address, "four_byte_as", as4, "flowspec", peer.flowspec, "hold", hold.String())
	go s.readLoop(conn, closeCh, hold)
	if hold > 0 {
		go s.keepaliveLoop(conn, closeCh, hold)
	}
	if err := s.replayDesired(ctx, conn, as4, peer.flowspec); err != nil {
		s.sessionEnded(conn, fmt.Errorf("replay desired announcements: %w", err))
		return err
	}
	if s.opts.OnEstablished != nil {
		go s.opts.OnEstablished()
	}
	return nil
}

// replayDesired re-announces the actions that the manager still considers
// active. It is called immediately after a new session becomes established.
func (s *Speaker) replayDesired(ctx context.Context, conn net.Conn, as4, peerFlowspec bool) error {
	s.mu.Lock()
	actions := make([]mitigate.Action, 0, len(s.desired))
	for _, action := range s.desired {
		actions = append(actions, action)
	}
	s.mu.Unlock()
	if len(actions) == 0 {
		return nil
	}
	replayed := 0
	for _, action := range actions {
		if action.Kind == mitigate.KindFlowspec && !peerFlowspec {
			s.logger.Warn("cannot replay Flowspec action without peer capability", "action", action.ID)
			continue
		}
		message, err := buildAnnouncement(action, s.opts, as4)
		if err != nil {
			return fmt.Errorf("%s: %w", action.ID, err)
		}
		if err := writeBGPMessage(conn, message, writeDeadline(ctx, s.opts.ConnectTimeout)); err != nil {
			return fmt.Errorf("%s: %w", action.ID, err)
		}
		s.updates.Add(1)
		replayed++
	}
	s.logger.Info("replayed BGP announcements after reconnect", "count", replayed)
	return nil
}

type peerOpen struct {
	myAS        uint16
	effectiveAS uint32
	hold        uint16
	routerID    uint32
	as4         bool
	flowspec    bool
	unicast     bool
}

func (s *Speaker) handshake(conn net.Conn) (peerOpen, bool, time.Duration, error) {
	openMessage, err := buildOpen(s.opts)
	if err != nil {
		return peerOpen{}, false, 0, err
	}
	deadline := time.Now().Add(s.opts.ConnectTimeout)
	if err := writeBGPMessage(conn, openMessage, deadline); err != nil {
		return peerOpen{}, false, 0, fmt.Errorf("send BGP OPEN: %w", err)
	}
	messageType, body, err := readBGPMessage(conn, s.opts.ConnectTimeout)
	if err != nil {
		return peerOpen{}, false, 0, fmt.Errorf("read BGP OPEN: %w", err)
	}
	if messageType == msgNotification {
		return peerOpen{}, false, 0, notificationError(body)
	}
	if messageType != msgOpen {
		return peerOpen{}, false, 0, fmt.Errorf("expected BGP OPEN, got message type %d", messageType)
	}
	peer, err := parseOpen(body)
	if err != nil {
		return peerOpen{}, false, 0, err
	}
	if peer.effectiveAS != s.opts.PeerAS {
		_ = writeBGPMessage(conn, bgpMessage(msgNotification, []byte{2, 2}), time.Now().Add(time.Second))
		return peerOpen{}, false, 0, fmt.Errorf("peer AS mismatch: configured %d, peer advertised %d", s.opts.PeerAS, peer.effectiveAS)
	}
	if err := writeBGPMessage(conn, bgpMessage(msgKeepalive, nil), deadline); err != nil {
		return peerOpen{}, false, 0, fmt.Errorf("send BGP KEEPALIVE: %w", err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		messageType, body, err = readBGPMessage(conn, s.opts.ConnectTimeout)
		if err != nil {
			return peerOpen{}, false, 0, fmt.Errorf("wait for BGP KEEPALIVE: %w", err)
		}
		switch messageType {
		case msgKeepalive:
			hold := s.opts.HoldTime
			if peer.hold == 0 {
				hold = 0
			} else if peerHold := time.Duration(peer.hold) * time.Second; peerHold < hold {
				hold = peerHold
			}
			return peer, peer.as4, hold, nil
		case msgNotification:
			return peerOpen{}, false, 0, notificationError(body)
		default:
			return peerOpen{}, false, 0, fmt.Errorf("expected BGP KEEPALIVE, got message type %d", messageType)
		}
	}
	return peerOpen{}, false, 0, errors.New("BGP peer did not send KEEPALIVE")
}

func parseOpen(body []byte) (peerOpen, error) {
	var peer peerOpen
	if len(body) < 10 {
		return peer, errors.New("short BGP OPEN message")
	}
	if body[0] != 4 {
		return peer, fmt.Errorf("unsupported BGP version %d", body[0])
	}
	peer.myAS = binary.BigEndian.Uint16(body[1:3])
	peer.hold = binary.BigEndian.Uint16(body[3:5])
	peer.routerID = binary.BigEndian.Uint32(body[5:9])
	optionLength := int(body[9])
	if 10+optionLength > len(body) {
		return peer, errors.New("BGP OPEN optional parameters exceed message")
	}
	options := body[10 : 10+optionLength]
	offset := 0
	var as4Value uint32
	for offset < len(options) {
		if offset+2 > len(options) {
			return peer, errors.New("truncated BGP OPEN optional parameter")
		}
		paramType := options[offset]
		paramLength := int(options[offset+1])
		offset += 2
		if offset+paramLength > len(options) {
			return peer, errors.New("BGP OPEN optional parameter overruns message")
		}
		value := options[offset : offset+paramLength]
		offset += paramLength
		if paramType != 2 {
			continue
		}
		capOffset := 0
		for capOffset < len(value) {
			if capOffset+2 > len(value) {
				return peer, errors.New("truncated BGP capability")
			}
			code := value[capOffset]
			length := int(value[capOffset+1])
			capOffset += 2
			if capOffset+length > len(value) {
				return peer, errors.New("BGP capability overruns optional parameter")
			}
			data := value[capOffset : capOffset+length]
			capOffset += length
			switch code {
			case capAS4:
				if len(data) != 4 {
					return peer, errors.New("malformed four-octet AS capability")
				}
				as4Value = binary.BigEndian.Uint32(data)
				peer.as4 = true
			case capMultiprotocol:
				if len(data) >= 4 {
					afi := binary.BigEndian.Uint16(data[0:2])
					safi := data[3]
					if afi == afiIPv4 && safi == safiFlowspec {
						peer.flowspec = true
					}
					if afi == afiIPv4 && safi == safiUnicast {
						peer.unicast = true
					}
				}
			}
		}
	}
	peer.effectiveAS = uint32(peer.myAS)
	if peer.myAS == asTrans && peer.as4 {
		peer.effectiveAS = as4Value
	}
	return peer, nil
}

func (s *Speaker) readLoop(conn net.Conn, closeCh chan struct{}, hold time.Duration) {
	defer s.wg.Done()
	for {
		select {
		case <-closeCh:
			return
		default:
		}
		// Any valid message refreshes the hold timer. Without a read deadline
		// a silently dead peer could keep a TCP session open indefinitely.
		messageType, body, err := readBGPMessage(conn, hold)
		if err != nil {
			select {
			case <-closeCh:
				return
			default:
			}
			s.sessionEnded(conn, err)
			return
		}
		switch messageType {
		case msgNotification:
			s.sessionEnded(conn, notificationError(body))
			return
		case msgOpen:
			s.sessionEnded(conn, errors.New("unexpected BGP OPEN on established session"))
			return
		case msgKeepalive, msgUpdate:
			// We have no routing table to update. KEEPALIVEs are implicitly
			// refreshed by TCP reads, and UPDATEs from the peer are ignored.
		default:
			// Unknown message types are ignored for forward compatibility.
		}
	}
}

func (s *Speaker) keepaliveLoop(conn net.Conn, closeCh chan struct{}, hold time.Duration) {
	defer s.wg.Done()
	interval := hold / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-closeCh:
			return
		case <-ticker.C:
			if err := writeBGPMessage(conn, bgpMessage(msgKeepalive, nil), time.Now().Add(s.opts.ConnectTimeout)); err != nil {
				s.sessionEnded(conn, fmt.Errorf("send BGP KEEPALIVE: %w", err))
				return
			}
		}
	}
}

func (s *Speaker) sessionEnded(conn net.Conn, err error) {
	s.mu.Lock()
	if s.conn != conn {
		s.mu.Unlock()
		return
	}
	s.conn = nil
	s.established = false
	if s.closeCh != nil {
		close(s.closeCh)
		s.closeCh = nil
	}
	if !s.closed {
		s.state = "disconnected"
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			s.lastErr = err.Error()
			s.lastErrAt = time.Now()
			s.logger.Warn("BGP session ended", "error", err.Error())
		}
	}
	s.mu.Unlock()
	_ = conn.Close()
}

func (s *Speaker) setError(err error) {
	s.mu.Lock()
	s.state = "disconnected"
	if err != nil {
		s.lastErr = err.Error()
		s.lastErrAt = time.Now()
	}
	s.mu.Unlock()
}

// Status returns a consistent snapshot of session state.
func (s *Speaker) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := Status{
		Enabled:         true,
		State:           s.state,
		Peer:            net.JoinHostPort(s.opts.PeerIP.String(), strconv.Itoa(s.opts.PeerPort)),
		LocalAS:         s.opts.LocalAS,
		PeerAS:          s.opts.PeerAS,
		As4:             s.as4,
		Flowspec:        s.peerFlowspec,
		ConnectedAt:     s.connectedAt,
		LastError:       s.lastErr,
		LastErrorAt:     s.lastErrAt,
		UpdatesSent:     s.updates.Load(),
		WithdrawalsSent: s.withdrawals.Load(),
		HoldSeconds:     s.hold.Seconds(),
	}
	if s.established {
		status.UptimeSeconds = time.Since(s.connectedAt).Seconds()
	}
	return status
}

// Close gracefully closes the session. It sends a Cease notification when
// possible, then stops keepalive and read loops.
func (s *Speaker) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		conn := s.conn
		s.state = "closed"
		s.mu.Unlock()
		if conn != nil {
			_ = writeBGPMessage(conn, bgpMessage(msgNotification, []byte{6, 0}), time.Now().Add(time.Second))
		}
		s.mu.Lock()
		if closeCh := s.closeCh; closeCh != nil {
			close(closeCh)
			s.closeCh = nil
		}
		s.conn = nil
		s.established = false
		s.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		s.wg.Wait()
	})
}

func readBGPMessage(conn net.Conn, timeout time.Duration) (byte, []byte, error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return 0, nil, err
		}
	} else {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return 0, nil, err
		}
	}
	header := make([]byte, 19)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	for i := 0; i < 16; i++ {
		if header[i] != 0xff {
			return 0, nil, errors.New("invalid BGP marker")
		}
	}
	length := int(binary.BigEndian.Uint16(header[16:18]))
	if length < 19 || length > maxBGPMessage {
		return 0, nil, fmt.Errorf("invalid BGP message length %d", length)
	}
	messageType := header[18]
	body := make([]byte, length-19)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}
	return messageType, body, nil
}

func writeBGPMessage(conn net.Conn, message []byte, deadline time.Time) error {
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	for len(message) > 0 {
		n, err := conn.Write(message)
		if err != nil {
			return err
		}
		message = message[n:]
	}
	return nil
}

func notificationError(body []byte) error {
	if len(body) < 2 {
		return errors.New("BGP NOTIFICATION received (malformed)")
	}
	code := body[0]
	subcode := body[1]
	return fmt.Errorf("BGP NOTIFICATION received: error code %d, subcode %d", code, subcode)
}
