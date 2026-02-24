package l2tp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

const (
	maxPacketSize        = 4096
	defaultRecvWindow    = 4
	tunnelSetupTimeout   = 10 * time.Second
	maxCtrlRetries       = 5
	ctrlRetryBaseTimeout = 1 * time.Second
)

var (
	errTunnelClosed   = errors.New("l2tp: tunnel closed")
	errControlTimeout = errors.New("l2tp: control response timeout")
)

// Tunnel represents an L2TPv2 tunnel to a single LNS.
type Tunnel struct {
	conn   net.Conn // UDP connection to LNS
	logger *zap.Logger

	localTunnelID  uint16
	remoteTunnelID uint16
	hostname       string
	secret         []byte
	helloInterval  time.Duration

	// Sequence numbers for reliable control delivery
	ns atomic.Uint32 // next send sequence number
	nr atomic.Uint32 // next expected receive sequence number

	// Session registry
	mu       sync.RWMutex
	sessions map[uint16]*Session
	nextSID  uint16

	// Serializes all packet writes to prevent interleaving
	writeMu sync.Mutex

	// Peer Nr tracking for reliable delivery of SCCCN/ICCN.
	// peerNrCh is closed-and-recreated each time the peer advances Nr.
	peerNrMu sync.Mutex
	peerNr   uint16
	peerNrCh chan struct{}

	// Channels for routing control responses (ICRP/CDN) from recvLoop
	// to session establishment goroutines, keyed by local session ID.
	pendingCtrlMu sync.Mutex
	pendingCtrls  map[uint16]chan controlMsg

	// Lifecycle
	closed    chan struct{}
	closeOnce sync.Once
	onClose   func() // callback to manager when tunnel dies
}

type controlMsg struct {
	avps    []AVP
	msgType uint16
}

func newTunnel(conn net.Conn, localTID uint16, hostname string, secret []byte, helloInterval time.Duration, logger *zap.Logger) *Tunnel {
	return &Tunnel{
		conn:          conn,
		logger:        logger,
		localTunnelID: localTID,
		hostname:      hostname,
		secret:        secret,
		helloInterval: helloInterval,
		sessions:      make(map[uint16]*Session),
		nextSID:       1,
		peerNrCh:      make(chan struct{}),
		pendingCtrls:  make(map[uint16]chan controlMsg),
		closed:        make(chan struct{}),
	}
}

// Establish performs the tunnel setup handshake (SCCRQ -> SCCRP -> SCCCN).
func (t *Tunnel) Establish() error {
	var challenge []byte
	if len(t.secret) > 0 {
		challenge = make([]byte, 16)
		if _, err := rand.Read(challenge); err != nil {
			return fmt.Errorf("generate challenge: %w", err)
		}
	}

	payload := BuildSCCRQ(t.hostname, t.localTunnelID, defaultRecvWindow, challenge)
	pkt := t.buildControl(0, 0, payload)
	t.logger.Debug("sending SCCRQ",
		zap.Uint16("tunnelID", t.localTunnelID),
		zap.String("hostname", t.hostname),
		zap.String("remoteAddr", t.conn.RemoteAddr().String()))

	var avps []AVP
	timeout := ctrlRetryBaseTimeout
	for attempt := 0; ; attempt++ {
		if err := t.resendControl(pkt); err != nil {
			return fmt.Errorf("send SCCRQ: %w", err)
		}
		var err error
		avps, err = t.recvControlDirect(timeout)
		if err == nil {
			break
		}
		if attempt >= maxCtrlRetries {
			return fmt.Errorf("recv SCCRP: %w (after %d retries)", err, maxCtrlRetries)
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			return fmt.Errorf("recv SCCRP: %w", err)
		}
		timeout = min(timeout*2, tunnelSetupTimeout)
		t.logger.Debug("SCCRQ timeout, retransmitting", zap.Int("attempt", attempt+1))
	}

	msgType, err := GetMessageType(avps)
	if err != nil {
		return err
	}
	if msgType == MsgTypeStopCCN {
		return fmt.Errorf("LNS rejected tunnel with StopCCN")
	}
	if msgType != MsgTypeSCCRP {
		return fmt.Errorf("expected SCCRP, got msg type %d", msgType)
	}

	// Extract Assigned Tunnel ID from SCCRP
	tidAVP := FindAVP(avps, 0, AVPAssignedTunnelID)
	if tidAVP == nil {
		return fmt.Errorf("%w: Assigned Tunnel ID in SCCRP", ErrMissingAVP)
	}
	remoteTID, err := AVPUint16(tidAVP)
	if err != nil {
		return err
	}
	t.remoteTunnelID = remoteTID

	t.logger.Debug("received SCCRP",
		zap.Uint16("remoteTunnelID", remoteTID))

	// Handle tunnel authentication
	var challengeResponse []byte
	if len(t.secret) > 0 {
		// Check for Challenge in SCCRP (LNS may challenge us)
		lnsChallenge := FindAVP(avps, 0, AVPChallenge)
		if lnsChallenge != nil {
			// Respond with MD5(SCCCN_type + secret + LNS_challenge)
			challengeResponse = ComputeChallengeResponse(byte(MsgTypeSCCCN), t.secret, lnsChallenge.Value)
		}

		// Verify LNS's Challenge Response if we sent a challenge
		lnsCR := FindAVP(avps, 0, AVPChallengeResponse)
		if lnsCR == nil {
			return fmt.Errorf("LNS did not respond to our challenge")
		}
		expected := ComputeChallengeResponse(byte(MsgTypeSCCRP), t.secret, challenge)
		if len(lnsCR.Value) != len(expected) {
			return fmt.Errorf("invalid challenge response from LNS")
		}
		for i := range expected {
			if lnsCR.Value[i] != expected[i] {
				return fmt.Errorf("invalid challenge response from LNS")
			}
		}
	}

	// Start recvLoop before sending SCCCN so any piggybacked control
	// payload on the ack packet is properly processed (not dropped).
	go t.recvLoop()
	if t.helloInterval > 0 {
		go t.helloLoop()
	}

	// Send SCCCN reliably: retry until the LNS acknowledges via Nr advance.
	t.logger.Debug("sending SCCCN",
		zap.Uint16("remoteTunnelID", t.remoteTunnelID))
	scccnPayload := BuildSCCCN(challengeResponse)
	scccnPkt := t.buildControl(t.remoteTunnelID, 0, scccnPayload)
	scccnNs := uint16(t.ns.Load() - 1)
	{
		timeout := ctrlRetryBaseTimeout
		for attempt := 0; ; attempt++ {
			if err := t.resendControl(scccnPkt); err != nil {
				t.Close()
				return fmt.Errorf("send SCCCN: %w", err)
			}
			err := t.waitForPeerAck(scccnNs, timeout)
			if err == nil {
				break
			}
			if attempt >= maxCtrlRetries || !errors.Is(err, errControlTimeout) {
				t.Close()
				return fmt.Errorf("SCCCN ack: %w", err)
			}
			timeout = min(timeout*2, tunnelSetupTimeout)
			t.logger.Debug("SCCCN ack timeout, retransmitting", zap.Int("attempt", attempt+1))
		}
	}

	t.logger.Debug("tunnel handshake complete")
	return nil
}

// CreateSession creates a new L2TP session on this tunnel.
func (t *Tunnel) CreateSession(info *ProxyInfo, callingNumber string) (*Session, error) {
	t.mu.Lock()
	sid := t.nextSID
	t.nextSID++
	s := newSession(t, sid, info, callingNumber)
	t.sessions[sid] = s
	t.mu.Unlock()

	if err := s.establish(); err != nil {
		t.mu.Lock()
		delete(t.sessions, sid)
		t.mu.Unlock()
		return nil, err
	}
	return s, nil
}

// removeSession removes a session from the registry.
// Returns the number of remaining sessions.
func (t *Tunnel) removeSession(sid uint16) int {
	t.mu.Lock()
	delete(t.sessions, sid)
	remaining := len(t.sessions)
	t.mu.Unlock()
	return remaining
}

// SessionCount returns the number of active sessions.
func (t *Tunnel) SessionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}

// Close sends StopCCN and tears down the tunnel.
func (t *Tunnel) Close() {
	t.closeOnce.Do(func() {
		close(t.closed)
		// Best-effort StopCCN
		payload := BuildStopCCN(t.localTunnelID, 1, 0, "LAC shutting down")
		_ = t.sendControl(t.remoteTunnelID, 0, payload)
		t.conn.Close()
		t.closeAllSessions()
	})
}

// Alive returns true if the tunnel has not been closed.
func (t *Tunnel) Alive() bool {
	select {
	case <-t.closed:
		return false
	default:
		return true
	}
}

func (t *Tunnel) closeAllSessions() {
	t.mu.Lock()
	sessions := make([]*Session, 0, len(t.sessions))
	for _, s := range t.sessions {
		sessions = append(sessions, s)
	}
	t.mu.Unlock()
	for _, s := range sessions {
		s.closeDueToTunnel()
	}
}

// buildControl allocates the next Ns and returns the serialized control packet.
func (t *Tunnel) buildControl(tunnelID, sessionID uint16, payload []byte) []byte {
	ns := uint16(t.ns.Add(1) - 1)
	nr := uint16(t.nr.Load())
	hdr := EncodeControlHeader(tunnelID, sessionID, ns, nr, len(payload))
	return append(hdr, payload...)
}

// resendControl retransmits a previously built control packet with an updated Nr.
func (t *Tunnel) resendControl(pkt []byte) error {
	if len(pkt) >= 12 {
		nr := uint16(t.nr.Load())
		binary.BigEndian.PutUint16(pkt[10:12], nr)
	}
	return t.writePacket(pkt)
}

func (t *Tunnel) sendControl(tunnelID, sessionID uint16, payload []byte) error {
	pkt := t.buildControl(tunnelID, sessionID, payload)
	return t.writePacket(pkt)
}

// sendZLB sends a Zero-Length Body acknowledgment.
func (t *Tunnel) sendZLB() {
	nr := uint16(t.nr.Load())
	ns := uint16(t.ns.Load())
	hdr := EncodeControlHeader(t.remoteTunnelID, 0, ns, nr, 0)
	_ = t.writePacket(hdr)
}

// updatePeerNr advances the tracked peer Nr and signals any waiters.
func (t *Tunnel) updatePeerNr(nr uint16) {
	t.peerNrMu.Lock()
	defer t.peerNrMu.Unlock()
	if nr != t.peerNr && int16(nr-t.peerNr) > 0 {
		t.peerNr = nr
		close(t.peerNrCh)
		t.peerNrCh = make(chan struct{})
	}
}

// waitForPeerAck waits for recvLoop to observe the peer advancing Nr past sentNs.
// Used after recvLoop has started (i.e., for ICCN during session setup).
func (t *Tunnel) waitForPeerAck(sentNs uint16, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		t.peerNrMu.Lock()
		if int16(t.peerNr-(sentNs+1)) >= 0 {
			t.peerNrMu.Unlock()
			return nil
		}
		ch := t.peerNrCh
		t.peerNrMu.Unlock()

		select {
		case <-ch:
		case <-deadline.C:
			return errControlTimeout
		case <-t.closed:
			return errTunnelClosed
		}
	}
}

func (t *Tunnel) writePacket(pkt []byte) error {
	select {
	case <-t.closed:
		return errTunnelClosed
	default:
	}
	t.writeMu.Lock()
	_, err := t.conn.Write(pkt)
	t.writeMu.Unlock()
	return err
}

// SendData sends a data packet for a session.
func (t *Tunnel) SendData(sessionID uint16, proto uint16, payload []byte) error {
	hdr := EncodeDataHeader(t.remoteTunnelID, sessionID)
	protoBuf := []byte{byte(proto >> 8), byte(proto & 0xFF)}
	pkt := make([]byte, 0, len(hdr)+2+len(payload))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, protoBuf...)
	pkt = append(pkt, payload...)
	return t.writePacket(pkt)
}

// recvControlDirect reads one control message with a deadline.
// Used ONLY during tunnel handshake before recvLoop starts.
func (t *Tunnel) recvControlDirect(timeout time.Duration) ([]AVP, error) {
	buf := make([]byte, maxPacketSize)
	t.conn.SetReadDeadline(time.Now().Add(timeout))
	defer t.conn.SetReadDeadline(time.Time{})

	for {
		n, err := t.conn.Read(buf)
		if err != nil {
			return nil, err
		}
		hdr, off, err := DecodeHeader(buf[:n])
		if err != nil {
			continue
		}
		if !hdr.IsControl {
			continue
		}
		t.updatePeerNr(hdr.Nr)
		expectedNr := uint16(t.nr.Load())
		if hdr.Ns != expectedNr {
			t.sendZLB()
			continue
		}
		t.nr.Store(uint32(hdr.Ns + 1))
		t.sendZLB()

		if off >= n {
			continue
		}
		avps, err := DecodeAVPs(buf[off:n])
		if err != nil {
			return nil, fmt.Errorf("decode AVPs: %w", err)
		}
		return avps, nil
	}
}

// registerPendingCtrl creates a buffered channel for receiving control
// responses routed by recvLoop for the given local session ID.
// Must be called before sending the request that triggers the response.
func (t *Tunnel) registerPendingCtrl(sid uint16) chan controlMsg {
	ch := make(chan controlMsg, 1)
	t.pendingCtrlMu.Lock()
	t.pendingCtrls[sid] = ch
	t.pendingCtrlMu.Unlock()
	return ch
}

func (t *Tunnel) unregisterPendingCtrl(sid uint16) {
	t.pendingCtrlMu.Lock()
	delete(t.pendingCtrls, sid)
	t.pendingCtrlMu.Unlock()
}

func (t *Tunnel) waitForControl(ch chan controlMsg, timeout time.Duration) ([]AVP, uint16, error) {
	select {
	case msg := <-ch:
		return msg.avps, msg.msgType, nil
	case <-time.After(timeout):
		return nil, 0, errControlTimeout
	case <-t.closed:
		return nil, 0, errTunnelClosed
	}
}

// recvLoop is the main receive loop for the tunnel.
// It demuxes packets to sessions and handles control messages.
func (t *Tunnel) recvLoop() {
	buf := make([]byte, maxPacketSize)
	for {
		select {
		case <-t.closed:
			return
		default:
		}
		if t.helloInterval > 0 {
			t.conn.SetReadDeadline(time.Now().Add(t.helloInterval * 3))
		}
		n, err := t.conn.Read(buf)
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
			}
			t.logger.Warn("tunnel read error, closing",
				zap.Uint16("tunnelID", t.localTunnelID),
				zap.Error(err))
			t.die()
			return
		}
		hdr, off, err := DecodeHeader(buf[:n])
		if err != nil {
			continue
		}
		if off > n {
			continue
		}

		if hdr.IsControl {
			t.handleControl(hdr, buf[off:n])
		} else {
			t.handleData(hdr, buf[off:n])
		}
	}
}

func (t *Tunnel) handleControl(hdr Header, payload []byte) {
	if len(payload) == 0 {
		t.updatePeerNr(hdr.Nr)
		return // ZLB ack
	}

	expectedNr := uint16(t.nr.Load())
	if hdr.Ns != expectedNr {
		t.sendZLB()
		return
	}
	t.nr.Store(uint32(hdr.Ns + 1))
	t.sendZLB()
	t.updatePeerNr(hdr.Nr)

	avps, err := DecodeAVPs(payload)
	if err != nil {
		t.logger.Debug("failed to decode control AVPs", zap.Error(err))
		return
	}
	msgType, err := GetMessageType(avps)
	if err != nil {
		t.logger.Debug("failed to get message type", zap.Error(err))
		return
	}

	if hdr.Session != 0 {
		t.mu.RLock()
		s := t.sessions[hdr.Session]
		t.mu.RUnlock()
		if s != nil {
			s.noteInboundControl(msgType, avps)
		}
	}

	// Route ICRP/CDN to the session that is waiting for it, keyed by
	// the header Session field (which is our local session ID per RFC 2661).
	if msgType == MsgTypeICRP || msgType == MsgTypeCDN {
		t.pendingCtrlMu.Lock()
		ch := t.pendingCtrls[hdr.Session]
		t.pendingCtrlMu.Unlock()
		if ch != nil {
			select {
			case ch <- controlMsg{avps: avps, msgType: msgType}:
				if msgType == MsgTypeICRP {
					return
				}
			default:
			}
		}
	}

	switch msgType {
	case MsgTypeStopCCN:
		logFields := []zap.Field{zap.Uint16("tunnelID", t.localTunnelID)}
		if rcAVP := FindAVP(avps, 0, AVPResultCode); rcAVP != nil && len(rcAVP.Value) >= 2 {
			resultCode := binary.BigEndian.Uint16(rcAVP.Value[0:2])
			logFields = append(logFields, zap.Uint16("resultCode", resultCode))
			if len(rcAVP.Value) >= 4 {
				errorCode := binary.BigEndian.Uint16(rcAVP.Value[2:4])
				logFields = append(logFields, zap.Uint16("errorCode", errorCode))
			}
			if len(rcAVP.Value) > 4 {
				logFields = append(logFields, zap.String("errorMsg", string(rcAVP.Value[4:])))
			}
		}
		t.logger.Warn("received StopCCN from LNS", logFields...)
		t.die()
	case MsgTypeHello:
		// Hello is just acknowledged (ZLB already sent above)
	case MsgTypeCDN:
		t.handleCDN(avps)
	default:
		t.logger.Debug("unhandled control message",
			zap.Uint16("type", msgType),
			zap.Uint16("tunnelID", t.localTunnelID))
	}
}

func (t *Tunnel) handleCDN(avps []AVP) {
	sidAVP := FindAVP(avps, 0, AVPAssignedSessionID)
	if sidAVP == nil {
		return
	}
	sid, err := AVPUint16(sidAVP)
	if err != nil {
		return
	}
	t.mu.RLock()
	s, ok := t.sessions[sid]
	t.mu.RUnlock()
	if ok {
		s.closeDueToLNS()
	}
}

func (t *Tunnel) handleData(hdr Header, payload []byte) {
	if len(payload) < 2 {
		return
	}
	t.mu.RLock()
	s, ok := t.sessions[hdr.Session]
	t.mu.RUnlock()
	if !ok {
		return
	}
	// Some LNS implementations include FF 03 address/control in data packets
	off := 0
	if len(payload) >= 4 && payload[0] == 0xFF && payload[1] == 0x03 {
		off = 2
	}
	if off+2 > len(payload) {
		return
	}
	proto := uint16(payload[off])<<8 | uint16(payload[off+1])
	s.deliverPPP(proto, payload[off+2:])
}

func (t *Tunnel) helloLoop() {
	ticker := time.NewTicker(t.helloInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.closed:
			return
		case <-ticker.C:
			payload := BuildHello()
			if err := t.sendControl(t.remoteTunnelID, 0, payload); err != nil {
				return
			}
		}
	}
}

func (t *Tunnel) die() {
	t.closeOnce.Do(func() {
		close(t.closed)
		t.conn.Close()
		count := t.SessionCount()
		t.logger.Warn("tunnel died",
			zap.Uint16("tunnelID", t.localTunnelID),
			zap.Int("sessionCount", count))
		t.closeAllSessions()
		if t.onClose != nil {
			t.onClose()
		}
	})
}
