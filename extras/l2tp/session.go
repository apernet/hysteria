package l2tp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

var errSessionClosed = errors.New("l2tp: session closed")

// Session represents an L2TP session within a tunnel.
type Session struct {
	tunnel *Tunnel
	logger *zap.Logger

	localSessionID  uint16
	remoteSessionID uint16
	callSerial      uint32
	callingNumber   string
	info            *ProxyInfo

	// Channel for receiving PPP frames from the tunnel's demux loop
	recvCh chan pppFrame

	closed    chan struct{}
	closeOnce sync.Once

	established            atomic.Bool
	firstInboundDataLogged atomic.Bool
	firstInboundCtrlLogged atomic.Bool
}

type pppFrame struct {
	Proto   uint16
	Payload []byte
}

var callSerialCounter atomic.Uint32

func newSession(t *Tunnel, localSID uint16, info *ProxyInfo, callingNumber string) *Session {
	return &Session{
		tunnel:         t,
		logger:         t.logger,
		localSessionID: localSID,
		callSerial:     callSerialCounter.Add(1),
		callingNumber:  callingNumber,
		info:           info,
		recvCh:         make(chan pppFrame, 256),
		closed:         make(chan struct{}),
	}
}

// establish performs the ICRQ -> ICRP -> ICCN handshake.
// The pending-control waiter is registered BEFORE sending ICRQ so that
// a fast LNS reply cannot be lost, and each session has its own channel
// so concurrent session setups on the same tunnel don't interfere.
func (s *Session) establish() error {
	ch := s.tunnel.registerPendingCtrl(s.localSessionID)
	defer s.tunnel.unregisterPendingCtrl(s.localSessionID)

	s.logger.Debug("sending ICRQ",
		zap.Uint16("localSessionID", s.localSessionID),
		zap.Uint32("callSerial", s.callSerial),
		zap.String("callingNumber", s.callingNumber))

	icrqPayload := BuildICRQ(s.localSessionID, s.callSerial, s.callingNumber)
	pkt := s.tunnel.buildControl(s.tunnel.remoteTunnelID, 0, icrqPayload)

	var avps []AVP
	var msgType uint16
	timeout := ctrlRetryBaseTimeout
	for attempt := 0; ; attempt++ {
		if err := s.tunnel.resendControl(pkt); err != nil {
			return fmt.Errorf("send ICRQ: %w", err)
		}
		var err error
		avps, msgType, err = s.tunnel.waitForControl(ch, timeout)
		if err == nil {
			break
		}
		if attempt >= maxCtrlRetries || !errors.Is(err, errControlTimeout) {
			return fmt.Errorf("recv ICRP: %w", err)
		}
		timeout = min(timeout*2, tunnelSetupTimeout)
		s.logger.Debug("ICRQ timeout, retransmitting", zap.Int("attempt", attempt+1))
	}

	if msgType == MsgTypeCDN {
		return fmt.Errorf("LNS rejected session with CDN")
	}
	if msgType != MsgTypeICRP {
		return fmt.Errorf("expected ICRP, got msg type %d", msgType)
	}

	sidAVP := FindAVP(avps, 0, AVPAssignedSessionID)
	if sidAVP == nil {
		return fmt.Errorf("%w: Assigned Session ID in ICRP", ErrMissingAVP)
	}
	remoteSID, err := AVPUint16(sidAVP)
	if err != nil {
		return err
	}
	s.remoteSessionID = remoteSID

	s.logger.Debug("received ICRP",
		zap.Uint16("remoteSessionID", remoteSID))

	iccnPayload := BuildICCN(s.info)
	iccnAVPs, err := DecodeAVPs(iccnPayload)
	if err != nil {
		return fmt.Errorf("decode ICCN payload: %w", err)
	}
	s.logger.Debug("sending ICCN with proxy info",
		zap.Uint16("remoteSessionID", s.remoteSessionID),
		zap.String("username", s.info.AuthName),
		zap.String("lastSentCONFREQ", hex.EncodeToString(s.info.LastSentCONFREQ)),
		zap.String("lastRecvCONFREQ", hex.EncodeToString(s.info.LastReceivedCONFREQ)),
		zap.Int("iccnLen", len(iccnPayload)),
		zap.String("iccnHex", hex.EncodeToString(iccnPayload)),
		zap.String("iccnAVPs", summarizeAVPs(iccnAVPs)))
	iccnPkt := s.tunnel.buildControl(s.tunnel.remoteTunnelID, s.remoteSessionID, iccnPayload)
	iccnNs := uint16(s.tunnel.ns.Load() - 1)
	{
		ackTimeout := ctrlRetryBaseTimeout
		for attempt := 0; ; attempt++ {
			if err := s.tunnel.resendControl(iccnPkt); err != nil {
				return fmt.Errorf("send ICCN: %w", err)
			}
			err := s.tunnel.waitForPeerAck(iccnNs, ackTimeout)
			if err == nil {
				break
			}
			if attempt >= maxCtrlRetries || !errors.Is(err, errControlTimeout) {
				return fmt.Errorf("ICCN ack: %w", err)
			}
			ackTimeout = min(ackTimeout*2, tunnelSetupTimeout)
			s.logger.Debug("ICCN ack timeout, retransmitting", zap.Int("attempt", attempt+1))
		}
	}

	s.logger.Debug("session handshake complete",
		zap.Uint16("localSessionID", s.localSessionID),
		zap.Uint16("remoteSessionID", s.remoteSessionID))
	s.established.Store(true)
	return nil
}

// SendPPP sends a PPP frame to the LNS via the tunnel.
// proto is the PPP protocol number, payload is the PPP information field.
func (s *Session) SendPPP(proto uint16, payload []byte) error {
	select {
	case <-s.closed:
		return errSessionClosed
	default:
	}
	return s.tunnel.SendData(s.remoteSessionID, proto, payload)
}

// RecvPPP receives a PPP frame from the LNS.
// Returns the PPP protocol number and information payload.
func (s *Session) RecvPPP() (uint16, []byte, error) {
	select {
	case <-s.closed:
		return 0, nil, errSessionClosed
	case frame, ok := <-s.recvCh:
		if !ok {
			return 0, nil, errSessionClosed
		}
		return frame.Proto, frame.Payload, nil
	}
}

// deliverPPP is called by the tunnel's demux loop to deliver a PPP frame.
func (s *Session) deliverPPP(proto uint16, payload []byte) {
	if s.established.Load() && s.firstInboundDataLogged.CompareAndSwap(false, true) {
		s.logger.Debug("first inbound PPP data after ICCN",
			zap.Uint16("sessionID", s.localSessionID),
			zap.Uint16("proto", proto),
			zap.Int("len", len(payload)),
			zap.String("hex", hex.EncodeToString(payload)))
	}
	data := make([]byte, len(payload))
	copy(data, payload)
	frame := pppFrame{Proto: proto, Payload: data}
	select {
	case s.recvCh <- frame:
	case <-s.closed:
	default:
		s.logger.Warn("L2TP session recvCh full, backpressure active",
			zap.Uint16("sessionID", s.localSessionID))
		select {
		case s.recvCh <- frame:
		case <-s.closed:
		}
	}
}

func (s *Session) noteInboundControl(msgType uint16, avps []AVP) {
	if !s.established.Load() || !s.firstInboundCtrlLogged.CompareAndSwap(false, true) {
		return
	}
	s.logger.Debug("first inbound control after ICCN",
		zap.Uint16("sessionID", s.localSessionID),
		zap.Uint16("msgType", msgType),
		zap.String("avps", summarizeAVPs(avps)))
}

func summarizeAVPs(avps []AVP) string {
	parts := make([]string, 0, len(avps))
	for _, avp := range avps {
		parts = append(parts, fmt.Sprintf("type=%d,len=%d,m=%t", avp.Type, len(avp.Value), avp.Mandatory))
	}
	return strings.Join(parts, "; ")
}

// Close sends CDN and cleans up the session.
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		// Best-effort CDN
		cdnPayload := BuildCDN(s.localSessionID, 2, 0, "LAC disconnect")
		_ = s.tunnel.sendControl(s.tunnel.remoteTunnelID, s.remoteSessionID, cdnPayload)
		remaining := s.tunnel.removeSession(s.localSessionID)
		s.logger.Info("session closed",
			zap.Uint16("tunnelID", s.tunnel.localTunnelID),
			zap.Uint16("sessionID", s.localSessionID),
			zap.String("username", s.info.AuthName))
		// If this was the last session, tear down the tunnel
		if remaining == 0 {
			s.logger.Info("last session ended, closing tunnel",
				zap.Uint16("tunnelID", s.tunnel.localTunnelID))
			s.tunnel.Close()
		}
	})
}

// closeDueToTunnel is called when the tunnel dies.
func (s *Session) closeDueToTunnel() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.logger.Warn("session died due to tunnel death",
			zap.Uint16("tunnelID", s.tunnel.localTunnelID),
			zap.Uint16("sessionID", s.localSessionID),
			zap.String("username", s.info.AuthName))
	})
}

// closeDueToLNS is called when the LNS sends CDN.
func (s *Session) closeDueToLNS() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.tunnel.removeSession(s.localSessionID)
		s.logger.Warn("session CDN received from LNS",
			zap.Uint16("tunnelID", s.tunnel.localTunnelID),
			zap.Uint16("sessionID", s.localSessionID),
			zap.String("username", s.info.AuthName))
	})
}
