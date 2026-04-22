package pppbridge

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/apernet/hysteria/extras/v2/l2tp"

	"go.uber.org/zap"
)

// PPP protocol numbers
const (
	pppProtoLCP  uint16 = 0xC021
	pppProtoPAP  uint16 = 0xC023
	pppProtoCHAP uint16 = 0xC223
)

// LCP code values
const (
	lcpConfigRequest uint8 = 1
	lcpConfigAck     uint8 = 2
	lcpConfigNak     uint8 = 3
	lcpConfigReject  uint8 = 4
	lcpTermRequest   uint8 = 5
	lcpTermAck       uint8 = 6
	lcpEchoRequest   uint8 = 9
	lcpEchoReply     uint8 = 10
)

// LCP option types
const (
	lcpOptMRU                   uint8 = 1
	lcpOptAuthProtocol          uint8 = 3
	lcpOptMagicNumber           uint8 = 5
	lcpOptMRRU                  uint8 = 17
	lcpOptShortSeqNum           uint8 = 18
	lcpOptEndpointDiscriminator uint8 = 19
)

// PAP code values
const (
	papAuthRequest uint8 = 1
	papAuthAck     uint8 = 2
	papAuthNak     uint8 = 3
)

// CHAP code values
const (
	chapChallenge uint8 = 1
	chapResponse  uint8 = 2
	chapSuccess   uint8 = 3
	chapFailure   uint8 = 4
)

var errLCPFailed = errors.New("LCP negotiation failed")

// NegotiateLCP performs LCP negotiation on the control stream and waits
// for PAP/CHAP authentication. Returns ProxyInfo with all collected data,
// and a *bufio.Reader wrapping the control stream that may contain buffered
// bytes beyond the auth message.
func NegotiateLCP(control io.ReadWriter, logger *zap.Logger) (*l2tp.ProxyInfo, *bufio.Reader, error) {
	n := &lcpNegotiator{
		control: control,
		reader:  bufio.NewReaderSize(control, 4096),
		logger:  logger,
		info:    &l2tp.ProxyInfo{},
	}
	if err := n.run(); err != nil {
		return nil, nil, err
	}
	return n.info, n.reader, nil
}

// SendAuthResult sends PAP-Ack/CHAP-Success (accept=true) or
// PAP-Nak/CHAP-Failure (accept=false) back to the client.
func SendAuthResult(control io.Writer, info *l2tp.ProxyInfo, accept bool) error {
	var pkt []byte
	switch info.AuthType {
	case l2tp.ProxyAuthenPAP:
		if accept {
			pkt = buildPAPResponse(papAuthAck, info.AuthID, "Authentication OK")
		} else {
			pkt = buildPAPResponse(papAuthNak, info.AuthID, "Authentication Failed")
		}
	case l2tp.ProxyAuthenCHAP:
		if accept {
			pkt = buildCHAPResult(chapSuccess, info.AuthID, "Authentication OK")
		} else {
			pkt = buildCHAPResult(chapFailure, info.AuthID, "Authentication Failed")
		}
	default:
		return fmt.Errorf("unknown auth type %d", info.AuthType)
	}
	frame := EncodeHDLC(pkt)
	_, err := control.Write(frame)
	return err
}

const (
	maxLCPRetries = 10
	defaultMRU    = 1500
)

type lcpNegotiator struct {
	control io.ReadWriter
	reader  *bufio.Reader
	logger  *zap.Logger
	info    *l2tp.ProxyInfo

	ourMagic     uint32
	ourMRU       uint16
	lcpOpen      bool
	weAccepted   bool   // we ACK'd peer's Config-Request
	peerAccepted bool   // peer ACK'd our Config-Request
	authProto    uint16 // negotiated auth protocol (pppProtoPAP or pppProtoCHAP)
	configID     byte
	nakCount     int

	// CHAP state
	chapChallengeSent []byte
	chapChallengeID   byte

	// HDLC reassembly buffer, persisted across readFrame calls
	hdlcBuf []byte
}

func (n *lcpNegotiator) run() error {
	n.ourMagic = 0xDEADBEEF
	n.ourMRU = defaultMRU
	n.authProto = pppProtoCHAP
	if err := n.sendOurConfigRequest(); err != nil {
		return err
	}

	// Main negotiation loop
	for {
		rawPPP, err := n.readFrame()
		if err != nil {
			return fmt.Errorf("read LCP frame: %w", err)
		}

		proto, payload := parsePPPFrame(rawPPP)
		switch proto {
		case pppProtoLCP:
			if err := n.handleLCP(payload); err != nil {
				return err
			}
		case pppProtoPAP:
			if !n.lcpOpen {
				continue
			}
			return n.handlePAP(payload)
		case pppProtoCHAP:
			if !n.lcpOpen {
				continue
			}
			return n.handleCHAPResponse(payload)
		default:
			n.logger.Debug("ignoring non-LCP frame during negotiation",
				zap.Uint16("proto", proto))
		}
	}
}

var lcpCodeNames = map[uint8]string{
	lcpConfigRequest: "Config-Request",
	lcpConfigAck:     "Config-Ack",
	lcpConfigNak:     "Config-Nak",
	lcpConfigReject:  "Config-Reject",
	lcpTermRequest:   "Terminate-Request",
	lcpTermAck:       "Terminate-Ack",
	lcpEchoRequest:   "Echo-Request",
	lcpEchoReply:     "Echo-Reply",
}

func (n *lcpNegotiator) handleLCP(payload []byte) error {
	if len(payload) < 4 {
		return nil
	}
	code := payload[0]
	id := payload[1]
	pktLen := binary.BigEndian.Uint16(payload[2:4])
	if int(pktLen) > len(payload) {
		pktLen = uint16(len(payload))
	}
	pkt := payload[:pktLen]

	codeName := lcpCodeNames[code]
	if codeName == "" {
		codeName = fmt.Sprintf("unknown(%d)", code)
	}
	n.logger.Debug("LCP received",
		zap.String("code", codeName),
		zap.Uint8("id", id),
		zap.Uint16("length", pktLen))

	switch code {
	case lcpConfigRequest:
		return n.handlePeerConfigRequest(id, pkt)
	case lcpConfigAck:
		return n.handleConfigAck(pkt)
	case lcpConfigNak:
		return n.handleConfigNak(pkt)
	case lcpConfigReject:
		return n.handleConfigReject(pkt)
	case lcpEchoRequest:
		return n.handleEchoRequest(id, pkt)
	case lcpTermRequest:
		return fmt.Errorf("%w: received Terminate-Request", errLCPFailed)
	}
	return nil
}

func (n *lcpNegotiator) handlePeerConfigRequest(id byte, pkt []byte) error {
	// Record the initial Config-Request from peer
	lcpRaw := make([]byte, len(pkt))
	copy(lcpRaw, pkt)

	if n.info.InitialReceivedCONFREQ == nil {
		n.info.InitialReceivedCONFREQ = lcpRaw
	}
	n.info.LastReceivedCONFREQ = lcpRaw

	// Extract Endpoint Discriminator (option 19) if present
	if len(pkt) > 4 {
		options := pkt[4:]
		for len(options) >= 2 {
			optType := options[0]
			optLen := int(options[1])
			if optLen < 2 || optLen > len(options) {
				break
			}
			if optType == lcpOptEndpointDiscriminator && optLen > 2 {
				n.info.EndpointDiscriminator = make([]byte, optLen-2)
				copy(n.info.EndpointDiscriminator, options[2:optLen])
			}
			options = options[optLen:]
		}
	}

	// ACK everything the peer sends
	ack := buildLCPPacket(lcpConfigAck, id, pkt[4:])
	if err := n.sendPPP(pppProtoLCP, ack); err != nil {
		return err
	}
	n.weAccepted = true
	n.checkLCPOpen()
	return nil
}

func (n *lcpNegotiator) handleConfigAck(pkt []byte) error {
	if len(pkt) < 4 {
		return nil
	}
	if pkt[1] != n.configID {
		return nil // stale ack from a previous request
	}
	if len(n.info.LastSentCONFREQ) < 4 || !bytes.Equal(pkt[4:], n.info.LastSentCONFREQ[4:]) {
		return nil // options don't match our request
	}
	n.peerAccepted = true
	n.checkLCPOpen()
	return nil
}

func (n *lcpNegotiator) handleConfigNak(pkt []byte) error {
	n.nakCount++
	if n.nakCount > maxLCPRetries {
		return fmt.Errorf("%w: too many Config-Nak retries", errLCPFailed)
	}
	if len(pkt) <= 4 {
		return nil
	}
	options := pkt[4:]
	for len(options) >= 2 {
		optType := options[0]
		optLen := int(options[1])
		if optLen < 2 || optLen > len(options) {
			break
		}
		switch optType {
		case lcpOptMRU:
			if optLen >= 4 {
				n.ourMRU = binary.BigEndian.Uint16(options[2:4])
				n.logger.Debug("peer NAK'd MRU, using suggested",
					zap.Uint16("mru", n.ourMRU))
			}
		case lcpOptAuthProtocol:
			if optLen >= 4 {
				suggestedAuth := binary.BigEndian.Uint16(options[2:4])
				n.logger.Debug("peer NAK'd auth, suggesting alternative",
					zap.Uint16("suggestedProto", suggestedAuth))
				if suggestedAuth == pppProtoPAP {
					n.authProto = pppProtoPAP
				} else if n.authProto == pppProtoCHAP {
					n.authProto = pppProtoPAP
				}
			}
		case lcpOptMagicNumber:
			if optLen >= 6 {
				n.ourMagic = binary.BigEndian.Uint32(options[2:6])
				n.logger.Debug("peer NAK'd magic number, using suggested",
					zap.Uint32("magic", n.ourMagic))
			}
		default:
			n.logger.Debug("ignoring unknown NAK'd option",
				zap.Uint8("optType", optType),
				zap.Int("optLen", optLen))
		}
		options = options[optLen:]
	}
	return n.sendOurConfigRequest()
}

func (n *lcpNegotiator) handleConfigReject(pkt []byte) error {
	n.nakCount++
	if n.nakCount > maxLCPRetries {
		return fmt.Errorf("%w: too many Config-Reject retries", errLCPFailed)
	}
	if len(pkt) <= 4 {
		return nil
	}
	options := pkt[4:]
	authRejected := false
	for len(options) >= 2 {
		optType := options[0]
		optLen := int(options[1])
		if optLen < 2 || optLen > len(options) {
			break
		}
		if optType == lcpOptAuthProtocol {
			authRejected = true
			n.logger.Debug("peer rejected auth protocol",
				zap.Uint16("proto", n.authProto))
		}
		options = options[optLen:]
	}
	if authRejected {
		if n.authProto == pppProtoCHAP {
			n.logger.Debug("falling back from CHAP to PAP")
			n.authProto = pppProtoPAP
			return n.sendOurConfigRequest()
		}
		return fmt.Errorf("%w: peer rejected all authentication protocols", errLCPFailed)
	}
	return n.sendOurConfigRequest()
}

func (n *lcpNegotiator) handleEchoRequest(id byte, pkt []byte) error {
	// Reply with our magic number
	reply := make([]byte, 8)
	reply[0] = lcpEchoReply
	reply[1] = id
	binary.BigEndian.PutUint16(reply[2:4], 8)
	binary.BigEndian.PutUint32(reply[4:8], n.ourMagic)
	return n.sendPPP(pppProtoLCP, reply)
}

func (n *lcpNegotiator) checkLCPOpen() {
	if n.weAccepted && n.peerAccepted && !n.lcpOpen {
		n.lcpOpen = true
		n.logger.Debug("LCP open, waiting for authentication")
		// If CHAP, we need to send a Challenge
		if n.authProto == pppProtoCHAP {
			n.sendCHAPChallenge()
		}
	}
}

func (n *lcpNegotiator) sendCHAPChallenge() {
	n.chapChallengeID++
	challenge := make([]byte, 16)
	_, _ = rand.Read(challenge)
	n.chapChallengeSent = challenge

	// CHAP Challenge packet: Code(1) + ID(1) + Length(2) + ValueSize(1) + Value + Name
	name := []byte("LAC")
	pktLen := 5 + len(challenge) + len(name)
	pkt := make([]byte, pktLen)
	pkt[0] = chapChallenge
	pkt[1] = n.chapChallengeID
	binary.BigEndian.PutUint16(pkt[2:4], uint16(pktLen))
	pkt[4] = byte(len(challenge))
	copy(pkt[5:5+len(challenge)], challenge)
	copy(pkt[5+len(challenge):], name)

	_ = n.sendPPP(pppProtoCHAP, pkt)
}

func (n *lcpNegotiator) handlePAP(payload []byte) error {
	if len(payload) < 4 {
		return fmt.Errorf("PAP packet too short")
	}
	code := payload[0]
	if code != papAuthRequest {
		return nil
	}
	id := payload[1]
	pktLen := binary.BigEndian.Uint16(payload[2:4])
	if int(pktLen) > len(payload) {
		pktLen = uint16(len(payload))
	}

	off := 4
	if off >= int(pktLen) {
		return fmt.Errorf("PAP: missing peer-id length")
	}
	peerIDLen := int(payload[off])
	off++
	if off+peerIDLen > int(pktLen) {
		return fmt.Errorf("PAP: peer-id truncated")
	}
	username := string(payload[off : off+peerIDLen])
	off += peerIDLen

	if off >= int(pktLen) {
		return fmt.Errorf("PAP: missing password length")
	}
	passwdLen := int(payload[off])
	off++
	if off+passwdLen > int(pktLen) {
		return fmt.Errorf("PAP: password truncated")
	}
	password := payload[off : off+passwdLen]

	n.info.AuthType = l2tp.ProxyAuthenPAP
	n.info.AuthID = id
	n.info.AuthName = username
	n.info.AuthResponse = make([]byte, len(password))
	copy(n.info.AuthResponse, password)
	n.info.Realm = extractRealm(username)

	n.logger.Debug("PAP auth received",
		zap.String("username", username),
		zap.String("realm", n.info.Realm))
	return nil
}

func (n *lcpNegotiator) handleCHAPResponse(payload []byte) error {
	if len(payload) < 4 {
		return fmt.Errorf("CHAP packet too short")
	}
	code := payload[0]
	if code != chapResponse {
		return nil
	}
	id := payload[1]
	pktLen := binary.BigEndian.Uint16(payload[2:4])
	if int(pktLen) > len(payload) {
		pktLen = uint16(len(payload))
	}

	off := 4
	if off >= int(pktLen) {
		return fmt.Errorf("CHAP: missing value size")
	}
	valueSize := int(payload[off])
	off++
	if off+valueSize > int(pktLen) {
		return fmt.Errorf("CHAP: response value truncated")
	}
	responseValue := payload[off : off+valueSize]
	off += valueSize
	username := string(payload[off:pktLen])

	n.info.AuthType = l2tp.ProxyAuthenCHAP
	n.info.AuthID = id
	n.info.AuthName = username
	n.info.AuthChallenge = make([]byte, len(n.chapChallengeSent))
	copy(n.info.AuthChallenge, n.chapChallengeSent)
	n.info.AuthResponse = make([]byte, len(responseValue))
	copy(n.info.AuthResponse, responseValue)
	n.info.Realm = extractRealm(username)

	n.logger.Debug("CHAP auth received",
		zap.String("username", username),
		zap.String("realm", n.info.Realm))
	return nil
}

func (n *lcpNegotiator) sendOurConfigRequest() error {
	n.configID++
	var opts []byte

	// MRU option
	opts = append(opts, lcpOptMRU, 4)
	opts = append(opts, byte(n.ourMRU>>8), byte(n.ourMRU))

	authName := "CHAP-MD5"
	// Auth-Protocol option
	switch n.authProto {
	case pppProtoCHAP:
		// Auth-Protocol: CHAP (0xC223), Algorithm: MD5 (5)
		opts = append(opts, lcpOptAuthProtocol, 5)
		opts = append(opts, byte(n.authProto>>8), byte(n.authProto))
		opts = append(opts, 5) // MD5
	case pppProtoPAP:
		authName = "PAP"
		opts = append(opts, lcpOptAuthProtocol, 4)
		opts = append(opts, byte(n.authProto>>8), byte(n.authProto))
	}

	// Magic-Number option
	opts = append(opts, lcpOptMagicNumber, 6)
	magicBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(magicBuf, n.ourMagic)
	opts = append(opts, magicBuf...)

	pkt := buildLCPPacket(lcpConfigRequest, n.configID, opts)

	// Record our Config-Request for proxy
	n.info.LastSentCONFREQ = make([]byte, len(pkt))
	copy(n.info.LastSentCONFREQ, pkt)

	n.logger.Debug("LCP sending Config-Request",
		zap.String("auth", authName),
		zap.Uint16("mru", n.ourMRU))

	n.peerAccepted = false
	return n.sendPPP(pppProtoLCP, pkt)
}

func (n *lcpNegotiator) sendPPP(proto uint16, payload []byte) error {
	// Build raw PPP frame: FF 03 + Protocol(2) + Payload
	rawPPP := make([]byte, 4+len(payload))
	rawPPP[0] = 0xFF
	rawPPP[1] = 0x03
	binary.BigEndian.PutUint16(rawPPP[2:4], proto)
	copy(rawPPP[4:], payload)
	frame := EncodeHDLC(rawPPP)
	_, err := n.control.Write(frame)
	return err
}

func (n *lcpNegotiator) readFrame() ([]byte, error) {
	buf := make([]byte, 4096)
	for {
		frame, rest, ok := extractHDLCFrame(n.hdlcBuf)
		if ok {
			n.hdlcBuf = rest
			rawPPP, err := decodeHDLCFramePayload(frame)
			if err != nil {
				continue
			}
			return rawPPP, nil
		}
		nr, err := n.reader.Read(buf)
		if err != nil {
			return nil, err
		}
		n.hdlcBuf = append(n.hdlcBuf, buf[:nr]...)
	}
}

func buildLCPPacket(code uint8, id byte, options []byte) []byte {
	pktLen := 4 + len(options)
	pkt := make([]byte, pktLen)
	pkt[0] = code
	pkt[1] = id
	binary.BigEndian.PutUint16(pkt[2:4], uint16(pktLen))
	copy(pkt[4:], options)
	return pkt
}

func buildPAPResponse(code uint8, id byte, msg string) []byte {
	// PAP: FF 03 + Protocol(2) + Code(1) + ID(1) + Length(2) + MsgLen(1) + Msg
	pktLen := 5 + len(msg)
	rawPPP := make([]byte, 4+pktLen)
	rawPPP[0] = 0xFF
	rawPPP[1] = 0x03
	binary.BigEndian.PutUint16(rawPPP[2:4], pppProtoPAP)
	rawPPP[4] = code
	rawPPP[5] = id
	binary.BigEndian.PutUint16(rawPPP[6:8], uint16(pktLen))
	rawPPP[8] = byte(len(msg))
	copy(rawPPP[9:], msg)
	return rawPPP
}

func buildCHAPResult(code uint8, id byte, msg string) []byte {
	// CHAP: FF 03 + Protocol(2) + Code(1) + ID(1) + Length(2) + Msg
	pktLen := 4 + len(msg)
	rawPPP := make([]byte, 4+pktLen)
	rawPPP[0] = 0xFF
	rawPPP[1] = 0x03
	binary.BigEndian.PutUint16(rawPPP[2:4], pppProtoCHAP)
	rawPPP[4] = code
	rawPPP[5] = id
	binary.BigEndian.PutUint16(rawPPP[6:8], uint16(pktLen))
	copy(rawPPP[8:], msg)
	return rawPPP
}

// parsePPPFrame extracts the PPP protocol and payload from a raw PPP frame.
// Handles both with and without FF 03 address/control bytes.
func parsePPPFrame(rawPPP []byte) (proto uint16, payload []byte) {
	off := 0
	if len(rawPPP) >= 2 && rawPPP[0] == 0xFF && rawPPP[1] == 0x03 {
		off = 2
	}
	if off >= len(rawPPP) {
		return 0, nil
	}
	// PFC: if low bit of first byte is 1, it's a compressed 1-byte protocol
	if rawPPP[off]&0x01 == 1 {
		return uint16(rawPPP[off]), rawPPP[off+1:]
	}
	if off+2 > len(rawPPP) {
		return 0, nil
	}
	proto = binary.BigEndian.Uint16(rawPPP[off : off+2])
	return proto, rawPPP[off+2:]
}

func extractRealm(username string) string {
	idx := strings.LastIndex(username, "@")
	if idx < 0 {
		return ""
	}
	return username[idx+1:]
}
