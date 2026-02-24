package pppbridge

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// PPP protocols used by MLPPP
const (
	pppProtoMP     uint16 = 0x003D
	pppProtoCCP    uint16 = 0x80FD
	pppProtoIPCP   uint16 = 0x8021
	pppProtoIPv6CP uint16 = 0x8057
)

// MP fragment header flags (short sequence number format, 12-bit)
const (
	mpFlagBegin uint8 = 0x80
	mpFlagEnd   uint8 = 0x40
	mpSeqMask         = 0x0FFF
)

// ---------------------------------------------------------------------------
// MP fragment encoding / decoding
// ---------------------------------------------------------------------------

// encodeMPFragment builds a complete PPP frame for an MP fragment.
// payload is the original PPP Information (protocol + data, without FF 03).
func encodeMPFragment(begin, end bool, seq uint16, payload []byte) []byte {
	frame := make([]byte, 4+2+len(payload))
	frame[0] = 0xFF
	frame[1] = 0x03
	binary.BigEndian.PutUint16(frame[2:4], pppProtoMP)

	var flags uint8
	if begin {
		flags |= mpFlagBegin
	}
	if end {
		flags |= mpFlagEnd
	}
	frame[4] = flags | uint8((seq>>8)&0x0F)
	frame[5] = uint8(seq & 0xFF)
	copy(frame[6:], payload)
	return frame
}

// decodeMPFragment parses an MP fragment from a raw PPP frame.
func decodeMPFragment(rawPPP []byte) (begin, end bool, seq uint16, payload []byte, err error) {
	off := 0
	if len(rawPPP) >= 2 && rawPPP[0] == 0xFF && rawPPP[1] == 0x03 {
		off = 2
	}
	if off >= len(rawPPP) {
		return false, false, 0, nil, errors.New("mp: frame too short for protocol")
	}
	var proto uint16
	if rawPPP[off]&0x01 == 1 {
		proto = uint16(rawPPP[off])
		off += 1
	} else {
		if off+2 > len(rawPPP) {
			return false, false, 0, nil, errors.New("mp: frame too short for protocol")
		}
		proto = binary.BigEndian.Uint16(rawPPP[off : off+2])
		off += 2
	}
	if proto != pppProtoMP {
		return false, false, 0, nil, fmt.Errorf("mp: unexpected protocol 0x%04x", proto)
	}
	if off+2 > len(rawPPP) {
		return false, false, 0, nil, errors.New("mp: header too short")
	}
	begin = rawPPP[off]&mpFlagBegin != 0
	end = rawPPP[off]&mpFlagEnd != 0
	seq = uint16(rawPPP[off]&0x0F)<<8 | uint16(rawPPP[off+1])
	payload = rawPPP[off+2:]
	return begin, end, seq, payload, nil
}

// ---------------------------------------------------------------------------
// MP reassembly (handles out-of-order fragment delivery across links)
// ---------------------------------------------------------------------------

type mpFragment struct {
	begin bool
	end   bool
	data  []byte
	ts    time.Time
}

type mpReassembler struct {
	mu        sync.Mutex
	fragments map[uint16]mpFragment
}

func newMPReassembler() *mpReassembler {
	return &mpReassembler{fragments: make(map[uint16]mpFragment)}
}

// AddFragment processes an MP fragment (raw PPP frame). If the fragment
// completes a reassembly, the complete PPP payload (protocol + data with
// FF 03 prepended) is returned. Handles out-of-order delivery: END
// fragments arriving before their matching BEGIN are buffered until the
// BEGIN arrives (or cleaned up after a timeout).
func (r *mpReassembler) AddFragment(rawPPP []byte) []byte {
	begin, end, seq, payload, err := decodeMPFragment(rawPPP)
	if err != nil || len(payload) == 0 {
		return nil
	}

	// Fast path: single-fragment packet (B=1, E=1)
	if begin && end {
		frame := make([]byte, 2+len(payload))
		frame[0] = 0xFF
		frame[1] = 0x03
		copy(frame[2:], payload)
		return frame
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.fragments[seq] = mpFragment{begin: begin, end: end, data: append([]byte(nil), payload...), ts: now}

	// Try to find a complete B...E run starting from each BEGIN fragment
	for startSeq, frag := range r.fragments {
		if !frag.begin {
			continue
		}
		assembled := append([]byte(nil), frag.data...)
		cur := startSeq
		complete := false
		for {
			next := (cur + 1) & mpSeqMask
			nf, ok := r.fragments[next]
			if !ok {
				break
			}
			assembled = append(assembled, nf.data...)
			if nf.end {
				complete = true
				// Clean up all fragments in this run
				delete(r.fragments, startSeq)
				for c := startSeq; ; {
					c = (c + 1) & mpSeqMask
					delete(r.fragments, c)
					if c == next {
						break
					}
				}
				break
			}
			cur = next
		}
		if complete {
			frame := make([]byte, 2+len(assembled))
			frame[0] = 0xFF
			frame[1] = 0x03
			copy(frame[2:], assembled)
			return frame
		}
	}

	// Periodic cleanup: discard fragments older than 5 seconds
	if len(r.fragments) > 16 {
		for k, f := range r.fragments {
			if now.Sub(f.ts) > 5*time.Second {
				delete(r.fragments, k)
			}
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// MLPPP LCP state machine (reusable for both Windows-facing and server-facing)
// ---------------------------------------------------------------------------

type mlpppLCPState struct {
	ourMagic      uint32
	mru           uint16 // MRU to advertise in Config-Request
	mrru          uint16 // 0 = don't negotiate MRRU
	discriminator []byte // nil = don't negotiate ED
	authPAP       bool   // include Auth-Protocol=PAP in Config-Request
	open          bool
	weAccepted    bool
	peerAccepted  bool
	sentRequest   bool
	nextID        uint8

	wantShortSeq          bool // request short-seq from peer
	shortSeqRejected      bool // peer Config-Rejected our short-seq
	peerRequestedShortSeq bool // peer included short-seq in Config-Request
}

func newMLPPPLCPState(magic uint32, mru uint16, mrru uint16, discriminator []byte) *mlpppLCPState {
	return &mlpppLCPState{
		ourMagic:      magic,
		mru:           mru,
		mrru:          mrru,
		discriminator: discriminator,
	}
}

// InitialRequest builds the first LCP Config-Request as a full PPP frame.
func (s *mlpppLCPState) InitialRequest() []byte {
	req := s.buildConfigRequest()
	s.sentRequest = true
	return makePPPFrame(pppProtoLCP, req)
}

// HandleLCP processes an incoming LCP packet (payload after protocol field)
// and returns zero or more PPP frames to send in response.
func (s *mlpppLCPState) HandleLCP(payload []byte) [][]byte {
	if len(payload) < 4 {
		return nil
	}
	code := payload[0]
	id := payload[1]

	switch code {
	case lcpConfigRequest:
		// Scan options for short-seq (option 18)
		opts := payload[4:]
		for len(opts) >= 2 {
			optType := opts[0]
			optLen := int(opts[1])
			if optLen < 2 || optLen > len(opts) {
				break
			}
			if optType == lcpOptShortSeqNum {
				s.peerRequestedShortSeq = true
			}
			opts = opts[optLen:]
		}
		ack := buildLCPPacket(lcpConfigAck, id, payload[4:])
		resp := [][]byte{makePPPFrame(pppProtoLCP, ack)}
		s.weAccepted = true
		if !s.sentRequest {
			req := s.buildConfigRequest()
			resp = append(resp, makePPPFrame(pppProtoLCP, req))
			s.sentRequest = true
		}
		s.checkOpen()
		return resp

	case lcpConfigAck:
		s.peerAccepted = true
		s.checkOpen()
		return nil

	case lcpConfigNak:
		s.peerAccepted = false
		if len(payload) > 4 {
			options := payload[4:]
			for len(options) >= 2 {
				optType := options[0]
				optLen := int(options[1])
				if optLen < 2 || optLen > len(options) {
					break
				}
				if optType == lcpOptMRRU && optLen >= 4 {
					s.mrru = binary.BigEndian.Uint16(options[2:4])
				}
				options = options[optLen:]
			}
		}
		req := s.buildConfigRequest()
		return [][]byte{makePPPFrame(pppProtoLCP, req)}

	case lcpConfigReject:
		s.peerAccepted = false
		if len(payload) > 4 {
			rejected := payload[4:]
			for len(rejected) >= 2 {
				optType := rejected[0]
				optLen := int(rejected[1])
				if optLen < 2 || optLen > len(rejected) {
					break
				}
				if optType == lcpOptMRRU {
					s.mrru = 0
				}
				if optType == lcpOptEndpointDiscriminator {
					s.discriminator = nil
				}
				if optType == lcpOptShortSeqNum {
					s.shortSeqRejected = true
				}
				rejected = rejected[optLen:]
			}
		}
		req := s.buildConfigRequest()
		return [][]byte{makePPPFrame(pppProtoLCP, req)}

	case lcpEchoRequest:
		reply := make([]byte, 8)
		reply[0] = lcpEchoReply
		reply[1] = id
		binary.BigEndian.PutUint16(reply[2:4], 8)
		binary.BigEndian.PutUint32(reply[4:8], s.ourMagic)
		return [][]byte{makePPPFrame(pppProtoLCP, reply)}

	case lcpTermRequest:
		termAck := buildLCPPacket(lcpTermAck, id, nil)
		return [][]byte{makePPPFrame(pppProtoLCP, termAck)}
	}

	return nil
}

func (s *mlpppLCPState) IsOpen() bool { return s.open }

func (s *mlpppLCPState) checkOpen() {
	if s.weAccepted && s.peerAccepted {
		s.open = true
	}
}

// splitOptions separates MLPPP options (MRRU=17, ShortSeq=18, ED=19) from the rest.
func splitOptions(options []byte) (mlppp, rest []byte) {
	for len(options) >= 2 {
		optType := options[0]
		optLen := int(options[1])
		if optLen < 2 || optLen > len(options) {
			break
		}
		if optType == lcpOptMRRU || optType == lcpOptShortSeqNum || optType == lcpOptEndpointDiscriminator {
			mlppp = append(mlppp, options[:optLen]...)
		} else {
			rest = append(rest, options[:optLen]...)
		}
		options = options[optLen:]
	}
	return
}

// collectNakOptions scans LCP options and returns a Nak option list for any
// values that need adjustment. Currently checks MRU against maxMRU; new
// checks can be added as additional if-blocks in the loop.
func collectNakOptions(opts []byte, maxMRU uint16) []byte {
	var nak []byte
	for i := 0; i+1 < len(opts); {
		optType := opts[i]
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			break
		}
		if optType == lcpOptMRU && optLen == 4 {
			val := binary.BigEndian.Uint16(opts[i+2 : i+4])
			if val > maxMRU {
				buf := make([]byte, 4)
				buf[0] = lcpOptMRU
				buf[1] = 4
				binary.BigEndian.PutUint16(buf[2:4], maxMRU)
				nak = append(nak, buf...)
			}
		}
		i += optLen
	}
	return nak
}

// buildMLPPPOptions builds the MLPPP LCP option bytes (MRRU, Short-Seq, ED).
func buildMLPPPOptions(mrru uint16, discriminator []byte, shortSeq bool) []byte {
	var opts []byte
	if mrru > 0 {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, mrru)
		opts = append(opts, lcpOptMRRU, 4)
		opts = append(opts, buf...)
	}
	if shortSeq {
		opts = append(opts, lcpOptShortSeqNum, 2)
	}
	if len(discriminator) > 0 {
		edLen := byte(3 + len(discriminator))
		opts = append(opts, lcpOptEndpointDiscriminator, edLen)
		opts = append(opts, 1) // Class 1 = Locally Assigned Address
		opts = append(opts, discriminator...)
	}
	return opts
}

func (s *mlpppLCPState) buildConfigRequest() []byte {
	s.nextID++
	var opts []byte

	// MRU
	opts = append(opts, lcpOptMRU, 4)
	mruBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(mruBuf, s.mru)
	opts = append(opts, mruBuf...)

	// Auth-Protocol (PAP)
	if s.authPAP {
		opts = append(opts, lcpOptAuthProtocol, 4, 0xC0, 0x23) // PAP
	}

	// Magic Number
	opts = append(opts, lcpOptMagicNumber, 6)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, s.ourMagic)
	opts = append(opts, buf...)

	// MLPPP options
	if s.mrru > 0 {
		opts = append(opts, buildMLPPPOptions(s.mrru, s.discriminator, s.wantShortSeq && !s.shortSeqRejected)...)
	}

	return buildLCPPacket(lcpConfigRequest, s.nextID, opts)
}

// makePPPFrame builds a raw PPP frame with address/control and protocol.
func makePPPFrame(proto uint16, payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	frame[0] = 0xFF
	frame[1] = 0x03
	binary.BigEndian.PutUint16(frame[2:4], proto)
	copy(frame[4:], payload)
	return frame
}

// ---------------------------------------------------------------------------
// SSTPBridge (unified: replaces SSTPStdioBridge + MLPPPMaster)
// ---------------------------------------------------------------------------

const (
	papLocalUser = "hysteria"
	papLocalPass = "hysteria"
)

// SSTPBridge runs a local TLS/SSTP server and bridges a single SSTP session
// to HDLC PPP on stdin/stdout. It handles LCP relay, PAP interception, and
// optionally MLPPP fragmentation/reassembly when configured.
type SSTPBridge struct {
	ListenAddr    string
	CertDir       string
	Logger        *zap.Logger
	Discriminator string // empty = no MLPPP options injected
	PAPUser       string // empty = forward Windows' PAP credentials to server
	PAPPass       string
	MTU           int
	IPCServer     *IPCServer // nil = no worker broadcast
	ServerRouteIP string     // non-empty = pin a host route for the server IP
}

func (b *SSTPBridge) Run() error {
	if b.Discriminator != "" && b.PAPUser == "" {
		return errors.New("PAPUser is required when Discriminator is set (MLPPP workers need credentials)")
	}

	if err := GenerateCerts(b.CertDir); err != nil {
		return fmt.Errorf("failed to generate certs: %w", err)
	}

	certPath := filepath.Join(b.CertDir, "server.crt")
	keyPath := filepath.Join(b.CertDir, "server.key")
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("failed to load cert: %w", err)
	}
	certHash := sha256.Sum256(serverCert.Certificate[0])

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	ln, err := tls.Listen("tcp", b.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer ln.Close()

	numLinks := 1
	if b.IPCServer != nil {
		numLinks = b.IPCServer.NumLinks()
	}
	b.Logger.Info("SSTP bridge listening",
		zap.String("addr", b.ListenAddr),
		zap.String("certDir", b.CertDir),
		zap.String("discriminator", b.Discriminator),
		zap.Int("numLinks", numLinks))

	// Stdin reader goroutine: detect parent death
	stdinCh := make(chan []byte, 64)
	stdinClosed := make(chan struct{})
	go func() {
		defer close(stdinClosed)
		defer close(stdinCh)
		buf := make([]byte, 16384)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				stdinCh <- chunk
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		<-stdinClosed
		ln.Close()
	}()

	if b.IPCServer != nil {
		go b.IPCServer.AcceptWorkers(b.Logger)
		defer b.IPCServer.Close()
	}

	conn, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("accept failed: %w", err)
	}
	defer conn.Close()
	ln.Close()

	var rs *routeState
	if b.ServerRouteIP != "" {
		rs = captureRouteState(b.ServerRouteIP, b.Logger)
		if rs != nil {
			defer rs.Cleanup()
		}
	}

	b.Logger.Info("SSTP client connected", zap.String("remoteAddr", conn.RemoteAddr().String()))

	reader := bufio.NewReader(conn)
	method, path, err := readSSTPHTTPRequest(reader)
	if err != nil {
		return fmt.Errorf("HTTP handshake failed: %w", err)
	}
	if !strings.HasSuffix(path, sstpDuplexURI) || method != "SSTP_DUPLEX_POST" {
		return fmt.Errorf("unexpected request: %s %s", method, path)
	}

	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\nServer: Microsoft-HTTPAPI/2.0\r\nDate: %s\r\n\r\n",
		time.Now().UTC().Format(http.TimeFormat))
	if _, err := conn.Write([]byte(resp)); err != nil {
		return fmt.Errorf("HTTP response failed: %w", err)
	}

	nonce, err := sstpHandshake(conn, reader)
	if err != nil {
		return fmt.Errorf("SSTP handshake failed: %w", err)
	}

	return b.bridgeLoop(conn, reader, nonce, certHash, stdinCh, rs)
}

func (b *SSTPBridge) bridgeLoop(sstpConn net.Conn, sstpReader *bufio.Reader, nonce [32]byte, certHash [32]byte, stdinCh <-chan []byte, rs *routeState) error {
	// MRRU calculation
	var relayMRRU uint16
	var discriminator []byte
	if b.IPCServer != nil {
		calc := b.IPCServer.MinMTU(b.MTU)
		if calc == 0 {
			calc = 1400
		}
		relayMRRU = uint16(calc - 4)
		discriminator = []byte(b.Discriminator)
	}
	mpNegotiated := false

	b.Logger.Info("LCP negotiation starting",
		zap.Int("masterMTU", b.MTU),
		zap.Uint16("relayMRRU", relayMRRU),
		zap.String("discriminator", b.Discriminator))

	var wg sync.WaitGroup
	errCh := make(chan error, 6)
	done := make(chan struct{})
	toWindows := make(chan []byte, 64)
	var sstpMu sync.Mutex
	var fragSeq atomic.Uint32

	var injectedOpts []byte
	var strippedOpts []byte
	var serverReqOpts []byte
	var shortSeqRejected bool
	var peerRequestedShortSeq bool
	var serverAcked bool
	var windowsAcked bool
	var windowsPAPDone bool
	var serverPAPDone bool
	var startBroadcasted bool

	reassembly := newMPReassembler()

	sendToWindows := func(pppFrame []byte) error {
		sstpMu.Lock()
		defer sstpMu.Unlock()
		return writeSSTPData(sstpConn, pppFrame)
	}

	sendToServer := func(pppFrame []byte) error {
		_, err := os.Stdout.Write(EncodeHDLC(pppFrame))
		return err
	}

	tryBroadcastStart := func() {
		if b.IPCServer == nil {
			return
		}
		if startBroadcasted {
			return
		}
		if !serverAcked || !windowsAcked || !windowsPAPDone || !serverPAPDone {
			return
		}
		if shortSeqRejected {
			errCh <- errors.New("server rejected short-seq, cannot continue")
			return
		}
		if !peerRequestedShortSeq {
			errCh <- errors.New("server did not request short-seq, cannot use short format")
			return
		}
		startBroadcasted = true
		mpNegotiated = true
		b.Logger.Info("LCP relay complete, broadcasting start to workers",
			zap.Uint16("mrru", relayMRRU),
			zap.Bool("shortSeq", true),
			zap.Int("numLinks", b.IPCServer.NumLinks()))
		payload := make([]byte, 3)
		binary.BigEndian.PutUint16(payload[0:2], relayMRRU)
		payload[2] = 1
		b.IPCServer.Broadcast(IPCMessage{Type: ipcMsgStart, Payload: payload})
	}

	distributeFragment := func(pppPayload []byte) {
		seq := uint16(fragSeq.Add(1) & uint32(mpSeqMask))
		mpFrame := encodeMPFragment(true, true, seq, pppPayload)
		numLinks := b.IPCServer.ActiveNumLinks()
		linkIdx := int(seq) % numLinks

		if ce := b.Logger.Check(zap.DebugLevel, "MP distribute"); ce != nil {
			ce.Write(zap.Uint16("seq", seq), zap.Int("link", linkIdx),
				zap.Int("totalLinks", numLinks), zap.Int("bytes", len(pppPayload)))
		}

		if linkIdx == 0 {
			_ = sendToServer(mpFrame)
		} else {
			workers := b.IPCServer.ActiveWorkers()
			wIdx := linkIdx - 1
			if wIdx < len(workers) {
				_ = workers[wIdx].SendTo(IPCMessage{Type: ipcMsgTXFragment, Payload: mpFrame})
			} else {
				_ = sendToServer(mpFrame)
			}
		}
	}

	// Goroutine: SSTP reader (Windows -> Server) with LCP relay + PAP interception
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			pppFrame, isData, err := readSSTPPacket(sstpReader)
			if err != nil {
				errCh <- err
				return
			}
			if !isData {
				if len(pppFrame) < 4 {
					continue
				}
				mt := binary.BigEndian.Uint16(pppFrame[0:2])
				switch mt {
			case sstpMsgCallConnected:
				if err := verifyCryptoBinding(pppFrame[4:], nonce, certHash); err != nil {
					b.Logger.Warn("SSTP CryptoBinding verification failed", zap.Error(err))
				} else {
					b.Logger.Info("SSTP CALL_CONNECTED verified")
				}
				if rs != nil {
					go rs.ApplyRoutes()
				}
				case sstpMsgEchoRequest:
					sstpMu.Lock()
					_ = writeSSTPControl(sstpConn, sstpMsgEchoResponse, nil)
					sstpMu.Unlock()
				case sstpMsgCallDisconnect:
					errCh <- errors.New("SSTP client disconnected")
					_ = writeSSTPControl(sstpConn, sstpMsgCallDisconnectAck, nil)
					return
				case sstpMsgCallAbort:
					errCh <- errors.New("SSTP client aborted")
					return
				}
				continue
			}

			proto, payload := parsePPPFrame(pppFrame)
			switch {
			case proto == pppProtoLCP:
				if len(payload) < 4 {
					continue
				}
				code := payload[0]
				id := payload[1]
				opts := payload[4:]
				switch code {
				case lcpConfigRequest:
					injectedOpts = buildMLPPPOptions(relayMRRU, discriminator, !shortSeqRejected)
					augmented := append(append([]byte(nil), opts...), injectedOpts...)
					pkt := buildLCPPacket(lcpConfigRequest, id, augmented)
					if err := sendToServer(makePPPFrame(pppProtoLCP, pkt)); err != nil {
						errCh <- err
						return
					}
					b.Logger.Info("LCP Config-Request (Windows->Server)",
						zap.Int("injectedOptsLen", len(injectedOpts)),
						zap.Uint16("relayMRRU", relayMRRU))
					serverAcked = false
				case lcpConfigAck:
					pkt := buildLCPPacket(lcpConfigAck, id, serverReqOpts)
					if err := sendToServer(makePPPFrame(pppProtoLCP, pkt)); err != nil {
						errCh <- err
						return
					}
					windowsAcked = true
					b.Logger.Info("LCP Config-Ack (Windows->Server)", zap.Bool("windowsAcked", true))
					tryBroadcastStart()
				case lcpConfigNak, lcpConfigReject:
					if err := sendToServer(pppFrame); err != nil {
						errCh <- err
						return
					}
					windowsAcked = false
				default:
					if err := sendToServer(pppFrame); err != nil {
						errCh <- err
						return
					}
				}

			case proto == pppProtoPAP:
				if len(payload) >= 4 && payload[0] == 1 {
					peerUser, peerPass := parsePAPAuthRequest(payload)
					if peerUser == papLocalUser && peerPass == papLocalPass {
						_ = sendToWindows(buildPAPResponse(2, payload[1], "OK"))
						windowsPAPDone = true
						b.Logger.Info("PAP authentication succeeded (Windows)")
						if b.PAPUser != "" {
							papReq := buildPAPAuthRequest(1, b.PAPUser, b.PAPPass)
							if err := sendToServer(papReq); err != nil {
								errCh <- err
								return
							}
						} else {
							papReq := buildPAPAuthRequest(1, peerUser, peerPass)
							if err := sendToServer(papReq); err != nil {
								errCh <- err
								return
							}
						}
						tryBroadcastStart()
					} else {
						_ = sendToWindows(buildPAPResponse(3, payload[1], "bad credentials"))
						errCh <- errors.New("Windows PAP auth failed")
						return
					}
				}

			default:
				if mpNegotiated {
					off := 0
					if len(pppFrame) >= 2 && pppFrame[0] == 0xFF && pppFrame[1] == 0x03 {
						off = 2
					}
					if off < len(pppFrame) {
						if proto == pppProtoIPCP || proto == pppProtoIPv6CP || proto == pppProtoCCP {
							seq := uint16(fragSeq.Add(1) & uint32(mpSeqMask))
							mpFrame := encodeMPFragment(true, true, seq, pppFrame[off:])
							if err := sendToServer(mpFrame); err != nil {
								errCh <- err
								return
							}
						} else {
							distributeFragment(pppFrame[off:])
						}
					}
				} else {
					hdlcFrame := EncodeHDLC(pppFrame)
					if _, err := os.Stdout.Write(hdlcFrame); err != nil {
						errCh <- fmt.Errorf("stdout write error: %w", err)
						return
					}
				}
			}
		}
	}()

	// Goroutine: stdin reader (Server -> Windows) with LCP relay + PAP handling
	wg.Add(1)
	go func() {
		defer wg.Done()
		var hdlcBuf []byte
		for {
			select {
			case chunk, ok := <-stdinCh:
				if !ok {
					errCh <- errors.New("stdin closed")
					return
				}
				hdlcBuf = append(hdlcBuf, chunk...)
				for {
					frame, rest, ok := extractHDLCFrame(hdlcBuf)
					if !ok {
						break
					}
					hdlcBuf = rest
					rawPPP, decErr := decodeHDLCFramePayload(frame)
					if decErr != nil {
						continue
					}
					proto, payload := parsePPPFrame(rawPPP)
					switch {
					case proto == pppProtoLCP:
						if len(payload) < 4 {
							continue
						}
						code := payload[0]
						id := payload[1]
						opts := payload[4:]
						if len(injectedOpts) > 0 {
							switch code {
							case lcpConfigRequest:
								mlpppOpts, restOpts := splitOptions(opts)
								for scan := mlpppOpts; len(scan) >= 2; {
									optLen := int(scan[1])
									if optLen < 2 || optLen > len(scan) {
										break
									}
									if scan[0] == lcpOptShortSeqNum {
										peerRequestedShortSeq = true
									}
									scan = scan[optLen:]
								}
								nakOpts := collectNakOptions(restOpts, relayMRRU)
								if len(nakOpts) > 0 {
									b.Logger.Info("LCP Config-Nak (Bridge->Server)",
										zap.Int("nakOptsLen", len(nakOpts)),
										zap.Uint16("relayMRRU", relayMRRU))
									pkt := buildLCPPacket(lcpConfigNak, id, nakOpts)
									if err := sendToServer(makePPPFrame(pppProtoLCP, pkt)); err != nil {
										errCh <- err
										return
									}
								} else {
									strippedOpts = mlpppOpts
									serverReqOpts = append([]byte(nil), opts...)
									b.Logger.Info("LCP Config-Request (Server->Windows)",
										zap.Int("strippedOptsLen", len(strippedOpts)),
										zap.Bool("peerRequestedShortSeq", peerRequestedShortSeq),
										zap.Uint16("relayMRRU", relayMRRU))
									pkt := buildLCPPacket(lcpConfigRequest, id, restOpts)
									if err := sendToWindows(makePPPFrame(pppProtoLCP, pkt)); err != nil {
										errCh <- err
										return
									}
									windowsAcked = false
								}
							case lcpConfigAck:
								_, restOpts := splitOptions(opts)
								pkt := buildLCPPacket(lcpConfigAck, id, restOpts)
								if err := sendToWindows(makePPPFrame(pppProtoLCP, pkt)); err != nil {
									errCh <- err
									return
								}
								serverAcked = true
								b.Logger.Info("LCP Config-Ack (Server->Windows)", zap.Bool("serverAcked", true))
								tryBroadcastStart()
							case lcpConfigNak:
								mlpppOpts, restOpts := splitOptions(opts)
								for scan := mlpppOpts; len(scan) >= 2; {
									optLen := int(scan[1])
									if optLen < 2 || optLen > len(scan) {
										break
									}
									if scan[0] == lcpOptMRRU && optLen >= 4 {
										oldMRRU := relayMRRU
										relayMRRU = binary.BigEndian.Uint16(scan[2:4])
										b.Logger.Info("Server NAK'd MRRU",
											zap.Uint16("oldMRRU", oldMRRU),
											zap.Uint16("newMRRU", relayMRRU))
									}
									scan = scan[optLen:]
								}
								if len(restOpts) > 0 {
									pkt := buildLCPPacket(lcpConfigNak, id, restOpts)
									if err := sendToWindows(makePPPFrame(pppProtoLCP, pkt)); err != nil {
										errCh <- err
										return
									}
								}
								serverAcked = false
							case lcpConfigReject:
								mlpppOpts, restOpts := splitOptions(opts)
								for scan := mlpppOpts; len(scan) >= 2; {
									optLen := int(scan[1])
									if optLen < 2 || optLen > len(scan) {
										break
									}
									if scan[0] == lcpOptShortSeqNum {
										shortSeqRejected = true
										b.Logger.Info("Server Rejected ShortSeq")
									}
									if scan[0] == lcpOptMRRU {
										relayMRRU = 0
										b.Logger.Info("Server Rejected MRRU, degrading to single-link")
									}
									scan = scan[optLen:]
								}
								if len(restOpts) > 0 {
									pkt := buildLCPPacket(lcpConfigReject, id, restOpts)
									if err := sendToWindows(makePPPFrame(pppProtoLCP, pkt)); err != nil {
										errCh <- err
										return
									}
								}
								serverAcked = false
							default:
								if err := sendToWindows(rawPPP); err != nil {
									errCh <- err
									return
								}
							}
						} else {
							// Non-MLPPP: forward LCP unchanged
							switch code {
							case lcpConfigAck:
								serverAcked = true
								b.Logger.Info("LCP Config-Ack (Server->Windows)", zap.Bool("serverAcked", true))
							case lcpConfigRequest:
								windowsAcked = false
							}
							if err := sendToWindows(rawPPP); err != nil {
								errCh <- err
								return
							}
						}

					case proto == pppProtoPAP:
						if len(payload) >= 1 {
							if payload[0] == 2 {
								b.Logger.Info("PAP authentication succeeded (server)")
								serverPAPDone = true
								b.Logger.Info("PAP completed",
									zap.Bool("windowsPAPDone", windowsPAPDone),
									zap.Bool("serverPAPDone", serverPAPDone))
								tryBroadcastStart()
							} else if payload[0] == 3 {
								errCh <- errors.New("PAP authentication rejected by server")
								return
							}
						}

					case proto == pppProtoMP:
						if assembled := reassembly.AddFragment(rawPPP); assembled != nil {
							select {
							case toWindows <- assembled:
							default:
							}
						}

					default:
						if mpNegotiated {
							select {
							case toWindows <- rawPPP:
							default:
							}
						} else {
							if err := writeSSTPData(sstpConn, rawPPP); err != nil {
								errCh <- fmt.Errorf("SSTP data write error: %w", err)
								return
							}
						}
					}
				}
			case <-done:
				return
			}
		}
	}()

	// Goroutine: IPC RX reader (worker fragments -> reassembly)
	if b.IPCServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case msg, ok := <-b.IPCServer.RxCh:
					if !ok {
						return
					}
					if msg.Type == ipcMsgRXFragment {
						if assembled := reassembly.AddFragment(msg.Payload); assembled != nil {
							select {
							case toWindows <- assembled:
							default:
							}
						}
					}
				case <-done:
					return
				}
			}
		}()
	}

	// Goroutine: SSTP writer (toWindows channel -> Windows)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case frame, ok := <-toWindows:
				if !ok {
					return
				}
				if err := sendToWindows(frame); err != nil {
					errCh <- err
					return
				}
			case <-done:
				return
			}
		}
	}()

	err := <-errCh
	close(done)
	_ = sstpConn.Close()
	if b.IPCServer != nil {
		b.IPCServer.Close()
	}
	wg.Wait()

	if !mpNegotiated && relayMRRU == 0 && b.Discriminator == "" {
		b.Logger.Info("Single-link PPP mode")
	}

	b.Logger.Info("SSTP session ended", zap.Error(err))
	return err
}

// ---------------------------------------------------------------------------
// MLPPPWorker
// ---------------------------------------------------------------------------

// MLPPPWorker runs as a worker bridge: negotiates MLPPP LCP with its own
// server and exchanges fragments with the master via IPC. On master loss
// it attempts to promote itself to master.
type MLPPPWorker struct {
	ListenAddr    string
	CertDir       string
	Discriminator string
	PAPUser       string
	PAPPass       string
	MTU           int
	Logger        *zap.Logger
	ServerRouteIP string
}

func (w *MLPPPWorker) Run() error {
	for {
		client, err := DialMaster(w.Discriminator)
		if err != nil {
			isMaster, ipcServer, tryErr := TryBecomeMaster(w.Discriminator)
			if tryErr != nil {
				return tryErr
			}
			if isMaster {
				w.Logger.Info("MLPPP worker promoted to master")
			m := &SSTPBridge{
				ListenAddr:    w.ListenAddr,
				CertDir:       w.CertDir,
				Discriminator: w.Discriminator,
				PAPUser:       w.PAPUser,
				PAPPass:       w.PAPPass,
				MTU:           w.MTU,
				IPCServer:     ipcServer,
				Logger:        w.Logger,
				ServerRouteIP: w.ServerRouteIP,
			}
				return m.Run()
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if regErr := client.SendRegister(w.MTU); regErr != nil {
			client.Close()
			w.Logger.Warn("MLPPP registration send failed, retrying", zap.Error(regErr))
			continue
		}
		linkIndex, totalLinks, welcomeErr := client.ReadWelcome()
		if welcomeErr != nil {
			client.Close()
			w.Logger.Warn("MLPPP welcome read failed, retrying", zap.Error(welcomeErr))
			continue
		}
		w.Logger.Info("MLPPP bridge: worker",
			zap.Int("linkIndex", linkIndex),
			zap.Int("totalLinks", totalLinks),
			zap.String("discriminator", w.Discriminator))

		err = w.runWorker(client)
		if err != nil {
			w.Logger.Info("MLPPP worker IPC lost, attempting promotion", zap.Error(err))
			continue
		}
		return nil
	}
}

func (w *MLPPPWorker) runWorker(client *IPCClient) error {
	defer client.Close()

	// Wait for master to complete LCP relay and broadcast start params
	w.Logger.Info("Worker waiting for master start signal")
	startMRRU, startShortSeq, err := client.WaitForStart()
	if err != nil {
		return fmt.Errorf("failed to receive start signal: %w", err)
	}
	w.Logger.Info("Worker received start signal",
		zap.Uint16("mrru", startMRRU),
		zap.Bool("shortSeq", startShortSeq))

	calc := w.MTU
	if calc == 0 {
		calc = 1400
	}
	srvLCP := newMLPPPLCPState(0xCAFEBABE, uint16(calc), startMRRU, []byte(w.Discriminator))
	srvLCP.wantShortSeq = startShortSeq
	errCh := make(chan error, 3)

	// Now send initial LCP Config-Request (deferred until after start signal)
	initFrame := srvLCP.InitialRequest()
	if _, err := os.Stdout.Write(EncodeHDLC(initFrame)); err != nil {
		return fmt.Errorf("failed to send initial LCP to server: %w", err)
	}

	// Goroutine: stdin (HDLC from server) -> classify, handle LCP or forward fragments to master
	go func() {
		buf := make([]byte, 16384)
		var hdlcBuf []byte
		papSent := false
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				hdlcBuf = append(hdlcBuf, buf[:n]...)
				for {
					frame, rest, ok := extractHDLCFrame(hdlcBuf)
					if !ok {
						break
					}
					hdlcBuf = rest
					rawPPP, decErr := decodeHDLCFramePayload(frame)
					if decErr != nil {
						continue
					}
					proto, payload := parsePPPFrame(rawPPP)
					switch {
					case proto == pppProtoLCP:
						responses := srvLCP.HandleLCP(payload)
						for _, resp := range responses {
							if _, werr := os.Stdout.Write(EncodeHDLC(resp)); werr != nil {
								errCh <- werr
								return
							}
						}
						// Abort if server rejected MLPPP options
						if srvLCP.shortSeqRejected {
							errCh <- errors.New("server rejected short-seq, aborting worker")
							return
						}
						if srvLCP.wantShortSeq && srvLCP.open && !srvLCP.peerRequestedShortSeq {
							errCh <- errors.New("server did not request short-seq, aborting worker")
							return
						}
						if srvLCP.mrru == 0 && startMRRU > 0 {
							errCh <- errors.New("server rejected MRRU, aborting worker")
							return
						}
						if srvLCP.IsOpen() && w.PAPUser != "" && !papSent {
							papReq := buildPAPAuthRequest(1, w.PAPUser, w.PAPPass)
							if _, werr := os.Stdout.Write(EncodeHDLC(papReq)); werr != nil {
								errCh <- werr
								return
							}
							papSent = true
						}
					case proto == pppProtoPAP:
						if len(payload) >= 1 {
							if payload[0] == 2 {
								w.Logger.Info("PAP authentication succeeded (worker)")
								if sendErr := client.Send(IPCMessage{Type: ipcMsgLinkReady}); sendErr != nil {
									errCh <- fmt.Errorf("IPC link-ready send failed: %w", sendErr)
									return
								}
							} else if payload[0] == 3 {
								errCh <- errors.New("PAP authentication rejected by server")
								return
							}
						}
					case proto == pppProtoMP:
						if err := client.Send(IPCMessage{Type: ipcMsgRXFragment, Payload: rawPPP}); err != nil {
							errCh <- fmt.Errorf("IPC send failed: %w", err)
							return
						}
					}
				}
			}
			if err != nil {
				errCh <- fmt.Errorf("stdin closed: %w", err)
				return
			}
		}
	}()

	// Goroutine: IPC reader (TX fragments from master) -> HDLC stdout
	go func() {
		for {
			msg, err := client.Read()
			if err != nil {
				errCh <- fmt.Errorf("IPC read failed: %w", err)
				return
			}
			if msg.Type == ipcMsgTXFragment {
				if _, err := os.Stdout.Write(EncodeHDLC(msg.Payload)); err != nil {
					errCh <- fmt.Errorf("stdout write failed: %w", err)
					return
				}
			}
		}
	}()

	return <-errCh
}

func buildPAPAuthRequest(id byte, user, pass string) []byte {
	pktLen := 4 + 1 + len(user) + 1 + len(pass)
	rawPPP := make([]byte, 4+pktLen)
	rawPPP[0] = 0xFF
	rawPPP[1] = 0x03
	binary.BigEndian.PutUint16(rawPPP[2:4], pppProtoPAP)
	rawPPP[4] = 1 // Authenticate-Request
	rawPPP[5] = id
	binary.BigEndian.PutUint16(rawPPP[6:8], uint16(pktLen))
	rawPPP[8] = byte(len(user))
	copy(rawPPP[9:9+len(user)], user)
	rawPPP[9+len(user)] = byte(len(pass))
	copy(rawPPP[10+len(user):], pass)
	return rawPPP
}

func parsePAPAuthRequest(payload []byte) (user, pass string) {
	if len(payload) < 6 {
		return "", ""
	}
	userLen := int(payload[4])
	if 5+userLen >= len(payload) {
		return "", ""
	}
	user = string(payload[5 : 5+userLen])
	passLen := int(payload[5+userLen])
	if 6+userLen+passLen > len(payload) {
		return user, ""
	}
	pass = string(payload[6+userLen : 6+userLen+passLen])
	return user, pass
}
