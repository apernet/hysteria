package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"sync"

	"github.com/apernet/hysteria/core/internal/congestion"
	"github.com/apernet/hysteria/core/internal/frag"
	"github.com/apernet/hysteria/core/internal/protocol"
	"github.com/apernet/hysteria/core/internal/utils"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	closeErrCodeOK                  = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeTrafficLimitReached = 0x107 // HTTP3 ErrCodeExcessiveLoad
)

type Server interface {
	Serve() error
	Close() error
}

func NewServer(config *Config) (Server, error) {
	if err := config.fill(); err != nil {
		return nil, err
	}
	tlsConfig := http3.ConfigureTLSConfig(&tls.Config{
		Certificates:   config.TLSConfig.Certificates,
		GetCertificate: config.TLSConfig.GetCertificate,
	})
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 config.QUICConfig.MaxIdleTimeout,
		MaxIncomingStreams:             config.QUICConfig.MaxIncomingStreams,
		DisablePathMTUDiscovery:        config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
	}
	listener, err := quic.Listen(config.Conn, tlsConfig, quicConfig)
	if err != nil {
		_ = config.Conn.Close()
		return nil, err
	}
	return &serverImpl{
		config:   config,
		listener: listener,
	}, nil
}

type serverImpl struct {
	config   *Config
	listener *quic.Listener
}

func (s *serverImpl) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleClient(conn)
	}
}

func (s *serverImpl) Close() error {
	err := s.listener.Close()
	_ = s.config.Conn.Close()
	return err
}

func (s *serverImpl) handleClient(conn quic.Connection) {
	handler := newH3sHandler(s.config, conn)
	h3s := http3.Server{
		EnableDatagrams: true,
		Handler:         handler,
		StreamHijacker:  handler.ProxyStreamHijacker,
	}
	err := h3s.ServeQUICConn(conn)
	// If the client is authenticated, we need to log the disconnect event
	if handler.authenticated && s.config.EventLogger != nil {
		s.config.EventLogger.Disconnect(conn.RemoteAddr(), handler.authID, err)
	}
	_ = conn.CloseWithError(closeErrCodeOK, "")
}

type h3sHandler struct {
	config *Config
	conn   quic.Connection

	authenticated bool
	authID        string

	udpOnce sync.Once
	udpSM   udpSessionManager
}

func newH3sHandler(config *Config, conn quic.Connection) *h3sHandler {
	return &h3sHandler{
		config: config,
		conn:   conn,
		udpSM: udpSessionManager{
			listenFunc: config.Outbound.ListenUDP,
			m:          make(map[uint32]*udpSessionEntry),
		},
	}
}

type udpSessionEntry struct {
	Conn   UDPConn
	D      *frag.Defragger
	Closed bool
}

type udpSessionManager struct {
	listenFunc func() (UDPConn, error)
	mutex      sync.RWMutex
	m          map[uint32]*udpSessionEntry
	nextID     uint32
}

// Add returns the session ID, the UDP connection and a function to close the UDP connection & delete the session.
func (m *udpSessionManager) Add() (uint32, UDPConn, func(), error) {
	conn, err := m.listenFunc()
	if err != nil {
		return 0, nil, nil, err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()
	id := m.nextID
	m.nextID++
	entry := &udpSessionEntry{
		Conn:   conn,
		D:      &frag.Defragger{},
		Closed: false,
	}
	m.m[id] = entry

	return id, conn, func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		if entry.Closed {
			// Already closed
			return
		}
		entry.Closed = true
		_ = conn.Close()
		delete(m.m, id)
	}, nil
}

// Feed feeds a UDP message to the session manager.
// If the message itself is a complete message, or it's the last fragment of a message,
// it will be sent to the UDP connection.
// The function will then return the number of bytes sent and any error occurred.
func (m *udpSessionManager) Feed(msg *protocol.UDPMessage) (int, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	entry, ok := m.m[msg.SessionID]
	if !ok {
		// No such session, drop the message
		return 0, nil
	}
	dfMsg := entry.D.Feed(msg)
	if dfMsg == nil {
		// Not a complete message yet
		return 0, nil
	}
	return entry.Conn.WriteTo(dfMsg.Data, dfMsg.Addr)
}

func (h *h3sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		if h.authenticated {
			// Already authenticated
			protocol.AuthResponseDataToHeader(w.Header(), h.config.BandwidthConfig.MaxRx)
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		auth, clientRx := protocol.AuthRequestDataFromHeader(r.Header)
		// actualTx = min(serverTx, clientRx)
		actualTx := clientRx
		if h.config.BandwidthConfig.MaxTx > 0 && actualTx > h.config.BandwidthConfig.MaxTx {
			actualTx = h.config.BandwidthConfig.MaxTx
		}
		ok, id := h.config.Authenticator.Authenticate(h.conn.RemoteAddr(), auth, actualTx)
		if ok {
			// Set authenticated flag
			h.authenticated = true
			h.authID = id
			// Update congestion control when applicable
			if actualTx > 0 {
				h.conn.SetCongestionControl(congestion.NewBrutalSender(actualTx))
			}
			// Auth OK, send response
			protocol.AuthResponseDataToHeader(w.Header(), h.config.BandwidthConfig.MaxRx)
			w.WriteHeader(protocol.StatusAuthOK)
			// Call event logger
			if h.config.EventLogger != nil {
				h.config.EventLogger.Connect(h.conn.RemoteAddr(), id, actualTx)
			}
			// Start UDP loop if UDP is not disabled
			// We use sync.Once to make sure that only one goroutine is started,
			// as ServeHTTP may be called by multiple goroutines simultaneously
			if !h.config.DisableUDP {
				h.udpOnce.Do(func() {
					go h.udpLoop()
				})
			}
		} else {
			// Auth failed, pretend to be a normal HTTP server
			h.masqHandler(w, r)
		}
	} else {
		// Not an auth request, pretend to be a normal HTTP server
		h.masqHandler(w, r)
	}
}

func (h *h3sHandler) ProxyStreamHijacker(ft http3.FrameType, conn quic.Connection, stream quic.Stream, err error) (bool, error) {
	if err != nil || !h.authenticated {
		return false, nil
	}

	// Wraps the stream with QStream, which handles Close() properly
	stream = &utils.QStream{Stream: stream}

	switch ft {
	case protocol.FrameTypeTCPRequest:
		go h.handleTCPRequest(stream)
		return true, nil
	case protocol.FrameTypeUDPRequest:
		go h.handleUDPRequest(stream)
		return true, nil
	default:
		return false, nil
	}
}

func (h *h3sHandler) handleTCPRequest(stream quic.Stream) {
	// Read request
	reqAddr, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	// Log the event
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPRequest(h.conn.RemoteAddr(), h.authID, reqAddr)
	}
	// Dial target
	tConn, err := h.config.Outbound.DialTCP(reqAddr)
	if err != nil {
		_ = protocol.WriteTCPResponse(stream, false, err.Error())
		_ = stream.Close()
		// Log the error
		if h.config.EventLogger != nil {
			h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
		}
		return
	}
	_ = protocol.WriteTCPResponse(stream, true, "")
	// Start proxying
	if h.config.TrafficLogger != nil {
		err = copyTwoWayWithLogger(h.authID, stream, tConn, h.config.TrafficLogger)
	} else {
		// Use the fast path if no traffic logger is set
		err = copyTwoWay(stream, tConn)
	}
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
	}
	// Cleanup
	_ = tConn.Close()
	_ = stream.Close()
	// Disconnect the client if TrafficLogger requested
	if err == errDisconnect {
		_ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
	}
}

func (h *h3sHandler) handleUDPRequest(stream quic.Stream) {
	if h.config.DisableUDP {
		// UDP is disabled, send error message and close the stream
		_ = protocol.WriteUDPResponse(stream, false, 0, "UDP is disabled on this server")
		_ = stream.Close()
		return
	}
	// Read request
	err := protocol.ReadUDPRequest(stream)
	if err != nil {
		_ = stream.Close()
		return
	}
	// Add to session manager
	sessionID, conn, connCloseFunc, err := h.udpSM.Add()
	if err != nil {
		_ = protocol.WriteUDPResponse(stream, false, 0, err.Error())
		_ = stream.Close()
		return
	}
	// Send response
	_ = protocol.WriteUDPResponse(stream, true, sessionID, "")
	// Call event logger
	if h.config.EventLogger != nil {
		h.config.EventLogger.UDPRequest(h.conn.RemoteAddr(), h.authID, sessionID)
	}

	// client <- remote direction
	go func() {
		udpBuf := make([]byte, protocol.MaxUDPSize)
		msgBuf := make([]byte, protocol.MaxUDPSize)
		for {
			udpN, rAddr, err := conn.ReadFrom(udpBuf)
			if udpN > 0 {
				if h.config.TrafficLogger != nil {
					ok := h.config.TrafficLogger.Log(h.authID, 0, uint64(udpN))
					if !ok {
						// TrafficLogger requested to disconnect the client
						_ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
						return
					}
				}
				// Try no frag first
				msg := protocol.UDPMessage{
					SessionID: sessionID,
					PacketID:  0,
					FragID:    0,
					FragCount: 1,
					Addr:      rAddr,
					Data:      udpBuf[:udpN],
				}
				msgN := msg.Serialize(msgBuf)
				if msgN < 0 {
					// Message even larger than MaxUDPSize, drop it
					continue
				}
				sendErr := h.conn.SendMessage(msgBuf[:msgN])
				var errTooLarge quic.ErrMessageTooLarge
				if errors.As(sendErr, &errTooLarge) {
					// Message too large, try fragmentation
					msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
					fMsgs := frag.FragUDPMessage(msg, int(errTooLarge))
					for _, fMsg := range fMsgs {
						msgN = fMsg.Serialize(msgBuf)
						_ = h.conn.SendMessage(msgBuf[:msgN])
					}
				}
			}
			if err != nil {
				break
			}
		}
		connCloseFunc()
		_ = stream.Close()
	}()

	// Hold (drain) the stream until the client closes it.
	// Closing the stream is the signal to stop the UDP session.
	_, err = io.Copy(io.Discard, stream)
	// Call event logger
	if h.config.EventLogger != nil {
		h.config.EventLogger.UDPError(h.conn.RemoteAddr(), h.authID, sessionID, err)
	}

	// Cleanup
	connCloseFunc()
	_ = stream.Close()
}

func (h *h3sHandler) udpLoop() {
	for {
		msg, err := h.conn.ReceiveMessage()
		if err != nil {
			return
		}
		ok := h.handleUDPMessage(msg)
		if !ok {
			// TrafficLogger requested to disconnect the client
			_ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			return
		}
	}
}

// client -> remote direction
// Returns a bool indicating whether the receiving loop should continue
func (h *h3sHandler) handleUDPMessage(msg []byte) (ok bool) {
	udpMsg, err := protocol.ParseUDPMessage(msg)
	if err != nil {
		return true
	}
	if h.config.TrafficLogger != nil {
		ok := h.config.TrafficLogger.Log(h.authID, uint64(len(udpMsg.Data)), 0)
		if !ok {
			return false
		}
	}
	_, _ = h.udpSM.Feed(udpMsg)
	return true
}

func (h *h3sHandler) masqHandler(w http.ResponseWriter, r *http.Request) {
	if h.config.MasqHandler != nil {
		h.config.MasqHandler.ServeHTTP(w, r)
	} else {
		// Return 404 for everything
		http.NotFound(w, r)
	}
}
