package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	coreErrs "github.com/apernet/hysteria/core/errors"
	"github.com/apernet/hysteria/core/internal/congestion"
	"github.com/apernet/hysteria/core/internal/frag"
	"github.com/apernet/hysteria/core/internal/protocol"
	"github.com/apernet/hysteria/core/internal/utils"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	udpMessageChanSize = 1024

	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type Client interface {
	DialTCP(addr string) (net.Conn, error)
	ListenUDP() (HyUDPConn, error)
	Close() error
}

type HyUDPConn interface {
	Receive() ([]byte, string, error)
	Send([]byte, string) error
	Close() error
}

func NewClient(config *Config) (Client, error) {
	if err := config.fill(); err != nil {
		return nil, err
	}
	c := &clientImpl{
		config: config,
	}
	c.conn = &autoReconnectConn{
		Connect: c.connect,
	}
	return c, nil
}

type clientImpl struct {
	config *Config
	conn   *autoReconnectConn

	udpSM udpSessionManager
}

type udpSessionEntry struct {
	Ch     chan *protocol.UDPMessage
	D      *frag.Defragger
	Closed bool
}

type udpSessionManager struct {
	mutex sync.RWMutex
	m     map[uint32]*udpSessionEntry
}

func (m *udpSessionManager) Init() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.m = make(map[uint32]*udpSessionEntry)
}

// Add returns both a channel for receiving messages and a function to close the channel & delete the session.
func (m *udpSessionManager) Add(id uint32) (<-chan *protocol.UDPMessage, func()) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Important: make sure we add and delete the channel in the same map,
	// as the map may be replaced by Init() at any time.
	currentM := m.m

	entry := &udpSessionEntry{
		Ch:     make(chan *protocol.UDPMessage, udpMessageChanSize),
		D:      &frag.Defragger{},
		Closed: false,
	}
	currentM[id] = entry

	return entry.Ch, func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		if entry.Closed {
			// Double close a channel will panic,
			// so we need a flag to make sure we only close it once.
			return
		}
		entry.Closed = true
		close(entry.Ch)
		delete(currentM, id)
	}
}

func (m *udpSessionManager) Feed(msg *protocol.UDPMessage) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	entry, ok := m.m[msg.SessionID]
	if !ok {
		// No such session, drop the message
		return
	}
	dfMsg := entry.D.Feed(msg)
	if dfMsg == nil {
		// Not a complete message yet
		return
	}
	select {
	case entry.Ch <- dfMsg:
		// OK
	default:
		// Channel is full, drop the message
	}
}

func (c *clientImpl) connect() (quic.Connection, func(), error) {
	// Use a new packet conn for each connection,
	// remember to close it after the QUIC connection is closed.
	pktConn, err := c.config.ConnFactory.New(c.config.ServerAddr)
	if err != nil {
		return nil, nil, err
	}
	// Convert config to TLS config & QUIC config
	tlsConfig := &tls.Config{
		ServerName:         c.config.TLSConfig.ServerName,
		InsecureSkipVerify: c.config.TLSConfig.InsecureSkipVerify,
		RootCAs:            c.config.TLSConfig.RootCAs,
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     c.config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.config.QUICConfig.MaxIdleTimeout,
		KeepAlivePeriod:                c.config.QUICConfig.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
	}
	// Prepare RoundTripper
	var conn quic.EarlyConnection
	rt := &http3.RoundTripper{
		EnableDatagrams: true,
		TLSClientConfig: tlsConfig,
		QuicConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialEarly(ctx, pktConn, c.config.ServerAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	// Send auth HTTP request
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	protocol.AuthRequestDataToHeader(req.Header, c.config.Auth, c.config.BandwidthConfig.MaxRx)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return nil, nil, &coreErrs.ConnectError{Err: err}
	}
	if resp.StatusCode != protocol.StatusAuthOK {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = pktConn.Close()
		return nil, nil, &coreErrs.AuthError{StatusCode: resp.StatusCode}
	}
	// Auth OK
	serverRx := protocol.AuthResponseDataFromHeader(resp.Header)
	// actualTx = min(serverRx, clientTx)
	actualTx := serverRx
	if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
		actualTx = c.config.BandwidthConfig.MaxTx
	}
	// Set congestion control when applicable
	if actualTx > 0 {
		conn.SetCongestionControl(congestion.NewBrutalSender(actualTx))
	}
	_ = resp.Body.Close()

	c.udpSM.Init()
	go c.udpLoop(conn)

	return conn, func() {
		_ = conn.CloseWithError(closeErrCodeOK, "")
		_ = pktConn.Close()
	}, nil
}

func (c *clientImpl) udpLoop(conn quic.Connection) {
	for {
		msg, err := conn.ReceiveMessage()
		if err != nil {
			return
		}
		c.handleUDPMessage(msg)
	}
}

// client <- remote direction
func (c *clientImpl) handleUDPMessage(msg []byte) {
	udpMsg, err := protocol.ParseUDPMessage(msg)
	if err != nil {
		return
	}
	c.udpSM.Feed(udpMsg)
}

// openStream wraps the stream with QStream, which handles Close() properly
func (c *clientImpl) openStream() (quic.Connection, quic.Stream, error) {
	qc, stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, nil, err
	}

	return qc, &utils.QStream{Stream: stream}, nil
}

func (c *clientImpl) DialTCP(addr string) (net.Conn, error) {
	qc, stream, err := c.openStream()
	if err != nil {
		return nil, err
	}
	// Send request
	err = protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if c.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  qc.LocalAddr(),
			PseudoRemoteAddr: qc.RemoteAddr(),
			Established:      false,
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: msg}
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  qc.LocalAddr(),
		PseudoRemoteAddr: qc.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *clientImpl) ListenUDP() (HyUDPConn, error) {
	qc, stream, err := c.openStream()
	if err != nil {
		return nil, err
	}
	// Send request
	err = protocol.WriteUDPRequest(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	// Read response
	ok, sessionID, msg, err := protocol.ReadUDPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: msg}
	}

	ch, closeFunc := c.udpSM.Add(sessionID)
	uc := &udpConn{
		QC:        qc,
		Stream:    stream,
		SessionID: sessionID,
		Ch:        ch,
		CloseFunc: closeFunc,
		SendBuf:   make([]byte, protocol.MaxUDPSize),
	}
	go uc.Hold()
	return uc, nil
}

func (c *clientImpl) Close() error {
	return c.conn.Close()
}

type tcpConn struct {
	Orig             quic.Stream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// Read response
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, coreErrs.DialError{Message: msg}
		}
		c.Established = true
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

func (c *tcpConn) Close() error {
	return c.Orig.Close()
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}

type udpConn struct {
	QC        quic.Connection
	Stream    quic.Stream
	SessionID uint32
	Ch        <-chan *protocol.UDPMessage
	CloseFunc func()
	SendBuf   []byte
}

func (c *udpConn) Hold() {
	// Hold (drain) the stream until someone closes it.
	// Closing the stream is the signal to stop the UDP session.
	_, _ = io.Copy(io.Discard, c.Stream)
	_ = c.Close()
}

func (c *udpConn) Receive() ([]byte, string, error) {
	msg := <-c.Ch
	if msg == nil {
		// Closed
		return nil, "", io.EOF
	}
	return msg.Data, msg.Addr, nil
}

// Send is not thread-safe as it uses a shared send buffer for now.
func (c *udpConn) Send(data []byte, addr string) error {
	// Try no frag first
	msg := &protocol.UDPMessage{
		SessionID: c.SessionID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      addr,
		Data:      data,
	}
	n := msg.Serialize(c.SendBuf)
	if n < 0 {
		// Message even larger than MaxUDPSize, drop it
		// Maybe we should return an error in the future?
		return nil
	}
	sendErr := c.QC.SendMessage(c.SendBuf[:n])
	if sendErr == nil {
		// All good
		return nil
	}
	var errTooLarge quic.ErrMessageTooLarge
	if errors.As(sendErr, &errTooLarge) {
		// Message too large, try fragmentation
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := frag.FragUDPMessage(msg, int(errTooLarge))
		for _, fMsg := range fMsgs {
			n = fMsg.Serialize(c.SendBuf)
			err := c.QC.SendMessage(c.SendBuf[:n])
			if err != nil {
				return err
			}
		}
		return nil
	}
	// Other error
	return sendErr
}

func (c *udpConn) Close() error {
	c.CloseFunc()
	return c.Stream.Close()
}
