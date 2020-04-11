package forwarder

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/lucas-clemente/quic-go"
	"github.com/tobyxdd/hysteria/internal/utils"
	"net"
	"sync"
	"sync/atomic"
)

type QUICClient struct {
	inboundBytes, outboundBytes uint64 // atomic

	reconnectMutex             sync.Mutex
	quicSession                quic.Session
	listener                   net.Listener
	remoteAddr                 string
	name                       string
	tlsConfig                  *tls.Config
	sendBPS, recvBPS           uint64
	recvWindowConn, recvWindow uint64
	closed                     bool

	newCongestion         CongestionFactory
	onServerConnected     ServerConnectedCallback
	onServerError         ServerErrorCallback
	onNewTCPConnection    NewTCPConnectionCallback
	onTCPConnectionClosed TCPConnectionClosedCallback
}

func NewQUICClient(addr string, remoteAddr string, name string, tlsConfig *tls.Config,
	sendBPS uint64, recvBPS uint64, recvWindowConn uint64, recvWindow uint64,
	newCongestion CongestionFactory,
	onServerConnected ServerConnectedCallback,
	onServerError ServerErrorCallback,
	onNewTCPConnection NewTCPConnectionCallback,
	onTCPConnectionClosed TCPConnectionClosedCallback) (*QUICClient, error) {
	// Local TCP listener
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	c := &QUICClient{
		listener:              listener,
		remoteAddr:            remoteAddr,
		name:                  name,
		tlsConfig:             tlsConfig,
		sendBPS:               sendBPS,
		recvBPS:               recvBPS,
		recvWindowConn:        recvWindowConn,
		recvWindow:            recvWindow,
		newCongestion:         newCongestion,
		onServerConnected:     onServerConnected,
		onServerError:         onServerError,
		onNewTCPConnection:    onNewTCPConnection,
		onTCPConnectionClosed: onTCPConnectionClosed,
	}
	if err := c.connectToServer(); err != nil {
		_ = c.listener.Close()
		return nil, err
	}
	go c.acceptLoop()
	return c, nil
}

func (c *QUICClient) Close() error {
	err1 := c.listener.Close()
	c.reconnectMutex.Lock()
	err2 := c.quicSession.CloseWithError(closeErrorCodeGeneric, "generic")
	c.closed = true
	c.reconnectMutex.Unlock()
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *QUICClient) Stats() (string, uint64, uint64) {
	return c.remoteAddr, atomic.LoadUint64(&c.inboundBytes), atomic.LoadUint64(&c.outboundBytes)
}

func (c *QUICClient) acceptLoop() {
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			break
		}
		go c.handleConn(conn)
	}
}

func (c *QUICClient) connectToServer() error {
	qs, err := quic.DialAddr(c.remoteAddr, c.tlsConfig, &quic.Config{
		MaxReceiveStreamFlowControlWindow:     c.recvWindowConn,
		MaxReceiveConnectionFlowControlWindow: c.recvWindow,
		KeepAlive:                             true,
	})
	if err != nil {
		c.onServerError(err)
		return err
	}
	// Control stream
	ctx, ctxCancel := context.WithTimeout(context.Background(), controlStreamTimeout)
	ctlStream, err := qs.OpenStreamSync(ctx)
	ctxCancel()
	if err != nil {
		_ = qs.CloseWithError(closeErrorCodeProtocolFailure, "control stream error")
		c.onServerError(err)
		return err
	}
	banner, cSendBPS, cRecvBPS, err := handleControlStream(qs, ctlStream, c.name, c.sendBPS, c.recvBPS, c.newCongestion)
	if err != nil {
		_ = qs.CloseWithError(closeErrorCodeProtocolFailure, "control stream handling error")
		c.onServerError(err)
		return err
	}
	// All good
	c.quicSession = qs
	c.onServerConnected(qs.RemoteAddr(), banner, cSendBPS, cRecvBPS)
	return nil
}

func (c *QUICClient) openStreamWithReconnect() (quic.Stream, error) {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	if c.closed {
		return nil, errors.New("client closed")
	}
	stream, err := c.quicSession.OpenStream()
	if err == nil {
		// All good
		return stream, nil
	}
	// Something is wrong
	c.onServerError(err)
	if nErr, ok := err.(net.Error); ok && nErr.Temporary() {
		// Temporary error, just return
		return nil, err
	}
	// Permanent error, need to reconnect
	if err := c.connectToServer(); err != nil {
		// Still error, oops
		return nil, err
	}
	// We are not going to try again even if it still fails the second time
	stream, err = c.quicSession.OpenStream()
	if err != nil {
		c.onServerError(err)
	}
	return stream, err
}

// Negotiate speed, return banner, send & receive speed
func handleControlStream(qs quic.Session, stream quic.Stream, name string, sendBPS uint64, recvBPS uint64,
	newCongestion CongestionFactory) (string, uint64, uint64, error) {
	err := writeClientSpeedRequest(stream, &ClientSpeedRequest{
		Name: name,
		Speed: &Speed{
			SendBps:    sendBPS,
			ReceiveBps: recvBPS,
		},
	})
	if err != nil {
		return "", 0, 0, err
	}
	// Response
	resp, err := readServerSpeedResponse(stream)
	if err != nil {
		return "", 0, 0, err
	}
	// Set the congestion accordingly
	if newCongestion != nil {
		qs.SetCongestion(newCongestion(resp.Speed.ReceiveBps))
	}
	return resp.Banner, resp.Speed.ReceiveBps, resp.Speed.SendBps, nil
}

func (c *QUICClient) handleConn(conn net.Conn) {
	c.onNewTCPConnection(conn.RemoteAddr())
	defer conn.Close()
	stream, err := c.openStreamWithReconnect()
	if err != nil {
		c.onTCPConnectionClosed(conn.RemoteAddr(), err)
		return
	}
	defer stream.Close()
	// Pipes
	errChan := make(chan error, 2)
	go func() {
		// TCP to QUIC
		errChan <- utils.Pipe(conn, stream, &c.outboundBytes)
		_ = conn.Close()
		_ = stream.Close()
	}()
	go func() {
		// QUIC to TCP
		errChan <- utils.Pipe(stream, conn, &c.inboundBytes)
		_ = conn.Close()
		_ = stream.Close()
	}()
	// We only need the first error
	err = <-errChan
	c.onTCPConnectionClosed(conn.RemoteAddr(), err)
}
