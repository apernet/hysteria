package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lunixbochs/struc"
	transport2 "github.com/tobyxdd/hysteria/pkg/transport"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	ErrClosed = errors.New("closed")
)

type CongestionFactory func(refBPS uint64) congestion.CongestionControl

type Client struct {
	transport         transport2.Transport
	serverAddr        string
	sendBPS, recvBPS  uint64
	auth              []byte
	congestionFactory CongestionFactory
	obfuscator        Obfuscator

	tlsConfig  *tls.Config
	quicConfig *quic.Config

	quicSession    quic.Session
	reconnectMutex sync.Mutex
	closed         bool

	udpSessionMutex sync.RWMutex
	udpSessionMap   map[uint32]chan *udpMessage
}

func NewClient(serverAddr string, auth []byte, tlsConfig *tls.Config, quicConfig *quic.Config, transport transport2.Transport,
	sendBPS uint64, recvBPS uint64, congestionFactory CongestionFactory, obfuscator Obfuscator) (*Client, error) {
	c := &Client{
		transport:         transport,
		serverAddr:        serverAddr,
		sendBPS:           sendBPS,
		recvBPS:           recvBPS,
		auth:              auth,
		congestionFactory: congestionFactory,
		obfuscator:        obfuscator,
		tlsConfig:         tlsConfig,
		quicConfig:        quicConfig,
	}
	if err := c.connectToServer(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) connectToServer() error {
	serverUDPAddr, err := c.transport.QUICResolveUDPAddr(c.serverAddr)
	if err != nil {
		return err
	}
	udpConn, err := c.transport.QUICListenUDP(nil)
	if err != nil {
		return err
	}
	var qs quic.Session
	if c.obfuscator != nil {
		// Wrap PacketConn with obfuscator
		qs, err = quic.Dial(&obfsUDPConn{
			Orig:       udpConn,
			Obfuscator: c.obfuscator,
		}, serverUDPAddr, c.serverAddr, c.tlsConfig, c.quicConfig)
		if err != nil {
			_ = udpConn.Close()
			return err
		}
	} else {
		qs, err = quic.Dial(udpConn, serverUDPAddr, c.serverAddr, c.tlsConfig, c.quicConfig)
		if err != nil {
			_ = udpConn.Close()
			return err
		}
	}
	// Control stream
	ctx, ctxCancel := context.WithTimeout(context.Background(), protocolTimeout)
	stream, err := qs.OpenStreamSync(ctx)
	ctxCancel()
	if err != nil {
		_ = qs.CloseWithError(closeErrorCodeProtocol, "protocol error")
		return err
	}
	ok, msg, err := c.handleControlStream(qs, stream)
	if err != nil {
		_ = qs.CloseWithError(closeErrorCodeProtocol, "protocol error")
		return err
	}
	if !ok {
		_ = qs.CloseWithError(closeErrorCodeAuth, "auth error")
		return fmt.Errorf("auth error: %s", msg)
	}
	// All good
	c.udpSessionMap = make(map[uint32]chan *udpMessage)
	go c.handleMessage(qs)
	c.quicSession = qs
	return nil
}

func (c *Client) handleControlStream(qs quic.Session, stream quic.Stream) (bool, string, error) {
	// Send protocol version
	_, err := stream.Write([]byte{protocolVersion})
	if err != nil {
		return false, "", err
	}
	// Send client hello
	err = struc.Pack(stream, &clientHello{
		Rate: transmissionRate{
			SendBPS: c.sendBPS,
			RecvBPS: c.recvBPS,
		},
		Auth: c.auth,
	})
	if err != nil {
		return false, "", err
	}
	// Receive server hello
	var sh serverHello
	err = struc.Unpack(stream, &sh)
	if err != nil {
		return false, "", err
	}
	// Set the congestion accordingly
	if sh.OK && c.congestionFactory != nil {
		qs.SetCongestionControl(c.congestionFactory(sh.Rate.RecvBPS))
	}
	return sh.OK, sh.Message, nil
}

func (c *Client) handleMessage(qs quic.Session) {
	for {
		msg, err := qs.ReceiveMessage()
		if err != nil {
			break
		}
		var udpMsg udpMessage
		err = struc.Unpack(bytes.NewBuffer(msg), &udpMsg)
		if err != nil {
			continue
		}
		c.udpSessionMutex.RLock()
		ch, ok := c.udpSessionMap[udpMsg.SessionID]
		if ok {
			select {
			case ch <- &udpMsg:
				// OK
			default:
				// Silently drop the message when the channel is full
			}
		}
		c.udpSessionMutex.RUnlock()
	}
}

func (c *Client) openStreamWithReconnect() (quic.Session, quic.Stream, error) {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	if c.closed {
		return nil, nil, ErrClosed
	}
	stream, err := c.quicSession.OpenStream()
	if err == nil {
		// All good
		return c.quicSession, &wrappedQUICStream{stream}, nil
	}
	// Something is wrong
	if nErr, ok := err.(net.Error); ok && nErr.Temporary() {
		// Temporary error, just return
		return nil, nil, err
	}
	// Permanent error, need to reconnect
	if err := c.connectToServer(); err != nil {
		// Still error, oops
		return nil, nil, err
	}
	// We are not going to try again even if it still fails the second time
	stream, err = c.quicSession.OpenStream()
	return c.quicSession, &wrappedQUICStream{stream}, err
}

func (c *Client) DialTCP(addr string) (net.Conn, error) {
	host, port, err := utils.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	session, stream, err := c.openStreamWithReconnect()
	if err != nil {
		return nil, err
	}
	// Send request
	err = struc.Pack(stream, &clientRequest{
		UDP:  false,
		Host: host,
		Port: port,
	})
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	// Read response
	var sr serverResponse
	err = struc.Unpack(stream, &sr)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if !sr.OK {
		_ = stream.Close()
		return nil, fmt.Errorf("connection rejected: %s", sr.Message)
	}
	return &quicConn{
		Orig:             stream,
		PseudoLocalAddr:  session.LocalAddr(),
		PseudoRemoteAddr: session.RemoteAddr(),
	}, nil
}

func (c *Client) DialUDP() (UDPConn, error) {
	session, stream, err := c.openStreamWithReconnect()
	if err != nil {
		return nil, err
	}
	// Send request
	err = struc.Pack(stream, &clientRequest{
		UDP: true,
	})
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	// Read response
	var sr serverResponse
	err = struc.Unpack(stream, &sr)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if !sr.OK {
		_ = stream.Close()
		return nil, fmt.Errorf("connection rejected: %s", sr.Message)
	}

	// Create a session in the map
	c.udpSessionMutex.Lock()
	nCh := make(chan *udpMessage, 1024)
	// Store the current session map for CloseFunc below
	// to ensures that we are adding and removing sessions on the same map,
	// as reconnecting will reassign the map
	sessionMap := c.udpSessionMap
	sessionMap[sr.UDPSessionID] = nCh
	c.udpSessionMutex.Unlock()

	pktConn := &quicPktConn{
		Session: session,
		Stream:  stream,
		CloseFunc: func() {
			c.udpSessionMutex.Lock()
			if ch, ok := sessionMap[sr.UDPSessionID]; ok {
				close(ch)
				delete(sessionMap, sr.UDPSessionID)
			}
			c.udpSessionMutex.Unlock()
		},
		UDPSessionID: sr.UDPSessionID,
		MsgCh:        nCh,
	}
	go pktConn.Hold()
	return pktConn, nil
}

func (c *Client) Close() error {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	err := c.quicSession.CloseWithError(closeErrorCodeGeneric, "")
	c.closed = true
	return err
}

type quicConn struct {
	Orig             quic.Stream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
}

func (w *quicConn) Read(b []byte) (n int, err error) {
	return w.Orig.Read(b)
}

func (w *quicConn) Write(b []byte) (n int, err error) {
	return w.Orig.Write(b)
}

func (w *quicConn) Close() error {
	return w.Orig.Close()
}

func (w *quicConn) LocalAddr() net.Addr {
	return w.PseudoLocalAddr
}

func (w *quicConn) RemoteAddr() net.Addr {
	return w.PseudoRemoteAddr
}

func (w *quicConn) SetDeadline(t time.Time) error {
	return w.Orig.SetDeadline(t)
}

func (w *quicConn) SetReadDeadline(t time.Time) error {
	return w.Orig.SetReadDeadline(t)
}

func (w *quicConn) SetWriteDeadline(t time.Time) error {
	return w.Orig.SetWriteDeadline(t)
}

type UDPConn interface {
	ReadFrom() ([]byte, string, error)
	WriteTo([]byte, string) error
	Close() error
}

type quicPktConn struct {
	Session      quic.Session
	Stream       quic.Stream
	CloseFunc    func()
	UDPSessionID uint32
	MsgCh        <-chan *udpMessage
}

func (c *quicPktConn) Hold() {
	// Hold the stream until it's closed
	buf := make([]byte, 1024)
	for {
		_, err := c.Stream.Read(buf)
		if err != nil {
			break
		}
	}
	_ = c.Close()
}

func (c *quicPktConn) ReadFrom() ([]byte, string, error) {
	msg := <-c.MsgCh
	if msg == nil {
		// Closed
		return nil, "", ErrClosed
	}
	return msg.Data, net.JoinHostPort(msg.Host, strconv.Itoa(int(msg.Port))), nil
}

func (c *quicPktConn) WriteTo(p []byte, addr string) error {
	host, port, err := utils.SplitHostPort(addr)
	if err != nil {
		return err
	}
	var msgBuf bytes.Buffer
	_ = struc.Pack(&msgBuf, &udpMessage{
		SessionID: c.UDPSessionID,
		Host:      host,
		Port:      port,
		Data:      p,
	})
	return c.Session.SendMessage(msgBuf.Bytes())
}

func (c *quicPktConn) Close() error {
	c.CloseFunc()
	return c.Stream.Close()
}
