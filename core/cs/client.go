package cs

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/pktconns"

	"github.com/apernet/hysteria/core/congestion"

	"github.com/apernet/hysteria/core/pmtud"
	"github.com/apernet/hysteria/core/utils"
	"github.com/lunixbochs/struc"
	"github.com/quic-go/quic-go"
)

var ErrClosed = errors.New("closed")

type Client struct {
	serverAddr string

	sendBPS, recvBPS uint64
	auth             []byte
	fastOpen         bool

	tlsConfig  *tls.Config
	quicConfig *quic.Config

	pktConnFunc pktconns.ClientPacketConnFunc

	reconnectMutex sync.Mutex
	pktConn        net.PacketConn
	quicConn       quic.Connection
	closed         bool

	udpSessionMutex sync.RWMutex
	udpSessionMap   map[uint32]chan *udpMessage
	udpDefragger    defragger

	quicReconnectFunc func(err error)
}

func NewClient(serverAddr string, auth []byte, tlsConfig *tls.Config, quicConfig *quic.Config,
	pktConnFunc pktconns.ClientPacketConnFunc, sendBPS uint64, recvBPS uint64, fastOpen bool,
	quicReconnectFunc func(err error),
) (*Client, error) {
	quicConfig.DisablePathMTUDiscovery = quicConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery
	c := &Client{
		serverAddr:        serverAddr,
		sendBPS:           sendBPS,
		recvBPS:           recvBPS,
		auth:              auth,
		fastOpen:          fastOpen,
		tlsConfig:         tlsConfig,
		quicConfig:        quicConfig,
		pktConnFunc:       pktConnFunc,
		quicReconnectFunc: quicReconnectFunc,
	}
	if err := c.connect(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) connect() error {
	// Clear previous connection
	if c.quicConn != nil {
		_ = c.quicConn.CloseWithError(0, "")
	}
	if c.pktConn != nil {
		_ = c.pktConn.Close()
	}
	// New connection
	pktConn, sAddr, err := c.pktConnFunc(c.serverAddr)
	if err != nil {
		return err
	}
	// Dial QUIC
	quicConn, err := quic.Dial(pktConn, sAddr, c.serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		_ = pktConn.Close()
		return err
	}
	// Control stream
	ctx, ctxCancel := context.WithTimeout(context.Background(), protocolTimeout)
	stream, err := quicConn.OpenStreamSync(ctx)
	ctxCancel()
	if err != nil {
		_ = qErrorProtocol.Send(quicConn)
		_ = pktConn.Close()
		return err
	}
	ok, msg, err := c.handleControlStream(quicConn, stream)
	if err != nil {
		_ = qErrorProtocol.Send(quicConn)
		_ = pktConn.Close()
		return err
	}
	if !ok {
		_ = qErrorAuth.Send(quicConn)
		_ = pktConn.Close()
		return fmt.Errorf("auth error: %s", msg)
	}
	// All good
	c.udpSessionMap = make(map[uint32]chan *udpMessage)
	go c.handleMessage(quicConn)
	c.pktConn = pktConn
	c.quicConn = quicConn
	return nil
}

func (c *Client) handleControlStream(qc quic.Connection, stream quic.Stream) (bool, string, error) {
	// Send protocol version
	_, err := stream.Write([]byte{protocolVersion})
	if err != nil {
		return false, "", err
	}
	// Send client hello
	err = struc.Pack(stream, &clientHello{
		Rate: maxRate{
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
	if sh.OK {
		qc.SetCongestionControl(congestion.NewBrutalSender(sh.Rate.RecvBPS))
	}
	return sh.OK, sh.Message, nil
}

func (c *Client) handleMessage(qc quic.Connection) {
	for {
		msg, err := qc.ReceiveMessage()
		if err != nil {
			break
		}
		var udpMsg udpMessage
		err = struc.Unpack(bytes.NewBuffer(msg), &udpMsg)
		if err != nil {
			continue
		}
		dfMsg := c.udpDefragger.Feed(udpMsg)
		if dfMsg == nil {
			continue
		}
		c.udpSessionMutex.RLock()
		ch, ok := c.udpSessionMap[dfMsg.SessionID]
		if ok {
			select {
			case ch <- dfMsg:
				// OK
			default:
				// Silently drop the message when the channel is full
			}
		}
		c.udpSessionMutex.RUnlock()
	}
}

func (c *Client) openStreamWithReconnect() (quic.Connection, quic.Stream, error) {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	if c.closed {
		return nil, nil, ErrClosed
	}
	stream, err := c.quicConn.OpenStream()
	if err == nil {
		// All good
		return c.quicConn, &qStream{stream}, nil
	}
	// Something is wrong
	if nErr, ok := err.(net.Error); ok && nErr.Temporary() {
		// Temporary error, just return
		return nil, nil, err
	}
	if c.quicReconnectFunc != nil {
		c.quicReconnectFunc(err)
	}
	// Permanent error, need to reconnect
	if err := c.connect(); err != nil {
		// Still error, oops
		return nil, nil, err
	}
	// We are not going to try again even if it still fails the second time
	stream, err = c.quicConn.OpenStream()
	return c.quicConn, &qStream{stream}, err
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
	// If fast open is enabled, we return the stream immediately
	// and defer the response handling to the first Read() call
	if !c.fastOpen {
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
	}
	return &hyTCPConn{
		Orig:             stream,
		PseudoLocalAddr:  session.LocalAddr(),
		PseudoRemoteAddr: session.RemoteAddr(),
		Established:      !c.fastOpen,
	}, nil
}

func (c *Client) DialUDP() (HyUDPConn, error) {
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
	// to ensure that we are adding and removing sessions on the same map,
	// as reconnecting will reassign the map
	sessionMap := c.udpSessionMap
	sessionMap[sr.UDPSessionID] = nCh
	c.udpSessionMutex.Unlock()

	pktConn := &hyUDPConn{
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
	err := qErrorGeneric.Send(c.quicConn)
	_ = c.pktConn.Close()
	c.closed = true
	return err
}

// hyTCPConn wraps a QUIC stream and implements net.Conn returned by Client.DialTCP
type hyTCPConn struct {
	Orig             quic.Stream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
}

func (w *hyTCPConn) Read(b []byte) (n int, err error) {
	if !w.Established {
		var sr serverResponse
		err := struc.Unpack(w.Orig, &sr)
		if err != nil {
			_ = w.Close()
			return 0, err
		}
		if !sr.OK {
			_ = w.Close()
			return 0, fmt.Errorf("connection rejected: %s", sr.Message)
		}
		w.Established = true
	}
	return w.Orig.Read(b)
}

func (w *hyTCPConn) Write(b []byte) (n int, err error) {
	return w.Orig.Write(b)
}

func (w *hyTCPConn) Close() error {
	return w.Orig.Close()
}

func (w *hyTCPConn) LocalAddr() net.Addr {
	return w.PseudoLocalAddr
}

func (w *hyTCPConn) RemoteAddr() net.Addr {
	return w.PseudoRemoteAddr
}

func (w *hyTCPConn) SetDeadline(t time.Time) error {
	return w.Orig.SetDeadline(t)
}

func (w *hyTCPConn) SetReadDeadline(t time.Time) error {
	return w.Orig.SetReadDeadline(t)
}

func (w *hyTCPConn) SetWriteDeadline(t time.Time) error {
	return w.Orig.SetWriteDeadline(t)
}

type HyUDPConn interface {
	ReadFrom() ([]byte, string, error)
	WriteTo([]byte, string) error
	Close() error
}

type hyUDPConn struct {
	Session      quic.Connection
	Stream       quic.Stream
	CloseFunc    func()
	UDPSessionID uint32
	MsgCh        <-chan *udpMessage
}

func (c *hyUDPConn) Hold() {
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

func (c *hyUDPConn) ReadFrom() ([]byte, string, error) {
	msg := <-c.MsgCh
	if msg == nil {
		// Closed
		return nil, "", ErrClosed
	}
	return msg.Data, net.JoinHostPort(msg.Host, strconv.Itoa(int(msg.Port))), nil
}

func (c *hyUDPConn) WriteTo(p []byte, addr string) error {
	host, port, err := utils.SplitHostPort(addr)
	if err != nil {
		return err
	}
	msg := udpMessage{
		SessionID: c.UDPSessionID,
		Host:      host,
		Port:      port,
		FragCount: 1,
		Data:      p,
	}
	// try no frag first
	var msgBuf bytes.Buffer
	_ = struc.Pack(&msgBuf, &msg)
	err = c.Session.SendMessage(msgBuf.Bytes())
	if err != nil {
		if errSize, ok := err.(quic.ErrMessageTooLarge); ok {
			// need to frag
			msg.MsgID = uint16(rand.Intn(0xFFFF)) + 1 // msgID must be > 0 when fragCount > 1
			fragMsgs := fragUDPMessage(msg, int(errSize))
			for _, fragMsg := range fragMsgs {
				msgBuf.Reset()
				_ = struc.Pack(&msgBuf, &fragMsg)
				err = c.Session.SendMessage(msgBuf.Bytes())
				if err != nil {
					return err
				}
			}
			return nil
		} else {
			// some other error
			return err
		}
	} else {
		return nil
	}
}

func (c *hyUDPConn) Close() error {
	c.CloseFunc()
	return c.Stream.Close()
}
