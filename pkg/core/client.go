package core

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/tobyxdd/hysteria/pkg/core/pb"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"sync"
	"sync/atomic"
)

var (
	ErrClosed = errors.New("client closed")
)

type Client struct {
	inboundBytes, outboundBytes uint64 // atomic

	reconnectMutex     sync.Mutex
	closed             bool
	quicSession        quic.Session
	serverAddr         string
	username, password string
	tlsConfig          *tls.Config
	quicConfig         *quic.Config
	sendBPS, recvBPS   uint64
	congestionFactory  CongestionFactory
	obfuscator         Obfuscator
}

func NewClient(serverAddr string, username string, password string, tlsConfig *tls.Config, quicConfig *quic.Config,
	sendBPS uint64, recvBPS uint64, congestionFactory CongestionFactory, obfuscator Obfuscator) (*Client, error) {
	c := &Client{
		serverAddr:        serverAddr,
		username:          username,
		password:          password,
		tlsConfig:         tlsConfig,
		quicConfig:        quicConfig,
		sendBPS:           sendBPS,
		recvBPS:           recvBPS,
		congestionFactory: congestionFactory,
		obfuscator:        obfuscator,
	}
	if err := c.connectToServer(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) Dial(packet bool, addr string) (net.Conn, error) {
	stream, localAddr, remoteAddr, err := c.openStreamWithReconnect()
	if err != nil {
		return nil, err
	}
	// Send request
	req := &pb.ClientConnectRequest{Address: addr}
	if packet {
		req.Type = pb.ConnectionType_Packet
	} else {
		req.Type = pb.ConnectionType_Stream
	}
	err = writeClientConnectRequest(stream, req)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	// Read response
	resp, err := readServerConnectResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if resp.Result != pb.ConnectResult_CONN_SUCCESS {
		_ = stream.Close()
		return nil, fmt.Errorf("server rejected the connection %s (msg: %s)",
			resp.Result.String(), resp.Message)
	}
	connWrap := &utils.QUICStreamWrapperConn{
		Orig:             stream,
		PseudoLocalAddr:  localAddr,
		PseudoRemoteAddr: remoteAddr,
	}
	if packet {
		return &utils.PacketWrapperConn{Orig: connWrap}, nil
	} else {
		return connWrap, nil
	}
}

func (c *Client) Stats() (uint64, uint64) {
	return atomic.LoadUint64(&c.inboundBytes), atomic.LoadUint64(&c.outboundBytes)
}

func (c *Client) Close() error {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	err := c.quicSession.CloseWithError(closeErrorCodeGeneric, "generic")
	c.closed = true
	return err
}

func (c *Client) connectToServer() error {
	serverUDPAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return err
	}
	packetConn, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	if c.obfuscator != nil {
		// Wrap PacketConn with obfuscator
		packetConn = &obfsPacketConn{
			Orig:       packetConn,
			Obfuscator: c.obfuscator,
		}
	}
	qs, err := quic.Dial(packetConn, serverUDPAddr, c.serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		return err
	}
	// Control stream
	ctx, ctxCancel := context.WithTimeout(context.Background(), controlStreamTimeout)
	ctlStream, err := qs.OpenStreamSync(ctx)
	ctxCancel()
	if err != nil {
		_ = qs.CloseWithError(closeErrorCodeProtocolFailure, "control stream error")
		return err
	}
	result, msg, err := c.handleControlStream(qs, ctlStream)
	if err != nil {
		_ = qs.CloseWithError(closeErrorCodeProtocolFailure, "control stream handling error")
		return err
	}
	if result != pb.AuthResult_AUTH_SUCCESS {
		_ = qs.CloseWithError(closeErrorCodeProtocolFailure, "authentication failure")
		return fmt.Errorf("authentication failure %s (msg: %s)", result.String(), msg)
	}
	// All good
	c.quicSession = qs
	return nil
}

func (c *Client) handleControlStream(qs quic.Session, stream quic.Stream) (pb.AuthResult, string, error) {
	err := writeClientAuthRequest(stream, &pb.ClientAuthRequest{
		Credential: &pb.Credential{
			Username: c.username,
			Password: c.password,
		},
		Speed: &pb.Speed{
			SendBps:    c.sendBPS,
			ReceiveBps: c.recvBPS,
		},
	})
	if err != nil {
		return 0, "", err
	}
	// Response
	resp, err := readServerAuthResponse(stream)
	if err != nil {
		return 0, "", err
	}
	// Set the congestion accordingly
	if resp.Result == pb.AuthResult_AUTH_SUCCESS && c.congestionFactory != nil {
		qs.SetCongestion(c.congestionFactory(resp.Speed.ReceiveBps))
	}
	return resp.Result, resp.Message, nil
}

func (c *Client) openStreamWithReconnect() (quic.Stream, net.Addr, net.Addr, error) {
	c.reconnectMutex.Lock()
	defer c.reconnectMutex.Unlock()
	if c.closed {
		return nil, nil, nil, ErrClosed
	}
	stream, err := c.quicSession.OpenStream()
	if err == nil {
		// All good
		return stream, c.quicSession.LocalAddr(), c.quicSession.RemoteAddr(), nil
	}
	// Something is wrong
	if nErr, ok := err.(net.Error); ok && nErr.Temporary() {
		// Temporary error, just return
		return nil, nil, nil, err
	}
	// Permanent error, need to reconnect
	if err := c.connectToServer(); err != nil {
		// Still error, oops
		return nil, nil, nil, err
	}
	// We are not going to try again even if it still fails the second time
	stream, err = c.quicSession.OpenStream()
	return stream, c.quicSession.LocalAddr(), c.quicSession.RemoteAddr(), err
}
