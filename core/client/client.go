package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	coreErrs "github.com/apernet/hysteria/core/errors"
	"github.com/apernet/hysteria/core/internal/congestion"
	"github.com/apernet/hysteria/core/internal/protocol"
	"github.com/apernet/hysteria/core/internal/utils"
	"github.com/apernet/hysteria/extras/outbounds"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type Client interface {
	TCP(addr string) (net.Conn, error)
	UDP() (UDPConn, error)
	Config() *Config
	Outbound() *Hy2ClientOutbound
	Close() error
}

type HandshakeInfo struct {
	UDPEnabled bool
	Tx         uint64 // 0 if using BBR
}

func NewClient(config *Config) (Client, *HandshakeInfo, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, nil, err
	}
	c := &ClientImpl{
		Hy2ClientOutbound{
			config: config,
		},
	}
	info, err := c.connect()
	if err != nil {
		return nil, nil, err
	}
	return c, info, nil
}

type Hy2ClientOutbound struct {
	config *Config

	pktConn net.PacketConn
	conn    quic.Connection

	udpSM *udpSessionManager
}

func (ob *Hy2ClientOutbound) connect() (*HandshakeInfo, error) {
	pktConn, err := ob.config.ConnFactory.New(ob.config.ServerAddr)
	if err != nil {
		return nil, err
	}
	// Convert config to TLS config & QUIC config
	tlsConfig := &tls.Config{
		ServerName:            ob.config.TLSConfig.ServerName,
		InsecureSkipVerify:    ob.config.TLSConfig.InsecureSkipVerify,
		VerifyPeerCertificate: ob.config.TLSConfig.VerifyPeerCertificate,
		RootCAs:               ob.config.TLSConfig.RootCAs,
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     ob.config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         ob.config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: ob.config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     ob.config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 ob.config.QUICConfig.MaxIdleTimeout,
		KeepAlivePeriod:                ob.config.QUICConfig.KeepAlivePeriod,
		DisablePathMTUDiscovery:        ob.config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
	}
	// Prepare RoundTripper
	var conn quic.EarlyConnection
	rt := &http3.RoundTripper{
		EnableDatagrams: true,
		TLSClientConfig: tlsConfig,
		QuicConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialEarly(ctx, pktConn, ob.config.ServerAddr, tlsCfg, cfg)
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
	protocol.AuthRequestToHeader(req.Header, protocol.AuthRequest{
		Auth: ob.config.Auth,
		Rx:   ob.config.BandwidthConfig.MaxRx,
	})
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return nil, coreErrs.ConnectError{Err: err}
	}
	if resp.StatusCode != protocol.StatusAuthOK {
		_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		_ = pktConn.Close()
		return nil, coreErrs.AuthError{StatusCode: resp.StatusCode}
	}
	// Auth OK
	authResp := protocol.AuthResponseFromHeader(resp.Header)
	var actualTx uint64
	if authResp.RxAuto {
		// Server asks client to use bandwidth detection,
		// ignore local bandwidth config and use BBR
		congestion.UseBBR(conn)
	} else {
		// actualTx = min(serverRx, clientTx)
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > ob.config.BandwidthConfig.MaxTx {
			// Server doesn't have a limit, or our clientTx is smaller than serverRx
			actualTx = ob.config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			congestion.UseBrutal(conn, actualTx)
		} else {
			// We don't know our own bandwidth either, use BBR
			congestion.UseBBR(conn)
		}
	}
	_ = resp.Body.Close()

	if ob.config.Outbound == nil {
		var uOb outbounds.PluggableOutbound // "unified" outbound

		for n, entry := range ob.config.Outbounds {
			if entry.Outbound == nil {
				ob.config.Outbounds[n].Outbound = ob
			}
		}

		// we use the first entry of the outbound by default
		uOb = ob.config.Outbounds[0].Outbound

		// ACL
		if ob.config.ACLs != "" {
			acl, err := outbounds.NewACLEngineFromString(ob.config.ACLs, ob.config.Outbounds, ob.config.GeoLoader)
			if err == nil {
				uOb = acl
			} else {
				panic(err)
			}
		}

		ob.config.Outbound = &PluggableClientOutboundAdapter{PluggableOutbound: uOb}
	}

	ob.pktConn = pktConn
	ob.conn = conn
	if authResp.UDPEnabled {
		ob.udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn})
	}
	return &HandshakeInfo{
		UDPEnabled: authResp.UDPEnabled,
		Tx:         actualTx,
	}, nil
}

// openStream wraps the stream with QStream, which handles Close() properly
func (ob *Hy2ClientOutbound) openStream() (quic.Stream, error) {
	stream, err := ob.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &utils.QStream{Stream: stream}, nil
}

func (ob *Hy2ClientOutbound) TCP(reqAddr *outbounds.AddrEx) (net.Conn, error) {
	stream, err := ob.openStream()
	if err != nil {
		return nil, wrapIfConnectionClosed(err)
	}
	// Send request
	err = protocol.WriteTCPRequest(stream, reqAddr.String())
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if ob.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  ob.conn.LocalAddr(),
			PseudoRemoteAddr: ob.conn.RemoteAddr(),
			Established:      false,
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, wrapIfConnectionClosed(err)
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: msg}
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  ob.conn.LocalAddr(),
		PseudoRemoteAddr: ob.conn.RemoteAddr(),
		Established:      true,
	}, nil
}

func (ob *Hy2ClientOutbound) UDP(reqAddr *outbounds.AddrEx) (outbounds.UDPConn, error) {
	if ob.udpSM == nil {
		return nil, coreErrs.DialError{Message: "UDP not enabled"}
	}
	return ob.udpSM.NewUDP()
}

func (ob *Hy2ClientOutbound) Close() error {
	_ = ob.conn.CloseWithError(closeErrCodeOK, "")
	_ = ob.pktConn.Close()
	return nil
}

type ClientImpl struct {
	ob Hy2ClientOutbound
}

// Outbound implements Client.
func (c *ClientImpl) Outbound() *Hy2ClientOutbound {
	return &c.ob
}

func (c *ClientImpl) connect() (*HandshakeInfo, error) {
	return c.ob.connect()
}

func (c *ClientImpl) Config() *Config {
	return c.ob.config
}

func (c *ClientImpl) TCP(addr string) (net.Conn, error) {
	return c.ob.config.Outbound.TCP(addr)
}

func (c *ClientImpl) UDP() (UDPConn, error) {
	return c.ob.config.Outbound.UDP("localhost:0")
}

func (c *ClientImpl) Close() error {
	return c.ob.Close()
}

// wrapIfConnectionClosed checks if the error returned by quic-go
// indicates that the QUIC connection has been permanently closed,
// and if so, wraps the error with coreErrs.ClosedError.
// PITFALL: sometimes quic-go has "internal errors" that are not net.Error,
// but we still need to treat them as ClosedError.
func wrapIfConnectionClosed(err error) error {
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Temporary() {
		return coreErrs.ClosedError{Err: err}
	} else {
		return err
	}
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

type udpIOImpl struct {
	Conn quic.Connection
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		msg, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			// Connection error, this will stop the session manager
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msg)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	return io.Conn.SendDatagram(buf[:msgN])
}
