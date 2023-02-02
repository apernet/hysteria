package cs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/apernet/hysteria/core/congestion"

	"github.com/apernet/hysteria/core/acl"
	"github.com/apernet/hysteria/core/pmtud"
	"github.com/apernet/hysteria/core/transport"
	"github.com/lunixbochs/struc"
	"github.com/quic-go/quic-go"
)

type (
	ConnectFunc    func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string)
	DisconnectFunc func(addr net.Addr, auth []byte, err error)
	TCPRequestFunc func(addr net.Addr, auth []byte, reqAddr string, action acl.Action, arg string)
	TCPErrorFunc   func(addr net.Addr, auth []byte, reqAddr string, err error)
	UDPRequestFunc func(addr net.Addr, auth []byte, sessionID uint32)
	UDPErrorFunc   func(addr net.Addr, auth []byte, sessionID uint32, err error)
)

type TrafficCounter interface {
	Rx(auth string, n int)
	Tx(auth string, n int)
	IncConn(auth string) // increase connection count
	DecConn(auth string) // decrease connection count
}

type Server struct {
	transport        *transport.ServerTransport
	sendBPS, recvBPS uint64
	disableUDP       bool
	aclEngine        *acl.Engine

	connectFunc    ConnectFunc
	disconnectFunc DisconnectFunc
	tcpRequestFunc TCPRequestFunc
	tcpErrorFunc   TCPErrorFunc
	udpRequestFunc UDPRequestFunc
	udpErrorFunc   UDPErrorFunc

	trafficCounter TrafficCounter

	pktConn  net.PacketConn
	listener quic.Listener
}

func NewServer(tlsConfig *tls.Config, quicConfig *quic.Config,
	pktConn net.PacketConn, transport *transport.ServerTransport,
	sendBPS uint64, recvBPS uint64, disableUDP bool, aclEngine *acl.Engine,
	connectFunc ConnectFunc, disconnectFunc DisconnectFunc,
	tcpRequestFunc TCPRequestFunc, tcpErrorFunc TCPErrorFunc,
	udpRequestFunc UDPRequestFunc, udpErrorFunc UDPErrorFunc,
	trafficCounter TrafficCounter,
) (*Server, error) {
	quicConfig.DisablePathMTUDiscovery = quicConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery
	listener, err := quic.Listen(pktConn, tlsConfig, quicConfig)
	if err != nil {
		_ = pktConn.Close()
		return nil, err
	}
	s := &Server{
		pktConn:        pktConn,
		listener:       listener,
		transport:      transport,
		sendBPS:        sendBPS,
		recvBPS:        recvBPS,
		disableUDP:     disableUDP,
		aclEngine:      aclEngine,
		connectFunc:    connectFunc,
		disconnectFunc: disconnectFunc,
		tcpRequestFunc: tcpRequestFunc,
		tcpErrorFunc:   tcpErrorFunc,
		udpRequestFunc: udpRequestFunc,
		udpErrorFunc:   udpErrorFunc,
		trafficCounter: trafficCounter,
	}
	return s, nil
}

func (s *Server) Serve() error {
	for {
		cc, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleClient(cc)
	}
}

func (s *Server) Close() error {
	err := s.listener.Close()
	_ = s.pktConn.Close()
	return err
}

func (s *Server) handleClient(cc quic.Connection) {
	// Expect the client to create a control stream to send its own information
	ctx, ctxCancel := context.WithTimeout(context.Background(), protocolTimeout)
	stream, err := cc.AcceptStream(ctx)
	ctxCancel()
	if err != nil {
		_ = qErrorProtocol.Send(cc)
		return
	}
	// Handle the control stream
	auth, ok, err := s.handleControlStream(cc, stream)
	if err != nil {
		_ = qErrorProtocol.Send(cc)
		return
	}
	if !ok {
		_ = qErrorAuth.Send(cc)
		return
	}
	// Start accepting streams and messages
	sc := newServerClient(cc, s.transport, auth, s.disableUDP, s.aclEngine,
		s.tcpRequestFunc, s.tcpErrorFunc, s.udpRequestFunc, s.udpErrorFunc,
		s.trafficCounter)
	err = sc.Run()
	_ = qErrorGeneric.Send(cc)
	s.disconnectFunc(cc.RemoteAddr(), auth, err)
}

// Auth & negotiate speed
func (s *Server) handleControlStream(cc quic.Connection, stream quic.Stream) ([]byte, bool, error) {
	// Check version
	vb := make([]byte, 1)
	_, err := stream.Read(vb)
	if err != nil {
		return nil, false, err
	}
	if vb[0] != protocolVersion {
		return nil, false, fmt.Errorf("unsupported protocol version %d, expecting %d", vb[0], protocolVersion)
	}
	// Parse client hello
	var ch clientHello
	err = struc.Unpack(stream, &ch)
	if err != nil {
		return nil, false, err
	}
	// Speed
	if ch.Rate.SendBPS == 0 || ch.Rate.RecvBPS == 0 {
		return nil, false, errors.New("invalid rate from client")
	}
	serverSendBPS, serverRecvBPS := ch.Rate.RecvBPS, ch.Rate.SendBPS
	if s.sendBPS > 0 && serverSendBPS > s.sendBPS {
		serverSendBPS = s.sendBPS
	}
	if s.recvBPS > 0 && serverRecvBPS > s.recvBPS {
		serverRecvBPS = s.recvBPS
	}
	// Auth
	ok, msg := s.connectFunc(cc.RemoteAddr(), ch.Auth, serverSendBPS, serverRecvBPS)
	// Response
	err = struc.Pack(stream, &serverHello{
		OK: ok,
		Rate: maxRate{
			SendBPS: serverSendBPS,
			RecvBPS: serverRecvBPS,
		},
		Message: msg,
	})
	if err != nil {
		return nil, false, err
	}
	// Set the congestion accordingly
	if ok {
		cc.SetCongestionControl(congestion.NewBrutalSender(serverSendBPS))
	}
	return ch.Auth, ok, nil
}
