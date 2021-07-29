package core

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/lunixbochs/struc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tobyxdd/hysteria/pkg/acl"
	transport2 "github.com/tobyxdd/hysteria/pkg/transport"
	"net"
)

type AuthFunc func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string)
type TCPRequestFunc func(addr net.Addr, auth []byte, reqAddr string, action acl.Action, arg string)
type TCPErrorFunc func(addr net.Addr, auth []byte, reqAddr string, err error)
type UDPRequestFunc func(addr net.Addr, auth []byte, sessionID uint32)
type UDPErrorFunc func(addr net.Addr, auth []byte, sessionID uint32, err error)

type Server struct {
	transport         transport2.Transport
	sendBPS, recvBPS  uint64
	congestionFactory CongestionFactory
	disableUDP        bool
	aclEngine         *acl.Engine

	authFunc       AuthFunc
	tcpRequestFunc TCPRequestFunc
	tcpErrorFunc   TCPErrorFunc
	udpRequestFunc UDPRequestFunc
	udpErrorFunc   UDPErrorFunc

	upCounterVec, downCounterVec *prometheus.CounterVec
	connGaugeVec                 *prometheus.GaugeVec

	listener quic.Listener
}

func NewServer(addr string, tlsConfig *tls.Config, quicConfig *quic.Config, transport transport2.Transport,
	sendBPS uint64, recvBPS uint64, congestionFactory CongestionFactory, disableUDP bool, aclEngine *acl.Engine,
	obfuscator Obfuscator, authFunc AuthFunc, tcpRequestFunc TCPRequestFunc, tcpErrorFunc TCPErrorFunc,
	udpRequestFunc UDPRequestFunc, udpErrorFunc UDPErrorFunc, promRegistry *prometheus.Registry) (*Server, error) {
	udpAddr, err := transport.QUICResolveUDPAddr(addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := transport.QUICListenUDP(udpAddr)
	if err != nil {
		return nil, err
	}
	var listener quic.Listener
	if obfuscator != nil {
		// Wrap PacketConn with obfuscator
		listener, err = quic.Listen(&obfsUDPConn{
			Orig:       udpConn,
			Obfuscator: obfuscator,
		}, tlsConfig, quicConfig)
		if err != nil {
			_ = udpConn.Close()
			return nil, err
		}
	} else {
		listener, err = quic.Listen(udpConn, tlsConfig, quicConfig)
		if err != nil {
			_ = udpConn.Close()
			return nil, err
		}
	}
	s := &Server{
		listener:          listener,
		transport:         transport,
		sendBPS:           sendBPS,
		recvBPS:           recvBPS,
		congestionFactory: congestionFactory,
		disableUDP:        disableUDP,
		aclEngine:         aclEngine,
		authFunc:          authFunc,
		tcpRequestFunc:    tcpRequestFunc,
		tcpErrorFunc:      tcpErrorFunc,
		udpRequestFunc:    udpRequestFunc,
		udpErrorFunc:      udpErrorFunc,
	}
	if promRegistry != nil {
		s.upCounterVec = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hysteria_traffic_uplink_bytes_total",
		}, []string{"auth"})
		s.downCounterVec = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hysteria_traffic_downlink_bytes_total",
		}, []string{"auth"})
		s.connGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hysteria_active_conn",
		}, []string{"auth"})
		promRegistry.MustRegister(s.upCounterVec, s.downCounterVec, s.connGaugeVec)
	}
	return s, nil
}

func (s *Server) Serve() error {
	for {
		cs, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleClient(cs)
	}
}

func (s *Server) Close() error {
	return s.listener.Close()
}

func (s *Server) handleClient(cs quic.Session) {
	// Expect the client to create a control stream to send its own information
	ctx, ctxCancel := context.WithTimeout(context.Background(), protocolTimeout)
	stream, err := cs.AcceptStream(ctx)
	ctxCancel()
	if err != nil {
		_ = cs.CloseWithError(closeErrorCodeProtocol, "protocol error")
		return
	}
	// Handle the control stream
	auth, ok, err := s.handleControlStream(cs, stream)
	if err != nil {
		_ = cs.CloseWithError(closeErrorCodeProtocol, "protocol error")
		return
	}
	if !ok {
		_ = cs.CloseWithError(closeErrorCodeAuth, "auth error")
		return
	}
	// Start accepting streams and messages
	sc := newServerClient(cs, s.transport, auth, s.disableUDP, s.aclEngine,
		s.tcpRequestFunc, s.tcpErrorFunc, s.udpRequestFunc, s.udpErrorFunc,
		s.upCounterVec, s.downCounterVec, s.connGaugeVec)
	sc.Run()
	_ = cs.CloseWithError(closeErrorCodeGeneric, "")
}

// Auth & negotiate speed
func (s *Server) handleControlStream(cs quic.Session, stream quic.Stream) ([]byte, bool, error) {
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
	ok, msg := s.authFunc(cs.RemoteAddr(), ch.Auth, serverSendBPS, serverRecvBPS)
	// Response
	err = struc.Pack(stream, &serverHello{
		OK: ok,
		Rate: transmissionRate{
			SendBPS: serverSendBPS,
			RecvBPS: serverRecvBPS,
		},
		Message: msg,
	})
	if err != nil {
		return nil, false, err
	}
	// Set the congestion accordingly
	if ok && s.congestionFactory != nil {
		cs.SetCongestionControl(s.congestionFactory(serverSendBPS))
	}
	return ch.Auth, ok, nil
}
