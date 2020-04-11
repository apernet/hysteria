package forwarder

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/lucas-clemente/quic-go"
	"github.com/tobyxdd/hysteria/internal/utils"
	"net"
	"sync/atomic"
)

type QUICServer struct {
	inboundBytes, outboundBytes uint64 // atomic

	listener         quic.Listener
	remoteAddr       string
	banner           string
	sendBPS, recvBPS uint64

	newCongestion        CongestionFactory
	onClientConnected    ClientConnectedCallback
	onClientDisconnected ClientDisconnectedCallback
	onClientNewStream    ClientNewStreamCallback
	onClientStreamClosed ClientStreamClosedCallback
	onTCPError           TCPErrorCallback
}

func NewQUICServer(addr string, remoteAddr string, banner string, tlsConfig *tls.Config,
	sendBPS uint64, recvBPS uint64, recvWindowConn uint64, recvWindowClients uint64,
	clientMaxConn int, newCongestion CongestionFactory,
	onClientConnected ClientConnectedCallback,
	onClientDisconnected ClientDisconnectedCallback,
	onClientNewStream ClientNewStreamCallback,
	onClientStreamClosed ClientStreamClosedCallback,
	onTCPError TCPErrorCallback) (*QUICServer, error) {
	listener, err := quic.ListenAddr(addr, tlsConfig, &quic.Config{
		MaxReceiveStreamFlowControlWindow:     recvWindowConn,
		MaxReceiveConnectionFlowControlWindow: recvWindowClients,
		MaxIncomingStreams:                    clientMaxConn,
		KeepAlive:                             true,
	})
	if err != nil {
		return nil, err
	}
	s := &QUICServer{
		listener:             listener,
		remoteAddr:           remoteAddr,
		banner:               banner,
		sendBPS:              sendBPS,
		recvBPS:              recvBPS,
		newCongestion:        newCongestion,
		onClientConnected:    onClientConnected,
		onClientDisconnected: onClientDisconnected,
		onClientNewStream:    onClientNewStream,
		onClientStreamClosed: onClientStreamClosed,
		onTCPError:           onTCPError,
	}
	go s.acceptLoop()
	return s, nil
}

func (s *QUICServer) Close() error {
	return s.listener.Close()
}

func (s *QUICServer) Stats() (string, uint64, uint64) {
	return s.remoteAddr, atomic.LoadUint64(&s.inboundBytes), atomic.LoadUint64(&s.outboundBytes)
}

func (s *QUICServer) acceptLoop() {
	for {
		cs, err := s.listener.Accept(context.Background())
		if err != nil {
			break
		}
		go s.handleClient(cs)
	}
}

func (s *QUICServer) handleClient(cs quic.Session) {
	// Expect the client to create a control stream and send its own information
	ctx, ctxCancel := context.WithTimeout(context.Background(), controlStreamTimeout)
	ctlStream, err := cs.AcceptStream(ctx)
	ctxCancel()
	if err != nil {
		_ = cs.CloseWithError(closeErrorCodeProtocolFailure, "control stream error")
		return
	}
	name, sSend, sRecv, err := s.handleControlStream(cs, ctlStream)
	if err != nil {
		_ = cs.CloseWithError(closeErrorCodeProtocolFailure, "control stream handling error")
		return
	}
	// Only after a successful exchange of information do we consider this a valid client
	s.onClientConnected(cs.RemoteAddr(), name, sSend, sRecv)
	// Start accepting streams to be forwarded
	var closeErr error
	for {
		stream, err := cs.AcceptStream(context.Background())
		if err != nil {
			closeErr = err
			break
		}
		go s.handleStream(cs.RemoteAddr(), name, stream)
	}
	s.onClientDisconnected(cs.RemoteAddr(), name, closeErr)
	_ = cs.CloseWithError(closeErrorCodeGeneric, "generic")
}

// Negotiate speed & return client name
func (s *QUICServer) handleControlStream(cs quic.Session, stream quic.Stream) (string, uint64, uint64, error) {
	req, err := readClientSpeedRequest(stream)
	if err != nil {
		return "", 0, 0, err
	}
	if req.Speed == nil || req.Speed.SendBps == 0 || req.Speed.ReceiveBps == 0 {
		return "", 0, 0, errors.New("incorrect speed information provided by the client")
	}
	limited := false
	serverSendBPS, serverReceiveBPS := req.Speed.ReceiveBps, req.Speed.SendBps
	if s.sendBPS > 0 && serverSendBPS > s.sendBPS {
		limited = true
		serverSendBPS = s.sendBPS
	}
	if s.recvBPS > 0 && serverReceiveBPS > s.recvBPS {
		limited = true
		serverReceiveBPS = s.recvBPS
	}
	// Response
	err = writeServerSpeedResponse(stream, &ServerSpeedResponse{
		Banner:  s.banner,
		Limited: limited,
		Limit: &Speed{
			SendBps:    s.sendBPS,
			ReceiveBps: s.recvBPS,
		},
		Speed: &Speed{
			SendBps:    serverSendBPS,
			ReceiveBps: serverReceiveBPS,
		},
	})
	if err != nil {
		return "", 0, 0, err
	}
	// Set the congestion accordingly
	if s.newCongestion != nil {
		cs.SetCongestion(s.newCongestion(serverSendBPS))
	}
	return req.Name, serverSendBPS, serverReceiveBPS, nil
}

func (s *QUICServer) handleStream(addr net.Addr, name string, stream quic.Stream) {
	s.onClientNewStream(addr, name, int(stream.StreamID()))
	defer stream.Close()
	tcpConn, err := net.Dial("tcp", s.remoteAddr)
	if err != nil {
		s.onTCPError(s.remoteAddr, err)
		s.onClientStreamClosed(addr, name, int(stream.StreamID()), err)
		return
	}
	defer tcpConn.Close()
	// Pipes
	errChan := make(chan error, 2)
	go func() {
		// TCP to QUIC
		errChan <- utils.Pipe(tcpConn, stream, &s.outboundBytes)
	}()
	go func() {
		// QUIC to TCP
		errChan <- utils.Pipe(stream, tcpConn, &s.inboundBytes)
	}()
	// We only need the first error
	err = <-errChan
	s.onClientStreamClosed(addr, name, int(stream.StreamID()), err)
}
