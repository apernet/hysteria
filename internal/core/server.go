package core

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/tobyxdd/hysteria/internal/utils"
	"io"
	"net"
	"sync/atomic"
)

type ClientAuthFunc func(addr net.Addr, username string, password string, sSend uint64, sRecv uint64) (AuthResult, string)
type ClientDisconnectedFunc func(addr net.Addr, username string, err error)
type HandleRequestFunc func(addr net.Addr, username string, id int, reqType ConnectionType, reqAddr string) (ConnectResult, string, io.ReadWriteCloser)
type RequestClosedFunc func(addr net.Addr, username string, id int, reqType ConnectionType, reqAddr string, err error)

type Server struct {
	inboundBytes, outboundBytes uint64 // atomic

	listener         quic.Listener
	sendBPS, recvBPS uint64

	congestionFactory      CongestionFactory
	clientAuthFunc         ClientAuthFunc
	clientDisconnectedFunc ClientDisconnectedFunc
	handleRequestFunc      HandleRequestFunc
	requestClosedFunc      RequestClosedFunc
}

func NewServer(addr string, tlsConfig *tls.Config, quicConfig *quic.Config,
	sendBPS uint64, recvBPS uint64, congestionFactory CongestionFactory,
	clientAuthFunc ClientAuthFunc,
	clientDisconnectedFunc ClientDisconnectedFunc,
	handleRequestFunc HandleRequestFunc,
	requestClosedFunc RequestClosedFunc) (*Server, error) {
	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}
	s := &Server{
		listener:               listener,
		sendBPS:                sendBPS,
		recvBPS:                recvBPS,
		congestionFactory:      congestionFactory,
		clientAuthFunc:         clientAuthFunc,
		clientDisconnectedFunc: clientDisconnectedFunc,
		handleRequestFunc:      handleRequestFunc,
		requestClosedFunc:      requestClosedFunc,
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

func (s *Server) Stats() (uint64, uint64) {
	return atomic.LoadUint64(&s.inboundBytes), atomic.LoadUint64(&s.outboundBytes)
}

func (s *Server) Close() error {
	return s.listener.Close()
}

func (s *Server) handleClient(cs quic.Session) {
	// Expect the client to create a control stream to send its own information
	ctx, ctxCancel := context.WithTimeout(context.Background(), controlStreamTimeout)
	ctlStream, err := cs.AcceptStream(ctx)
	ctxCancel()
	if err != nil {
		_ = cs.CloseWithError(closeErrorCodeProtocolFailure, "control stream error")
		return
	}
	// Handle the control stream
	username, ok, err := s.handleControlStream(cs, ctlStream)
	if err != nil {
		_ = cs.CloseWithError(closeErrorCodeProtocolFailure, "control stream handling error")
		return
	}
	if !ok {
		_ = cs.CloseWithError(closeErrorCodeGeneric, "authentication failure")
		return
	}
	// Start accepting streams
	var closeErr error
	for {
		stream, err := cs.AcceptStream(context.Background())
		if err != nil {
			closeErr = err
			break
		}
		go s.handleStream(cs.RemoteAddr(), username, stream)
	}
	s.clientDisconnectedFunc(cs.RemoteAddr(), username, closeErr)
	_ = cs.CloseWithError(closeErrorCodeGeneric, "generic")
}

// Auth & negotiate speed
func (s *Server) handleControlStream(cs quic.Session, stream quic.Stream) (string, bool, error) {
	req, err := readClientAuthRequest(stream)
	if err != nil {
		return "", false, err
	}
	// Speed
	if req.Speed == nil || req.Speed.SendBps == 0 || req.Speed.ReceiveBps == 0 {
		return "", false, errors.New("incorrect speed provided by the client")
	}
	serverSendBPS, serverReceiveBPS := req.Speed.ReceiveBps, req.Speed.SendBps
	if s.sendBPS > 0 && serverSendBPS > s.sendBPS {
		serverSendBPS = s.sendBPS
	}
	if s.recvBPS > 0 && serverReceiveBPS > s.recvBPS {
		serverReceiveBPS = s.recvBPS
	}
	// Auth
	if req.Credential == nil {
		return "", false, errors.New("incorrect credential provided by the client")
	}
	authResult, msg := s.clientAuthFunc(cs.RemoteAddr(), req.Credential.Username, req.Credential.Password,
		serverSendBPS, serverReceiveBPS)
	// Response
	err = writeServerAuthResponse(stream, &ServerAuthResponse{
		Result:  authResult,
		Message: msg,
		Speed: &Speed{
			SendBps:    serverSendBPS,
			ReceiveBps: serverReceiveBPS,
		},
	})
	if err != nil {
		return "", false, err
	}
	// Set the congestion accordingly
	if authResult == AuthResult_AUTH_SUCCESS && s.congestionFactory != nil {
		cs.SetCongestion(s.congestionFactory(serverSendBPS))
	}
	return req.Credential.Username, authResult == AuthResult_AUTH_SUCCESS, nil
}

func (s *Server) handleStream(addr net.Addr, username string, stream quic.Stream) {
	defer stream.Close()
	// Read request
	req, err := readClientConnectRequest(stream)
	if err != nil {
		return
	}
	// Create connection with the handler
	result, msg, conn := s.handleRequestFunc(addr, username, int(stream.StreamID()), req.Type, req.Address)
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	// Send response
	err = writeServerConnectResponse(stream, &ServerConnectResponse{
		Result:  result,
		Message: msg,
	})
	if err != nil {
		s.requestClosedFunc(addr, username, int(stream.StreamID()), req.Type, req.Address, err)
		return
	}
	if result != ConnectResult_CONN_SUCCESS {
		s.requestClosedFunc(addr, username, int(stream.StreamID()), req.Type, req.Address,
			fmt.Errorf("handler returned an unsuccessful state %s (msg: %s)", result.String(), msg))
		return
	}
	switch req.Type {
	case ConnectionType_TCP:
		err = s.pipePair(stream, conn)
	case ConnectionType_UDP:
		err = s.pipePair(&utils.PacketReadWriteCloser{Orig: stream}, conn)
	default:
		err = fmt.Errorf("unsupported connection type %s", req.Type.String())
	}
	s.requestClosedFunc(addr, username, int(stream.StreamID()), req.Type, req.Address, err)
}

func (s *Server) pipePair(rw1, rw2 io.ReadWriter) error {
	// Pipes
	errChan := make(chan error, 2)
	go func() {
		errChan <- utils.Pipe(rw2, rw1, &s.outboundBytes)
	}()
	go func() {
		errChan <- utils.Pipe(rw1, rw2, &s.inboundBytes)
	}()
	// We only need the first error
	return <-errChan
}
