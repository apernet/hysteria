package integration_tests

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"

	"github.com/apernet/hysteria/core/server"
)

// This file provides utilities for the integration tests.

const (
	testCertFile = "test.crt"
	testKeyFile  = "test.key"
)

func serverTLSConfig() server.TLSConfig {
	cert, err := tls.LoadX509KeyPair(testCertFile, testKeyFile)
	if err != nil {
		panic(err)
	}
	return server.TLSConfig{
		Certificates: []tls.Certificate{cert},
	}
}

type pwAuthenticator struct {
	Password string
	ID       string
}

func (a *pwAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	if auth != a.Password {
		return false, ""
	}
	return true, a.ID
}

// tcpEchoServer is a TCP server that echoes what it reads from the connection.
// It will never actively close the connection.
type tcpEchoServer struct {
	Listener net.Listener
}

func (s *tcpEchoServer) Serve() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			_, _ = io.Copy(conn, conn)
			_ = conn.Close()
		}()
	}
}

func (s *tcpEchoServer) Close() error {
	return s.Listener.Close()
}

type sinkEvent struct {
	Data []byte
	Err  error
}

// tcpSinkServer is a TCP server that reads data from the connection,
// and sends what it read to the channel when the connection is closed.
type tcpSinkServer struct {
	Listener net.Listener
	Ch       chan<- sinkEvent
}

func (s *tcpSinkServer) Serve() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			var buf bytes.Buffer
			_, err := io.Copy(&buf, conn)
			_ = conn.Close()
			s.Ch <- sinkEvent{Data: buf.Bytes(), Err: err}
		}()
	}
}

func (s *tcpSinkServer) Close() error {
	return s.Listener.Close()
}

// tcpSenderServer is a TCP server that sends data to the connection,
// and closes the connection when all data has been sent.
type tcpSenderServer struct {
	Listener net.Listener
	Data     []byte
}

func (s *tcpSenderServer) Serve() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			_, _ = conn.Write(s.Data)
			_ = conn.Close()
		}()
	}
}

func (s *tcpSenderServer) Close() error {
	return s.Listener.Close()
}

// udpEchoServer is a UDP server that echoes what it reads from the connection.
// It will never actively close the connection.
type udpEchoServer struct {
	Conn net.PacketConn
}

func (s *udpEchoServer) Serve() error {
	buf := make([]byte, 65536)
	for {
		n, addr, err := s.Conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		_, err = s.Conn.WriteTo(buf[:n], addr)
		if err != nil {
			return err
		}
	}
}

func (s *udpEchoServer) Close() error {
	return s.Conn.Close()
}

type connectEvent struct {
	Addr net.Addr
	ID   string
	TX   uint64
}

type disconnectEvent struct {
	Addr net.Addr
	ID   string
	Err  error
}

type tcpRequestEvent struct {
	Addr    net.Addr
	ID      string
	ReqAddr string
}

type tcpErrorEvent struct {
	Addr    net.Addr
	ID      string
	ReqAddr string
	Err     error
}

type udpRequestEvent struct {
	Addr      net.Addr
	ID        string
	SessionID uint32
}

type udpErrorEvent struct {
	Addr      net.Addr
	ID        string
	SessionID uint32
	Err       error
}

type channelEventLogger struct {
	ConnectEventCh    chan connectEvent
	DisconnectEventCh chan disconnectEvent
	TCPRequestEventCh chan tcpRequestEvent
	TCPErrorEventCh   chan tcpErrorEvent
	UDPRequestEventCh chan udpRequestEvent
	UDPErrorEventCh   chan udpErrorEvent
}

func (l *channelEventLogger) Connect(addr net.Addr, id string, tx uint64) {
	if l.ConnectEventCh != nil {
		l.ConnectEventCh <- connectEvent{
			Addr: addr,
			ID:   id,
			TX:   tx,
		}
	}
}

func (l *channelEventLogger) Disconnect(addr net.Addr, id string, err error) {
	if l.DisconnectEventCh != nil {
		l.DisconnectEventCh <- disconnectEvent{
			Addr: addr,
			ID:   id,
			Err:  err,
		}
	}
}

func (l *channelEventLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	if l.TCPRequestEventCh != nil {
		l.TCPRequestEventCh <- tcpRequestEvent{
			Addr:    addr,
			ID:      id,
			ReqAddr: reqAddr,
		}
	}
}

func (l *channelEventLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	if l.TCPErrorEventCh != nil {
		l.TCPErrorEventCh <- tcpErrorEvent{
			Addr:    addr,
			ID:      id,
			ReqAddr: reqAddr,
			Err:     err,
		}
	}
}

func (l *channelEventLogger) UDPRequest(addr net.Addr, id string, sessionID uint32) {
	if l.UDPRequestEventCh != nil {
		l.UDPRequestEventCh <- udpRequestEvent{
			Addr:      addr,
			ID:        id,
			SessionID: sessionID,
		}
	}
}

func (l *channelEventLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	if l.UDPErrorEventCh != nil {
		l.UDPErrorEventCh <- udpErrorEvent{
			Addr:      addr,
			ID:        id,
			SessionID: sessionID,
			Err:       err,
		}
	}
}
