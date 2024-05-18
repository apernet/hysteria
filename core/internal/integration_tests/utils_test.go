package integration_tests

import (
	"crypto/tls"
	"io"
	"net"

	"github.com/apernet/hysteria/core/v2/server"
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

func serverConn() (net.PacketConn, net.Addr, error) {
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14514}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, nil, err
	}
	return udpConn, udpAddr, nil
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
