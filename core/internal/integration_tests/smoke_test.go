package integration_tests

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/apernet/hysteria/core/client"
	coreErrs "github.com/apernet/hysteria/core/errors"
	"github.com/apernet/hysteria/core/server"
)

// Smoke tests that act as a sanity check for client & server to ensure they can talk to each other correctly.

// TestClientNoServer tests how the client handles a server that doesn't exist.
// The client should still be able to be created, but TCP & UDP requests should fail.
func TestClientNoServer(t *testing.T) {
	// Create client
	c, err := client.NewClient(&client.Config{
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14514},
	})
	if err != nil {
		t.Fatal("error creating client:", err)
	}
	defer c.Close()

	var cErr *coreErrs.ConnectError

	// Try TCP
	_, err = c.TCP("google.com:443")
	if !errors.As(err, &cErr) {
		t.Fatal("expected connect error from TCP")
	}

	// Try UDP
	_, err = c.UDP()
	if !errors.As(err, &cErr) {
		t.Fatal("expected connect error from DialUDP")
	}
}

// TestClientServerBadAuth tests two things:
// - The server uses Authenticator when a client connects.
// - How the client handles failed authentication.
func TestClientServerBadAuth(t *testing.T) {
	// Create server
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14514}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal("error creating server:", err)
	}
	s, err := server.NewServer(&server.Config{
		TLSConfig: serverTLSConfig(),
		Conn:      udpConn,
		Authenticator: &pwAuthenticator{
			Password: "correct password",
			ID:       "nobody",
		},
	})
	if err != nil {
		t.Fatal("error creating server:", err)
	}
	defer s.Close()
	go s.Serve()

	// Create client
	c, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		Auth:       "wrong password",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal("error creating client:", err)
	}
	defer c.Close()

	var aErr *coreErrs.AuthError

	// Try TCP
	_, err = c.TCP("google.com:443")
	if !errors.As(err, &aErr) {
		t.Fatal("expected auth error from TCP")
	}

	// Try UDP
	_, err = c.UDP()
	if !errors.As(err, &aErr) {
		t.Fatal("expected auth error from DialUDP")
	}
}

// TestClientServerTCPEcho tests TCP forwarding using a TCP echo server.
func TestClientServerTCPEcho(t *testing.T) {
	// Create server
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14514}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal("error creating server:", err)
	}
	s, err := server.NewServer(&server.Config{
		TLSConfig: serverTLSConfig(),
		Conn:      udpConn,
		Authenticator: &pwAuthenticator{
			Password: "password",
			ID:       "nobody",
		},
	})
	if err != nil {
		t.Fatal("error creating server:", err)
	}
	defer s.Close()
	go s.Serve()

	// Create TCP echo server
	echoTCPAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14515}
	echoListener, err := net.ListenTCP("tcp", echoTCPAddr)
	if err != nil {
		t.Fatal("error creating TCP echo server:", err)
	}
	echoServer := &tcpEchoServer{Listener: echoListener}
	defer echoServer.Close()
	go echoServer.Serve()

	// Create client
	c, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		Auth:       "password",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal("error creating client:", err)
	}
	defer c.Close()

	// Dial TCP
	conn, err := c.TCP(echoTCPAddr.String())
	if err != nil {
		t.Fatal("error dialing TCP:", err)
	}
	defer conn.Close()

	// Send and receive data
	sData := []byte("hello world")
	_, err = conn.Write(sData)
	if err != nil {
		t.Fatal("error writing to TCP:", err)
	}
	rData := make([]byte, len(sData))
	_, err = io.ReadFull(conn, rData)
	if err != nil {
		t.Fatal("error reading from TCP:", err)
	}
	if string(rData) != string(sData) {
		t.Fatalf("expected %q, got %q", sData, rData)
	}
}

// TestClientServerUDPEcho tests UDP forwarding using a UDP echo server.
func TestClientServerUDPEcho(t *testing.T) {
	// Create server
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14514}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal("error creating server:", err)
	}
	s, err := server.NewServer(&server.Config{
		TLSConfig: serverTLSConfig(),
		Conn:      udpConn,
		Authenticator: &pwAuthenticator{
			Password: "password",
			ID:       "nobody",
		},
	})
	if err != nil {
		t.Fatal("error creating server:", err)
	}
	defer s.Close()
	go s.Serve()

	// Create UDP echo server
	echoUDPAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55555}
	echoConn, err := net.ListenUDP("udp", echoUDPAddr)
	if err != nil {
		t.Fatal("error creating UDP echo server:", err)
	}
	echoServer := &udpEchoServer{Conn: echoConn}
	defer echoServer.Close()
	go echoServer.Serve()

	// Create client
	c, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		Auth:       "password",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal("error creating client:", err)
	}
	defer c.Close()

	// Listen UDP
	conn, err := c.UDP()
	if err != nil {
		t.Fatal("error listening UDP:", err)
	}
	defer conn.Close()

	// Send and receive data
	sData := []byte("hello world")
	err = conn.Send(sData, echoUDPAddr.String())
	if err != nil {
		t.Fatal("error sending UDP:", err)
	}
	rData, rAddr, err := conn.Receive()
	if err != nil {
		t.Fatal("error receiving UDP:", err)
	}
	if string(rData) != string(sData) {
		t.Fatalf("expected %q, got %q", sData, rData)
	}
	if rAddr != echoUDPAddr.String() {
		t.Fatalf("expected %q, got %q", echoUDPAddr.String(), rAddr)
	}
}
