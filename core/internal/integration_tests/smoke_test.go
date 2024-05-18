package integration_tests

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
)

// Smoke tests that act as a sanity check for client & server to ensure they can talk to each other correctly.

// TestClientNoServer tests how the client handles a server address it cannot connect to.
// NewClient should return a ConnectError.
func TestClientNoServer(t *testing.T) {
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55666},
	})
	assert.Nil(t, c)
	_, ok := err.(coreErrs.ConnectError)
	assert.True(t, ok)
}

// TestClientServerBadAuth tests two things:
// - The server uses Authenticator when a client connects.
// - How the client handles failed authentication.
func TestClientServerBadAuth(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "badpassword", uint64(0)).Return(false, "").Once()
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		Auth:       "badpassword",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.Nil(t, c)
	_, ok := err.(coreErrs.AuthError)
	assert.True(t, ok)
}

// TestClientServerUDPDisabled tests how the client handles a server that does not support UDP.
// UDP should return a DialError.
func TestClientServerUDPDisabled(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		DisableUDP:    true,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	conn, err := c.UDP()
	assert.Nil(t, conn)
	_, ok := err.(coreErrs.DialError)
	assert.True(t, ok)
}

// TestClientServerTCPEcho tests TCP forwarding using a TCP echo server.
func TestClientServerTCPEcho(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create TCP echo server
	echoAddr := "127.0.0.1:22333"
	echoListener, err := net.Listen("tcp", echoAddr)
	assert.NoError(t, err)
	echoServer := &tcpEchoServer{Listener: echoListener}
	defer echoServer.Close()
	go echoServer.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	// Dial TCP
	conn, err := c.TCP(echoAddr)
	assert.NoError(t, err)
	defer conn.Close()

	// Send and receive data
	sData := []byte("hello world")
	_, err = conn.Write(sData)
	assert.NoError(t, err)
	rData := make([]byte, len(sData))
	_, err = io.ReadFull(conn, rData)
	assert.NoError(t, err)
	assert.Equal(t, sData, rData)
}

// TestClientServerUDPEcho tests UDP forwarding using a UDP echo server.
func TestClientServerUDPEcho(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Create UDP echo server
	echoAddr := "127.0.0.1:22333"
	echoConn, err := net.ListenPacket("udp", echoAddr)
	assert.NoError(t, err)
	echoServer := &udpEchoServer{Conn: echoConn}
	defer echoServer.Close()
	go echoServer.Serve()

	// Create client
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	// Listen UDP
	conn, err := c.UDP()
	assert.NoError(t, err)
	defer conn.Close()

	// Send and receive data
	sData := []byte("hello world")
	err = conn.Send(sData, echoAddr)
	assert.NoError(t, err)
	rData, rAddr, err := conn.Receive()
	assert.NoError(t, err)
	assert.Equal(t, sData, rData)
	assert.Equal(t, echoAddr, rAddr)
}

// TestClientServerHandshakeInfo tests that the client returns the correct handshake info.
func TestClientServerHandshakeInfo(t *testing.T) {
	// Create server 1, UDP enabled, unlimited bandwidth
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	go s.Serve()

	// Create client 1, with specified tx bandwidth
	c, info, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
		BandwidthConfig: client.BandwidthConfig{
			MaxTx: 123456,
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, &client.HandshakeInfo{
		UDPEnabled: true,
		Tx:         123456,
	}, info)

	// Close server 1 and client 1
	_ = s.Close()
	_ = c.Close()

	// Create server 2, UDP disabled, limited rx bandwidth
	udpConn, udpAddr, err = serverConn()
	assert.NoError(t, err)
	s, err = server.NewServer(&server.Config{
		TLSConfig: serverTLSConfig(),
		Conn:      udpConn,
		BandwidthConfig: server.BandwidthConfig{
			MaxRx: 100000,
		},
		DisableUDP:    true,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	go s.Serve()

	// Create client 2, with specified tx bandwidth
	c, info, err = client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
		BandwidthConfig: client.BandwidthConfig{
			MaxTx: 123456,
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, &client.HandshakeInfo{
		UDPEnabled: false,
		Tx:         100000,
	}, info)

	// Close server 2 and client 2
	_ = s.Close()
	_ = c.Close()

	// Create server 3, UDP enabled, ignore client bandwidth
	udpConn, udpAddr, err = serverConn()
	assert.NoError(t, err)
	s, err = server.NewServer(&server.Config{
		TLSConfig:             serverTLSConfig(),
		Conn:                  udpConn,
		IgnoreClientBandwidth: true,
		Authenticator:         auth,
	})
	assert.NoError(t, err)
	go s.Serve()

	// Create client 3, with specified tx bandwidth
	c, info, err = client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
		BandwidthConfig: client.BandwidthConfig{
			MaxTx: 123456,
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, &client.HandshakeInfo{
		UDPEnabled: true,
		Tx:         0,
	}, info)

	// Close server 3 and client 3
	_ = s.Close()
	_ = c.Close()
}
