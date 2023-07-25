package integration_tests

import (
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/apernet/hysteria/core/client"
	"github.com/apernet/hysteria/core/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/server"
)

// TestClientServerTCPClose tests whether the client/server propagates the close of a connection correctly.
// In other words, closing one of the client/remote connections should cause the other to close as well.
func TestClientServerTCPClose(t *testing.T) {
	// Create server
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14514}
	udpConn, err := net.ListenUDP("udp", udpAddr)
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

	// Create client
	c, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()

	t.Run("Close local", func(t *testing.T) {
		// TCP sink server
		sinkAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 33344}
		sinkListener, err := net.ListenTCP("tcp", sinkAddr)
		assert.NoError(t, err)
		sinkCh := make(chan sinkEvent, 1)
		sinkServer := &tcpSinkServer{
			Listener: sinkListener,
			Ch:       sinkCh,
		}
		defer sinkServer.Close()
		go sinkServer.Serve()

		// Generate some random data
		sData := make([]byte, 1024000)
		_, err = rand.Read(sData)
		assert.NoError(t, err)

		// Dial and send data to TCP sink server
		conn, err := c.DialTCP(sinkAddr.String())
		assert.NoError(t, err)
		_, err = conn.Write(sData)
		assert.NoError(t, err)

		// Close the connection
		// This should cause the sink server to send an event to the channel
		_ = conn.Close()
		event := <-sinkCh
		assert.NoError(t, event.Err)
		assert.Equal(t, sData, event.Data)
	})

	t.Run("Close remote", func(t *testing.T) {
		// Generate some random data
		sData := make([]byte, 1024000)
		_, err = rand.Read(sData)
		assert.NoError(t, err)

		// TCP sender server
		senderAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 33345}
		senderListener, err := net.ListenTCP("tcp", senderAddr)
		assert.NoError(t, err)

		senderServer := &tcpSenderServer{
			Listener: senderListener,
			Data:     sData,
		}
		defer senderServer.Close()
		go senderServer.Serve()

		// Dial and read data from TCP sender server
		conn, err := c.DialTCP(senderAddr.String())
		assert.NoError(t, err)
		defer conn.Close()
		rData, err := io.ReadAll(conn)
		assert.NoError(t, err)
		assert.Equal(t, sData, rData)
	})
}

// TestClientServerUDPClose is the same as TestClientServerTCPClose, but for UDP.
// Checking for UDP close is a bit tricky, so we will rely on the server event for now.
func TestClientServerUDPClose(t *testing.T) {
	urCh := make(chan udpRequestEvent, 1)
	ueCh := make(chan udpErrorEvent, 1)

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
		EventLogger: &channelEventLogger{
			UDPRequestEventCh: urCh,
			UDPErrorEventCh:   ueCh,
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
		Auth:       "password",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal("error creating client:", err)
	}
	defer c.Close()

	// Listen UDP and close it, then check the server events
	conn, err := c.ListenUDP()
	if err != nil {
		t.Fatal("error listening UDP:", err)
	}
	_ = conn.Close()

	reqEvent := <-urCh
	if reqEvent.ID != "nobody" {
		t.Fatal("incorrect ID in request event")
	}
	errEvent := <-ueCh
	if errEvent.ID != "nobody" {
		t.Fatal("incorrect ID in error event")
	}
	if errEvent.Err != nil {
		t.Fatal("non-nil error received from server:", errEvent.Err)
	}
}
