package integration_tests

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/apernet/hysteria/core/client"
	"github.com/apernet/hysteria/core/server"
)

// TestClientServerTCPClose tests whether the client/server propagates the close of a connection correctly.
// In other words, closing one of the client/remote connections should cause the other to close as well.
func TestClientServerTCPClose(t *testing.T) {
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

	// Create client
	c, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		ServerName: udpAddr.String(),
		Auth:       "password",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal("error creating client:", err)
	}
	defer c.Close()

	t.Run("Close local", func(t *testing.T) {
		// TCP sink server
		sinkAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 33344}
		sinkListener, err := net.ListenTCP("tcp", sinkAddr)
		if err != nil {
			t.Fatal("error creating sink server:", err)
		}
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
		if err != nil {
			t.Fatal("error generating random data:", err)
		}

		// Dial and send data to TCP sink server
		conn, err := c.DialTCP(sinkAddr.String())
		if err != nil {
			t.Fatal("error dialing TCP:", err)
		}
		defer conn.Close()
		_, err = conn.Write(sData)
		if err != nil {
			t.Fatal("error writing to TCP:", err)
		}

		// Close the connection
		// This should cause the sink server to send an event to the channel
		_ = conn.Close()
		event := <-sinkCh
		if event.Err != nil {
			t.Fatal("non-nil error received from sink server:", event.Err)
		}
		if !bytes.Equal(event.Data, sData) {
			t.Fatal("data mismatch")
		}
	})

	t.Run("Close remote", func(t *testing.T) {
		// Generate some random data
		sData := make([]byte, 1024000)
		_, err = rand.Read(sData)
		if err != nil {
			t.Fatal("error generating random data:", err)
		}

		// TCP sender server
		senderAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 33345}
		senderListener, err := net.ListenTCP("tcp", senderAddr)
		if err != nil {
			t.Fatal("error creating sender server:", err)
		}
		senderServer := &tcpSenderServer{
			Listener: senderListener,
			Data:     sData,
		}
		defer senderServer.Close()
		go senderServer.Serve()

		// Dial and read data from TCP sender server
		conn, err := c.DialTCP(senderAddr.String())
		if err != nil {
			t.Fatal("error dialing TCP:", err)
		}
		defer conn.Close()
		rData, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal("error reading from TCP:", err)
		}
		if !bytes.Equal(rData, sData) {
			t.Fatal("data mismatch")
		}
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
		ServerName: udpAddr.String(),
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
