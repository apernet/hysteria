package integration_tests

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/time/rate"

	"github.com/apernet/hysteria/core/client"
	"github.com/apernet/hysteria/core/server"
)

type tcpStressor struct {
	DialFunc   func() (net.Conn, error)
	Size       int
	Parallel   int
	Iterations int
}

func (s *tcpStressor) Run(t *testing.T) {
	// Make some random data
	sData := make([]byte, s.Size)
	_, err := rand.Read(sData)
	if err != nil {
		t.Fatal("error generating random data:", err)
	}

	// Run iterations
	for i := 0; i < s.Iterations; i++ {
		var wg sync.WaitGroup
		errChan := make(chan error, s.Parallel)
		for j := 0; j < s.Parallel; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				conn, err := s.DialFunc()
				if err != nil {
					errChan <- err
					return
				}
				defer conn.Close()
				go conn.Write(sData)

				rData := make([]byte, len(sData))
				_, err = io.ReadFull(conn, rData)
				if err != nil {
					errChan <- err
					return
				}
			}()
		}
		wg.Wait()

		if len(errChan) > 0 {
			t.Fatal("error reading from TCP:", <-errChan)
		}
	}
}

type udpStressor struct {
	ListenFunc func() (client.HyUDPConn, error)
	ServerAddr string
	Size       int
	Count      int
	Parallel   int
	Iterations int
}

func (s *udpStressor) Run(t *testing.T) {
	// Make some random data
	sData := make([]byte, s.Size)
	_, err := rand.Read(sData)
	if err != nil {
		t.Fatal("error generating random data:", err)
	}

	// Due to UDP's unreliability, we need to limit the rate of sending
	// to reduce packet loss. This is hardcoded to 1 MiB/s for now.
	limiter := rate.NewLimiter(1048576, 1048576)

	// Run iterations
	for i := 0; i < s.Iterations; i++ {
		var wg sync.WaitGroup
		errChan := make(chan error, s.Parallel)
		for j := 0; j < s.Parallel; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				conn, err := s.ListenFunc()
				if err != nil {
					errChan <- err
					return
				}
				defer conn.Close()
				go func() {
					// Sending routine
					for i := 0; i < s.Count; i++ {
						_ = limiter.WaitN(context.Background(), len(sData))
						_ = conn.Send(sData, s.ServerAddr)
					}
				}()

				minCount := s.Count * 8 / 10 // Tolerate 20% packet loss
				for i := 0; i < minCount; i++ {
					rData, _, err := conn.Receive()
					if err != nil {
						errChan <- err
						return
					}
					if len(rData) != len(sData) {
						errChan <- fmt.Errorf("incomplete data received: %d/%d bytes", len(rData), len(sData))
						return
					}
				}
			}()
		}
		wg.Wait()

		if len(errChan) > 0 {
			t.Fatal("error reading from UDP:", <-errChan)
		}
	}
}

func TestClientServerTCPStress(t *testing.T) {
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
		ServerName: udpAddr.String(),
		Auth:       "password",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal("error creating client:", err)
	}
	defer c.Close()

	dialFunc := func() (net.Conn, error) {
		return c.DialTCP(echoTCPAddr.String())
	}

	t.Run("Single 500m", (&tcpStressor{DialFunc: dialFunc, Size: 524288000, Parallel: 1, Iterations: 1}).Run)

	t.Run("Sequential 1000x1m", (&tcpStressor{DialFunc: dialFunc, Size: 1048576, Parallel: 1, Iterations: 1000}).Run)
	t.Run("Sequential 10000x100k", (&tcpStressor{DialFunc: dialFunc, Size: 102400, Parallel: 1, Iterations: 10000}).Run)

	t.Run("Parallel 100x10m", (&tcpStressor{DialFunc: dialFunc, Size: 10485760, Parallel: 100, Iterations: 1}).Run)
	t.Run("Parallel 1000x1m", (&tcpStressor{DialFunc: dialFunc, Size: 1048576, Parallel: 1000, Iterations: 1}).Run)
}

func TestClientServerUDPStress(t *testing.T) {
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
	echoUDPAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14515}
	echoListener, err := net.ListenUDP("udp", echoUDPAddr)
	if err != nil {
		t.Fatal("error creating UDP echo server:", err)
	}
	echoServer := &udpEchoServer{Conn: echoListener}
	defer echoServer.Close()
	go echoServer.Serve()

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

	t.Run("Single 1000x100b", (&udpStressor{
		ListenFunc: c.ListenUDP,
		ServerAddr: echoUDPAddr.String(),
		Size:       100,
		Count:      1000,
		Parallel:   1,
		Iterations: 1,
	}).Run)
	t.Run("Single 1000x3k", (&udpStressor{
		ListenFunc: c.ListenUDP,
		ServerAddr: echoUDPAddr.String(),
		Size:       3000,
		Count:      1000,
		Parallel:   1,
		Iterations: 1,
	}).Run)

	t.Run("5 Sequential 1000x100b", (&udpStressor{
		ListenFunc: c.ListenUDP,
		ServerAddr: echoUDPAddr.String(),
		Size:       100,
		Count:      1000,
		Parallel:   1,
		Iterations: 5,
	}).Run)
	t.Run("5 Sequential 200x3k", (&udpStressor{
		ListenFunc: c.ListenUDP,
		ServerAddr: echoUDPAddr.String(),
		Size:       3000,
		Count:      200,
		Parallel:   1,
		Iterations: 5,
	}).Run)

	t.Run("2 Sequential 5 Parallel 1000x100b", (&udpStressor{
		ListenFunc: c.ListenUDP,
		ServerAddr: echoUDPAddr.String(),
		Size:       100,
		Count:      1000,
		Parallel:   5,
		Iterations: 2,
	}).Run)

	t.Run("2 Sequential 5 Parallel 200x3k", (&udpStressor{
		ListenFunc: c.ListenUDP,
		ServerAddr: echoUDPAddr.String(),
		Size:       3000,
		Count:      200,
		Parallel:   5,
		Iterations: 2,
	}).Run)

	t.Run("10 Sequential 5 Parallel 200x3k", (&udpStressor{
		ListenFunc: c.ListenUDP,
		ServerAddr: echoUDPAddr.String(),
		Size:       3000,
		Count:      200,
		Parallel:   5,
		Iterations: 10,
	}).Run)
}
