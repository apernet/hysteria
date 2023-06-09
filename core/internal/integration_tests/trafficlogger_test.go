package integration_tests

import (
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/apernet/hysteria/core/client"
	"github.com/apernet/hysteria/core/server"
)

type testTrafficLogger struct {
	Tx, Rx uint64
	Block  atomic.Bool
}

func (l *testTrafficLogger) Log(id string, tx, rx uint64) bool {
	atomic.AddUint64(&l.Tx, tx)
	atomic.AddUint64(&l.Rx, rx)
	return !l.Block.Load()
}

func (l *testTrafficLogger) Get() (tx, rx uint64) {
	return atomic.LoadUint64(&l.Tx), atomic.LoadUint64(&l.Rx)
}

func (l *testTrafficLogger) SetBlock(block bool) {
	l.Block.Store(block)
}

func (l *testTrafficLogger) Reset() {
	atomic.StoreUint64(&l.Tx, 0)
	atomic.StoreUint64(&l.Rx, 0)
}

// TestServerTrafficLogger tests that the server's TrafficLogger interface is working correctly.
// More specifically, it tests that the server is correctly logging traffic in both directions,
// and that it is correctly disconnecting clients when the traffic logger returns false.
func TestServerTrafficLogger(t *testing.T) {
	tl := &testTrafficLogger{}

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
		TrafficLogger: tl,
	})
	if err != nil {
		t.Fatal("error creating server:", err)
	}
	defer s.Close()
	go s.Serve()

	// Create TCP double echo server
	// We use double echo to test that the traffic logger is correctly logging both directions.
	echoTCPAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14515}
	echoListener, err := net.ListenTCP("tcp", echoTCPAddr)
	if err != nil {
		t.Fatal("error creating TCP echo server:", err)
	}
	tEchoServer := &tcpDoubleEchoServer{Listener: echoListener}
	defer tEchoServer.Close()
	go tEchoServer.Serve()

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
	tConn, err := c.DialTCP(echoTCPAddr.String())
	if err != nil {
		t.Fatal("error dialing TCP:", err)
	}
	defer tConn.Close()

	// Send and receive TCP data
	sData := []byte("1234")
	_, err = tConn.Write(sData)
	if err != nil {
		t.Fatal("error writing to TCP:", err)
	}
	rData := make([]byte, len(sData)*2)
	_, err = io.ReadFull(tConn, rData)
	if err != nil {
		t.Fatal("error reading from TCP:", err)
	}
	expected := string(sData) + string(sData)
	if string(rData) != expected {
		t.Fatalf("expected %q, got %q", expected, string(rData))
	}

	// Check traffic logger
	tx, rx := tl.Get()
	if tx != uint64(len(sData)) || rx != uint64(len(rData)) {
		t.Fatalf("expected TrafficLogger Tx=%d, Rx=%d, got Tx=%d, Rx=%d", len(sData), len(rData), tx, rx)
	}
	tl.Reset()

	// Create UDP double echo server
	echoUDPAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55555}
	echoConn, err := net.ListenUDP("udp", echoUDPAddr)
	if err != nil {
		t.Fatal("error creating UDP echo server:", err)
	}
	uEchoServer := &udpDoubleEchoServer{Conn: echoConn}
	defer uEchoServer.Close()
	go uEchoServer.Serve()

	// Listen UDP
	uConn, err := c.ListenUDP()
	if err != nil {
		t.Fatal("error listening UDP:", err)
	}
	defer uConn.Close()

	// Send and receive UDP data
	sData = []byte("gucci gang")
	err = uConn.Send(sData, echoUDPAddr.String())
	if err != nil {
		t.Fatal("error sending UDP:", err)
	}
	for i := 0; i < 2; i++ {
		rData, rAddr, err := uConn.Receive()
		if err != nil {
			t.Fatal("error receiving UDP:", err)
		}
		if string(rData) != string(sData) {
			t.Fatalf("expected %q, got %q", string(sData), string(rData))
		}
		if rAddr != echoUDPAddr.String() {
			t.Fatalf("expected %q, got %q", echoUDPAddr.String(), rAddr)
		}
	}

	// Check traffic logger
	tx, rx = tl.Get()
	if tx != uint64(len(sData)) || rx != uint64(len(sData)*2) {
		t.Fatalf("expected TrafficLogger Tx=%d, Rx=%d, got Tx=%d, Rx=%d", len(sData), len(sData)*2, tx, rx)
	}

	// Check the disconnect client functionality
	tl.SetBlock(true)

	// Send and receive TCP data again
	sData = []byte("1234")
	_, err = tConn.Write(sData)
	if err != nil {
		t.Fatal("error writing to TCP:", err)
	}
	// This should fail instantly without reading any data
	// io.Copy should return nil as EOF is treated as a non-error though
	n, err := io.Copy(io.Discard, tConn)
	if n != 0 || err != nil {
		t.Fatal("expected 0 bytes read and nil error, got", n, err)
	}
}
