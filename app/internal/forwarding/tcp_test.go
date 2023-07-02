package forwarding

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"

	"github.com/apernet/hysteria/app/internal/utils_test"
)

func TestTCPTunnel(t *testing.T) {
	// Start the tunnel
	tunnel := &TCPTunnel{
		HyClient: &utils_test.MockEchoHyClient{},
		Remote:   "whatever",
	}
	l, err := net.Listen("tcp", "127.0.0.1:34567")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go tunnel.Serve(l)

	for i := 0; i < 10; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:34567")
		if err != nil {
			t.Fatal(err)
		}

		data := make([]byte, 1024)
		_, _ = rand.Read(data)
		_, err = conn.Write(data)
		if err != nil {
			t.Fatal(err)
		}
		recv := make([]byte, 1024)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(data, recv) {
			t.Fatalf("connection %d: data mismatch", i)
		}

		_ = conn.Close()
	}
}
