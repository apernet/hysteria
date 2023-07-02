package forwarding

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"

	"github.com/apernet/hysteria/app/internal/utils_test"
)

func TestUDPTunnel(t *testing.T) {
	// Start the tunnel
	tunnel := &UDPTunnel{
		HyClient: &utils_test.MockEchoHyClient{},
		Remote:   "whatever",
	}
	l, err := net.ListenPacket("udp", "127.0.0.1:34567")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go tunnel.Serve(l)

	for i := 0; i < 10; i++ {
		conn, err := net.Dial("udp", "127.0.0.1:34567")
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
