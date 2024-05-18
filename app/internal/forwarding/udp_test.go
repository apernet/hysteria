package forwarding

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/app/v2/internal/utils_test"
)

func TestUDPTunnel(t *testing.T) {
	// Start the tunnel
	l, err := net.ListenPacket("udp", "127.0.0.1:34567")
	assert.NoError(t, err)
	defer l.Close()
	tunnel := &UDPTunnel{
		HyClient: &utils_test.MockEchoHyClient{},
	}
	go tunnel.Serve(l)

	for i := 0; i < 10; i++ {
		conn, err := net.Dial("udp", "127.0.0.1:34567")
		assert.NoError(t, err)

		data := make([]byte, 1024)
		_, _ = rand.Read(data)
		_, err = conn.Write(data)
		assert.NoError(t, err)

		recv := make([]byte, 1024)
		_, err = conn.Read(recv)
		assert.NoError(t, err)

		assert.Equal(t, data, recv)
		_ = conn.Close()
	}
}
