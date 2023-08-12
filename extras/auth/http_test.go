package auth

import (
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHTTPAuthenticator(t *testing.T) {
	// Run the Python test auth server
	cmd := exec.Command("python", "http_test.py")
	err := cmd.Start()
	assert.NoError(t, err)
	defer cmd.Process.Kill()

	time.Sleep(1 * time.Second) // Wait for the server to start

	auth := NewHTTPAuthenticator("http://127.0.0.1:5000/auth", false)

	ok, id := auth.Authenticate(&net.UDPAddr{
		IP:   net.ParseIP("1.2.3.4"),
		Port: 34567,
	}, "idk", 123)
	assert.False(t, ok)
	assert.Equal(t, "", id)

	ok, id = auth.Authenticate(&net.UDPAddr{
		IP:   net.ParseIP("123.123.123.123"),
		Port: 5566,
	}, "wahaha", 12345)
	assert.True(t, ok)
	assert.Equal(t, "some_unique_id", id)
}
