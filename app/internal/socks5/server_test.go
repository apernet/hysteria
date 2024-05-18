package socks5

import (
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/app/v2/internal/utils_test"
)

func TestServer(t *testing.T) {
	// Start the server
	l, err := net.Listen("tcp", "127.0.0.1:11080")
	assert.NoError(t, err)
	defer l.Close()
	s := &Server{
		HyClient: &utils_test.MockEchoHyClient{},
	}
	go s.Serve(l)

	// Run the Python test script
	cmd := exec.Command("python", "server_test.py")
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err)
	assert.Equal(t, "OK", strings.TrimSpace(string(out)))
}
