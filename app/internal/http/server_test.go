package http

import (
	"errors"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/core/v2/client"
)

const (
	testCertFile = "test.crt"
	testKeyFile  = "test.key"
)

type mockHyClient struct{}

func (c *mockHyClient) TCP(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func (c *mockHyClient) UDP() (client.HyUDPConn, error) {
	return nil, errors.New("not implemented")
}

func (c *mockHyClient) Close() error {
	return nil
}

func TestServer(t *testing.T) {
	// Start the server
	l, err := net.Listen("tcp", "127.0.0.1:18080")
	assert.NoError(t, err)
	defer l.Close()
	s := &Server{
		HyClient: &mockHyClient{},
	}
	go s.Serve(l)

	// Start a test HTTP & HTTPS server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("control is an illusion"))
	})
	go http.ListenAndServe("127.0.0.1:18081", nil)
	go http.ListenAndServeTLS("127.0.0.1:18082", testCertFile, testKeyFile, nil)

	// Run the Python test script
	cmd := exec.Command("python", "server_test.py")
	// Suppress HTTPS warning text from Python
	cmd.Env = append(cmd.Env, "PYTHONWARNINGS=ignore:Unverified HTTPS request")
	out, err := cmd.CombinedOutput()
	assert.NoError(t, err)
	assert.Equal(t, "OK", strings.TrimSpace(string(out)))
}
