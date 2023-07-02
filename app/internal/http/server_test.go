package http

import (
	"errors"
	"net"
	"net/http"
	"os/exec"
	"testing"

	"github.com/apernet/hysteria/core/client"
)

const (
	testCertFile = "test.crt"
	testKeyFile  = "test.key"
)

type mockHyClient struct{}

func (c *mockHyClient) DialTCP(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

func (c *mockHyClient) ListenUDP() (client.HyUDPConn, error) {
	// Not implemented
	return nil, errors.New("not implemented")
}

func (c *mockHyClient) Close() error {
	return nil
}

func TestServer(t *testing.T) {
	// Start the server
	s := &Server{
		HyClient: &mockHyClient{},
	}
	l, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go s.Serve(l)

	// Start a test HTTP & HTTPS server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("control is an illusion"))
	})
	go http.ListenAndServe("127.0.0.1:18081", nil)
	go http.ListenAndServeTLS("127.0.0.1:18082", testCertFile, testKeyFile, nil)

	// Run the Python test script
	cmd := exec.Command("python", "server_test.py")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run test script: %v\n%s", err, out)
	}
}
