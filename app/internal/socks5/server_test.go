package socks5

import (
	"net"
	"os/exec"
	"testing"

	"github.com/apernet/hysteria/app/internal/utils_test"
)

func TestServer(t *testing.T) {
	// Start the server
	s := &Server{
		HyClient: &utils_test.MockEchoHyClient{},
	}
	l, err := net.Listen("tcp", "127.0.0.1:11080")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go s.Serve(l)

	// Run the Python test script
	cmd := exec.Command("python", "server_test.py")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run test script: %v\n%s", err, out)
	}
}
