package socks5

import (
	"io"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/client"
)

type mockEchoHyClient struct{}

func (c *mockEchoHyClient) DialTCP(addr string) (net.Conn, error) {
	return &mockEchoTCPConn{
		BufChan: make(chan []byte, 10),
	}, nil
}

func (c *mockEchoHyClient) ListenUDP() (client.HyUDPConn, error) {
	return &mockEchoUDPConn{
		BufChan: make(chan mockEchoUDPPacket, 10),
	}, nil
}

func (c *mockEchoHyClient) Close() error {
	return nil
}

type mockEchoTCPConn struct {
	BufChan chan []byte
}

func (c *mockEchoTCPConn) Read(b []byte) (n int, err error) {
	buf := <-c.BufChan
	if buf == nil {
		// EOF
		return 0, io.EOF
	}
	return copy(b, buf), nil
}

func (c *mockEchoTCPConn) Write(b []byte) (n int, err error) {
	c.BufChan <- b
	return len(b), nil
}

func (c *mockEchoTCPConn) Close() error {
	close(c.BufChan)
	return nil
}

func (c *mockEchoTCPConn) LocalAddr() net.Addr {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) RemoteAddr() net.Addr {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) SetDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) SetReadDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *mockEchoTCPConn) SetWriteDeadline(t time.Time) error {
	// Not implemented
	return nil
}

type mockEchoUDPPacket struct {
	Data []byte
	Addr string
}

type mockEchoUDPConn struct {
	BufChan chan mockEchoUDPPacket
}

func (c *mockEchoUDPConn) Receive() ([]byte, string, error) {
	p := <-c.BufChan
	if p.Data == nil {
		// EOF
		return nil, "", io.EOF
	}
	return p.Data, p.Addr, nil
}

func (c *mockEchoUDPConn) Send(bytes []byte, s string) error {
	c.BufChan <- mockEchoUDPPacket{
		Data: bytes,
		Addr: s,
	}
	return nil
}

func (c *mockEchoUDPConn) Close() error {
	close(c.BufChan)
	return nil
}

func TestServer(t *testing.T) {
	// Start the server
	s := &Server{
		HyClient: &mockEchoHyClient{},
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
