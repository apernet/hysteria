package forwarding

import (
	"io"
	"net"

	"github.com/apernet/hysteria/core/v2/client"
)

type TCPTunnel struct {
	HyClient    client.Client
	Remote      string
	EventLogger TCPEventLogger
}

type TCPEventLogger interface {
	Connect(addr net.Addr)
	Error(addr net.Addr, err error)
}

func (t *TCPTunnel) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go t.handle(conn)
	}
}

func (t *TCPTunnel) handle(conn net.Conn) {
	defer conn.Close()

	if t.EventLogger != nil {
		t.EventLogger.Connect(conn.RemoteAddr())
	}
	var closeErr error
	defer func() {
		if t.EventLogger != nil {
			t.EventLogger.Error(conn.RemoteAddr(), closeErr)
		}
	}()

	rc, err := t.HyClient.TCP(t.Remote)
	if err != nil {
		closeErr = err
		return
	}
	defer rc.Close()

	// Start forwarding
	copyErrChan := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(rc, conn)
		copyErrChan <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(conn, rc)
		copyErrChan <- copyErr
	}()
	closeErr = <-copyErrChan
}
