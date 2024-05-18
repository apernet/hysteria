package tproxy

import (
	"io"
	"net"

	"github.com/apernet/go-tproxy"
	"github.com/apernet/hysteria/core/v2/client"
)

type TCPTProxy struct {
	HyClient    client.Client
	EventLogger TCPEventLogger
}

type TCPEventLogger interface {
	Connect(addr, reqAddr net.Addr)
	Error(addr, reqAddr net.Addr, err error)
}

func (r *TCPTProxy) ListenAndServe(laddr *net.TCPAddr) error {
	listener, err := tproxy.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		c, err := listener.Accept()
		if err != nil {
			return err
		}
		go r.handle(c)
	}
}

func (r *TCPTProxy) handle(conn net.Conn) {
	defer conn.Close()
	// In TProxy mode, we are masquerading as the remote server.
	// So LocalAddr is actually the target the user is trying to connect to,
	// and RemoteAddr is the local address.
	if r.EventLogger != nil {
		r.EventLogger.Connect(conn.RemoteAddr(), conn.LocalAddr())
	}
	var closeErr error
	defer func() {
		if r.EventLogger != nil {
			r.EventLogger.Error(conn.RemoteAddr(), conn.LocalAddr(), closeErr)
		}
	}()

	rc, err := r.HyClient.TCP(conn.LocalAddr().String())
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
