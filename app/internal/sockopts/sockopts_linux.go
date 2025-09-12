//go:build linux

package sockopts

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/exp/constraints"
	"golang.org/x/sys/unix"
)

const (
	fdControlUnixTimeout = 3 * time.Second
)

func init() {
	bindInterfaceFunc = bindInterfaceImpl
	firewallMarkFunc = firewallMarkImpl
	fdControlUnixSocketFunc = fdControlUnixSocketImpl
}

func controlUDPConn(c *net.UDPConn, cb func(fd int) error) (err error) {
	rconn, err := c.SyscallConn()
	if err != nil {
		return err
	}
	cerr := rconn.Control(func(fd uintptr) {
		err = cb(int(fd))
	})
	if err != nil {
		return err
	}
	if cerr != nil {
		err = fmt.Errorf("failed to control fd: %w", cerr)
		return err
	}
	return err
}

func bindInterfaceImpl(c *net.UDPConn, device string) error {
	return controlUDPConn(c, func(fd int) error {
		return unix.BindToDevice(fd, device)
	})
}

func firewallMarkImpl(c *net.UDPConn, fwmark uint32) error {
	return controlUDPConn(c, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(fwmark))
	})
}

func fdControlUnixSocketImpl(c *net.UDPConn, path string) error {
	return controlUDPConn(c, func(fd int) error {
		socketFd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			return fmt.Errorf("failed to create unix socket: %w", err)
		}
		defer unix.Close(socketFd)

		var timeout unix.Timeval
		timeUsec := fdControlUnixTimeout.Microseconds()
		castAssignInteger(timeUsec/1e6, &timeout.Sec)
		// Specifying the type explicitly is not necessary here, but it makes GoLand happy.
		castAssignInteger[int64](timeUsec%1e6, &timeout.Usec)

		_ = unix.SetsockoptTimeval(socketFd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)
		_ = unix.SetsockoptTimeval(socketFd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout)

		err = unix.Connect(socketFd, &unix.SockaddrUnix{Name: path})
		if err != nil {
			return fmt.Errorf("failed to connect: %w", err)
		}

		err = unix.Sendmsg(socketFd, nil, unix.UnixRights(fd), nil, 0)
		if err != nil {
			return fmt.Errorf("failed to send: %w", err)
		}

		dummy := []byte{1}
		n, err := unix.Read(socketFd, dummy)
		if err != nil {
			return fmt.Errorf("failed to receive: %w", err)
		}
		if n != 1 {
			return fmt.Errorf("socket closed unexpectedly")
		}

		return nil
	})
}

func castAssignInteger[F, T constraints.Integer](from F, to *T) {
	*to = T(from)
}
