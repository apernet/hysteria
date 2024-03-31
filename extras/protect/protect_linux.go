//go:build linux

package protect

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

const (
	timevalSec = 3
)

func protect(connFd int, path string) error {
	if path == "" {
		return nil
	}

	socketFd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, unix.PROT_NONE)
	if err != nil {
		return err
	}
	defer unix.Close(socketFd)

	_ = unix.SetsockoptTimeval(socketFd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: timevalSec})
	_ = unix.SetsockoptTimeval(socketFd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: timevalSec})

	err = unix.Connect(socketFd, &unix.SockaddrUnix{Name: path})
	if err != nil {
		return err
	}

	err = unix.Sendmsg(socketFd, nil, unix.UnixRights(connFd), nil, 0)
	if err != nil {
		return err
	}

	dummy := []byte{1}
	n, err := unix.Read(socketFd, dummy)
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("protect failed")
	}

	return nil
}

func ListenUDP(protectPath string) ListenUDPFunc {
	return func() (net.PacketConn, error) {
		udpConn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}

		udpFile, err := udpConn.File()
		if err != nil {
			return nil, err
		}

		err = protect(int(udpFile.Fd()), protectPath)
		if err != nil {
			_ = udpConn.Close()
			return nil, err
		}

		return udpConn, nil
	}
}
