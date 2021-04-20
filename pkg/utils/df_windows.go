package utils

import (
	"net"
	"syscall"
)

func SetDontFragment(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var err1, err2 error
	err1 = rawConn.Control(func(fd uintptr) {
		// https://docs.microsoft.com/en-us/troubleshoot/windows/win32/header-library-requirement-socket-ipproto-ip
		// #define IP_DONTFRAGMENT        14     /* don't fragment IP datagrams */
		err2 = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, 14, 1)
	})
	if err1 != nil {
		return err1
	}
	return err2
}
