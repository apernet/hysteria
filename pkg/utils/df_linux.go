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
		err2 = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
	})
	if err1 != nil {
		return err1
	}
	return err2
}
