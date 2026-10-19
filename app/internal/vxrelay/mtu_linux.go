//go:build linux

package vxrelay

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// allowFragmentation lets the kernel fragment a VXLAN datagram that does not
// fit the LAN MTU. The default discovery setting sets DF and then returns
// EMSGSIZE instead of sending the packet.
func allowFragmentation(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		sockErr = errors.Join(
			setOptional(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT),
			setOptional(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DONT),
		)
	})
	return errors.Join(ctrlErr, sockErr)
}

func setOptional(fd, proto, opt, value int) error {
	err := unix.SetsockoptInt(fd, proto, opt, value)
	if err == nil || errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	return err
}
