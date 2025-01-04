//go:build unix

package tun

import (
	"golang.org/x/sys/unix"
)

func isIPv6Supported() bool {
	sock, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return false
	}
	_ = unix.Close(sock)
	return true
}
