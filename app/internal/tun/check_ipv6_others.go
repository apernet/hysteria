//go:build !unix && !windows

package tun

import "net"

func isIPv6Supported() bool {
	lis, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = lis.Close()
	return true
}
