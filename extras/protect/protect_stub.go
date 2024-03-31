//go:build !linux

package protect

import (
	"net"
)

func ListenUDP(protectPath string) ListenUDPFunc {
	return func() (net.PacketConn, error) {
		return net.ListenUDP("udp", nil)
	}
}
