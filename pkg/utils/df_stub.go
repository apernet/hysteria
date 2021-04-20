// +build !linux,!windows

package utils

import "net"

func SetDontFragment(conn *net.UDPConn) error {
	// Not implemented
	return nil
}
