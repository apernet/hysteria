//go:build !linux

package vxrelay

import "net"

func allowFragmentation(*net.UDPConn) error { return nil }
