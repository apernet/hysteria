//go:build !linux

package sockopt

import (
	"net"
	"syscall"
)

func bindRawConn(network string, c syscall.RawConn, bindIface *net.Interface) error { return nil }
