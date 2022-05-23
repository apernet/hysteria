package sockopt

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func bindRawConn(network string, c syscall.RawConn, bindIface *net.Interface) error {
	return c.Control(func(fd uintptr) {
		if bindIface != nil {
			unix.BindToDevice(int(fd), bindIface.Name)
		}
	})
}
