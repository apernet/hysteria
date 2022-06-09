package redirect

import (
	"syscall"
	"unsafe"
)

const (
	SYS_GETSOCKOPT       = 15
	SO_ORIGINAL_DST      = 80
	IP6T_SO_ORIGINAL_DST = 80
)

type sockAddr struct {
	family uint16
	port   [2]byte  // big endian regardless of host byte order
	data   [24]byte // check sockaddr_in or sockaddr_in6 for more information
}

func getOrigDst(fd uintptr) (*sockAddr, error) {
	var addr sockAddr
	addrSize := uint32(unsafe.Sizeof(addr))
	// try IPv6 first
	_, _, err := syscall.Syscall6(syscall.SYS_SOCKETCALL, SYS_GETSOCKOPT, fd, syscall.SOL_IPV6, IP6T_SO_ORIGINAL_DST,
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&addrSize)))
	if err != 0 {
		// try IPv4
		_, _, err = syscall.Syscall6(syscall.SYS_SOCKETCALL, SYS_GETSOCKOPT, fd, syscall.SOL_IP, SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&addrSize)))
		if err != 0 {
			// failed
			return nil, err
		}
	}
	return &addr, nil
}
