package redirect

import (
	"syscall"
	"unsafe"
)

const (
	SYS_GETSOCKOPT = 15
)

// we cannot call socketcall with syscall.Syscall6, it always fails with EFAULT.
// we have to call syscall.socketcall with this trick.
func syscall_socketcall(call int, a0, a1, a2, a3, a4, a5 uintptr) (n int, err syscall.Errno)

func getsockopt(s, level, name uintptr, val unsafe.Pointer, vallen *uint32) (err error) {
	_, e := syscall_socketcall(SYS_GETSOCKOPT, s, level, name, uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e != 0 {
		err = e
	}
	return
}
