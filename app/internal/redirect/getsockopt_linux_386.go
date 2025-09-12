package redirect

import (
	"syscall"
	"unsafe"
)

const (
	sysGetsockopt = 15
)

// On 386 we cannot call socketcall with syscall.Syscall6, as it always fails with EFAULT.
// Use our own syscall.socketcall hack instead.

func syscall_socketcall(call int, a0, a1, a2, a3, a4, a5 uintptr) (n int, err syscall.Errno)

func getsockopt(s, level, name uintptr, val unsafe.Pointer, vallen *uint32) (err error) {
	_, e := syscall_socketcall(sysGetsockopt, s, level, name, uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e != 0 {
		err = e
	}
	return err
}
