//go:build !386
// +build !386

package redirect

import (
	"syscall"
	"unsafe"
)

func getsockopt(s, level, name uintptr, val unsafe.Pointer, vallen *uint32) (err error) {
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, s, level, name, uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e != 0 {
		err = e
	}
	return err
}
