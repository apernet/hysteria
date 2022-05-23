package tunconf

import (
	"golang.org/x/sys/unix"
	"unsafe"
)

func ioctl(fd int, code, data uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), code, data)
	if errno != 0 {
		return errno
	}
	return nil
}

type socketAddrRequest struct {
	name [unix.IFNAMSIZ]byte
	addr unix.RawSockaddrInet4
}

type socketFlagsRequest struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	pad   [22]byte
}

func SetAddress(name string, ip, mask []byte) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	sa := socketAddrRequest{}
	copy(sa.name[:], name)
	sa.addr.Family = unix.AF_INET
	copy(sa.addr.Addr[:], ip)

	err = ioctl(fd, unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&sa)))
	if err != nil {
		return err
	}

	// Set netmask
	if mask != nil {
		copy(sa.addr.Addr[:], mask)
		err = ioctl(fd, unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&sa)))
		if err != nil {
			return err
		}
	}

	// Get flags
	sf := socketFlagsRequest{}
	sf.name = sa.name

	err = ioctl(fd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&sf)))
	if err != nil {
		return err
	}

	sf.flags |= unix.IFF_UP | unix.IFF_RUNNING
	err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&sf)))
	if err != nil {
		return err
	}
	return nil
}
