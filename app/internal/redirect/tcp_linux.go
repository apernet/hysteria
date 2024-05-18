package redirect

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"unsafe"

	"github.com/apernet/hysteria/core/v2/client"
)

const (
	soOriginalDst   = 80
	soOriginalDstV6 = 80
)

type TCPRedirect struct {
	HyClient    client.Client
	EventLogger TCPEventLogger
}

type TCPEventLogger interface {
	Connect(addr, reqAddr net.Addr)
	Error(addr, reqAddr net.Addr, err error)
}

func (r *TCPRedirect) ListenAndServe(laddr *net.TCPAddr) error {
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		c, err := listener.AcceptTCP()
		if err != nil {
			return err
		}
		go r.handle(c)
	}
}

func (r *TCPRedirect) handle(conn *net.TCPConn) {
	defer conn.Close()
	dstAddr, err := getDstAddr(conn)
	if err != nil {
		// Fail silently if we can't get the original destination.
		// Maybe we should print something to the log?
		return
	}
	if r.EventLogger != nil {
		r.EventLogger.Connect(conn.RemoteAddr(), dstAddr)
	}
	var closeErr error
	defer func() {
		if r.EventLogger != nil {
			r.EventLogger.Error(conn.RemoteAddr(), dstAddr, closeErr)
		}
	}()

	rc, err := r.HyClient.TCP(dstAddr.String())
	if err != nil {
		closeErr = err
		return
	}
	defer rc.Close()

	// Start forwarding
	copyErrChan := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(rc, conn)
		copyErrChan <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(conn, rc)
		copyErrChan <- copyErr
	}()
	closeErr = <-copyErrChan
}

type sockAddr struct {
	family uint16
	port   [2]byte  // always big endian regardless of platform
	data   [24]byte // sockaddr_in or sockaddr_in6
}

func getOriginalDst(fd uintptr) (*sockAddr, error) {
	var addr sockAddr
	addrSize := uint32(unsafe.Sizeof(addr))
	// Try IPv6 first
	err := getsockopt(fd, syscall.SOL_IPV6, soOriginalDstV6, unsafe.Pointer(&addr), &addrSize)
	if err == nil {
		return &addr, nil
	}
	// Then IPv4
	err = getsockopt(fd, syscall.SOL_IP, soOriginalDst, unsafe.Pointer(&addr), &addrSize)
	return &addr, err
}

// getDstAddr returns the original destination of a redirected TCP connection.
func getDstAddr(conn *net.TCPConn) (*net.TCPAddr, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var addr *sockAddr
	var err2 error
	err = rc.Control(func(fd uintptr) {
		addr, err2 = getOriginalDst(fd)
	})
	if err != nil {
		return nil, err
	}
	if err2 != nil {
		return nil, err2
	}
	switch addr.family {
	case syscall.AF_INET:
		return &net.TCPAddr{IP: addr.data[:4], Port: int(binary.BigEndian.Uint16(addr.port[:]))}, nil
	case syscall.AF_INET6:
		return &net.TCPAddr{IP: addr.data[4:20], Port: int(binary.BigEndian.Uint16(addr.port[:]))}, nil
	default:
		return nil, errors.New("address family not IPv4 or IPv6")
	}
}
