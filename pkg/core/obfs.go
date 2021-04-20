package core

import (
	"net"
	"os"
	"syscall"
	"time"
)

type Obfuscator interface {
	Deobfuscate(in []byte, out []byte) int
	Obfuscate(p []byte) []byte
}

type obfsUDPConn struct {
	Orig       *net.UDPConn
	Obfuscator Obfuscator
}

func (c *obfsUDPConn) SyscallConn() (syscall.RawConn, error) {
	return c.Orig.SyscallConn()
}

func (c *obfsUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, udpBufferSize)
	for {
		n, addr, err := c.Orig.ReadFrom(buf)
		if n <= 0 {
			return 0, addr, err
		}
		newN := c.Obfuscator.Deobfuscate(buf[:n], p)
		if newN > 0 {
			// Valid packet
			return newN, addr, err
		} else if err != nil {
			// Not valid and Orig.ReadFrom had some error
			return 0, addr, err
		}
	}
}

func (c *obfsUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	np := c.Obfuscator.Obfuscate(p)
	_, err = c.Orig.WriteTo(np, addr)
	if err != nil {
		return 0, err
	} else {
		return len(p), nil
	}
}

func (c *obfsUDPConn) Close() error {
	return c.Orig.Close()
}

func (c *obfsUDPConn) LocalAddr() net.Addr {
	return c.Orig.LocalAddr()
}

func (c *obfsUDPConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

func (c *obfsUDPConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

func (c *obfsUDPConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}

func (c *obfsUDPConn) SetReadBuffer(bytes int) error {
	return c.Orig.SetReadBuffer(bytes)
}

func (c *obfsUDPConn) SetWriteBuffer(bytes int) error {
	return c.Orig.SetWriteBuffer(bytes)
}

func (c *obfsUDPConn) File() (f *os.File, err error) {
	return c.Orig.File()
}
