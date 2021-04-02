package core

import (
	"net"
	"os"
	"syscall"
	"time"
)

type Obfuscator interface {
	Deobfuscate(buf []byte, n int) int
	Obfuscate(p []byte) []byte
}

type obfsUDPConn struct {
	Orig       *net.UDPConn
	Obfuscator Obfuscator
}

func (c *obfsUDPConn) SyscallConn() (syscall.RawConn, error) {
	return c.Orig.SyscallConn()
}

func (c *obfsUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	oldN, addr, err := c.Orig.ReadFrom(p)
	if oldN > 0 {
		newN := c.Obfuscator.Deobfuscate(p, oldN)
		return newN, addr, err
	} else {
		return 0, addr, err
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
