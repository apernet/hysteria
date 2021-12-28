package core

import (
	"github.com/tobyxdd/hysteria/pkg/faketcp"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

type Obfuscator interface {
	Deobfuscate(in []byte, out []byte) int
	Obfuscate(in []byte, out []byte) int
}

type obfsUDPConn struct {
	orig *net.UDPConn
	obfs Obfuscator

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func newObfsUDPConn(orig *net.UDPConn, obfs Obfuscator) *obfsUDPConn {
	return &obfsUDPConn{
		orig:     orig,
		obfs:     obfs,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
	}
}

func (c *obfsUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.readMutex.Lock()
		n, addr, err := c.orig.ReadFrom(c.readBuf)
		if n <= 0 {
			c.readMutex.Unlock()
			return 0, addr, err
		}
		newN := c.obfs.Deobfuscate(c.readBuf[:n], p)
		c.readMutex.Unlock()
		if newN > 0 {
			// Valid packet
			return newN, addr, err
		} else if err != nil {
			// Not valid and orig.ReadFrom had some error
			return 0, addr, err
		}
	}
}

func (c *obfsUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMutex.Lock()
	bn := c.obfs.Obfuscate(p, c.writeBuf)
	_, err = c.orig.WriteTo(c.writeBuf[:bn], addr)
	c.writeMutex.Unlock()
	if err != nil {
		return 0, err
	} else {
		return len(p), nil
	}
}

func (c *obfsUDPConn) Close() error {
	return c.orig.Close()
}

func (c *obfsUDPConn) LocalAddr() net.Addr {
	return c.orig.LocalAddr()
}

func (c *obfsUDPConn) SetDeadline(t time.Time) error {
	return c.orig.SetDeadline(t)
}

func (c *obfsUDPConn) SetReadDeadline(t time.Time) error {
	return c.orig.SetReadDeadline(t)
}

func (c *obfsUDPConn) SetWriteDeadline(t time.Time) error {
	return c.orig.SetWriteDeadline(t)
}

func (c *obfsUDPConn) SetReadBuffer(bytes int) error {
	return c.orig.SetReadBuffer(bytes)
}

func (c *obfsUDPConn) SetWriteBuffer(bytes int) error {
	return c.orig.SetWriteBuffer(bytes)
}

func (c *obfsUDPConn) SyscallConn() (syscall.RawConn, error) {
	return c.orig.SyscallConn()
}

func (c *obfsUDPConn) File() (f *os.File, err error) {
	return c.orig.File()
}

type obfsFakeTCPConn struct {
	orig *faketcp.TCPConn
	obfs Obfuscator

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func newObfsFakeTCPConn(orig *faketcp.TCPConn, obfs Obfuscator) *obfsFakeTCPConn {
	return &obfsFakeTCPConn{
		orig:     orig,
		obfs:     obfs,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
	}
}

func (c *obfsFakeTCPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.readMutex.Lock()
		n, addr, err := c.orig.ReadFrom(c.readBuf)
		if n <= 0 {
			c.readMutex.Unlock()
			return 0, addr, err
		}
		newN := c.obfs.Deobfuscate(c.readBuf[:n], p)
		c.readMutex.Unlock()
		if newN > 0 {
			// Valid packet
			return newN, addr, err
		} else if err != nil {
			// Not valid and orig.ReadFrom had some error
			return 0, addr, err
		}
	}
}

func (c *obfsFakeTCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMutex.Lock()
	bn := c.obfs.Obfuscate(p, c.writeBuf)
	_, err = c.orig.WriteTo(c.writeBuf[:bn], addr)
	c.writeMutex.Unlock()
	if err != nil {
		return 0, err
	} else {
		return len(p), nil
	}
}

func (c *obfsFakeTCPConn) Close() error {
	return c.orig.Close()
}

func (c *obfsFakeTCPConn) LocalAddr() net.Addr {
	return c.orig.LocalAddr()
}

func (c *obfsFakeTCPConn) SetDeadline(t time.Time) error {
	return c.orig.SetDeadline(t)
}

func (c *obfsFakeTCPConn) SetReadDeadline(t time.Time) error {
	return c.orig.SetReadDeadline(t)
}

func (c *obfsFakeTCPConn) SetWriteDeadline(t time.Time) error {
	return c.orig.SetWriteDeadline(t)
}

func (c *obfsFakeTCPConn) SetReadBuffer(bytes int) error {
	return c.orig.SetReadBuffer(bytes)
}

func (c *obfsFakeTCPConn) SetWriteBuffer(bytes int) error {
	return c.orig.SetWriteBuffer(bytes)
}

func (c *obfsFakeTCPConn) SyscallConn() (syscall.RawConn, error) {
	return c.orig.SyscallConn()
}
