package faketcp

import (
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/hysteria/core/pktconns/obfs"
)

const udpBufferSize = 4096

type ObfsFakeTCPPacketConn struct {
	orig *TCPConn
	obfs obfs.Obfuscator

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewObfsFakeTCPConn(orig *TCPConn, obfs obfs.Obfuscator) *ObfsFakeTCPPacketConn {
	return &ObfsFakeTCPPacketConn{
		orig:     orig,
		obfs:     obfs,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
	}
}

func (c *ObfsFakeTCPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
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

func (c *ObfsFakeTCPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
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

func (c *ObfsFakeTCPPacketConn) Close() error {
	return c.orig.Close()
}

func (c *ObfsFakeTCPPacketConn) LocalAddr() net.Addr {
	return c.orig.LocalAddr()
}

func (c *ObfsFakeTCPPacketConn) SetDeadline(t time.Time) error {
	return c.orig.SetDeadline(t)
}

func (c *ObfsFakeTCPPacketConn) SetReadDeadline(t time.Time) error {
	return c.orig.SetReadDeadline(t)
}

func (c *ObfsFakeTCPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.orig.SetWriteDeadline(t)
}

func (c *ObfsFakeTCPPacketConn) SetReadBuffer(bytes int) error {
	return c.orig.SetReadBuffer(bytes)
}

func (c *ObfsFakeTCPPacketConn) SetWriteBuffer(bytes int) error {
	return c.orig.SetWriteBuffer(bytes)
}

func (c *ObfsFakeTCPPacketConn) SyscallConn() (syscall.RawConn, error) {
	return c.orig.SyscallConn()
}
