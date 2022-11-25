package wechat

import (
	"encoding/binary"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/hysteria/core/pktconns/obfs"
)

const udpBufferSize = 4096

// ObfsWeChatUDPPacketConn is still a UDP packet conn, but it adds WeChat video call header to each packet.
// Obfs in this case can be nil
type ObfsWeChatUDPPacketConn struct {
	orig *net.UDPConn
	obfs obfs.Obfuscator

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
	sn         uint32
}

func NewObfsWeChatUDPConn(orig *net.UDPConn, obfs obfs.Obfuscator) *ObfsWeChatUDPPacketConn {
	return &ObfsWeChatUDPPacketConn{
		orig:     orig,
		obfs:     obfs,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
		sn:       rand.Uint32() & 0xFFFF,
	}
}

func (c *ObfsWeChatUDPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.readMutex.Lock()
		n, addr, err := c.orig.ReadFrom(c.readBuf)
		if n <= 13 {
			c.readMutex.Unlock()
			return 0, addr, err
		}
		var newN int
		if c.obfs != nil {
			newN = c.obfs.Deobfuscate(c.readBuf[13:n], p)
		} else {
			newN = copy(p, c.readBuf[13:n])
		}
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

func (c *ObfsWeChatUDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMutex.Lock()
	c.writeBuf[0] = 0xa1
	c.writeBuf[1] = 0x08
	binary.BigEndian.PutUint32(c.writeBuf[2:], c.sn)
	c.sn++
	c.writeBuf[6] = 0x00
	c.writeBuf[7] = 0x10
	c.writeBuf[8] = 0x11
	c.writeBuf[9] = 0x18
	c.writeBuf[10] = 0x30
	c.writeBuf[11] = 0x22
	c.writeBuf[12] = 0x30
	var bn int
	if c.obfs != nil {
		bn = c.obfs.Obfuscate(p, c.writeBuf[13:])
	} else {
		bn = copy(c.writeBuf[13:], p)
	}
	_, err = c.orig.WriteTo(c.writeBuf[:13+bn], addr)
	c.writeMutex.Unlock()
	if err != nil {
		return 0, err
	} else {
		return len(p), nil
	}
}

func (c *ObfsWeChatUDPPacketConn) Close() error {
	return c.orig.Close()
}

func (c *ObfsWeChatUDPPacketConn) LocalAddr() net.Addr {
	return c.orig.LocalAddr()
}

func (c *ObfsWeChatUDPPacketConn) SetDeadline(t time.Time) error {
	return c.orig.SetDeadline(t)
}

func (c *ObfsWeChatUDPPacketConn) SetReadDeadline(t time.Time) error {
	return c.orig.SetReadDeadline(t)
}

func (c *ObfsWeChatUDPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.orig.SetWriteDeadline(t)
}

func (c *ObfsWeChatUDPPacketConn) SetReadBuffer(bytes int) error {
	return c.orig.SetReadBuffer(bytes)
}

func (c *ObfsWeChatUDPPacketConn) SetWriteBuffer(bytes int) error {
	return c.orig.SetWriteBuffer(bytes)
}

func (c *ObfsWeChatUDPPacketConn) SyscallConn() (syscall.RawConn, error) {
	return c.orig.SyscallConn()
}

func (c *ObfsWeChatUDPPacketConn) File() (f *os.File, err error) {
	return c.orig.File()
}
