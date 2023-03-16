package dns

import (
	"encoding/binary"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const udpBufferSize = 4096

type DnsUDPPacketConn struct {
	orig *net.UDPConn

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
	header     []byte
}

func NewDnsUDPConn(orig *net.UDPConn, domain string) *DnsUDPPacketConn {
	var header []byte

	header = binary.BigEndian.AppendUint16(header, 0x0000) // Transaction ID
	header = binary.BigEndian.AppendUint16(header, 0x0100) // Flags: Standard query
	header = binary.BigEndian.AppendUint16(header, 0x0001) // Questions
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Answer RRs
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Authority RRs
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Additional RRs

	buf := make([]byte, 0x100)

	off1, err := dns.PackDomainName(dns.Fqdn(domain), buf, 0, nil, false)

	if err != nil {
		return nil
	}

	header = append(header, buf[:off1]...)

	header = binary.BigEndian.AppendUint16(header, 0x0001) // Type: A
	header = binary.BigEndian.AppendUint16(header, 0x0001) // Class: IN

	return &DnsUDPPacketConn{
		orig:     orig,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
		header:   header,
	}
}

func (c *DnsUDPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.readMutex.Lock()
		n, addr, err := c.orig.ReadFrom(c.readBuf)
		if n <= len(c.header) {
			c.readMutex.Unlock()
			return 0, addr, err
		}

		var newN = copy(p, c.readBuf[len(c.header):n])

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

func (c *DnsUDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.writeMutex.Lock()

	copy(c.writeBuf, c.header)
	binary.BigEndian.PutUint16(c.writeBuf[0:], uint16(rand.Uint32()))

	var bn = copy(c.writeBuf[len(c.header):], p)

	_, err = c.orig.WriteTo(c.writeBuf[:len(c.header)+bn], addr)
	c.writeMutex.Unlock()
	if err != nil {
		return 0, err
	} else {
		return len(p), nil
	}
}

func (c *DnsUDPPacketConn) Close() error {
	return c.orig.Close()
}

func (c *DnsUDPPacketConn) LocalAddr() net.Addr {
	return c.orig.LocalAddr()
}

func (c *DnsUDPPacketConn) SetDeadline(t time.Time) error {
	return c.orig.SetDeadline(t)
}

func (c *DnsUDPPacketConn) SetReadDeadline(t time.Time) error {
	return c.orig.SetReadDeadline(t)
}

func (c *DnsUDPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.orig.SetWriteDeadline(t)
}

func (c *DnsUDPPacketConn) SetReadBuffer(bytes int) error {
	return c.orig.SetReadBuffer(bytes)
}

func (c *DnsUDPPacketConn) SetWriteBuffer(bytes int) error {
	return c.orig.SetWriteBuffer(bytes)
}

func (c *DnsUDPPacketConn) SyscallConn() (syscall.RawConn, error) {
	return c.orig.SyscallConn()
}

func (c *DnsUDPPacketConn) File() (f *os.File, err error) {
	return c.orig.File()
}
