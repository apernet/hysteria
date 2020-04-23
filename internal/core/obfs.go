package core

import (
	"net"
	"time"
)

type Obfuscator interface {
	Deobfuscate(buf []byte, n int) int
	Obfuscate(p []byte) []byte
}

type obfsPacketConn struct {
	Orig       net.PacketConn
	Obfuscator Obfuscator
}

func (c *obfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	oldN, addr, err := c.Orig.ReadFrom(p)
	if oldN > 0 {
		newN := c.Obfuscator.Deobfuscate(p, oldN)
		return newN, addr, err
	} else {
		return 0, addr, err
	}
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	np := c.Obfuscator.Obfuscate(p)
	_, err = c.Orig.WriteTo(np, addr)
	if err != nil {
		return 0, err
	} else {
		return len(p), nil
	}
}

func (c *obfsPacketConn) Close() error {
	return c.Orig.Close()
}

func (c *obfsPacketConn) LocalAddr() net.Addr {
	return c.Orig.LocalAddr()
}

func (c *obfsPacketConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

func (c *obfsPacketConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

func (c *obfsPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}
