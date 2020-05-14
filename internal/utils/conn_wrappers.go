package utils

import (
	"encoding/binary"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"io"
	"net"
	"time"
)

type PacketWrapperConn struct {
	Orig net.Conn
}

func (w *PacketWrapperConn) Read(b []byte) (n int, err error) {
	var sz uint32
	if err := binary.Read(w.Orig, binary.BigEndian, &sz); err != nil {
		return 0, err
	}
	if int(sz) <= len(b) {
		return io.ReadFull(w.Orig, b[:sz])
	} else {
		return 0, fmt.Errorf("the buffer is too small to hold %d bytes of packet data", sz)
	}
}

func (w *PacketWrapperConn) Write(b []byte) (n int, err error) {
	sz := uint32(len(b))
	if err := binary.Write(w.Orig, binary.BigEndian, &sz); err != nil {
		return 0, err
	}
	return w.Orig.Write(b)
}

func (w *PacketWrapperConn) Close() error {
	return w.Orig.Close()
}

func (w *PacketWrapperConn) LocalAddr() net.Addr {
	return w.Orig.LocalAddr()
}

func (w *PacketWrapperConn) RemoteAddr() net.Addr {
	return w.Orig.RemoteAddr()
}

func (w *PacketWrapperConn) SetDeadline(t time.Time) error {
	return w.Orig.SetDeadline(t)
}

func (w *PacketWrapperConn) SetReadDeadline(t time.Time) error {
	return w.Orig.SetReadDeadline(t)
}

func (w *PacketWrapperConn) SetWriteDeadline(t time.Time) error {
	return w.Orig.SetWriteDeadline(t)
}

type QUICStreamWrapperConn struct {
	Orig             quic.Stream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
}

func (w *QUICStreamWrapperConn) Read(b []byte) (n int, err error) {
	return w.Orig.Read(b)
}

func (w *QUICStreamWrapperConn) Write(b []byte) (n int, err error) {
	return w.Orig.Write(b)
}

func (w *QUICStreamWrapperConn) Close() error {
	return w.Orig.Close()
}

func (w *QUICStreamWrapperConn) LocalAddr() net.Addr {
	return w.PseudoLocalAddr
}

func (w *QUICStreamWrapperConn) RemoteAddr() net.Addr {
	return w.PseudoRemoteAddr
}

func (w *QUICStreamWrapperConn) SetDeadline(t time.Time) error {
	return w.Orig.SetDeadline(t)
}

func (w *QUICStreamWrapperConn) SetReadDeadline(t time.Time) error {
	return w.Orig.SetReadDeadline(t)
}

func (w *QUICStreamWrapperConn) SetWriteDeadline(t time.Time) error {
	return w.Orig.SetWriteDeadline(t)
}
