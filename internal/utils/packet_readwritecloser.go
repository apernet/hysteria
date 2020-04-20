package utils

import (
	"encoding/binary"
	"fmt"
	"io"
)

type PacketReadWriteCloser struct {
	Orig io.ReadWriteCloser
}

func (rw *PacketReadWriteCloser) Read(p []byte) (n int, err error) {
	var sz uint32
	if err := binary.Read(rw.Orig, binary.BigEndian, &sz); err != nil {
		return 0, err
	}
	if int(sz) <= len(p) {
		return io.ReadFull(rw.Orig, p[:sz])
	} else {
		return 0, fmt.Errorf("the buffer is too small to hold %d bytes of packet data", sz)
	}
}

func (rw *PacketReadWriteCloser) Write(p []byte) (n int, err error) {
	sz := uint32(len(p))
	if err := binary.Write(rw.Orig, binary.BigEndian, &sz); err != nil {
		return 0, err
	}
	return rw.Orig.Write(p)
}

func (rw *PacketReadWriteCloser) Close() error {
	return rw.Orig.Close()
}
