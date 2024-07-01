package quic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/apernet/quic-go/quicvarint"
)

// The Header represents a QUIC header.
type Header struct {
	Type             uint8
	Version          uint32
	SrcConnectionID  []byte
	DestConnectionID []byte
	Length           int64
	Token            []byte
}

// ParseInitialHeader parses the initial packet of a QUIC connection,
// return the initial header and number of bytes read so far.
func ParseInitialHeader(data []byte) (*Header, int64, error) {
	br := bytes.NewReader(data)
	hdr, err := parseLongHeader(br)
	if err != nil {
		return nil, 0, err
	}
	n := int64(len(data) - br.Len())
	return hdr, n, nil
}

func parseLongHeader(b *bytes.Reader) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	h := &Header{}
	ver, err := beUint32(b)
	if err != nil {
		return nil, err
	}
	h.Version = ver
	if h.Version != 0 && typeByte&0x40 == 0 {
		return nil, errors.New("not a QUIC packet")
	}
	destConnIDLen, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	h.DestConnectionID = make([]byte, int(destConnIDLen))
	if err := readConnectionID(b, h.DestConnectionID); err != nil {
		return nil, err
	}
	srcConnIDLen, err := b.ReadByte()
	if err != nil {
		return nil, err
	}
	h.SrcConnectionID = make([]byte, int(srcConnIDLen))
	if err := readConnectionID(b, h.SrcConnectionID); err != nil {
		return nil, err
	}

	initialPacketType := byte(0b00)
	if h.Version == V2 {
		initialPacketType = 0b01
	}
	if (typeByte >> 4 & 0b11) == initialPacketType {
		tokenLen, err := quicvarint.Read(b)
		if err != nil {
			return nil, err
		}
		if tokenLen > uint64(b.Len()) {
			return nil, io.EOF
		}
		h.Token = make([]byte, tokenLen)
		if _, err := io.ReadFull(b, h.Token); err != nil {
			return nil, err
		}
	}

	pl, err := quicvarint.Read(b)
	if err != nil {
		return nil, err
	}
	h.Length = int64(pl)
	return h, err
}

func readConnectionID(r io.Reader, cid []byte) error {
	_, err := io.ReadFull(r, cid)
	if err == io.ErrUnexpectedEOF {
		return io.EOF
	}
	return nil
}

func beUint32(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}
