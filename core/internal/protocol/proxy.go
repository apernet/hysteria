package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/apernet/hysteria/core/errors"

	"github.com/quic-go/quic-go/quicvarint"
)

const (
	FrameTypeTCPRequest = 0x401
	FrameTypeUDPRequest = 0x402

	MaxAddressLength = 2048 // for preventing DoS attack by sending a very large address length
	MaxMessageLength = 2048 // for preventing DoS attack by sending a very large message length

	MaxUDPSize = 4096

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// TCPRequest format:
// 0x401 (QUIC varint)
// Address length (QUIC varint)
// Address (bytes)

func ReadTCPRequest(r io.Reader) (string, error) {
	bReader := quicvarint.NewReader(r)
	l, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if l == 0 || l > MaxAddressLength {
		return "", errors.ProtocolError{Message: "invalid address length"}
	}
	buf := make([]byte, l)
	_, err = io.ReadFull(r, buf)
	return string(buf), err
}

func WriteTCPRequest(w io.Writer, addr string) error {
	l := len(addr)
	sz := int(quicvarint.Len(FrameTypeTCPRequest)) + int(quicvarint.Len(uint64(l))) + l
	buf := make([]byte, sz)
	i := varintPut(buf, FrameTypeTCPRequest)
	i += varintPut(buf[i:], uint64(l))
	copy(buf[i:], addr)
	_, err := w.Write(buf)
	return err
}

// TCPResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (QUIC varint)
// Message (bytes)

func ReadTCPResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	bReader := quicvarint.NewReader(r)
	l, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if l == 0 {
		// No message is ok
		return status[0] == 0, "", nil
	}
	if l > MaxMessageLength {
		return false, "", errors.ProtocolError{Message: "invalid message length"}
	}
	buf := make([]byte, l)
	_, err = io.ReadFull(r, buf)
	return status[0] == 0, string(buf), err
}

func WriteTCPResponse(w io.Writer, ok bool, msg string) error {
	l := len(msg)
	sz := 1 + int(quicvarint.Len(uint64(l))) + l
	buf := make([]byte, sz)
	if ok {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	i := varintPut(buf[1:], uint64(l))
	copy(buf[1+i:], msg)
	_, err := w.Write(buf)
	return err
}

// UDPRequest format:
// 0x402 (QUIC varint)

// Nothing to read

func WriteUDPRequest(w io.Writer) error {
	buf := make([]byte, quicvarint.Len(FrameTypeUDPRequest))
	varintPut(buf, FrameTypeUDPRequest)
	_, err := w.Write(buf)
	return err
}

// UDPResponse format:
// Status (byte, 0=ok, 1=error)
// Session ID (uint32 BE)
// Message length (QUIC varint)
// Message (bytes)

func ReadUDPResponse(r io.Reader) (bool, uint32, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, 0, "", err
	}
	var sessionID uint32
	if err := binary.Read(r, binary.BigEndian, &sessionID); err != nil {
		return false, 0, "", err
	}
	bReader := quicvarint.NewReader(r)
	l, err := quicvarint.Read(bReader)
	if err != nil {
		return false, 0, "", err
	}
	if l == 0 {
		// No message is ok
		return status[0] == 0, sessionID, "", nil
	}
	if l > MaxMessageLength {
		return false, 0, "", errors.ProtocolError{Message: "invalid message length"}
	}
	buf := make([]byte, l)
	_, err = io.ReadFull(r, buf)
	return status[0] == 0, sessionID, string(buf), err
}

func WriteUDPResponse(w io.Writer, ok bool, sessionID uint32, msg string) error {
	l := len(msg)
	buf := make([]byte, 5+int(quicvarint.Len(uint64(l)))+l)
	if ok {
		buf[0] = 0
	} else {
		buf[0] = 1
	}
	binary.BigEndian.PutUint32(buf[1:], sessionID)
	i := varintPut(buf[5:], uint64(l))
	copy(buf[5+i:], msg)
	_, err := w.Write(buf)
	return err
}

// UDPMessage format:
// Session ID (uint32 BE)
// Packet ID (uint16 BE)
// Fragment ID (uint8)
// Fragment count (uint8)
// Address length (QUIC varint)
// Address (bytes)
// Data...

type UDPMessage struct {
	SessionID uint32 // 4
	PacketID  uint16 // 2
	FragID    uint8  // 1
	FragCount uint8  // 1
	Addr      string // varint + bytes
	Data      []byte
}

func (m *UDPMessage) HeaderSize() int {
	lAddr := len(m.Addr)
	return 4 + 2 + 1 + 1 + int(quicvarint.Len(uint64(lAddr))) + lAddr
}

func (m *UDPMessage) Size() int {
	return m.HeaderSize() + len(m.Data)
}

func (m *UDPMessage) Serialize(buf []byte) int {
	// Make sure the buffer is big enough
	if len(buf) < m.Size() {
		return -1
	}
	binary.BigEndian.PutUint32(buf, m.SessionID)
	binary.BigEndian.PutUint16(buf[4:], m.PacketID)
	buf[6] = m.FragID
	buf[7] = m.FragCount
	i := varintPut(buf[8:], uint64(len(m.Addr)))
	i += copy(buf[8+i:], m.Addr)
	i += copy(buf[8+i:], m.Data)
	return 8 + i
}

func ParseUDPMessage(msg []byte) (*UDPMessage, error) {
	m := &UDPMessage{}
	buf := bytes.NewBuffer(msg)
	if err := binary.Read(buf, binary.BigEndian, &m.SessionID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &m.PacketID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &m.FragID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &m.FragCount); err != nil {
		return nil, err
	}
	lAddr, err := quicvarint.Read(buf)
	if err != nil {
		return nil, err
	}
	if lAddr == 0 || lAddr > MaxMessageLength {
		return nil, errors.ProtocolError{Message: "invalid address length"}
	}
	bs := buf.Bytes()
	m.Addr = string(bs[:lAddr])
	m.Data = bs[lAddr:]
	return m, nil
}

// varintPut is like quicvarint.Append, but instead of appending to a slice,
// it writes to a fixed-size buffer. Returns the number of bytes written.
func varintPut(b []byte, i uint64) int {
	if i <= maxVarInt1 {
		b[0] = uint8(i)
		return 1
	}
	if i <= maxVarInt2 {
		b[0] = uint8(i>>8) | 0x40
		b[1] = uint8(i)
		return 2
	}
	if i <= maxVarInt4 {
		b[0] = uint8(i>>24) | 0x80
		b[1] = uint8(i >> 16)
		b[2] = uint8(i >> 8)
		b[3] = uint8(i)
		return 4
	}
	if i <= maxVarInt8 {
		b[0] = uint8(i>>56) | 0xc0
		b[1] = uint8(i >> 48)
		b[2] = uint8(i >> 40)
		b[3] = uint8(i >> 32)
		b[4] = uint8(i >> 24)
		b[5] = uint8(i >> 16)
		b[6] = uint8(i >> 8)
		b[7] = uint8(i)
		return 8
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}
