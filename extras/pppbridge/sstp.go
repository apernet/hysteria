package pppbridge

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// SSTP constants
const (
	sstpVersion = 0x10

	sstpMsgCallConnectRequest = 0x0001
	sstpMsgCallConnectAck     = 0x0002
	sstpMsgCallConnected      = 0x0004
	sstpMsgCallAbort          = 0x0005
	sstpMsgCallDisconnect     = 0x0006
	sstpMsgCallDisconnectAck  = 0x0007
	sstpMsgEchoRequest        = 0x0008
	sstpMsgEchoResponse       = 0x0009

	sstpAttrCryptoBinding    = 0x03
	sstpAttrCryptoBindingReq = 0x04

	sstpCertHashProtocolBitmask = 0x03 // SHA1 + SHA256

	sstpDuplexURI = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"
)

// readSSTPHTTPRequest manually parses the SSTP HTTP request without using
// http.ReadRequest, which rejects the SSTP-mandated Content-Length of
// ULONGLONG_MAX (18446744073709551615) because Go parses it as int64.
func readSSTPHTTPRequest(reader *bufio.Reader) (method, path string, err error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", "", fmt.Errorf("failed to read request line: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return "", "", fmt.Errorf("malformed request line: %q", line)
	}
	method, path = parts[0], parts[1]

	// Consume remaining headers until blank line
	for {
		hdr, err := reader.ReadString('\n')
		if err != nil {
			return "", "", fmt.Errorf("failed to read headers: %w", err)
		}
		if hdr == "\r\n" || hdr == "\n" {
			break
		}
	}
	return method, path, nil
}

// SSTP packet format:
// [1 byte: version 0x10] [1 byte: C bit + reserved] [2 bytes: length BE]
// If C=1 (control): [2 bytes: message type] [2 bytes: num attributes] [attributes...]
// If C=0 (data): [PPP frame bytes...]

func readSSTPPacket(reader *bufio.Reader) (payload []byte, isData bool, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(reader, hdr[:]); err != nil {
		return nil, false, err
	}
	if hdr[0] != sstpVersion {
		return nil, false, fmt.Errorf("unexpected SSTP version: 0x%02x", hdr[0])
	}
	isControl := (hdr[1] & 0x01) != 0
	length := binary.BigEndian.Uint16(hdr[2:4])
	if length < 4 {
		return nil, false, fmt.Errorf("SSTP packet too short: %d", length)
	}
	payload = make([]byte, length-4)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, false, err
	}
	return payload, !isControl, nil
}

func readSSTPControl(reader *bufio.Reader) (msgType uint16, attrs []byte, err error) {
	payload, isData, err := readSSTPPacket(reader)
	if err != nil {
		return 0, nil, err
	}
	if isData {
		return 0, nil, errors.New("expected control packet, got data")
	}
	if len(payload) < 4 {
		return 0, nil, errors.New("control packet too short")
	}
	msgType = binary.BigEndian.Uint16(payload[0:2])
	// payload[2:4] = num attributes
	return msgType, payload[4:], nil
}

func writeSSTPControl(conn net.Conn, msgType uint16, attrPayload []byte) error {
	// Header(4) + msgType(2) + numAttrs(2) + attrs
	numAttrs := uint16(0)
	if len(attrPayload) > 0 {
		numAttrs = 1
	}
	totalLen := 4 + 4 + len(attrPayload)
	buf := make([]byte, totalLen)
	buf[0] = sstpVersion
	buf[1] = 0x01 // C=1 (control)
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], msgType)
	binary.BigEndian.PutUint16(buf[6:8], numAttrs)
	copy(buf[8:], attrPayload)
	_, err := conn.Write(buf)
	return err
}

func writeSSTPData(conn net.Conn, pppFrame []byte) error {
	totalLen := 4 + len(pppFrame)
	buf := make([]byte, totalLen)
	buf[0] = sstpVersion
	buf[1] = 0x00 // C=0 (data)
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	copy(buf[4:], pppFrame)
	_, err := conn.Write(buf)
	return err
}

func buildConnectAck(nonce [32]byte) []byte {
	// CryptoBindingReq attribute per MS-SSTP 2.2.4 + 2.2.6:
	// Reserved(1) + AttrID(1) + LengthPacket(2) + Reserved1(3) + HashBitmask(1) + Nonce(32) = 40
	attrLen := 4 + 3 + 1 + 32
	buf := make([]byte, attrLen)
	buf[0] = 0                        // Reserved
	buf[1] = sstpAttrCryptoBindingReq // Attribute ID
	binary.BigEndian.PutUint16(buf[2:4], uint16(attrLen))
	// buf[4:7] = Reserved1 (zeroes)
	buf[7] = sstpCertHashProtocolBitmask // Hash Protocol Bitmask
	copy(buf[8:], nonce[:])
	return buf
}

func sstpHandshake(conn net.Conn, reader *bufio.Reader) ([32]byte, error) {
	var nonce [32]byte

	msgType, _, err := readSSTPControl(reader)
	if err != nil {
		return nonce, fmt.Errorf("failed to read connect request: %w", err)
	}
	if msgType != sstpMsgCallConnectRequest {
		return nonce, fmt.Errorf("expected CALL_CONNECT_REQUEST, got 0x%04x", msgType)
	}

	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, err
	}

	ackPayload := buildConnectAck(nonce)
	if err := writeSSTPControl(conn, sstpMsgCallConnectAck, ackPayload); err != nil {
		return nonce, fmt.Errorf("failed to write connect ack: %w", err)
	}

	return nonce, nil
}

func verifyCryptoBinding(attrs []byte, expectedNonce [32]byte, expectedCertHash [32]byte) error {
	// CryptoBinding attribute per MS-SSTP 2.2.4 + 2.2.7:
	// Reserved(1) + AttrID(1) + Length(2) + Reserved1(3) + HashProto(1) + Nonce(32) + CertHash(32) + MAC(32) = 104
	for len(attrs) >= 4 {
		attrID := attrs[1]
		attrLen := binary.BigEndian.Uint16(attrs[2:4])
		if int(attrLen) > len(attrs) {
			break
		}
		if attrID == sstpAttrCryptoBinding && attrLen >= 104 {
			data := attrs[4:attrLen]
			// data[0:3] = Reserved1, data[3] = Hash Protocol
			nonce := data[4:36]
			certHash := data[36:68]
			// data[68:100] = Compound MAC (skip verification for localhost)

			var gotNonce [32]byte
			copy(gotNonce[:], nonce)
			if gotNonce != expectedNonce {
				return errors.New("nonce mismatch")
			}

			var gotHash [32]byte
			copy(gotHash[:], certHash)
			if gotHash != expectedCertHash {
				return errors.New("cert hash mismatch")
			}

			return nil
		}
		attrs = attrs[attrLen:]
	}
	return errors.New("CryptoBinding attribute not found")
}
