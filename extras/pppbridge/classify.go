package pppbridge

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const hexHeadMax = 64

// hexHead returns a hex dump of the first hexHeadMax bytes of b,
// appending "...(N total)" when truncated.
func hexHead(b []byte) string {
	if len(b) <= hexHeadMax {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%s...(%d total)", hex.EncodeToString(b[:hexHeadMax]), len(b))
}

// isControlFrame checks if a raw PPP frame is a control frame (protocol >= 0x4000).
// Handles both ACFC (address/control field compression) and PFC (protocol field compression).
func isControlFrame(rawPPP []byte) bool {
	off := 0
	if len(rawPPP) >= 2 && rawPPP[0] == 0xFF && rawPPP[1] == 0x03 {
		off = 2
	}
	if off >= len(rawPPP) {
		return true // empty or malformed → treat as control to stay safe
	}
	if rawPPP[off]&0x01 == 1 {
		// PFC: 1-byte protocol, always < 0x100, therefore < 0x4000 → data
		return false
	}
	if off+2 > len(rawPPP) {
		return true
	}
	proto := binary.BigEndian.Uint16(rawPPP[off : off+2])
	return proto >= 0x4000
}

// isMPWithControlPayload returns true when rawPPP is a single-fragment MP
// frame (B=1,E=1) whose inner payload is a control protocol (>= 0x4000).
// Used by the bridge to route NCP-containing MP through the reliable control
// stream instead of unreliable datagrams.
func isMPWithControlPayload(rawPPP []byte) bool {
	off := 0
	if len(rawPPP) >= 2 && rawPPP[0] == 0xFF && rawPPP[1] == 0x03 {
		off = 2
	}
	if off >= len(rawPPP) {
		return false
	}

	// Determine outer protocol (with PFC handling).
	var outerProto uint16
	if rawPPP[off]&0x01 == 1 {
		outerProto = uint16(rawPPP[off])
		off++
	} else {
		if off+2 > len(rawPPP) {
			return false
		}
		outerProto = binary.BigEndian.Uint16(rawPPP[off : off+2])
		off += 2
	}
	if outerProto != 0x003D { // not MP
		return false
	}

	// MP short-seq header: 1 byte flags + 1 byte seq-low = 2 bytes.
	if off+2 > len(rawPPP) {
		return false
	}
	flags := rawPPP[off]
	if flags&0xC0 != 0xC0 { // not single-fragment (B=1,E=1)
		return false
	}
	off += 2

	// Inner protocol (with PFC handling).
	if off >= len(rawPPP) {
		return false
	}
	if rawPPP[off]&0x01 == 1 {
		return false // 1-byte proto always < 0x4000
	}
	if off+2 > len(rawPPP) {
		return false
	}
	innerProto := binary.BigEndian.Uint16(rawPPP[off : off+2])
	return innerProto >= 0x4000
}

// extractHDLCFrame finds the first complete HDLC frame in the buffer.
// Returns the frame bytes (including flags), remaining bytes, and whether a frame was found.
func extractHDLCFrame(buf []byte) (frame, rest []byte, ok bool) {
	start := -1
	for i, b := range buf {
		if b == hdlcFlag {
			if start == -1 {
				start = i
			} else if i > start+1 {
				return buf[start : i+1], buf[i:], true
			} else {
				start = i
			}
		}
	}
	return nil, buf, false
}

// decodeHDLCFramePayload decodes a single HDLC frame (with flags) and returns the PPP payload.
func decodeHDLCFramePayload(frame []byte) ([]byte, error) {
	return DecodeHDLC(frame)
}
