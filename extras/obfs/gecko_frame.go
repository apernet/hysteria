package obfs

import "errors"

const (
	geckoFlagFragment = 0x80
	geckoMaskPadLen   = 0x7f

	geckoHeaderNonFrag = 1
	geckoHeaderFrag    = 3

	geckoMaxPadding        = 1<<7 - 1
	geckoMinFragmentChunks = 2
	geckoMaxFragmentChunks = 8
)

var (
	errFrameTruncated = errors.New("gecko frame truncated")
	errFrameInvalid   = errors.New("gecko frame invalid")
)

// frameHeader is the parsed Gecko frame header.
// Wire layout (after Salamander decrypts the datagram):
//
//	byte 0: [F:1 | padLen:7]               F = isFragment, padLen ∈ [0, 127]
//	if F=1:
//	  byte 1: msgID:8
//	  byte 2: [chunkIdx:4 | totalChunks:4] totalChunks ∈ [2, 10]; chunkIdx < totalChunks
//	then padLen bytes of random padding
//	then the QUIC payload (or one chunk of it)
type frameHeader struct {
	isFragment  bool
	padLen      uint8 // 0..127
	msgID       uint8 // valid only when isFragment
	chunkIdx    uint8 // 0..totalChunks-1
	totalChunks uint8 // 2..8
}

func (h frameHeader) headerSize() int {
	if h.isFragment {
		return geckoHeaderFrag
	}
	return geckoHeaderNonFrag
}

// encodeFrame writes a frame into out: header bytes, then h.padLen random
// padding bytes copied from padding, then the entire payload. out must be at
// least h.headerSize() + h.padLen + len(payload) long; padding must hold at
// least h.padLen bytes. Returns total bytes written.
func encodeFrame(h frameHeader, padding, payload, out []byte) (int, error) {
	if h.padLen > geckoMaxPadding {
		return 0, errFrameInvalid
	}
	if int(h.padLen) > len(padding) {
		return 0, errFrameInvalid
	}
	if h.isFragment {
		if h.totalChunks < geckoMinFragmentChunks || h.totalChunks > geckoMaxFragmentChunks {
			return 0, errFrameInvalid
		}
		if h.chunkIdx >= h.totalChunks {
			return 0, errFrameInvalid
		}
	}
	needed := h.headerSize() + int(h.padLen) + len(payload)
	if len(out) < needed {
		return 0, errFrameTruncated
	}
	b0 := h.padLen & geckoMaskPadLen
	if h.isFragment {
		b0 |= geckoFlagFragment
	}
	out[0] = b0
	off := 1
	if h.isFragment {
		out[1] = h.msgID
		out[2] = (h.chunkIdx&0x0f)<<4 | (h.totalChunks & 0x0f)
		off = 3
	}
	copy(out[off:], padding[:h.padLen])
	off += int(h.padLen)
	copy(out[off:], payload)
	off += len(payload)
	return off, nil
}

// decodeFrame parses a frame from in. The returned payload is a sub-slice of
// in (zero-copy) covering the bytes after the header and padding.
func decodeFrame(in []byte) (frameHeader, []byte, error) {
	if len(in) < 1 {
		return frameHeader{}, nil, errFrameTruncated
	}
	var h frameHeader
	h.isFragment = in[0]&geckoFlagFragment != 0
	h.padLen = in[0] & geckoMaskPadLen
	off := 1
	if h.isFragment {
		if len(in) < geckoHeaderFrag {
			return frameHeader{}, nil, errFrameTruncated
		}
		h.msgID = in[1]
		h.chunkIdx = (in[2] >> 4) & 0x0f
		h.totalChunks = in[2] & 0x0f
		if h.totalChunks < geckoMinFragmentChunks || h.totalChunks > geckoMaxFragmentChunks {
			return frameHeader{}, nil, errFrameInvalid
		}
		if h.chunkIdx >= h.totalChunks {
			return frameHeader{}, nil, errFrameInvalid
		}
		off = geckoHeaderFrag
	}
	if off+int(h.padLen) > len(in) {
		return frameHeader{}, nil, errFrameTruncated
	}
	return h, in[off+int(h.padLen):], nil
}
