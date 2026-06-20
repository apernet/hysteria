package obfs

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeDecodeFrame(t *testing.T) {
	payload := []byte{0xa1, 0xb2, 0xc3, 0xd4}
	for total := geckoMinFragmentChunks; total <= geckoMaxFragmentChunks; total++ {
		for idx := 0; idx < total; idx++ {
			for _, padLen := range []int{0, 1, 64, 127, 512, 1100} {
				h := frameHeader{
					padLen:      uint16(padLen),
					msgID:       0xa5,
					chunkIdx:    uint8(idx),
					totalChunks: uint8(total),
				}
				out := make([]byte, geckoHeaderSize+padLen+len(payload))
				n, err := encodeFrame(h, payload, out)
				if err != nil {
					t.Fatalf("encode total=%d idx=%d padLen=%d: %v", total, idx, padLen, err)
				}
				if n != len(out) {
					t.Fatalf("encode wrote %d, want %d", n, len(out))
				}
				got, body, err := decodeFrame(out)
				if err != nil {
					t.Fatalf("decode total=%d idx=%d padLen=%d: %v", total, idx, padLen, err)
				}
				if got != h {
					t.Fatalf("header mismatch: got %+v want %+v", got, h)
				}
				if !bytes.Equal(body, payload) {
					t.Fatalf("payload mismatch total=%d idx=%d padLen=%d", total, idx, padLen)
				}
			}
		}
	}
}

func TestEncodeFrameRejectsInvalid(t *testing.T) {
	payload := []byte{0xff}
	cases := []struct {
		name string
		h    frameHeader
		err  error
	}{
		{"totalChunks zero", frameHeader{totalChunks: 0}, errFrameInvalid},
		{"totalChunks one", frameHeader{totalChunks: 1}, errFrameInvalid},
		{"totalChunks nine", frameHeader{totalChunks: 9}, errFrameInvalid},
		{"chunkIdx out of range", frameHeader{totalChunks: 4, chunkIdx: 4}, errFrameInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := make([]byte, 1024)
			if _, err := encodeFrame(tc.h, payload, out); !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
		})
	}
}

func TestEncodeFrameRejectsShortBuffer(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	h := frameHeader{padLen: 8, totalChunks: 2, chunkIdx: 0}
	out := make([]byte, 5) // need 5 + 8 + 3 = 16
	if _, err := encodeFrame(h, payload, out); !errors.Is(err, errFrameTruncated) {
		t.Fatalf("got %v, want %v", err, errFrameTruncated)
	}
}

func TestDecodeFrameRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		err  error
	}{
		{"empty", []byte{}, errFrameTruncated},
		{"header truncated", []byte{0x80, 0x55, 0x22, 0x00}, errFrameTruncated},
		{"not a fragment", []byte{0x00, 0x00, 0x22, 0x00, 0x00}, errFrameInvalid},
		{"totalChunks zero", []byte{0x80, 0x00, 0x00, 0x00, 0x00}, errFrameInvalid},
		{"totalChunks one", []byte{0x80, 0x00, 0x01, 0x00, 0x00}, errFrameInvalid},
		{"totalChunks nine", []byte{0x80, 0x00, 0x09, 0x00, 0x00}, errFrameInvalid},
		{"chunkIdx == totalChunks", []byte{0x80, 0x00, 0x44, 0x00, 0x00}, errFrameInvalid},
		{"padLen overrun", []byte{0x80, 0x00, 0x02, 0x00, 0x12, 0x01, 0x02}, errFrameTruncated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := decodeFrame(tc.in); !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
		})
	}
}
