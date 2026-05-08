package obfs

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeDecodeFrameNonFragment(t *testing.T) {
	payload := []byte{0xc0, 0xff, 0xee, 0x12, 0x34}
	pad := make([]byte, geckoMaxPadding)
	for i := range pad {
		pad[i] = byte(i)
	}
	for padLen := 0; padLen <= geckoMaxPadding; padLen++ {
		h := frameHeader{padLen: uint8(padLen)}
		out := make([]byte, geckoHeaderNonFrag+padLen+len(payload))
		n, err := encodeFrame(h, pad, payload, out)
		if err != nil {
			t.Fatalf("padLen=%d encode: %v", padLen, err)
		}
		if n != len(out) {
			t.Fatalf("padLen=%d wrote %d, want %d", padLen, n, len(out))
		}
		got, body, err := decodeFrame(out)
		if err != nil {
			t.Fatalf("padLen=%d decode: %v", padLen, err)
		}
		if got != h {
			t.Fatalf("padLen=%d header mismatch: got %+v want %+v", padLen, got, h)
		}
		if !bytes.Equal(body, payload) {
			t.Fatalf("padLen=%d payload mismatch: got %x want %x", padLen, body, payload)
		}
	}
}

func TestEncodeDecodeFrameFragment(t *testing.T) {
	payload := []byte{0xa1, 0xb2, 0xc3, 0xd4}
	pad := make([]byte, geckoMaxPadding)
	for i := range pad {
		pad[i] = byte(i ^ 0x55)
	}
	for total := geckoMinFragmentChunks; total <= geckoMaxFragmentChunks; total++ {
		for idx := 0; idx < total; idx++ {
			for _, padLen := range []int{0, 1, 64, geckoMaxPadding} {
				h := frameHeader{
					isFragment:  true,
					padLen:      uint8(padLen),
					msgID:       0xa5,
					chunkIdx:    uint8(idx),
					totalChunks: uint8(total),
				}
				out := make([]byte, geckoHeaderFrag+padLen+len(payload))
				if _, err := encodeFrame(h, pad, payload, out); err != nil {
					t.Fatalf("encode total=%d idx=%d padLen=%d: %v", total, idx, padLen, err)
				}
				got, body, err := decodeFrame(out)
				if err != nil {
					t.Fatalf("decode total=%d idx=%d padLen=%d: %v", total, idx, padLen, err)
				}
				if got != h {
					t.Fatalf("header mismatch total=%d idx=%d padLen=%d: got %+v want %+v",
						total, idx, padLen, got, h)
				}
				if !bytes.Equal(body, payload) {
					t.Fatalf("payload mismatch total=%d idx=%d padLen=%d", total, idx, padLen)
				}
			}
		}
	}
}

func TestEncodeFrameRejectsInvalid(t *testing.T) {
	pad := make([]byte, 200)
	payload := []byte{0xff}
	cases := []struct {
		name string
		h    frameHeader
		err  error
	}{
		{"padLen too large", frameHeader{padLen: 128}, errFrameInvalid},
		{"fragment totalChunks zero", frameHeader{isFragment: true, totalChunks: 0}, errFrameInvalid},
		{"fragment totalChunks one", frameHeader{isFragment: true, totalChunks: 1}, errFrameInvalid},
		{"fragment totalChunks eleven", frameHeader{isFragment: true, totalChunks: 11}, errFrameInvalid},
		{"fragment chunkIdx out of range", frameHeader{isFragment: true, totalChunks: 4, chunkIdx: 4}, errFrameInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := make([]byte, 1024)
			if _, err := encodeFrame(tc.h, pad, payload, out); !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
		})
	}
}

func TestEncodeFrameRejectsShortBuffer(t *testing.T) {
	pad := make([]byte, 16)
	payload := []byte{0x01, 0x02, 0x03}
	h := frameHeader{padLen: 8}
	out := make([]byte, 5) // need 1 + 8 + 3 = 12
	if _, err := encodeFrame(h, pad, payload, out); !errors.Is(err, errFrameTruncated) {
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
		{"non-fragment padLen overrun", []byte{0x10, 0xaa, 0xbb}, errFrameTruncated},
		{"fragment header truncated", []byte{0x80, 0x55}, errFrameTruncated},
		{"fragment totalChunks zero", []byte{0x80, 0x00, 0x00}, errFrameInvalid},
		{"fragment totalChunks one", []byte{0x80, 0x00, 0x01}, errFrameInvalid},
		{"fragment totalChunks eleven", []byte{0x80, 0x00, 0x0b}, errFrameInvalid},
		{"fragment chunkIdx == totalChunks", []byte{0x80, 0x00, 0x44}, errFrameInvalid},
		{"fragment padLen overrun", []byte{0x83, 0x00, 0x12, 0x01, 0x02}, errFrameTruncated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := decodeFrame(tc.in); !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
		})
	}
}
