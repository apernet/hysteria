package quic

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/apernet/quic-go/quicvarint"
	"golang.org/x/crypto/hkdf"
)

const (
	maxCryptoFrameDataLen = 256 * 1024 // 256 KiB
	maxCryptoPayloadLen   = 256 * 1024 // 256 KiB
)

func ReadCryptoPayload(packet []byte) ([]byte, error) {
	hdr, offset, err := ParseInitialHeader(packet)
	if err != nil {
		return nil, err
	}
	// Some sanity checks
	if hdr.Version != V1 && hdr.Version != V2 {
		return nil, fmt.Errorf("unsupported version: %x", hdr.Version)
	}
	if offset == 0 || hdr.Length == 0 {
		return nil, errors.New("invalid packet")
	}

	initialSecret := hkdf.Extract(crypto.SHA256.New, hdr.DestConnectionID, getSalt(hdr.Version))
	clientSecret := hkdfExpandLabel(crypto.SHA256.New, initialSecret, "client in", []byte{}, crypto.SHA256.Size())
	key, err := NewInitialProtectionKey(clientSecret, hdr.Version)
	if err != nil {
		return nil, fmt.Errorf("NewInitialProtectionKey: %w", err)
	}
	pp := NewPacketProtector(key)
	// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#name-client-initial
	//
	// "The unprotected header includes the connection ID and a 4-byte packet number encoding for a packet number of 2"
	if int64(len(packet)) < offset+hdr.Length {
		return nil, fmt.Errorf("packet is too short: %d < %d", len(packet), offset+hdr.Length)
	}
	unProtectedPayload, err := pp.UnProtect(packet[:offset+hdr.Length], offset, 2)
	if err != nil {
		return nil, err
	}
	frs, err := extractCryptoFrames(bytes.NewReader(unProtectedPayload))
	if err != nil {
		return nil, err
	}
	data := assembleCryptoFrames(frs)
	if data == nil {
		return nil, errors.New("unable to assemble crypto frames")
	}
	return data, nil
}

const (
	paddingFrameType = 0x00
	pingFrameType    = 0x01
	cryptoFrameType  = 0x06
)

type cryptoFrame struct {
	Offset int64
	Data   []byte
}

func extractCryptoFrames(r *bytes.Reader) ([]cryptoFrame, error) {
	var frames []cryptoFrame
	for r.Len() > 0 {
		typ, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		if typ == paddingFrameType || typ == pingFrameType {
			continue
		}
		if typ != cryptoFrameType {
			return nil, fmt.Errorf("encountered unexpected frame type: %d", typ)
		}
		var frame cryptoFrame
		offset, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		if offset > uint64(math.MaxInt64) {
			return nil, errors.New("invalid crypto frame offset")
		}
		frame.Offset = int64(offset)
		dataLen, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		if dataLen > maxCryptoFrameDataLen {
			return nil, errors.New("crypto frame data too large")
		}
		if dataLen > uint64(r.Len()) {
			return nil, io.ErrUnexpectedEOF
		}
		frame.Data = make([]byte, dataLen)
		if _, err := io.ReadFull(r, frame.Data); err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

// assembleCryptoFrames assembles multiple crypto frames into a single slice (if possible).
// It returns an error if the frames cannot be assembled. This can happen if the frames are not contiguous.
func assembleCryptoFrames(frames []cryptoFrame) []byte {
	if len(frames) == 0 {
		return nil
	}
	if len(frames) == 1 {
		return frames[0].Data
	}
	// sort the frames by offset
	sort.Slice(frames, func(i, j int) bool { return frames[i].Offset < frames[j].Offset })
	// check if the frames are contiguous
	for i := 1; i < len(frames); i++ {
		if frames[i].Offset != frames[i-1].Offset+int64(len(frames[i-1].Data)) {
			return nil
		}
	}
	// concatenate the frames
	last := frames[len(frames)-1]
	if last.Offset < 0 {
		return nil
	}
	if last.Offset > maxCryptoPayloadLen {
		return nil
	}
	end := last.Offset + int64(len(last.Data))
	if end < 0 || end > maxCryptoPayloadLen {
		return nil
	}
	data := make([]byte, end)
	for _, frame := range frames {
		copy(data[frame.Offset:], frame.Data)
	}
	return data
}
