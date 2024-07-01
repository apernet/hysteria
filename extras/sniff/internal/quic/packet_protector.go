package quic

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

// NewProtectionKey creates a new ProtectionKey.
func NewProtectionKey(suite uint16, secret []byte, v uint32) (*ProtectionKey, error) {
	return newProtectionKey(suite, secret, v)
}

// NewInitialProtectionKey is like NewProtectionKey, but the returned protection key
// is used for encrypt/decrypt Initial Packet only.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#name-initial-secrets
func NewInitialProtectionKey(secret []byte, v uint32) (*ProtectionKey, error) {
	return NewProtectionKey(tls.TLS_AES_128_GCM_SHA256, secret, v)
}

// NewPacketProtector creates a new PacketProtector.
func NewPacketProtector(key *ProtectionKey) *PacketProtector {
	return &PacketProtector{key: key}
}

// PacketProtector is used for protecting a QUIC packet.
//
// See: https://www.rfc-editor.org/rfc/rfc9001.html#name-packet-protection
type PacketProtector struct {
	key *ProtectionKey
}

// UnProtect decrypts a QUIC packet.
func (pp *PacketProtector) UnProtect(packet []byte, pnOffset, pnMax int64) ([]byte, error) {
	if isLongHeader(packet[0]) && int64(len(packet)) < pnOffset+4+16 {
		return nil, errors.New("packet with long header is too small")
	}

	// https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection-sample
	sampleOffset := pnOffset + 4
	sample := packet[sampleOffset : sampleOffset+16]

	// https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection-applicati
	mask := pp.key.headerProtection(sample)
	if isLongHeader(packet[0]) {
		// Long header: 4 bits masked
		packet[0] ^= mask[0] & 0x0f
	} else {
		// Short header: 5 bits masked
		packet[0] ^= mask[0] & 0x1f
	}

	pnLen := packet[0]&0x3 + 1
	pn := int64(0)
	for i := uint8(0); i < pnLen; i++ {
		packet[pnOffset:][i] ^= mask[1+i]
		pn = (pn << 8) | int64(packet[pnOffset:][i])
	}
	pn = decodePacketNumber(pnMax, pn, pnLen)
	hdr := packet[:pnOffset+int64(pnLen)]
	payload := packet[pnOffset:][pnLen:]
	dec, err := pp.key.aead.Open(payload[:0], pp.key.nonce(pn), payload, hdr)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return dec, nil
}

// ProtectionKey is the key used to protect a QUIC packet.
type ProtectionKey struct {
	aead             cipher.AEAD
	headerProtection func(sample []byte) (mask []byte)
	iv               []byte
}

// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#name-aead-usage
//
// "The 62 bits of the reconstructed QUIC packet number in network byte order are
// left-padded with zeros to the size of the IV. The exclusive OR of the padded
// packet number and the IV forms the AEAD nonce."
func (pk *ProtectionKey) nonce(pn int64) []byte {
	nonce := make([]byte, len(pk.iv))
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(pn))
	for i := range pk.iv {
		nonce[i] ^= pk.iv[i]
	}
	return nonce
}

func newProtectionKey(suite uint16, secret []byte, v uint32) (*ProtectionKey, error) {
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
		key := hkdfExpandLabel(crypto.SHA256.New, secret, keyLabel(v), nil, 16)
		c, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		aead, err := cipher.NewGCM(c)
		if err != nil {
			panic(err)
		}
		iv := hkdfExpandLabel(crypto.SHA256.New, secret, ivLabel(v), nil, aead.NonceSize())
		hpKey := hkdfExpandLabel(crypto.SHA256.New, secret, headerProtectionLabel(v), nil, 16)
		hp, err := aes.NewCipher(hpKey)
		if err != nil {
			panic(err)
		}
		k := &ProtectionKey{}
		k.aead = aead
		// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#name-aes-based-header-protection
		k.headerProtection = func(sample []byte) []byte {
			mask := make([]byte, hp.BlockSize())
			hp.Encrypt(mask, sample)
			return mask
		}
		k.iv = iv
		return k, nil
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		key := hkdfExpandLabel(crypto.SHA256.New, secret, keyLabel(v), nil, chacha20poly1305.KeySize)
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		iv := hkdfExpandLabel(crypto.SHA256.New, secret, ivLabel(v), nil, aead.NonceSize())
		hpKey := hkdfExpandLabel(sha256.New, secret, headerProtectionLabel(v), nil, chacha20.KeySize)
		k := &ProtectionKey{}
		k.aead = aead
		// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#name-chacha20-based-header-prote
		k.headerProtection = func(sample []byte) []byte {
			nonce := sample[4:16]
			c, err := chacha20.NewUnauthenticatedCipher(hpKey, nonce)
			if err != nil {
				panic(err)
			}
			c.SetCounter(binary.LittleEndian.Uint32(sample[:4]))
			mask := make([]byte, 5)
			c.XORKeyStream(mask, mask)
			return mask
		}
		k.iv = iv
		return k, nil
	}
	return nil, errors.New("not supported cipher suite")
}

// decodePacketNumber decode the packet number after header protection removed.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-quic-transport-32#section-appendix.a
func decodePacketNumber(largest, truncated int64, nbits uint8) int64 {
	expected := largest + 1
	win := int64(1 << (nbits * 8))
	hwin := win / 2
	mask := win - 1
	candidate := (expected &^ mask) | truncated
	switch {
	case candidate <= expected-hwin && candidate < (1<<62)-win:
		return candidate + win
	case candidate > expected+hwin && candidate >= win:
		return candidate - win
	}
	return candidate
}

// Copied from crypto/tls/key_schedule.go.
func hkdfExpandLabel(hash func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)
	n, err := hkdf.Expand(hash, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}
