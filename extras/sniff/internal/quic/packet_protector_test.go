package quic

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/hex"
	"strings"
	"testing"
	"unicode"

	"golang.org/x/crypto/hkdf"
)

func TestInitialPacketProtector_UnProtect(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#name-server-initial
	protect := mustHexDecodeString(`
			c7ff0000200008f067a5502a4262b500 4075fb12ff07823a5d24534d906ce4c7
			6782a2167e3479c0f7f6395dc2c91676 302fe6d70bb7cbeb117b4ddb7d173498
			44fd61dae200b8338e1b932976b61d91 e64a02e9e0ee72e3a6f63aba4ceeeec5
			be2f24f2d86027572943533846caa13e 6f163fb257473d0eda5047360fd4a47e
			fd8142fafc0f76
		`)
	unProtect := mustHexDecodeString(`
			02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
			88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
			0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00
			020304
		`)

	connID := mustHexDecodeString(`8394c8f03e515708`)

	packet := append([]byte{}, protect...)
	hdr, offset, err := ParseInitialHeader(packet)
	if err != nil {
		t.Fatal(err)
	}

	initialSecret := hkdf.Extract(crypto.SHA256.New, connID, getSalt(hdr.Version))
	serverSecret := hkdfExpandLabel(crypto.SHA256.New, initialSecret, "server in", []byte{}, crypto.SHA256.Size())
	key, err := NewInitialProtectionKey(serverSecret, hdr.Version)
	if err != nil {
		t.Fatal(err)
	}
	pp := NewPacketProtector(key)
	got, err := pp.UnProtect(protect, offset, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, unProtect) {
		t.Error("UnProtect returns wrong result")
	}
}

func TestPacketProtectorShortHeader_UnProtect(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-32#name-chacha20-poly1305-short-hea
	protect := mustHexDecodeString(`4cfe4189655e5cd55c41f69080575d7999c25a5bfb`)
	unProtect := mustHexDecodeString(`01`)
	hdr := mustHexDecodeString(`4200bff4`)

	secret := mustHexDecodeString(`9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b`)
	k, err := NewProtectionKey(tls.TLS_CHACHA20_POLY1305_SHA256, secret, V1)
	if err != nil {
		t.Fatal(err)
	}

	pnLen := int(hdr[0]&0x03) + 1
	offset := len(hdr) - pnLen
	pp := NewPacketProtector(k)
	got, err := pp.UnProtect(protect, int64(offset), 654360564)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, unProtect) {
		t.Error("UnProtect returns wrong result")
	}
}

func mustHexDecodeString(s string) []byte {
	b, err := hex.DecodeString(normalizeHex(s))
	if err != nil {
		panic(err)
	}
	return b
}

func normalizeHex(s string) string {
	return strings.Map(func(c rune) rune {
		if unicode.IsSpace(c) {
			return -1
		}
		return c
	}, s)
}
