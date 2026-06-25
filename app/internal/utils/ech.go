package utils

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"strings"
)

// ECH (Encrypted Client Hello) wire constants, per draft-ietf-tls-esni-13
// (published as RFC 9849), which is the version supported by crypto/tls.
const (
	echConfigVersion       uint16 = 0xfe0d // ECHConfig.version
	echKemX25519HKDFSHA256 uint16 = 0x0020 // DHKEM(X25519, HKDF-SHA256)
	echKDFHKDFSHA256       uint16 = 0x0001 // HKDF-SHA256
	echAEADAES128GCM       uint16 = 0x0001 // AES-128-GCM
	echAEADAES256GCM       uint16 = 0x0002 // AES-256-GCM
	echAEADChaCha20Poly    uint16 = 0x0003 // ChaCha20Poly1305
)

// DeriveECHKeyConfig deterministically derives an ECH key pair from seed and
// builds the matching ECHConfig. The same (seed, publicName) pair always yields
// the same key pair, so a server can regenerate it on every start (e.g. from a
// shared secret) without persisting anything, and clients can be handed the
// resulting ECHConfigList out of band.
//
// It returns:
//   - key:        the server-side key (private key + a single marshalled
//     ECHConfig), ready to put in tls.Config.EncryptedClientHelloKeys.
//   - configList: the marshalled ECHConfigList that clients put in
//     tls.Config.EncryptedClientHelloConfigList.
func DeriveECHKeyConfig(seed []byte, publicName string) (key tls.EncryptedClientHelloKey, configList []byte, err error) {
	if len(seed) == 0 {
		return key, nil, errors.New("empty ECH seed")
	}
	if publicName == "" {
		return key, nil, errors.New("empty ECH public name")
	}
	if len(publicName) > 255 {
		return key, nil, errors.New("ECH public name too long (max 255 bytes)")
	}

	// Derive a 32-byte X25519 private scalar from the seed via HKDF-SHA256.
	// X25519 performs the required clamping internally, so any 32 bytes are a
	// valid private key.
	prk, err := hkdf.Extract(sha256.New, seed, []byte("hysteria ech v1"))
	if err != nil {
		return key, nil, err
	}
	skBytes, err := hkdf.Expand(sha256.New, prk, "ech x25519 key", 32)
	if err != nil {
		return key, nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(skBytes)
	if err != nil {
		return key, nil, err
	}

	// Deterministic 1-byte config id, also derived from the seed.
	idBytes, err := hkdf.Expand(sha256.New, prk, "ech config id", 1)
	if err != nil {
		return key, nil, err
	}

	echConfig := buildECHConfig(idBytes[0], priv.PublicKey().Bytes(), publicName)
	configList = buildECHConfigList(echConfig)

	key = tls.EncryptedClientHelloKey{
		Config:      echConfig,
		PrivateKey:  priv.Bytes(),
		SendAsRetry: true,
	}
	return key, configList, nil
}

// buildECHConfig marshals a single ECHConfig (version 0xfe0d).
func buildECHConfig(configID byte, publicKey []byte, publicName string) []byte {
	// HpkeKeyConfig + ECHConfigContents body.
	var contents []byte
	contents = append(contents, configID)
	contents = appendUint16(contents, echKemX25519HKDFSHA256)
	contents = appendUint16(contents, uint16(len(publicKey)))
	contents = append(contents, publicKey...)

	// HpkeSymmetricCipherSuite list (uint16-length-prefixed): one KDF, all AEADs.
	var cs []byte
	for _, aead := range []uint16{echAEADAES128GCM, echAEADAES256GCM, echAEADChaCha20Poly} {
		cs = appendUint16(cs, echKDFHKDFSHA256)
		cs = appendUint16(cs, aead)
	}
	contents = appendUint16(contents, uint16(len(cs)))
	contents = append(contents, cs...)

	// maximum_name_length (uint8): used by the client to pad the inner
	// ClientHello. The inner SNI is the same domain as the public name here.
	contents = append(contents, byte(len(publicName)))

	// public_name (uint8-length-prefixed).
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, []byte(publicName)...)

	// extensions (uint16-length-prefixed, empty).
	contents = appendUint16(contents, 0)

	// ECHConfig = version (uint16) + length (uint16) + contents.
	out := appendUint16(nil, echConfigVersion)
	out = appendUint16(out, uint16(len(contents)))
	return append(out, contents...)
}

// buildECHConfigList wraps one or more marshalled ECHConfigs into an
// ECHConfigList (uint16-length-prefixed concatenation).
func buildECHConfigList(configs ...[]byte) []byte {
	var body []byte
	for _, c := range configs {
		body = append(body, c...)
	}
	out := appendUint16(nil, uint16(len(body)))
	return append(out, body...)
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// EncodeECHConfigList returns the standard base64 encoding of an ECHConfigList,
// the form used by the management API and client config.
func EncodeECHConfigList(configList []byte) string {
	return base64.StdEncoding.EncodeToString(configList)
}

// DecodeECHConfigList parses a base64-encoded ECHConfigList, tolerating
// surrounding whitespace/newlines (e.g. when read from a file).
func DecodeECHConfigList(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty ECH config")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Tolerate raw-URL / unpadded variants.
		b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}
