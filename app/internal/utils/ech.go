package utils

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
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

	key, configList = keyConfigFromPrivate(priv, idBytes[0], publicName)
	return key, configList, nil
}

// GenerateECHKeyConfig generates a random ECH key pair and builds the matching
// ECHConfig. Unlike DeriveECHKeyConfig, the result is non-deterministic; it is
// meant to be persisted (see SaveECHKey) so it stays stable across restarts
// independently of any seed.
func GenerateECHKeyConfig(publicName string) (key tls.EncryptedClientHelloKey, configList []byte, err error) {
	if publicName == "" {
		return key, nil, errors.New("empty ECH public name")
	}
	if len(publicName) > 255 {
		return key, nil, errors.New("ECH public name too long (max 255 bytes)")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return key, nil, err
	}
	var idByte [1]byte
	if _, err := rand.Read(idByte[:]); err != nil {
		return key, nil, err
	}
	key, configList = keyConfigFromPrivate(priv, idByte[0], publicName)
	return key, configList, nil
}

// keyConfigFromPrivate builds the server-side key and the client-side
// ECHConfigList from an existing X25519 private key.
func keyConfigFromPrivate(priv *ecdh.PrivateKey, configID byte, publicName string) (tls.EncryptedClientHelloKey, []byte) {
	echConfig := buildECHConfig(configID, priv.PublicKey().Bytes(), publicName)
	return tls.EncryptedClientHelloKey{
		Config:      echConfig,
		PrivateKey:  priv.Bytes(),
		SendAsRetry: true,
	}, buildECHConfigList(echConfig)
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

// echKeyFile is the on-disk representation of a persisted ECH key pair.
type echKeyFile struct {
	PublicName string `json:"publicName"`
	PrivateKey string `json:"privateKey"` // base64 X25519 private key
	Config     string `json:"config"`     // base64 single ECHConfig
	ConfigList string `json:"configList"` // base64 ECHConfigList
}

// SaveECHKey writes the key pair to path as JSON (0600). It is written
// atomically via a temp file + rename so a crash mid-write can't corrupt it.
func SaveECHKey(path, publicName string, key tls.EncryptedClientHelloKey, configList []byte) error {
	f := echKeyFile{
		PublicName: publicName,
		PrivateKey: base64.StdEncoding.EncodeToString(key.PrivateKey),
		Config:     base64.StdEncoding.EncodeToString(key.Config),
		ConfigList: base64.StdEncoding.EncodeToString(configList),
	}
	data, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadECHKey loads a key pair previously written by SaveECHKey. The returned
// error wraps os.ErrNotExist when the file is absent, so callers can detect a
// first run with errors.Is(err, os.ErrNotExist).
func LoadECHKey(path string) (key tls.EncryptedClientHelloKey, configList []byte, publicName string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return key, nil, "", err
	}
	var f echKeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return key, nil, "", err
	}
	priv, err := base64.StdEncoding.DecodeString(f.PrivateKey)
	if err != nil {
		return key, nil, "", err
	}
	config, err := base64.StdEncoding.DecodeString(f.Config)
	if err != nil {
		return key, nil, "", err
	}
	configList, err = base64.StdEncoding.DecodeString(f.ConfigList)
	if err != nil {
		return key, nil, "", err
	}
	key = tls.EncryptedClientHelloKey{
		Config:      config,
		PrivateKey:  priv,
		SendAsRetry: true,
	}
	return key, configList, f.PublicName, nil
}
