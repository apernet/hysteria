package utils

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ECH (Encrypted Client Hello) helpers.
//
// Hysteria does not generate ECH keys itself. Users create a key pair with
// `sing-box generate ech-keypair <public_name>`, which emits two PEM blocks:
//
//	-----BEGIN ECH KEYS-----      (private, kept on the server)
//	-----BEGIN ECH CONFIGS-----   (public, published to clients)
//
// The ECH KEYS block is a concatenation of entries, each being:
//
//	uint16 len | X25519 private key
//	uint16 len | ECHConfig
//
// where the embedded ECHConfig is byte-identical to the corresponding entry in
// the ECH CONFIGS block (an ECHConfigList). The server derives the client-facing
// ECHConfigList from the keys so the two are guaranteed to agree.

const (
	pemBlockECHKeys    = "ECH KEYS"
	pemBlockECHConfigs = "ECH CONFIGS"
)

var errInvalidECHKeys = errors.New("invalid ECH keys")

// LoadECHKeys reads an ECH key file as produced by sing-box, and returns the
// server-side ECH keys together with the client-facing ECHConfigList derived
// from them. All returned keys have SendAsRetry set so the server advertises
// them as retry configs when a client offers a stale config.
func LoadECHKeys(path string) (keys []tls.EncryptedClientHelloKey, configList []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	blob := findPEMBlock(data, pemBlockECHKeys)
	if blob == nil {
		return nil, nil, fmt.Errorf("%w: no %q PEM block found (generate one with `sing-box generate ech-keypair <public_name>`)", errInvalidECHKeys, pemBlockECHKeys)
	}
	keys, err = parseECHKeysBlob(blob)
	if err != nil {
		return nil, nil, err
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("%w: no key entries", errInvalidECHKeys)
	}
	for i := range keys {
		keys[i].SendAsRetry = true
	}
	return keys, marshalConfigListFromKeys(keys), nil
}

// ParseECHConfigList accepts either a base64-encoded ECHConfigList or a path to
// a file containing base64 or a PEM "ECH CONFIGS" block, and returns the raw
// ECHConfigList bytes. It is used for the client-side tls.ech option.
//
// The value is first tried as an inline base64 ECHConfigList; only if that does
// not yield a structurally valid list is it treated as a file path.
func ParseECHConfigList(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty ECH config list")
	}
	if list, ok := decodeECHConfigList(s); ok {
		return list, nil
	}
	// Fall back to treating the value as a file path.
	data, err := os.ReadFile(s)
	if err != nil {
		return nil, fmt.Errorf("ECH config is neither a valid base64 config list nor a readable file: %w", err)
	}
	if blob := findPEMBlock(data, pemBlockECHConfigs); blob != nil {
		if err := validateECHConfigList(blob); err != nil {
			return nil, err
		}
		return blob, nil
	}
	if list, ok := decodeECHConfigList(string(data)); ok {
		return list, nil
	}
	return nil, errors.New("file does not contain a valid ECH config list")
}

// decodeECHConfigList base64-decodes s (standard or URL alphabet) and returns
// the bytes if they form a structurally valid ECHConfigList.
func decodeECHConfigList(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(s); err == nil {
			if validateECHConfigList(raw) == nil {
				return raw, true
			}
		}
	}
	return nil, false
}

// findPEMBlock returns the bytes of the first PEM block of the given type, or
// nil if none is present. Input that is not PEM at all yields nil.
func findPEMBlock(data []byte, blockType string) []byte {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type == blockType {
			return block.Bytes
		}
	}
}

// parseECHKeysBlob parses the body of an ECH KEYS PEM block into ECH keys.
func parseECHKeysBlob(blob []byte) ([]tls.EncryptedClientHelloKey, error) {
	var keys []tls.EncryptedClientHelloKey
	for len(blob) > 0 {
		priv, rest, err := readU16Prefixed(blob)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalidECHKeys, err)
		}
		config, rest2, err := readU16Prefixed(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalidECHKeys, err)
		}
		keys = append(keys, tls.EncryptedClientHelloKey{
			Config:     config,
			PrivateKey: priv,
		})
		blob = rest2
	}
	return keys, nil
}

// marshalConfigListFromKeys builds an ECHConfigList by concatenating the
// ECHConfig of every key and prepending a uint16 total length. Each key.Config
// is a complete ECHConfig (version + length + body), so the list is just the
// concatenation wrapped in the outer length prefix.
func marshalConfigListFromKeys(keys []tls.EncryptedClientHelloKey) []byte {
	var body []byte
	for _, k := range keys {
		body = append(body, k.Config...)
	}
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out, uint16(len(body)))
	copy(out[2:], body)
	return out
}

// validateECHConfigList checks that list is a structurally well-formed
// ECHConfigList: a uint16 length prefix covering one or more ECHConfig entries,
// each being version(2) + uint16 length + body.
func validateECHConfigList(list []byte) error {
	body, rest, err := readU16Prefixed(list)
	if err != nil {
		return fmt.Errorf("malformed ECH config list: %w", err)
	}
	if len(rest) != 0 {
		return errors.New("malformed ECH config list: trailing data")
	}
	n := 0
	for len(body) > 0 {
		if len(body) < 4 {
			return errors.New("malformed ECH config list: truncated config header")
		}
		// body[0:2] is the config version; body[2:4] is the config length.
		cfg, next, err := readU16Prefixed(body[2:])
		if err != nil {
			return fmt.Errorf("malformed ECH config list: %w", err)
		}
		_ = cfg
		body = next
		n++
	}
	if n == 0 {
		return errors.New("ECH config list contains no configs")
	}
	return nil
}

// readU16Prefixed reads a uint16 length prefix and that many following bytes,
// returning the payload and the remaining data.
func readU16Prefixed(data []byte) (payload, rest []byte, err error) {
	if len(data) < 2 {
		return nil, nil, errors.New("truncated length prefix")
	}
	n := int(binary.BigEndian.Uint16(data))
	if len(data) < 2+n {
		return nil, nil, errors.New("length prefix exceeds available data")
	}
	return data[2 : 2+n], data[2+n:], nil
}
