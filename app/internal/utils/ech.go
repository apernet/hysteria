package utils

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/cryptobyte"
)

// ParseECHConfigFile reads an ECH configs PEM file and returns the raw config list bytes
// for use with tls.Config.EncryptedClientHelloConfigList.
func ParseECHConfigFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ECH CONFIGS" {
		return nil, fmt.Errorf("invalid ECH configs PEM")
	}
	return block.Bytes, nil
}

// ParseECHKeyFile reads an ECH keys PEM file and returns the parsed keys.
func ParseECHKeyFile(path string) ([]tls.EncryptedClientHelloKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "ECH KEYS" {
		return nil, fmt.Errorf("invalid ECH keys PEM")
	}
	return unmarshalECHKeys(block.Bytes)
}

// unmarshalECHKeys parses the binary ECH keys format.
// Each key entry is: uint16-length-prefixed private key + uint16-length-prefixed config.
func unmarshalECHKeys(raw []byte) ([]tls.EncryptedClientHelloKey, error) {
	var keys []tls.EncryptedClientHelloKey
	s := cryptobyte.String(raw)
	for !s.Empty() {
		var key tls.EncryptedClientHelloKey
		if !s.ReadUint16LengthPrefixed((*cryptobyte.String)(&key.PrivateKey)) {
			return nil, fmt.Errorf("error parsing ECH private key")
		}
		if !s.ReadUint16LengthPrefixed((*cryptobyte.String)(&key.Config)) {
			return nil, fmt.Errorf("error parsing ECH config")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("empty ECH keys")
	}
	return keys, nil
}

// ECHKeygen generates an ECH key pair for the given public name.
// Returns the config PEM (for clients) and key PEM (for the server).
func ECHKeygen(publicName string) (configPem string, keyPem string, err error) {
	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	echConfig, err := marshalECHConfig(0, echKey.PublicKey().Bytes(), publicName, 0)
	if err != nil {
		return
	}

	configBuilder := cryptobyte.NewBuilder(nil)
	configBuilder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(echConfig)
	})
	configBytes, err := configBuilder.Bytes()
	if err != nil {
		return
	}

	keyBuilder := cryptobyte.NewBuilder(nil)
	keyBuilder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(echKey.Bytes())
	})
	keyBuilder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(echConfig)
	})
	keyBytes, err := keyBuilder.Bytes()
	if err != nil {
		return
	}

	configPem = string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: configBytes}))
	keyPem = string(pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: keyBytes}))
	return
}

// marshalECHConfig builds the binary ECH config structure per the ECH specification.
func marshalECHConfig(id uint8, pubKey []byte, publicName string, maxNameLen uint8) ([]byte, error) {
	const (
		extensionEncryptedClientHello = 0xfe0d
		dhkemX25519HKDFSHA256         = 0x0020
		kdfHKDFSHA256                 = 0x0001
		aeadAES128GCM                 = 0x0001
		aeadAES256GCM                 = 0x0002
		aeadChaCha20Poly1305          = 0x0003
	)

	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(extensionEncryptedClientHello)
	builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(id)
		b.AddUint16(dhkemX25519HKDFSHA256)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(pubKey)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, aeadID := range []uint16{aeadAES128GCM, aeadAES256GCM, aeadChaCha20Poly1305} {
				b.AddUint16(kdfHKDFSHA256)
				b.AddUint16(aeadID)
			}
		})
		b.AddUint8(maxNameLen)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(publicName))
		})
		b.AddUint16(0) // extensions
	})
	return builder.Bytes()
}
