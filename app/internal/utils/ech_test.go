package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeriveECHKeyConfigDeterministic verifies that the same (seed, publicName)
// always produces byte-identical keys and config, so a server can regenerate
// them on every start without persisting anything.
func TestDeriveECHKeyConfigDeterministic(t *testing.T) {
	key1, list1, err := DeriveECHKeyConfig([]byte("super-secret"), "public.example.com")
	require.NoError(t, err)
	key2, list2, err := DeriveECHKeyConfig([]byte("super-secret"), "public.example.com")
	require.NoError(t, err)
	assert.Equal(t, list1, list2)
	assert.Equal(t, key1.Config, key2.Config)
	assert.Equal(t, key1.PrivateKey, key2.PrivateKey)

	// A different seed must produce a different key.
	key3, _, err := DeriveECHKeyConfig([]byte("other-secret"), "public.example.com")
	require.NoError(t, err)
	assert.NotEqual(t, key1.PrivateKey, key3.PrivateKey)
}

func TestDeriveECHKeyConfigErrors(t *testing.T) {
	_, _, err := DeriveECHKeyConfig(nil, "public.example.com")
	assert.Error(t, err)
	_, _, err = DeriveECHKeyConfig([]byte("x"), "")
	assert.Error(t, err)
}

func TestEncodeDecodeECHConfigList(t *testing.T) {
	_, list, err := DeriveECHKeyConfig([]byte("seed"), "public.example.com")
	require.NoError(t, err)
	b64 := EncodeECHConfigList(list)
	decoded, err := DecodeECHConfigList("  " + b64 + "\n")
	require.NoError(t, err)
	assert.Equal(t, list, decoded)
}

// TestECHHandshake validates that the ECHConfig we build is byte-compatible
// with crypto/tls by running a full TLS 1.3 handshake with ECH and asserting
// that ECH was actually accepted on both ends. This is the real proof that the
// hand-rolled wire encoding matches what the standard library expects.
func TestECHHandshake(t *testing.T) {
	const publicName = "public.example.com"
	const innerName = "secret.internal"

	key, configList, err := DeriveECHKeyConfig([]byte("shared-secret-seed"), publicName)
	require.NoError(t, err)

	cert := selfSignedCert(t, innerName, publicName)

	serverCfg := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key},
	}
	clientCfg := &tls.Config{
		ServerName:                     innerName,
		InsecureSkipVerify:             true,
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: configList,
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	serverConn := tls.Server(c1, serverCfg)
	clientConn := tls.Client(c2, clientCfg)

	errCh := make(chan error, 1)
	go func() {
		errCh <- serverConn.Handshake()
	}()

	require.NoError(t, clientConn.Handshake())
	require.NoError(t, <-errCh)

	assert.True(t, clientConn.ConnectionState().ECHAccepted, "client: ECH should be accepted")
	assert.True(t, serverConn.ConnectionState().ECHAccepted, "server: ECH should be accepted")
}

func TestGenerateECHKeyConfig(t *testing.T) {
	key1, list1, err := GenerateECHKeyConfig("public.example.com")
	require.NoError(t, err)
	key2, _, err := GenerateECHKeyConfig("public.example.com")
	require.NoError(t, err)
	// Random generation: two keys must differ.
	assert.NotEqual(t, key1.PrivateKey, key2.PrivateKey)
	// And the generated config must produce an accepted ECH handshake.
	assertECHAccepted(t, key1, list1, "secret.internal", "public.example.com")
}

func TestSaveLoadECHKey(t *testing.T) {
	const publicName = "public.example.com"
	key, configList, err := DeriveECHKeyConfig([]byte("seed"), publicName)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "ech.json")
	require.NoError(t, SaveECHKey(path, publicName, key, configList))

	gotKey, gotList, gotName, err := LoadECHKey(path)
	require.NoError(t, err)
	assert.Equal(t, key.PrivateKey, gotKey.PrivateKey)
	assert.Equal(t, key.Config, gotKey.Config)
	assert.True(t, gotKey.SendAsRetry)
	assert.Equal(t, configList, gotList)
	assert.Equal(t, publicName, gotName)
	// The loaded key still yields an accepted handshake.
	assertECHAccepted(t, gotKey, gotList, "secret.internal", publicName)

	// Missing file reports os.ErrNotExist so callers can detect first run.
	_, _, _, err = LoadECHKey(filepath.Join(t.TempDir(), "nope.json"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// assertECHAccepted runs a TLS 1.3 handshake with ECH and asserts acceptance.
func assertECHAccepted(t *testing.T, key tls.EncryptedClientHelloKey, configList []byte, innerName, publicName string) {
	t.Helper()
	cert := selfSignedCert(t, innerName, publicName)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	serverConn := tls.Server(c1, &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key},
	})
	clientConn := tls.Client(c2, &tls.Config{
		ServerName:                     innerName,
		InsecureSkipVerify:             true,
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: configList,
	})
	errCh := make(chan error, 1)
	go func() { errCh <- serverConn.Handshake() }()
	require.NoError(t, clientConn.Handshake())
	require.NoError(t, <-errCh)
	assert.True(t, clientConn.ConnectionState().ECHAccepted)
	assert.True(t, serverConn.ConnectionState().ECHAccepted)
}

func selfSignedCert(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(der)
		require.NoError(t, err)
	}
	return cert
}
