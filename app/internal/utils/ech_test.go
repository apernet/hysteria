package utils

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// buildTestECHKeyPEM produces an ECH key file in the same format as
// `sing-box generate ech-keypair <publicName>`: an "ECH KEYS" PEM block (private)
// and an "ECH CONFIGS" PEM block (public ECHConfigList). It returns the PEM bytes
// and the raw ECHConfigList for comparison.
func buildTestECHKeyPEM(t *testing.T, publicName string) (pemBytes, configList []byte) {
	t.Helper()

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	pub := priv.PublicKey().Bytes()

	// ECHConfig contents (draft-ietf-tls-esni-18).
	var contents []byte
	contents = append(contents, 0x00)                          // config_id
	contents = binary.BigEndian.AppendUint16(contents, 0x0020) // kem_id: DHKEM(X25519, HKDF-SHA256)
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(pub)))
	contents = append(contents, pub...)
	// cipher_suites: HKDF-SHA256 with AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305
	suites := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03}
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(suites)))
	contents = append(contents, suites...)
	contents = append(contents, 0x00) // maximum_name_length
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = binary.BigEndian.AppendUint16(contents, 0) // extensions (empty)

	// ECHConfig = version(0xfe0d) + uint16 length + contents.
	var config []byte
	config = binary.BigEndian.AppendUint16(config, 0xfe0d)
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	config = append(config, contents...)

	// ECHConfigList = uint16 length + config(s).
	configList = binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	configList = append(configList, config...)

	// ECH KEYS entry = uint16 len(priv) + priv + uint16 len(config) + config.
	var keyBlob []byte
	keyBlob = binary.BigEndian.AppendUint16(keyBlob, uint16(len(priv.Bytes())))
	keyBlob = append(keyBlob, priv.Bytes()...)
	keyBlob = binary.BigEndian.AppendUint16(keyBlob, uint16(len(config)))
	keyBlob = append(keyBlob, config...)

	pemBytes = pem.EncodeToMemory(&pem.Block{Type: pemBlockECHKeys, Bytes: keyBlob})
	pemBytes = append(pemBytes, pem.EncodeToMemory(&pem.Block{Type: pemBlockECHConfigs, Bytes: configList})...)
	return pemBytes, configList
}

func TestLoadECHKeys(t *testing.T) {
	const publicName = "decoy.example.com"
	pemBytes, wantList := buildTestECHKeyPEM(t, publicName)

	dir := t.TempDir()
	path := filepath.Join(dir, "ech.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	keys, gotList, err := LoadECHKeys(path)
	if err != nil {
		t.Fatalf("LoadECHKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if !keys[0].SendAsRetry {
		t.Error("expected SendAsRetry to be set")
	}
	// The derived config list must be byte-identical to the CONFIGS block, so
	// clients and server agree on the exact same config bytes.
	if !equalBytes(gotList, wantList) {
		t.Errorf("derived config list mismatch:\n got %x\nwant %x", gotList, wantList)
	}

	// End-to-end: a real TLS handshake must accept ECH using these keys and the
	// derived config list. This validates the whole parse chain against stdlib.
	assertECHHandshake(t, keys, gotList, true)
}

func TestLoadECHKeysErrors(t *testing.T) {
	dir := t.TempDir()

	// Missing file.
	if _, _, err := LoadECHKeys(filepath.Join(dir, "nope.pem")); err == nil {
		t.Error("expected error for missing file")
	}

	// File without an ECH KEYS block.
	badPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPath, []byte("not pem at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadECHKeys(badPath); err == nil {
		t.Error("expected error for file without ECH KEYS block")
	}
}

func TestParseECHConfigList(t *testing.T) {
	_, list := buildTestECHKeyPEM(t, "decoy.example.com")
	b64 := base64.StdEncoding.EncodeToString(list)

	// Inline base64.
	got, err := ParseECHConfigList(b64)
	if err != nil {
		t.Fatalf("inline base64: %v", err)
	}
	if !equalBytes(got, list) {
		t.Error("inline base64 result mismatch")
	}

	// base64url without padding (as used in share URIs).
	got, err = ParseECHConfigList(base64.RawURLEncoding.EncodeToString(list))
	if err != nil {
		t.Fatalf("base64url: %v", err)
	}
	if !equalBytes(got, list) {
		t.Error("base64url result mismatch")
	}

	// File containing a PEM CONFIGS block.
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "configs.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemBlockECHConfigs, Bytes: list})
	if err := os.WriteFile(pemPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = ParseECHConfigList(pemPath)
	if err != nil {
		t.Fatalf("PEM file: %v", err)
	}
	if !equalBytes(got, list) {
		t.Error("PEM file result mismatch")
	}

	// File containing raw base64.
	b64Path := filepath.Join(dir, "configs.txt")
	if err := os.WriteFile(b64Path, []byte(b64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = ParseECHConfigList(b64Path)
	if err != nil {
		t.Fatalf("base64 file: %v", err)
	}
	if !equalBytes(got, list) {
		t.Error("base64 file result mismatch")
	}

	// Garbage.
	if _, err := ParseECHConfigList("this-is-not-valid"); err == nil {
		t.Error("expected error for garbage input")
	}
	if _, err := ParseECHConfigList(""); err == nil {
		t.Error("expected error for empty input")
	}
}

// assertECHHandshake runs a loopback TLS 1.3 handshake with the given server ECH
// keys and client config list, and asserts whether ECH is accepted.
func assertECHHandshake(t *testing.T, keys []tls.EncryptedClientHelloKey, configList []byte, wantAccepted bool) {
	t.Helper()

	cert := selfSignedCert(t)
	serverConf := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		EncryptedClientHelloKeys: keys,
		MinVersion:               tls.VersionTLS13,
	}
	clientConf := &tls.Config{
		ServerName:                     "secret.internal", // the real (inner) name
		InsecureSkipVerify:             true,
		EncryptedClientHelloConfigList: configList,
		MinVersion:                     tls.VersionTLS13,
	}

	cConn, sConn := net.Pipe()
	defer cConn.Close()
	defer sConn.Close()

	errCh := make(chan error, 1)
	go func() {
		s := tls.Server(sConn, serverConf)
		errCh <- s.Handshake()
	}()

	c := tls.Client(cConn, clientConf)
	_ = cConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if got := c.ConnectionState().ECHAccepted; got != wantAccepted {
		t.Errorf("ECHAccepted = %v, want %v", got, wantAccepted)
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "secret.internal"},
		DNSNames:     []string{"secret.internal", "decoy.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
