package cmd

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunCertGeneratesValidPairAndConfig(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	var out bytes.Buffer

	result, err := runCert(certOptions{
		Hosts:    "example.com,127.0.0.1,[::1]",
		CertFile: certPath,
		KeyFile:  keyPath,
		ValidFor: time.Hour,
		Out:      &out,
	})
	require.NoError(t, err)
	assert.Equal(t, certPath, result.CertFile)
	assert.Equal(t, keyPath, result.KeyFile)

	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	cert := readCertFile(t, certPath)
	assert.Contains(t, cert.DNSNames, "example.com")
	assert.True(t, hasIP(cert.IPAddresses, "127.0.0.1"))
	assert.True(t, hasIP(cert.IPAddresses, "::1"))
	assert.NoError(t, cert.VerifyHostname("example.com"))
	assert.NoError(t, cert.VerifyHostname("127.0.0.1"))
	assert.NoError(t, cert.VerifyHostname("::1"))

	pinSum := sha256.Sum256(cert.Raw)
	expectedPin := hex.EncodeToString(pinSum[:])
	assert.Equal(t, expectedPin, result.PinSHA256)

	output := out.String()
	assert.Contains(t, output, "# server.yaml")
	assert.Contains(t, output, "  cert: "+certPath)
	assert.Contains(t, output, "  key: "+keyPath)
	assert.Contains(t, output, "# client.yaml")
	assert.Contains(t, output, "  insecure: true")
	assert.Contains(t, output, "  pinSHA256: "+expectedPin)
	assert.Contains(t, output, "WARNING:")
}

func TestRunCertDoesNotOverwriteExistingFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(certPath, []byte("old-cert"), 0o644))
	require.NoError(t, os.WriteFile(keyPath, []byte("old-key"), 0o600))

	_, err := runCert(certOptions{
		Hosts:    "example.com",
		CertFile: certPath,
		KeyFile:  keyPath,
		ValidFor: time.Hour,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	certData, err := os.ReadFile(certPath)
	require.NoError(t, err)
	keyData, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("old-cert"), certData)
	assert.Equal(t, []byte("old-key"), keyData)
}

func TestRunCertOverwritesExistingFilesWithFlag(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(certPath, []byte("old-cert"), 0o644))
	require.NoError(t, os.WriteFile(keyPath, []byte("old-key"), 0o600))

	_, err := runCert(certOptions{
		Hosts:     "example.com",
		CertFile:  certPath,
		KeyFile:   keyPath,
		ValidFor:  time.Hour,
		Overwrite: true,
	})
	require.NoError(t, err)
	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
}

func readCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func hasIP(ips []net.IP, target string) bool {
	targetIP := net.ParseIP(target)
	for _, ip := range ips {
		if ip.Equal(targetIP) {
			return true
		}
	}
	return false
}
