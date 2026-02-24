package pppbridge

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCerts(t *testing.T) {
	dir := t.TempDir()
	err := GenerateCerts(dir)
	require.NoError(t, err)

	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	for _, path := range []string{caPath, caKeyPath, certPath, keyPath} {
		_, err := os.Stat(path)
		require.NoError(t, err, "file should exist: %s", path)
	}

	// Parse CA cert
	caPEM, err := os.ReadFile(caPath)
	require.NoError(t, err)
	caBlock, _ := pem.Decode(caPEM)
	require.NotNil(t, caBlock, "ca.crt must be valid PEM")
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)
	assert.True(t, caCert.IsCA, "CA cert must have IsCA=true")

	// Parse server cert
	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)
	certBlock, _ := pem.Decode(certPEM)
	require.NotNil(t, certBlock, "server.crt must be valid PEM")
	serverCert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)

	// Verify server cert is signed by CA
	err = serverCert.CheckSignatureFrom(caCert)
	assert.NoError(t, err, "server cert must be signed by CA")

	// Verify SAN contains 127.0.0.1 and ::1
	foundV4 := false
	foundV6 := false
	for _, ip := range serverCert.IPAddresses {
		if ip.Equal(net.IPv4(127, 0, 0, 1)) {
			foundV4 = true
		}
		if ip.Equal(net.IPv6loopback) {
			foundV6 = true
		}
	}
	assert.True(t, foundV4, "server cert must have SAN 127.0.0.1")
	assert.True(t, foundV6, "server cert must have SAN ::1")

	// Verify SAN contains localhost DNS name
	assert.Contains(t, serverCert.DNSNames, "localhost", "server cert must have SAN localhost")
}

func TestCertsIdempotent(t *testing.T) {
	dir := t.TempDir()
	err := GenerateCerts(dir)
	require.NoError(t, err)

	// Record modification times
	caInfo1, _ := os.Stat(filepath.Join(dir, "ca.crt"))
	caKeyInfo1, _ := os.Stat(filepath.Join(dir, "ca.key"))
	certInfo1, _ := os.Stat(filepath.Join(dir, "server.crt"))
	keyInfo1, _ := os.Stat(filepath.Join(dir, "server.key"))

	// Generate again -- should skip
	err = GenerateCerts(dir)
	require.NoError(t, err)

	caInfo2, _ := os.Stat(filepath.Join(dir, "ca.crt"))
	caKeyInfo2, _ := os.Stat(filepath.Join(dir, "ca.key"))
	certInfo2, _ := os.Stat(filepath.Join(dir, "server.crt"))
	keyInfo2, _ := os.Stat(filepath.Join(dir, "server.key"))

	assert.Equal(t, caInfo1.ModTime(), caInfo2.ModTime(), "ca.crt should not be overwritten")
	assert.Equal(t, caKeyInfo1.ModTime(), caKeyInfo2.ModTime(), "ca.key should not be overwritten")
	assert.Equal(t, certInfo1.ModTime(), certInfo2.ModTime(), "server.crt should not be overwritten")
	assert.Equal(t, keyInfo1.ModTime(), keyInfo2.ModTime(), "server.key should not be overwritten")
}

func TestCertsReuseCA(t *testing.T) {
	dir := t.TempDir()

	// Generate everything first
	err := GenerateCerts(dir)
	require.NoError(t, err)

	// Read original CA cert content
	origCA, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	require.NoError(t, err)
	origCAKey, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	require.NoError(t, err)

	// Delete only server cert + key
	require.NoError(t, os.Remove(filepath.Join(dir, "server.crt")))
	require.NoError(t, os.Remove(filepath.Join(dir, "server.key")))

	// Regenerate -- should reuse existing CA
	err = GenerateCerts(dir)
	require.NoError(t, err)

	// CA files should be unchanged
	newCA, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	require.NoError(t, err)
	newCAKey, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	require.NoError(t, err)
	assert.Equal(t, origCA, newCA, "ca.crt should be unchanged")
	assert.Equal(t, origCAKey, newCAKey, "ca.key should be unchanged")

	// New server cert should be valid and signed by the same CA
	caPEM, _ := pem.Decode(newCA)
	caCert, _ := x509.ParseCertificate(caPEM.Bytes)

	certPEM, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	require.NoError(t, err)
	certBlock, _ := pem.Decode(certPEM)
	serverCert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)

	err = serverCert.CheckSignatureFrom(caCert)
	assert.NoError(t, err, "new server cert must be signed by the reused CA")
}

func TestCertsErrorIncompleteServerCert(t *testing.T) {
	dir := t.TempDir()

	// Generate everything, then delete only server.key
	require.NoError(t, GenerateCerts(dir))
	require.NoError(t, os.Remove(filepath.Join(dir, "server.key")))

	err := GenerateCerts(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete server certificate")
}

func TestCertsErrorMissingCAKey(t *testing.T) {
	dir := t.TempDir()

	// Generate everything, then delete server cert/key AND ca.key
	require.NoError(t, GenerateCerts(dir))
	require.NoError(t, os.Remove(filepath.Join(dir, "server.crt")))
	require.NoError(t, os.Remove(filepath.Join(dir, "server.key")))
	require.NoError(t, os.Remove(filepath.Join(dir, "ca.key")))

	// ca.crt exists but ca.key is missing -> error
	err := GenerateCerts(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.key is missing")
}

func TestCertsErrorMissingCACert(t *testing.T) {
	dir := t.TempDir()

	// Generate everything, then delete server cert/key AND ca.crt
	require.NoError(t, GenerateCerts(dir))
	require.NoError(t, os.Remove(filepath.Join(dir, "server.crt")))
	require.NoError(t, os.Remove(filepath.Join(dir, "server.key")))
	require.NoError(t, os.Remove(filepath.Join(dir, "ca.crt")))

	// ca.key exists but ca.crt is missing -> error
	err := GenerateCerts(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.crt is missing")
}

func TestCertsSkipWithoutCAKey(t *testing.T) {
	dir := t.TempDir()

	// Generate everything, then delete only ca.key
	// Server cert exists, so we should skip without error
	require.NoError(t, GenerateCerts(dir))
	require.NoError(t, os.Remove(filepath.Join(dir, "ca.key")))

	err := GenerateCerts(dir)
	assert.NoError(t, err, "should skip when server cert exists, even without ca.key")
}

func TestCertsTLSHandshake(t *testing.T) {
	dir := t.TempDir()
	err := GenerateCerts(dir)
	require.NoError(t, err)

	// Load server cert/key
	serverTLS, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
	)
	require.NoError(t, err)

	// Load CA cert into pool
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM))

	// Start TLS server
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverTLS},
	})
	require.NoError(t, err)
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		// Force TLS handshake to complete on server side
		tlsConn := conn.(*tls.Conn)
		done <- tlsConn.Handshake()
	}()

	// Connect with CA-verified client
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    caPool,
		ServerName: "127.0.0.1",
	})
	require.NoError(t, err, "TLS handshake should succeed with CA cert")
	conn.Close()

	serverErr := <-done
	require.NoError(t, serverErr, "server-side TLS handshake should succeed")
}
