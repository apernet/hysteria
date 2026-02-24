package pppbridge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// GenerateCerts ensures a CA and server certificate exist for the local SSTP
// server. Files in dir: ca.crt, ca.key, server.crt, server.key.
//
// Existing files are never overwritten. If server.crt and server.key already
// exist, the function returns immediately (CA files are not needed). If the
// server cert is missing but a CA exists (ca.crt + ca.key), the CA is loaded
// and used to sign a new server cert. If nothing exists, everything is
// generated fresh. Inconsistent states (e.g. ca.crt without ca.key when a
// server cert needs to be generated) produce an error.
func GenerateCerts(dir string) error {
	caPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	srvHasCert := fileExists(certPath)
	srvHasKey := fileExists(keyPath)

	if srvHasCert && srvHasKey {
		return nil
	}
	if srvHasCert != srvHasKey {
		return fmt.Errorf("incomplete server certificate: server.crt exists=%v, server.key exists=%v; "+
			"provide both or delete both to regenerate", srvHasCert, srvHasKey)
	}

	// Server cert is missing — we need to generate it, which requires a CA.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	caHasCert := fileExists(caPath)
	caHasKey := fileExists(caKeyPath)

	var caCert *x509.Certificate
	var caKey *ecdsa.PrivateKey

	switch {
	case caHasCert && caHasKey:
		var err error
		caCert, caKey, err = loadCA(caPath, caKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load existing CA: %w", err)
		}
	case caHasCert && !caHasKey:
		return fmt.Errorf("ca.crt exists but ca.key is missing; "+
			"need the CA private key to sign a new server certificate (dir: %s)", dir)
	case !caHasCert && caHasKey:
		return fmt.Errorf("ca.key exists but ca.crt is missing; "+
			"provide both or delete both to regenerate (dir: %s)", dir)
	default:
		var err error
		caCert, caKey, err = generateCA()
		if err != nil {
			return err
		}
		caDER := caCert.Raw
		if err := writePEM(caPath, "CERTIFICATE", caDER); err != nil {
			return err
		}
		caKeyDER, err := x509.MarshalECPrivateKey(caKey)
		if err != nil {
			return err
		}
		if err := writePEM(caKeyPath, "EC PRIVATE KEY", caKeyDER); err != nil {
			return err
		}
	}

	return generateServerCert(certPath, keyPath, caCert, caKey)
}

func generateCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: "Hysteria2 PPP CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, caKey, nil
}

func generateServerCert(certPath, keyPath string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) error {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: "Hysteria2 PPP Server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", serverDER); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return err
	}
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER)
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", certPath, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("%s is not valid PEM", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", certPath, err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", keyPath, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("%s is not valid PEM", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", keyPath, err)
	}

	return cert, key, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func writePEM(path, pemType string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: pemType, Bytes: data})
}

func newSerial() *big.Int {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return serial
}
