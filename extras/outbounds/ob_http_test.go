package outbounds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestHTTPOutboundHTTPSUsesConfiguredServerName(t *testing.T) {
	cert, err := newHTTPOutboundTestCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotSNI := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				gotSNI <- hello.ServerName
				return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
			},
		})
		_ = tlsConn.Handshake()
	}()

	outbound := &httpOutbound{
		Dialer:     &net.Dialer{Timeout: time.Second},
		Addr:       ln.Addr().String(),
		HTTPS:      true,
		Insecure:   true,
		ServerName: "proxy.example.com",
	}
	conn, err := outbound.dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.(*tls.Conn).Handshake(); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-gotSNI:
		if got != outbound.ServerName {
			t.Fatalf("SNI = %q, want %q", got, outbound.ServerName)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ClientHello")
	}
}

func newHTTPOutboundTestCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
