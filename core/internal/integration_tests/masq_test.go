package integration_tests

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/internal/protocol"
	"github.com/apernet/hysteria/core/server"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// TestServerMasquerade is a test to ensure that the server behaves as a normal
// HTTP/3 server when dealing with an unauthenticated client. This is mainly to
// confirm that the server does not expose itself to active probers.
func TestServerMasquerade(t *testing.T) {
	// Create server
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14514}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal("error creating server:", err)
	}
	s, err := server.NewServer(&server.Config{
		TLSConfig: serverTLSConfig(),
		Conn:      udpConn,
		Authenticator: &pwAuthenticator{
			Password: "password",
			ID:       "nobody",
		},
	})
	if err != nil {
		t.Fatal("error creating server:", err)
	}
	defer s.Close()
	go s.Serve()

	// QUIC connection & RoundTripper
	var conn quic.EarlyConnection
	rt := &http3.RoundTripper{
		EnableDatagrams: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialAddrEarlyContext(ctx, udpAddr.String(), tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	defer rt.Close() // This will close the QUIC connection

	// Send the bogus request
	// We expect 404 (from the default handler)
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal("error sending request:", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, resp.StatusCode)
	}
	for k := range resp.Header {
		// Make sure no strange headers are sent
		if strings.Contains(k, "Hysteria") {
			t.Fatal("expected no Hysteria headers, got", k)
		}
	}

	buf := make([]byte, 1024)

	// We send a TCP request anyway, see if we get a response
	tcpStream, err := conn.OpenStream()
	if err != nil {
		t.Fatal("error opening stream:", err)
	}
	defer tcpStream.Close()
	err = protocol.WriteTCPRequest(tcpStream, "www.google.com:443")
	if err != nil {
		t.Fatal("error sending request:", err)
	}

	// We should receive nothing
	_ = tcpStream.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := tcpStream.Read(buf)
	if n != 0 {
		t.Fatal("expected no response, got", n)
	}
	if nErr, ok := err.(net.Error); !ok || !nErr.Timeout() {
		t.Fatal("expected timeout, got", err)
	}

	// Try UDP request
	udpStream, err := conn.OpenStream()
	if err != nil {
		t.Fatal("error opening stream:", err)
	}
	defer udpStream.Close()
	err = protocol.WriteUDPRequest(udpStream)
	if err != nil {
		t.Fatal("error sending request:", err)
	}

	// We should receive nothing
	_ = udpStream.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = udpStream.Read(buf)
	if n != 0 {
		t.Fatal("expected no response, got", n)
	}
	if nErr, ok := err.(net.Error); !ok || !nErr.Timeout() {
		t.Fatal("expected timeout, got", err)
	}
}
