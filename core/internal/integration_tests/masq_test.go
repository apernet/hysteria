package integration_tests

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/server"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// TestServerMasquerade is a test to ensure that the server behaves as a normal
// HTTP/3 server when dealing with an unauthenticated client. This is mainly to
// confirm that the server does not expose itself to active probing.
func TestServerMasquerade(t *testing.T) {
	// Create server
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "", uint64(0)).Return(false, "").Once()
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Authenticator: auth,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// QUIC connection & RoundTripper
	var conn *quic.Conn
	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			qc, err := quic.DialAddrEarly(ctx, udpAddr.String(), tlsCfg, cfg)
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
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	for k := range resp.Header {
		// Make sure no strange headers are sent by the server
		assert.NotContains(t, k, "Hysteria")
	}

	buf := make([]byte, 1024)

	// We send a TCP request anyway, see if we get a response
	tcpStream, err := conn.OpenStream()
	assert.NoError(t, err)
	defer tcpStream.Close()
	err = protocol.WriteTCPRequest(tcpStream, "www.google.com:443")
	assert.NoError(t, err)

	// We should receive nothing
	_ = tcpStream.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := tcpStream.Read(buf)
	assert.Equal(t, 0, n)
	nErr, ok := err.(net.Error)
	assert.True(t, ok)
	assert.True(t, nErr.Timeout())
}
