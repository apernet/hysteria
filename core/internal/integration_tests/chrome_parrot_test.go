package integration_tests

import (
	"io"
	"net"
	"testing"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestClientServerChromeParrot runs a real Hysteria client/server pair both with
// the Chrome handshake fingerprint (the default) and with it turned off, proving
// each works end to end through Hysteria's own config plumbing rather than only
// at the quic-go layer.
func TestClientServerChromeParrot(t *testing.T) {
	tests := []struct {
		name       string
		quicConfig client.QUICConfig
	}{
		{"default", client.QUICConfig{}},
		{"disabled", client.QUICConfig{DisableChromeParrot: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			udpConn, udpAddr, err := serverConn()
			assert.NoError(t, err)
			auth := mocks.NewMockAuthenticator(t)
			auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody")
			s, err := server.NewServer(&server.Config{
				TLSConfig:     serverTLSConfig(),
				Conn:          udpConn,
				Authenticator: auth,
			})
			assert.NoError(t, err)
			defer s.Close()
			go s.Serve()

			echoAddr := "127.0.0.1:22444"
			echoListener, err := net.Listen("tcp", echoAddr)
			assert.NoError(t, err)
			echoServer := &tcpEchoServer{Listener: echoListener}
			defer echoServer.Close()
			go echoServer.Serve()

			c, _, err := client.NewClient(&client.Config{
				ServerAddr: udpAddr,
				TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
				QUICConfig: test.quicConfig,
			})
			assert.NoError(t, err)
			defer c.Close()

			conn, err := c.TCP(echoAddr)
			assert.NoError(t, err)
			defer conn.Close()

			sData := []byte("hello from a chrome-shaped handshake")
			_, err = conn.Write(sData)
			assert.NoError(t, err)
			rData := make([]byte, len(sData))
			_, err = io.ReadFull(conn, rData)
			assert.NoError(t, err)
			assert.Equal(t, sData, rData)
		})
	}
}
