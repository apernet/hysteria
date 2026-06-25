package integration_tests

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
)

// buildTestECH generates an ECH key pair and the matching ECHConfig/ECHConfigList.
// This is an independent, minimal implementation of the ECHConfig wire format
// (RFC 9849 / version 0xfe0d), used to verify that the QUIC stack passes the
// ECH tls.Config fields through correctly.
func buildTestECH(t *testing.T, publicName string) (tls.EncryptedClientHelloKey, []byte) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := priv.PublicKey().Bytes()

	au16 := func(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

	var contents []byte
	contents = append(contents, 0x01) // config_id
	contents = au16(contents, 0x0020) // kem: DHKEM(X25519, HKDF-SHA256)
	contents = au16(contents, uint16(len(pub)))
	contents = append(contents, pub...)
	cs := au16(au16(nil, 0x0001), 0x0001) // HKDF-SHA256 + AES-128-GCM
	contents = au16(contents, uint16(len(cs)))
	contents = append(contents, cs...)
	contents = append(contents, byte(len(publicName))) // maximum_name_length
	contents = append(contents, byte(len(publicName))) // public_name length
	contents = append(contents, []byte(publicName)...)
	contents = au16(contents, 0) // extensions

	echConfig := au16(nil, 0xfe0d)
	echConfig = au16(echConfig, uint16(len(contents)))
	echConfig = append(echConfig, contents...)

	configList := au16(nil, uint16(len(echConfig)))
	configList = append(configList, echConfig...)

	return tls.EncryptedClientHelloKey{
		Config:      echConfig,
		PrivateKey:  priv.Bytes(),
		SendAsRetry: true,
	}, configList
}

// TestClientServerECH verifies that Encrypted Client Hello works end-to-end over
// the real Hysteria QUIC stack. A matching ECHConfig lets the client connect; a
// mismatched one (server holds a different key) makes the handshake fail with an
// ECH rejection, proving ECH is genuinely exercised rather than ignored.
func TestClientServerECH(t *testing.T) {
	const innerSNI = "hysteria.network"
	const publicName = "public.example.com"

	echKey, echConfigList := buildTestECH(t, publicName)

	udpConn, udpAddr, err := serverConn()
	require.NoError(t, err)
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, mock.Anything, mock.Anything).Return(true, "nobody").Maybe()

	sTLS := serverTLSConfig()
	sTLS.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{echKey}
	s, err := server.NewServer(&server.Config{
		TLSConfig:     sTLS,
		Conn:          udpConn,
		Authenticator: auth,
	})
	require.NoError(t, err)
	defer s.Close()
	go s.Serve()

	// Echo server to prove the tunnel actually carries data once ECH is up.
	echoAddr := "127.0.0.1:22344"
	echoListener, err := net.Listen("tcp", echoAddr)
	require.NoError(t, err)
	echoServer := &tcpEchoServer{Listener: echoListener}
	defer echoServer.Close()
	go echoServer.Serve()

	t.Run("matching config connects", func(t *testing.T) {
		c, _, err := client.NewClient(&client.Config{
			ServerAddr: udpAddr,
			TLSConfig: client.TLSConfig{
				ServerName:                     innerSNI,
				InsecureSkipVerify:             true,
				EncryptedClientHelloConfigList: echConfigList,
			},
		})
		require.NoError(t, err)
		defer c.Close()

		conn, err := c.TCP(echoAddr)
		require.NoError(t, err)
		defer conn.Close()

		sData := []byte("hello ech")
		_, err = conn.Write(sData)
		require.NoError(t, err)
		rData := make([]byte, len(sData))
		_, err = io.ReadFull(conn, rData)
		require.NoError(t, err)
		assert.Equal(t, sData, rData)
	})

	t.Run("mismatched config is rejected", func(t *testing.T) {
		// Client offers ECH with a config the server has no private key for.
		_, otherList := buildTestECH(t, publicName)
		c, _, err := client.NewClient(&client.Config{
			ServerAddr: udpAddr,
			TLSConfig: client.TLSConfig{
				ServerName:                     innerSNI,
				InsecureSkipVerify:             true,
				EncryptedClientHelloConfigList: otherList,
			},
		})
		// Connection must fail because ECH is rejected by the server.
		if err == nil {
			c.Close()
			t.Fatal("expected ECH rejection, but client connected")
		}
	})
}
