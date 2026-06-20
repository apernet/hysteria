package integration_tests

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoAuth authenticates everyone, using the client's auth string as the user
// id. This lets each client present a distinct identity for per-user routing.
type echoAuth struct{}

func (echoAuth) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	return true, auth
}

// recordOutbound is a real outbound (it actually dials the target) that counts
// how many TCP connections were routed through it, so a test can assert which
// outbound a given user's traffic took.
type recordOutbound struct {
	tcpDials atomic.Int32
}

func (o *recordOutbound) TCP(reqAddr string) (net.Conn, error) {
	o.tcpDials.Add(1)
	return net.Dial("tcp", reqAddr)
}

func (o *recordOutbound) UDP(reqAddr string) (server.UDPConn, error) {
	return nil, net.UnknownNetworkError("udp not used")
}

func (o *recordOutbound) CheckUDP(reqAddr string) error { return nil }

// mutableProvider is a minimal thread-safe server.OutboundProvider whose mapping
// can be changed at runtime, mirroring how the real registry is updated via the
// HTTP API.
type mutableProvider struct {
	mu sync.RWMutex
	m  map[string]server.Outbound
}

func (p *mutableProvider) Outbound(authID string) server.Outbound {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.m[authID]
}

func (p *mutableProvider) set(authID string, ob server.Outbound) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[authID] = ob
}

// echoRoundTrip opens a TCP stream through the client to addr and verifies the
// echo server returns what we sent.
func echoRoundTrip(t *testing.T, c client.Client, addr string) {
	t.Helper()
	conn, err := c.TCP(addr)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("ping"), buf)
}

func TestClientServerPerUserOutbound(t *testing.T) {
	const echoAddr = "127.0.0.1:27031"

	// Echo target.
	echoListener, err := net.Listen("tcp", echoAddr)
	require.NoError(t, err)
	defer echoListener.Close()
	go (&tcpEchoServer{Listener: echoListener}).Serve()

	defOb := &recordOutbound{}  // default outbound (fallback)
	userOb := &recordOutbound{} // alice's dedicated outbound
	lateOb := &recordOutbound{} // assigned to bob at runtime

	prov := &mutableProvider{m: map[string]server.Outbound{"alice": userOb}}

	udpConn, udpAddr, err := serverConn()
	require.NoError(t, err)
	s, err := server.NewServer(&server.Config{
		TLSConfig:        serverTLSConfig(),
		Conn:             udpConn,
		Authenticator:    echoAuth{},
		Outbound:         defOb,
		OutboundProvider: prov,
	})
	require.NoError(t, err)
	defer s.Close()
	go s.Serve()

	newClient := func(user string) client.Client {
		c, _, err := client.NewClient(&client.Config{
			ServerAddr: udpAddr,
			Auth:       user,
			TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
		})
		require.NoError(t, err)
		return c
	}

	// alice has a per-user outbound -> her traffic must take userOb, not the default.
	alice := newClient("alice")
	defer alice.Close()
	echoRoundTrip(t, alice, echoAddr)
	assert.Equal(t, int32(1), userOb.tcpDials.Load(), "alice must route through her per-user outbound")
	assert.Equal(t, int32(0), defOb.tcpDials.Load(), "alice must not use the default outbound")

	// bob has no per-user outbound -> falls back to the default outbound.
	bob := newClient("bob")
	defer bob.Close()
	echoRoundTrip(t, bob, echoAddr)
	assert.Equal(t, int32(1), defOb.tcpDials.Load(), "bob must fall back to the default outbound")

	// Assign bob an outbound at runtime (no server restart) and make a fresh
	// request: it must now take the newly assigned outbound.
	prov.set("bob", lateOb)
	echoRoundTrip(t, bob, echoAddr)
	assert.Equal(t, int32(1), lateOb.tcpDials.Load(), "runtime-assigned outbound must take effect without restart")
	assert.Equal(t, int32(1), defOb.tcpDials.Load(), "bob's later request must not hit the default outbound again")
}
