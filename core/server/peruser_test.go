package server

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// tagOutbound is a fake Outbound whose CheckUDP returns a sentinel error, so
// tests can tell which outbound a request was routed to.
type tagOutbound struct {
	err error
}

func (o *tagOutbound) TCP(reqAddr string) (net.Conn, error) { return nil, o.err }
func (o *tagOutbound) UDP(reqAddr string) (UDPConn, error)  { return nil, o.err }
func (o *tagOutbound) CheckUDP(reqAddr string) error        { return o.err }

type fakeProvider struct {
	ob Outbound
}

func (p *fakeProvider) Outbound(authID string) Outbound { return p.ob }

func TestEffectiveOutboundNoProvider(t *testing.T) {
	def := &tagOutbound{err: errors.New("default")}
	h := &h3sHandler{config: &Config{Outbound: def}}
	// Without a provider, the default outbound is used as-is (no wrapper).
	assert.Same(t, def, h.effectiveOutbound("alice"))
}

func TestEffectiveOutboundDynamic(t *testing.T) {
	errDefault := errors.New("default")
	errUser := errors.New("user")
	def := &tagOutbound{err: errDefault}
	userOb := &tagOutbound{err: errUser}

	prov := &fakeProvider{}
	h := &h3sHandler{config: &Config{Outbound: def, OutboundProvider: prov}}
	eff := h.effectiveOutbound("alice")

	// Provider has no entry for this user yet -> falls back to default.
	assert.Equal(t, errDefault, eff.CheckUDP("x:1"))

	// Provider now routes the user to a dedicated outbound -> used immediately,
	// without rebuilding eff (proves runtime updates reach live sessions).
	prov.ob = userOb
	assert.Equal(t, errUser, eff.CheckUDP("x:1"))
	_, tcpErr := eff.TCP("x:1")
	assert.Equal(t, errUser, tcpErr)
	_, udpErr := eff.UDP("x:1")
	assert.Equal(t, errUser, udpErr)

	// Removing the per-user outbound reverts to the default again.
	prov.ob = nil
	assert.Equal(t, errDefault, eff.CheckUDP("x:1"))
}
