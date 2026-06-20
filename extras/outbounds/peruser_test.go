package outbounds

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPerUserOutbounds(t *testing.T) {
	p := NewPerUserOutbounds()

	// Unknown user falls back (nil).
	assert.Nil(t, p.Outbound("alice"))
	assert.Empty(t, p.List())

	// Set a user.
	specA := SOCKS5Spec{Addr: "1.1.1.1:1080", Username: "u", Password: "p"}
	p.SetSOCKS5("alice", specA)
	obA := p.Outbound("alice")
	assert.NotNil(t, obA)
	assert.Nil(t, p.Outbound("bob"))
	assert.Equal(t, map[string]SOCKS5Spec{"alice": specA}, p.List())

	// Setting the same spec keeps the cached outbound (same pointer).
	p.SetSOCKS5("alice", specA)
	assert.Same(t, obA, p.Outbound("alice"))

	// Setting a different spec rebuilds the outbound.
	specA2 := SOCKS5Spec{Addr: "2.2.2.2:1080"}
	p.SetSOCKS5("alice", specA2)
	obA2 := p.Outbound("alice")
	assert.NotNil(t, obA2)
	assert.NotSame(t, obA, obA2)
	assert.Equal(t, specA2, p.List()["alice"])

	// Multiple users are independent.
	p.SetSOCKS5("bob", SOCKS5Spec{Addr: "3.3.3.3:1080"})
	assert.NotNil(t, p.Outbound("bob"))
	assert.Len(t, p.List(), 2)

	// Delete reverts to fallback.
	assert.True(t, p.Delete("alice"))
	assert.Nil(t, p.Outbound("alice"))
	assert.False(t, p.Delete("alice")) // already gone
	assert.Len(t, p.List(), 1)
}
