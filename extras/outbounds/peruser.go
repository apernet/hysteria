package outbounds

import (
	"sync"

	"github.com/apernet/hysteria/core/v2/server"
)

// PerUserOutbounds is a thread-safe registry that maps an authenticated user id
// (the id returned by the Authenticator) to a dedicated outbound. It implements
// server.OutboundProvider, so the Hysteria core consults it per request: a user
// with an entry here has all of their traffic routed through that outbound,
// while users without an entry fall back to the server's default outbound.
//
// Entries can be added, replaced and removed at runtime (e.g. via the traffic
// stats HTTP API) without restarting the server or dropping existing
// connections. Built outbounds are cached and only rebuilt when their spec
// changes, so repeated idempotent updates are cheap.
type PerUserOutbounds struct {
	mu sync.RWMutex
	m  map[string]*perUserEntry
}

// SOCKS5Spec describes a per-user SOCKS5 outbound. It is the only outbound type
// supported for per-user routing for now; an empty/zero spec is invalid.
type SOCKS5Spec struct {
	Addr     string
	Username string
	Password string
}

func (s SOCKS5Spec) equal(o SOCKS5Spec) bool {
	return s.Addr == o.Addr && s.Username == o.Username && s.Password == o.Password
}

type perUserEntry struct {
	spec SOCKS5Spec
	ob   server.Outbound
}

// NewPerUserOutbounds creates an empty registry.
func NewPerUserOutbounds() *PerUserOutbounds {
	return &PerUserOutbounds{
		m: make(map[string]*perUserEntry),
	}
}

// Outbound implements server.OutboundProvider. It returns the outbound for the
// given user, or nil if the user has no per-user outbound configured (the caller
// then falls back to the default outbound).
func (p *PerUserOutbounds) Outbound(authID string) server.Outbound {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if e := p.m[authID]; e != nil {
		return e.ob
	}
	return nil
}

// SetSOCKS5 sets (or replaces) the SOCKS5 outbound for a user. The built
// outbound is cached; if the spec is unchanged from the current entry, the
// existing outbound is kept so in-flight lookups are not disturbed.
func (p *PerUserOutbounds) SetSOCKS5(authID string, spec SOCKS5Spec) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.m[authID]; e != nil && e.spec.equal(spec) {
		return
	}
	ob := &PluggableOutboundAdapter{PluggableOutbound: NewSOCKS5Outbound(spec.Addr, spec.Username, spec.Password)}
	p.m[authID] = &perUserEntry{spec: spec, ob: ob}
}

// Delete removes the per-user outbound for a user, reverting them to the default
// outbound. It returns true if an entry was removed.
func (p *PerUserOutbounds) Delete(authID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.m[authID]; !ok {
		return false
	}
	delete(p.m, authID)
	return true
}

// List returns a snapshot of the current per-user SOCKS5 specs keyed by user id.
func (p *PerUserOutbounds) List() map[string]SOCKS5Spec {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]SOCKS5Spec, len(p.m))
	for id, e := range p.m {
		out[id] = e.spec
	}
	return out
}
