package l2tp

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// TunnelManager manages on-demand L2TP tunnels to LNS endpoints.
// Tunnels are created when first needed and reused by multiple sessions.
// When the last session on a tunnel closes, the tunnel is torn down.
type TunnelManager struct {
	hostname      string
	helloInterval time.Duration
	logger        *zap.Logger

	mu      sync.Mutex
	tunnels map[string]*Tunnel // keyed by LNS address
	nextTID uint16
}

// NewTunnelManager creates a new tunnel manager.
func NewTunnelManager(hostname string, helloInterval time.Duration, logger *zap.Logger) *TunnelManager {
	return &TunnelManager{
		hostname:      hostname,
		helloInterval: helloInterval,
		logger:        logger,
		tunnels:       make(map[string]*Tunnel),
		nextTID:       uint16(1 + rand.Intn(65534)),
	}
}

// CreateSession establishes (or reuses) a tunnel to the given LNS address
// and creates a new L2TP session with the provided proxy information.
func (m *TunnelManager) CreateSession(lnsAddr string, secret string, info *ProxyInfo, callingNumber string) (*Session, error) {
	t, err := m.getOrCreateTunnel(lnsAddr, secret)
	if err != nil {
		return nil, err
	}

	session, err := t.CreateSession(info, callingNumber)
	if err != nil {
		return nil, fmt.Errorf("create session to %s: %w", lnsAddr, err)
	}

	m.logger.Info("L2TP session established",
		zap.String("lns", lnsAddr),
		zap.Uint16("tunnelID", t.localTunnelID),
		zap.Uint16("sessionID", session.localSessionID),
		zap.String("username", info.AuthName))

	return session, nil
}

func (m *TunnelManager) getOrCreateTunnel(lnsAddr string, secret string) (*Tunnel, error) {
	m.mu.Lock()

	// Check for existing alive tunnel
	if t, ok := m.tunnels[lnsAddr]; ok && t.Alive() {
		m.mu.Unlock()
		return t, nil
	}

	// Clean up dead tunnel entry if present
	delete(m.tunnels, lnsAddr)

	// Allocate tunnel ID
	tid := m.nextTID
	m.nextTID++
	if m.nextTID == 0 {
		m.nextTID = 1
	}

	m.mu.Unlock()

	// Establish new tunnel (outside lock to avoid blocking)
	conn, err := net.Dial("udp", lnsAddr)
	if err != nil {
		return nil, fmt.Errorf("dial LNS %s: %w", lnsAddr, err)
	}

	var secretBytes []byte
	if secret != "" {
		secretBytes = []byte(secret)
	}

	t := newTunnel(conn, tid, m.hostname, secretBytes, m.helloInterval, m.logger)
	t.onClose = func() {
		m.mu.Lock()
		// Only remove if it's still the same tunnel
		if existing, ok := m.tunnels[lnsAddr]; ok && existing == t {
			delete(m.tunnels, lnsAddr)
		}
		m.mu.Unlock()
	}

	if err := t.Establish(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("establish tunnel to %s: %w", lnsAddr, err)
	}

	m.logger.Info("L2TP tunnel established",
		zap.String("lns", lnsAddr),
		zap.Uint16("tunnelID", tid))

	m.mu.Lock()
	// Another goroutine may have created a tunnel concurrently
	if existing, ok := m.tunnels[lnsAddr]; ok && existing.Alive() {
		m.mu.Unlock()
		t.Close()
		return existing, nil
	}
	m.tunnels[lnsAddr] = t
	m.mu.Unlock()

	return t, nil
}

// TODO: wire into server graceful shutdown
func (m *TunnelManager) Close() {
	m.mu.Lock()
	tunnels := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		tunnels = append(tunnels, t)
	}
	m.tunnels = make(map[string]*Tunnel)
	m.mu.Unlock()

	for _, t := range tunnels {
		t.Close()
	}
}

// LNSConfig holds configuration for a single LNS endpoint.
type LNSConfig struct {
	Address string
	Secret  string
	Weight  int
}

// RealmRouter maps PPP realms to LNS group names.
type RealmRouter struct {
	rules []realmRule
}

type realmRule struct {
	pattern string
	group   string
}

// NewRealmRouter creates a realm router from a list of pattern->group mappings.
// Rules are evaluated in order; first match wins.
func NewRealmRouter(rules []RealmRule) *RealmRouter {
	rr := &RealmRouter{}
	for _, r := range rules {
		rr.rules = append(rr.rules, realmRule{pattern: r.Pattern, group: r.Group})
	}
	return rr
}

// RealmRule is a configuration-level realm routing rule.
type RealmRule struct {
	Pattern string
	Group   string
}

// Match finds the LNS group for a realm. Returns empty string if no match.
func (r *RealmRouter) Match(realm string) string {
	for _, rule := range r.rules {
		if matchPattern(rule.pattern, realm) {
			return rule.group
		}
	}
	return ""
}

// matchPattern matches a realm against a pattern.
// Supports exact match and wildcard prefix (e.g., "*.example.net").
func matchPattern(pattern, realm string) bool {
	if pattern == realm {
		return true
	}
	if len(pattern) > 2 && pattern[0] == '*' && pattern[1] == '.' {
		suffix := pattern[1:] // ".example.net"
		if len(realm) > len(suffix) && realm[len(realm)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

// LoadBalancer provides weighted round-robin selection across LNS groups.
type LoadBalancer struct {
	groups map[string]*lbGroup
}

type lbGroup struct {
	flatList []LNSConfig
	counter  atomic.Uint64
}

// NewLoadBalancer creates a load balancer from group configurations.
func NewLoadBalancer(groups map[string][]LNSConfig) *LoadBalancer {
	lb := &LoadBalancer{groups: make(map[string]*lbGroup)}
	for name, lnsList := range groups {
		g := &lbGroup{}
		for _, lns := range lnsList {
			w := lns.Weight
			if w <= 0 {
				w = 1
			}
			for range w {
				g.flatList = append(g.flatList, lns)
			}
		}
		lb.groups[name] = g
	}
	return lb
}

// PickSticky selects an LNS with session affinity for Multilink PPP.
// When ed (Endpoint Discriminator) is empty, falls back to round-robin.
// When ed is set, hashes username+ed to deterministically select the same LNS,
// ensuring all links in an MLPPP bundle reach the same LNS for bundling.
func (lb *LoadBalancer) PickSticky(group string, username string, ed []byte) (LNSConfig, bool) {
	if len(ed) == 0 {
		g, ok := lb.groups[group]
		if !ok || len(g.flatList) == 0 {
			return LNSConfig{}, false
		}
		idx := g.counter.Add(1) - 1
		return g.flatList[idx%uint64(len(g.flatList))], true
	}
	g, ok := lb.groups[group]
	if !ok || len(g.flatList) == 0 {
		return LNSConfig{}, false
	}
	h := fnv.New32a()
	h.Write([]byte(username))
	h.Write(ed)
	idx := h.Sum32() % uint32(len(g.flatList))
	return g.flatList[idx], true
}
