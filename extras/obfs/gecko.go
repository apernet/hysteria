package obfs

import (
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Gecko adds shape obfuscation on top of a Salamander cipher. Long-header
// QUIC packets (handshake) are fragmented into 2–N random chunks with random
// padding to hide the 1200-byte initial-packet fingerprint; short-header
// (1-RTT) packets pass through untouched. The receiver dispatches on the top
// bit of the Salamander-decrypted plaintext, which RFC 9000 §17 guarantees
// is 1 for long-header and 0 for short-header.
const (
	geckoReassemblyTTL = 8 * time.Second
	geckoMaxReassembly = 4096
	geckoMaxPerSource  = 8

	geckoBufferSize = 2048 // QUIC packets should fit comfortably
)

type GeckoOptions struct {
	Password []byte
}

func WrapPacketConnGecko(conn net.PacketConn, opts GeckoOptions) (net.PacketConn, error) {
	if len(opts.Password) == 0 {
		return nil, errors.New("gecko: password is required")
	}
	inner, err := WrapPacketConnSalamander(conn, opts.Password)
	if err != nil {
		return nil, err
	}
	return newGeckoPacketConn(inner), nil
}

type reassemblyKey struct {
	addr  string
	msgID uint8
}

type reassemblyEntry struct {
	chunks   [][]byte
	received int
	total    uint8
	deadline time.Time
}

type geckoPacketConn struct {
	inner net.PacketConn

	msgID atomic.Uint32

	mu         sync.Mutex
	reassembly map[reassemblyKey]*reassemblyEntry
	perSource  map[string]int

	closeCh   chan struct{}
	closeOnce sync.Once
}

func newGeckoPacketConn(inner net.PacketConn) *geckoPacketConn {
	g := &geckoPacketConn{
		inner:      inner,
		reassembly: make(map[reassemblyKey]*reassemblyEntry),
		perSource:  make(map[string]int),
		closeCh:    make(chan struct{}),
	}
	go g.gcLoop()
	return g
}

// --- Send path ---

func (g *geckoPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if p[0]&0x80 != 0 {
		// QUIC long header: fragment + pad.
		return g.writeFragmented(p, addr)
	}
	// QUIC short header (data): bypass.
	return g.inner.WriteTo(p, addr)
}

func (g *geckoPacketConn) writeFragmented(p []byte, addr net.Addr) (int, error) {
	chunks := randomFragmentChunks()
	chunkSize := (len(p) + chunks - 1) / chunks
	msgID := uint8(g.msgID.Add(1))
	var pad [geckoMaxPadding]byte
	for i := 0; i < chunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(p) {
			end = len(p)
		}
		chunk := p[start:end]
		padLen := randomPadLen()
		if padLen > 0 {
			_, _ = rand.Read(pad[:padLen])
		}
		h := frameHeader{
			isFragment:  true,
			padLen:      padLen,
			msgID:       msgID,
			chunkIdx:    uint8(i),
			totalChunks: uint8(chunks),
		}
		buf := make([]byte, geckoHeaderFrag+int(padLen)+len(chunk))
		n, err := encodeFrame(h, pad[:], chunk, buf)
		if err != nil {
			return 0, err
		}
		if _, err := g.inner.WriteTo(buf[:n], addr); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func randomPadLen() uint8 {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0] & geckoMaskPadLen
}

func randomFragmentChunks() int {
	var b [1]byte
	_, _ = rand.Read(b[:])
	span := geckoMaxFragmentChunks - geckoMinFragmentChunks + 1 // 9
	return geckoMinFragmentChunks + int(b[0])%span
}

// --- Receive path ---

func (g *geckoPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, geckoBufferSize)
	for {
		n, addr, err := g.inner.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= 0 {
			continue
		}
		// Top bit of the Salamander-decrypted byte 0 distinguishes Gecko
		// fragment frames from plain QUIC short-header packets. Any QUIC
		// long-header packet must have arrived as a fragment (the sender
		// always fragments long-header), so a top-bit-clear plaintext is
		// either a real short-header packet or unrelated garbage; either
		// way we just return it and let the upper layer (QUIC) decide.
		if buf[0]&0x80 == 0 {
			return copy(p, buf[:n]), addr, nil
		}
		h, payload, decErr := decodeFrame(buf[:n])
		if decErr != nil || !h.isFragment {
			// Malformed fragment frame; drop silently.
			continue
		}
		out, ready := g.acceptChunk(addr, h, payload)
		if !ready {
			continue
		}
		return copy(p, out), addr, nil
	}
}

func (g *geckoPacketConn) acceptChunk(addr net.Addr, h frameHeader, payload []byte) ([]byte, bool) {
	key := reassemblyKey{addr: addr.String(), msgID: h.msgID}

	g.mu.Lock()
	defer g.mu.Unlock()

	e, exists := g.reassembly[key]
	if !exists {
		// Per-source cap.
		if g.perSource[key.addr] >= geckoMaxPerSource {
			return nil, false
		}
		// Global cap with eviction.
		if len(g.reassembly) >= geckoMaxReassembly {
			g.evictOldestLocked()
		}
		e = &reassemblyEntry{
			chunks:   make([][]byte, h.totalChunks),
			total:    h.totalChunks,
			deadline: time.Now().Add(geckoReassemblyTTL),
		}
		g.reassembly[key] = e
		g.perSource[key.addr]++
	} else if e.total != h.totalChunks {
		// Inconsistent total chunks — the other end (or a flooder) sent
		// something we can't reconcile. Drop this frame.
		return nil, false
	}
	if int(h.chunkIdx) >= len(e.chunks) || e.chunks[h.chunkIdx] != nil {
		// Bad index or duplicate; drop.
		return nil, false
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	e.chunks[h.chunkIdx] = cp
	e.received++
	if e.received < int(e.total) {
		return nil, false
	}

	total := 0
	for _, c := range e.chunks {
		total += len(c)
	}
	out := make([]byte, total)
	off := 0
	for _, c := range e.chunks {
		off += copy(out[off:], c)
	}
	g.dropEntryLocked(key)
	return out, true
}

// --- Maintenance ---

func (g *geckoPacketConn) gcLoop() {
	t := time.NewTicker(geckoReassemblyTTL / 2)
	defer t.Stop()
	for {
		select {
		case <-g.closeCh:
			return
		case now := <-t.C:
			g.gcExpired(now)
		}
	}
}

func (g *geckoPacketConn) gcExpired(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, e := range g.reassembly {
		if now.After(e.deadline) {
			g.dropEntryLocked(k)
		}
	}
}

// dropEntryLocked must be called with mu held.
func (g *geckoPacketConn) dropEntryLocked(k reassemblyKey) {
	if _, ok := g.reassembly[k]; !ok {
		return
	}
	delete(g.reassembly, k)
	g.perSource[k.addr]--
	if g.perSource[k.addr] <= 0 {
		delete(g.perSource, k.addr)
	}
}

// evictOldestLocked must be called with mu held. O(n) over the map; n is
// bounded by geckoMaxReassembly.
func (g *geckoPacketConn) evictOldestLocked() {
	var oldestKey reassemblyKey
	var oldestDeadline time.Time
	first := true
	for k, e := range g.reassembly {
		if first || e.deadline.Before(oldestDeadline) {
			oldestKey = k
			oldestDeadline = e.deadline
			first = false
		}
	}
	if !first {
		g.dropEntryLocked(oldestKey)
	}
}

// --- net.PacketConn boilerplate ---

func (g *geckoPacketConn) Close() error {
	g.closeOnce.Do(func() { close(g.closeCh) })
	return g.inner.Close()
}

func (g *geckoPacketConn) LocalAddr() net.Addr               { return g.inner.LocalAddr() }
func (g *geckoPacketConn) SetDeadline(t time.Time) error     { return g.inner.SetDeadline(t) }
func (g *geckoPacketConn) SetReadDeadline(t time.Time) error { return g.inner.SetReadDeadline(t) }
func (g *geckoPacketConn) SetWriteDeadline(t time.Time) error {
	return g.inner.SetWriteDeadline(t)
}

// --- UDP-flavor passthrough ---

func (g *geckoPacketConn) SyscallConn() (syscall.RawConn, error) {
	if u, ok := g.inner.(udpLikePacketConn); ok {
		return u.SyscallConn()
	}
	return nil, errors.ErrUnsupported
}

func (g *geckoPacketConn) SetReadBuffer(bytes int) error {
	if u, ok := g.inner.(udpLikePacketConn); ok {
		return u.SetReadBuffer(bytes)
	}
	return errors.ErrUnsupported
}

func (g *geckoPacketConn) SetWriteBuffer(bytes int) error {
	if u, ok := g.inner.(udpLikePacketConn); ok {
		return u.SetWriteBuffer(bytes)
	}
	return errors.ErrUnsupported
}
