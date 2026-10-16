package server

import (
	"sync"
	"sync/atomic"

	"github.com/apernet/quic-go"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/l3"
	"github.com/apernet/hysteria/core/v2/internal/l3frag"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

const l3RecvQueue = 128

// HyL3Conn is the single L3 peer binding for this server.
// Send drops the packet when no client is bound. Receive waits for the next
// reassembled IP packet from the current peer.
type HyL3Conn interface {
	Send(ipPkt []byte) error
	Receive() ([]byte, error)
}

type l3Hub struct {
	mu     sync.Mutex
	cur    *l3Peer
	recv   chan []byte
	done   chan struct{}
	once   sync.Once
	closed bool
}

func newL3Hub() *l3Hub {
	return &l3Hub{
		recv: make(chan []byte, l3RecvQueue),
		done: make(chan struct{}),
	}
}

func (h *l3Hub) adopt(conn *quic.Conn, authID string, tl TrafficLogger) *l3Peer {
	p := &l3Peer{
		hub:    h,
		conn:   conn,
		authID: authID,
		tl:     tl,
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.cur = p
	return p
}

func (h *l3Hub) clear(p *l3Peer) {
	if p == nil {
		return
	}
	h.mu.Lock()
	if h.cur == p {
		h.cur = nil
	}
	h.mu.Unlock()
}

func (h *l3Hub) current() *l3Peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur
}

func (h *l3Hub) push(pkt []byte) {
	select {
	case <-h.done:
		return
	default:
	}
	select {
	case <-h.done:
	case h.recv <- pkt:
	default:
	}
}

func (h *l3Hub) Send(ipPkt []byte) error {
	select {
	case <-h.done:
		return coreErrs.ClosedError{}
	default:
	}
	p := h.current()
	if p == nil {
		return nil
	}
	if p.tl != nil && len(ipPkt) > 0 && len(ipPkt) <= protocol.L3MaxPacketSize {
		if !p.tl.LogTraffic(p.authID, 0, uint64(len(ipPkt))) {
			_ = p.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			h.clear(p)
			return nil
		}
	}
	if err := p.send(ipPkt); err != nil {
		// A gone client must not tear down the local TUN. Drop the packet.
		if p.conn.Context().Err() != nil {
			h.clear(p)
		}
		return nil
	}
	return nil
}

func (h *l3Hub) Receive() ([]byte, error) {
	select {
	case <-h.done:
		return nil, coreErrs.ClosedError{}
	case pkt := <-h.recv:
		return pkt, nil
	}
}

func (h *l3Hub) close() {
	h.once.Do(func() {
		h.mu.Lock()
		h.closed = true
		h.cur = nil
		h.mu.Unlock()
		close(h.done)
	})
}

type l3Peer struct {
	hub    *l3Hub
	conn   *quic.Conn
	authID string
	tl     TrafficLogger
	asm    l3frag.Assembler
	next   atomic.Uint32
}

func (p *l3Peer) send(ip []byte) error {
	return l3.Send(p.conn.SendDatagram, &p.next, ip)
}

func (p *l3Peer) accept(frag protocol.L3Fragment) {
	if p.hub.current() != p {
		return
	}
	pkt := p.asm.Feed(frag.PacketID, frag.FragID, frag.FragCount, frag.Data)
	if pkt == nil {
		return
	}
	if p.tl != nil {
		if !p.tl.LogTraffic(p.authID, uint64(len(pkt)), 0) {
			_ = p.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			return
		}
	}
	p.hub.push(pkt)
}
