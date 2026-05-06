package realm

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/pion/stun/v3"
)

const defaultPunchEventBuffer = 16

var ErrInvalidPunchAttempt = errors.New("invalid punch attempt")

type PunchPacketEvent struct {
	AttemptID string
	From      netip.AddrPort
	Packet    PunchPacket
}

type STUNPacketEvent struct {
	Message *stun.Message
	Addr    netip.AddrPort
}

// PunchPacketConn routes registered punch packets to Events while exposing all
// other packets through the wrapped PacketConn for QUIC.
type PunchPacketConn struct {
	net.PacketConn

	// udp is non-nil when the wrapped PacketConn is a *net.UDPConn. It is used
	// to expose UDP-specific methods (SyscallConn, SetReadBuffer,
	// SetWriteBuffer) so quic-go and obfs wrappers can keep their UDP
	// optimizations even when sitting above us.
	udp *net.UDPConn

	mu       sync.RWMutex
	attempts map[string]PunchMetadata
	events   chan PunchPacketEvent
	stun     chan STUNPacketEvent
}

func NewPunchPacketConn(conn net.PacketConn, eventBuffer int) (*PunchPacketConn, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: conn is nil", ErrInvalidPunchAttempt)
	}
	if eventBuffer <= 0 {
		eventBuffer = defaultPunchEventBuffer
	}
	udp, _ := conn.(*net.UDPConn)
	return &PunchPacketConn{
		PacketConn: conn,
		udp:        udp,
		attempts:   make(map[string]PunchMetadata),
		events:     make(chan PunchPacketEvent, eventBuffer),
		stun:       make(chan STUNPacketEvent, eventBuffer),
	}, nil
}

// SyscallConn returns the underlying *net.UDPConn's syscall.RawConn. Returns
// errors.ErrUnsupported when the wrapped PacketConn is not a *net.UDPConn.
func (c *PunchPacketConn) SyscallConn() (syscall.RawConn, error) {
	if c.udp == nil {
		return nil, errors.ErrUnsupported
	}
	return c.udp.SyscallConn()
}

// SetReadBuffer proxies to the underlying *net.UDPConn. Returns
// errors.ErrUnsupported when the wrapped PacketConn is not a *net.UDPConn.
func (c *PunchPacketConn) SetReadBuffer(bytes int) error {
	if c.udp == nil {
		return errors.ErrUnsupported
	}
	return c.udp.SetReadBuffer(bytes)
}

// SetWriteBuffer proxies to the underlying *net.UDPConn. Returns
// errors.ErrUnsupported when the wrapped PacketConn is not a *net.UDPConn.
func (c *PunchPacketConn) SetWriteBuffer(bytes int) error {
	if c.udp == nil {
		return errors.ErrUnsupported
	}
	return c.udp.SetWriteBuffer(bytes)
}

func (c *PunchPacketConn) Events() <-chan PunchPacketEvent {
	return c.events
}

func (c *PunchPacketConn) STUNEvents() <-chan STUNPacketEvent {
	return c.stun
}

func (c *PunchPacketConn) AddPunchAttempt(id string, meta PunchMetadata) error {
	if id == "" {
		return fmt.Errorf("%w: id is required", ErrInvalidPunchAttempt)
	}
	if _, _, err := decodePunchMetadata(meta); err != nil {
		return err
	}
	c.mu.Lock()
	c.attempts[id] = meta
	c.mu.Unlock()
	return nil
}

func (c *PunchPacketConn) RemovePunchAttempt(id string) {
	c.mu.Lock()
	delete(c.attempts, id)
	c.mu.Unlock()
}

func (c *PunchPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if ev, ok := c.decodeSTUNPacket(p[:n]); ok {
			c.emitSTUN(ev)
			continue
		}
		if ev, ok := c.decodePunchPacket(p[:n], addr); ok {
			c.emitPunch(ev)
			continue
		}
		return n, addr, nil
	}
}

func (c *PunchPacketConn) decodeSTUNPacket(packet []byte) (STUNPacketEvent, bool) {
	if !stun.IsMessage(packet) {
		return STUNPacketEvent{}, false
	}
	msg, addr, err := parseSTUNBindingResponse(packet)
	if err != nil {
		return STUNPacketEvent{}, false
	}
	return STUNPacketEvent{Message: msg, Addr: addr}, true
}

func (c *PunchPacketConn) decodePunchPacket(packet []byte, from net.Addr) (PunchPacketEvent, bool) {
	fromAddr, ok := addrToAddrPort(from)
	if !ok {
		return PunchPacketEvent{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for id, meta := range c.attempts {
		punchPacket, err := DecodePunchPacket(packet, meta)
		if err != nil {
			continue
		}
		return PunchPacketEvent{
			AttemptID: id,
			From:      fromAddr,
			Packet:    punchPacket,
		}, true
	}
	return PunchPacketEvent{}, false
}

func (c *PunchPacketConn) emitPunch(ev PunchPacketEvent) {
	select {
	case c.events <- ev:
	default:
	}
}

func (c *PunchPacketConn) emitSTUN(ev STUNPacketEvent) {
	select {
	case c.stun <- ev:
	default:
	}
}
