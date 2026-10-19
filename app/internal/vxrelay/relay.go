package vxrelay

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"go.uber.org/zap"
)

// L3Conn is the tunnel side of the relay. Send and Receive carry whole IP packets.
type L3Conn interface {
	Send(ipPkt []byte) error
	Receive() ([]byte, error)
}

// VNI is one overlay network and the LAN endpoint it is pinned to.
type VNI struct {
	ID    uint32
	VTEP  netip.AddrPort
	Allow []netip.Prefix
}

// Config is the LAN socket and the tunnel addresses written into the outer header.
type Config struct {
	Listen  string
	Address netip.Addr
	Peer    netip.Addr
	VNIs    []VNI
}

// Relay copies VXLAN datagrams between a LAN UDP socket and an L3 tunnel.
// It does not create a TUN device.
type Relay struct {
	Logger *zap.Logger

	local netip.Addr
	peer  netip.Addr
	table map[uint32]vniEntry

	mu     sync.Mutex
	conn   *net.UDPConn
	done   chan struct{}
	closed bool
}

type vniEntry struct {
	vtep  netip.AddrPort
	allow []netip.Prefix
}

// New checks the VNI table and binds the LAN socket.
func New(cfg Config) (*Relay, error) {
	local := cfg.Address.Unmap()
	peer := cfg.Peer.Unmap()
	if !local.IsValid() || !peer.IsValid() {
		return nil, errors.New("address or peer is empty")
	}
	if local.Is4() != peer.Is4() {
		return nil, errors.New("address and peer are different IP versions")
	}
	if cfg.Listen == "" {
		return nil, errors.New("listen is empty")
	}
	if len(cfg.VNIs) == 0 {
		return nil, errors.New("at least one vni is required")
	}
	table := make(map[uint32]vniEntry, len(cfg.VNIs))
	for _, v := range cfg.VNIs {
		if v.ID == 0 || v.ID > 0xffffff {
			return nil, fmt.Errorf("vni %d is outside 1-16777215", v.ID)
		}
		if _, dup := table[v.ID]; dup {
			return nil, fmt.Errorf("duplicate vni %d", v.ID)
		}
		if !v.VTEP.IsValid() {
			return nil, fmt.Errorf("vni %d has an empty vtep", v.ID)
		}
		vtep := netip.AddrPortFrom(v.VTEP.Addr().Unmap(), v.VTEP.Port())
		if vtep.Port() == 0 {
			vtep = netip.AddrPortFrom(vtep.Addr(), vxlanPort)
		}
		allow := make([]netip.Prefix, len(v.Allow))
		copy(allow, v.Allow)
		table[v.ID] = vniEntry{vtep: vtep, allow: allow}
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	if err := allowFragmentation(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("allow fragmentation: %w", err)
	}
	return &Relay{
		local: local,
		peer:  peer,
		table: table,
		conn:  conn,
		done:  make(chan struct{}),
	}, nil
}

// LocalAddr is the bound LAN address. VTEPs send to it.
func (r *Relay) LocalAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn == nil {
		return nil
	}
	return r.conn.LocalAddr()
}

// Serve copies packets until Close.
// A datagram from a configured VTEP is wrapped and sent into the tunnel.
// A tunnel packet is unwrapped and sent to the VTEP for its VNI.
func (r *Relay) Serve(conn L3Conn) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	udp := r.conn
	done := r.done
	r.mu.Unlock()

	errCh := make(chan error, 2)
	go func() { errCh <- r.readLoop(udp, conn) }()
	go func() { errCh <- r.writeLoop(udp, conn) }()
	select {
	case err := <-errCh:
		_ = r.Close()
		return err
	case <-done:
		return nil
	}
}

// Close closes the LAN socket and unblocks Serve.
func (r *Relay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	close(r.done)
	if r.conn != nil {
		err := r.conn.Close()
		r.conn = nil
		return err
	}
	return nil
}

func (r *Relay) readLoop(udp *net.UDPConn, conn L3Conn) error {
	buf := make([]byte, 65535)
	for {
		n, addr, err := udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if r.isClosed() {
				return nil
			}
			return err
		}
		vxlan := buf[:n]
		vni, ok := parseVNI(vxlan)
		if !ok {
			continue
		}
		entry, ok := r.table[vni]
		if !ok || !entry.allows(addr.Addr().Unmap()) {
			continue
		}
		pkt := Wrap(r.local, r.peer, FlowPort(vxlan, addr.Port()), append([]byte(nil), vxlan...))
		if pkt == nil {
			continue
		}
		if err := conn.Send(pkt); err != nil {
			if r.isClosed() {
				return nil
			}
			return err
		}
	}
}

func (r *Relay) writeLoop(udp *net.UDPConn, conn L3Conn) error {
	for {
		pkt, err := conn.Receive()
		if err != nil {
			if r.isClosed() {
				return nil
			}
			return err
		}
		vxlan, vni, ok := Unwrap(pkt, r.local, r.peer)
		if !ok {
			continue
		}
		entry, ok := r.table[vni]
		if !ok {
			continue
		}
		if _, err := udp.WriteToUDPAddrPort(vxlan, entry.vtep); err != nil {
			if r.isClosed() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			r.log().Debug("L3 relay write dropped packet", zap.Error(err))
		}
	}
}

func (e vniEntry) allows(src netip.Addr) bool {
	if src == e.vtep.Addr() {
		return true
	}
	for _, p := range e.allow {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

func (r *Relay) log() *zap.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return zap.NewNop()
}

func (r *Relay) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}
