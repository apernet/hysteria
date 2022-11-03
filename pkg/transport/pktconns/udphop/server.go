package udphop

import (
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/HyNetwork/hysteria/pkg/transport/pktconns/obfs"
	"github.com/HyNetwork/hysteria/pkg/transport/pktconns/udp"
)

const (
	addrMapEntryTTL = time.Minute
)

// ObfsUDPHopServerPacketConn is the UDP port-hopping packet connection for server side.
// It listens on multiple UDP ports and replies to a client using the port it received packet from.
type ObfsUDPHopServerPacketConn struct {
	localAddr net.Addr
	conns     []net.PacketConn

	recvQueue chan *udpPacket
	closeChan chan struct{}

	addrMapMutex sync.RWMutex
	addrMap      map[string]addrMapEntry

	bufPool sync.Pool
}

type addrMapEntry struct {
	index int
	last  time.Time
}

func NewObfsUDPHopServerPacketConn(listen string, obfs obfs.Obfuscator) (*ObfsUDPHopServerPacketConn, error) {
	host, ports, err := parseAddr(listen)
	if err != nil {
		return nil, err
	}
	conns := make([]net.PacketConn, len(ports))
	for i, port := range ports {
		addr := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			conns[i] = udp.NewObfsUDPConn(conn, obfs)
		} else {
			conns[i] = conn
		}
	}
	c := &ObfsUDPHopServerPacketConn{
		localAddr: &udpHopAddr{listen},
		conns:     conns,
		recvQueue: make(chan *udpPacket, packetQueueSize),
		closeChan: make(chan struct{}),
		addrMap:   make(map[string]addrMapEntry),
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, udpBufferSize)
			},
		},
	}
	c.startRecvRoutines()
	go c.addrMapCleanupRoutine()
	return c, nil
}

func (c *ObfsUDPHopServerPacketConn) startRecvRoutines() {
	for i, conn := range c.conns {
		go c.recvRoutine(i, conn)
	}
}

func (c *ObfsUDPHopServerPacketConn) recvRoutine(i int, conn net.PacketConn) {
	log.Printf("udphop: receiving on %s", conn.LocalAddr())
	for {
		buf := c.bufPool.Get().([]byte)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("udphop: routine %d read error: %v", i, err)
			return
		}
		// Update addrMap
		c.addrMapMutex.Lock()
		c.addrMap[addr.String()] = addrMapEntry{i, time.Now()}
		c.addrMapMutex.Unlock()
		select {
		case c.recvQueue <- &udpPacket{buf, n, addr}:
			// Packet sent to queue
		default:
			log.Printf("udphop: recv queue full, dropping packet from %s", addr)
			c.bufPool.Put(buf)
		}
	}
}

func (c *ObfsUDPHopServerPacketConn) addrMapCleanupRoutine() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.addrMapMutex.Lock()
			for addr, entry := range c.addrMap {
				if time.Since(entry.last) > addrMapEntryTTL {
					delete(c.addrMap, addr)
				}
			}
			c.addrMapMutex.Unlock()
		case <-c.closeChan:
			return
		}
	}
}

func (c *ObfsUDPHopServerPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-c.recvQueue:
		n := copy(b, p.buf[:p.n])
		c.bufPool.Put(p.buf)
		return n, p.addr, nil
	case <-c.closeChan:
		return 0, nil, net.ErrClosed
	}
}

func (c *ObfsUDPHopServerPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Find index from addrMap
	c.addrMapMutex.RLock()
	entry := c.addrMap[addr.String()]
	c.addrMapMutex.RUnlock()
	return c.conns[entry.index].WriteTo(b, addr)
}

func (c *ObfsUDPHopServerPacketConn) Close() error {
	for _, conn := range c.conns {
		_ = conn.Close() // recvRoutines will exit on error
	}
	close(c.closeChan)
	return nil
}

func (c *ObfsUDPHopServerPacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *ObfsUDPHopServerPacketConn) SetDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *ObfsUDPHopServerPacketConn) SetReadDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *ObfsUDPHopServerPacketConn) SetWriteDeadline(t time.Time) error {
	// Not implemented
	return nil
}
