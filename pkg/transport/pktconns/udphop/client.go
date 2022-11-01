package udphop

import (
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/HyNetwork/hysteria/pkg/transport/pktconns/obfs"
	"github.com/HyNetwork/hysteria/pkg/transport/pktconns/udp"
)

const (
	portHoppingInterval = 30 * time.Second
)

// ObfsUDPHopClientPacketConn is the UDP port-hopping packet connection for client side.
// It hops to a different local & server port every once in a while (portHoppingInterval).
type ObfsUDPHopClientPacketConn struct {
	serverAddr  net.Addr // Combined udpHopAddr
	serverAddrs []net.Addr

	obfs obfs.Obfuscator

	connMutex   sync.RWMutex
	prevConn    net.PacketConn
	currentConn net.PacketConn
	addrIndex   int

	recvQueue chan *udpPacket
	closeChan chan struct{}

	bufPool sync.Pool
}

func NewObfsUDPHopClientPacketConn(server string, obfs obfs.Obfuscator) (*ObfsUDPHopClientPacketConn, net.Addr, error) {
	host, ports, err := parseAddr(server)
	if err != nil {
		return nil, nil, err
	}
	// Resolve the server IP address, then attach the ports to UDP addresses
	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, nil, err
	}
	serverAddrs := make([]net.Addr, len(ports))
	for i, port := range ports {
		serverAddrs[i] = &net.UDPAddr{
			IP:   ip.IP,
			Port: int(port),
		}
		log.Printf("udphop: server address %s", serverAddrs[i])
	}
	conn := &ObfsUDPHopClientPacketConn{
		serverAddr:  &udpHopAddr{server},
		serverAddrs: serverAddrs,
		obfs:        obfs,
		addrIndex:   rand.Intn(len(serverAddrs)),
		recvQueue:   make(chan *udpPacket, packetQueueSize),
		closeChan:   make(chan struct{}),
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, udpBufferSize)
			},
		},
	}
	curConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, err
	}
	if obfs != nil {
		conn.currentConn = udp.NewObfsUDPConn(curConn, obfs)
	} else {
		conn.currentConn = curConn
	}
	go conn.recvRoutine(conn.currentConn)
	go conn.hopRoutine()
	return conn, conn.serverAddr, nil
}

func (c *ObfsUDPHopClientPacketConn) recvRoutine(conn net.PacketConn) {
	for {
		buf := c.bufPool.Get().([]byte)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("udphop: read error (local %s): %v", conn.LocalAddr(), err)
			return
		}
		select {
		case c.recvQueue <- &udpPacket{buf, n, addr}:
		default:
			log.Printf("udphop: recv queue full, dropping packet from %s", addr)
			c.bufPool.Put(buf)
		}
	}
}

func (c *ObfsUDPHopClientPacketConn) hopRoutine() {
	ticker := time.NewTicker(portHoppingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.hop()
		case <-c.closeChan:
			return
		}
	}
}

func (c *ObfsUDPHopClientPacketConn) hop() {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	if c.prevConn != nil {
		_ = c.prevConn.Close() // recvRoutine will exit on error
	}
	// We need to keep receiving packets from the previous connection,
	// or there will be packet loss because there might be packets
	// still in flight sent to the old port.
	c.prevConn = c.currentConn
	c.addrIndex = rand.Intn(len(c.serverAddrs))
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf("udphop: failed to listen on %s: %v", conn.LocalAddr(), err)
		return
	}
	if c.obfs != nil {
		c.currentConn = udp.NewObfsUDPConn(conn, c.obfs)
	} else {
		c.currentConn = conn
	}
	go c.recvRoutine(c.currentConn)
	log.Printf("udphop: hopping to %s", c.serverAddrs[c.addrIndex])
}

func (c *ObfsUDPHopClientPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case p := <-c.recvQueue:
			// Check if the packet is from one of the server addresses
			for _, addr := range c.serverAddrs {
				if addr.String() == p.addr.String() {
					// Copy the packet to the buffer
					n := copy(b, p.buf[:p.n])
					c.bufPool.Put(p.buf)
					return n, c.serverAddr, nil
				}
			}
			// Drop the packet, continue
			c.bufPool.Put(p.buf)
		case <-c.closeChan:
			return 0, nil, net.ErrClosed
		}
		// Ignore packets from other addresses
	}
}

func (c *ObfsUDPHopClientPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()
	// Check if the address is the server address
	if addr.String() != c.serverAddr.String() {
		log.Printf("udphop: invalid write address %s", addr)
		return 0, net.ErrWriteToConnected
	}
	return c.currentConn.WriteTo(b, c.serverAddrs[c.addrIndex])
}

func (c *ObfsUDPHopClientPacketConn) Close() error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	if c.prevConn != nil {
		_ = c.prevConn.Close()
	}
	err := c.currentConn.Close()
	close(c.closeChan)
	return err
}

func (c *ObfsUDPHopClientPacketConn) LocalAddr() net.Addr {
	c.connMutex.RLock()
	defer c.connMutex.RUnlock()
	return c.currentConn.LocalAddr()
}

func (c *ObfsUDPHopClientPacketConn) SetDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *ObfsUDPHopClientPacketConn) SetReadDeadline(t time.Time) error {
	// Not implemented
	return nil
}

func (c *ObfsUDPHopClientPacketConn) SetWriteDeadline(t time.Time) error {
	// Not implemented
	return nil
}
