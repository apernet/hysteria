package outbounds

import (
	"net"
	"sync"
	"time"

	"github.com/database64128/tfo-go/v2"
)

type fastOpenDialer struct {
	dialer *tfo.Dialer
}

func newFastOpenDialer(netDialer *net.Dialer) *fastOpenDialer {
	return &fastOpenDialer{
		dialer: &tfo.Dialer{
			Dialer: *netDialer,
		},
	}
}

// Dial returns immediately without actually establishing a connection.
// The connection will be established by the first Write() call.
func (d *fastOpenDialer) Dial(network, address string) (net.Conn, error) {
	return &fastOpenConn{
		dialer:    d.dialer,
		network:   network,
		address:   address,
		readyChan: make(chan struct{}),
	}, nil
}

type fastOpenConn struct {
	dialer  *tfo.Dialer
	network string
	address string

	conn      net.Conn
	connLock  sync.RWMutex
	readyChan chan struct{}

	// States before connection ready
	deadline      *time.Time
	readDeadline  *time.Time
	writeDeadline *time.Time
}

func (c *fastOpenConn) Read(b []byte) (n int, err error) {
	c.connLock.RLock()
	conn := c.conn
	c.connLock.RUnlock()

	if conn != nil {
		return conn.Read(b)
	}

	// Wait until the connection is ready or closed
	<-c.readyChan

	if c.conn == nil {
		// This is equivalent to isClosedBeforeReady() == true
		return 0, net.ErrClosed
	}

	return c.conn.Read(b)
}

func (c *fastOpenConn) Write(b []byte) (n int, err error) {
	c.connLock.RLock()
	conn := c.conn
	c.connLock.RUnlock()

	if conn != nil {
		return conn.Write(b)
	}

	c.connLock.RLock()
	closed := c.isClosedBeforeReady()
	c.connLock.RUnlock()

	if closed {
		return 0, net.ErrClosed
	}

	c.connLock.Lock()
	defer c.connLock.Unlock()

	if c.isClosedBeforeReady() {
		// Closed by other goroutine
		return 0, net.ErrClosed
	}

	conn = c.conn
	if conn != nil {
		// Established by other goroutine
		return conn.Write(b)
	}

	conn, err = c.dialer.Dial(c.network, c.address, b)
	if err != nil {
		close(c.readyChan)
		return 0, err
	}

	// Apply pre-set states
	if c.deadline != nil {
		_ = conn.SetDeadline(*c.deadline)
	}
	if c.readDeadline != nil {
		_ = conn.SetReadDeadline(*c.readDeadline)
	}
	if c.writeDeadline != nil {
		_ = conn.SetWriteDeadline(*c.writeDeadline)
	}

	c.conn = conn
	close(c.readyChan)
	return len(b), nil
}

func (c *fastOpenConn) Close() error {
	c.connLock.RLock()
	defer c.connLock.RUnlock()

	if c.isClosedBeforeReady() {
		return net.ErrClosed
	}

	if c.conn != nil {
		return c.conn.Close()
	}

	close(c.readyChan)
	return nil
}

// isClosedBeforeReady returns true if the connection is closed before the real connection is established.
// This function should be called with connLock.RLock().
func (c *fastOpenConn) isClosedBeforeReady() bool {
	select {
	case <-c.readyChan:
		if c.conn == nil {
			return true
		}
	default:
	}
	return false
}

func (c *fastOpenConn) LocalAddr() net.Addr {
	c.connLock.RLock()
	defer c.connLock.RUnlock()

	if c.conn != nil {
		return c.conn.LocalAddr()
	}

	return nil
}

func (c *fastOpenConn) RemoteAddr() net.Addr {
	c.connLock.RLock()
	conn := c.conn
	c.connLock.RUnlock()

	if conn != nil {
		return conn.RemoteAddr()
	}

	addr, err := net.ResolveTCPAddr(c.network, c.address)
	if err != nil {
		return nil
	}
	return addr
}

func (c *fastOpenConn) SetDeadline(t time.Time) error {
	c.connLock.RLock()
	defer c.connLock.RUnlock()

	c.deadline = &t

	if c.conn != nil {
		return c.conn.SetDeadline(t)
	}

	if c.isClosedBeforeReady() {
		return net.ErrClosed
	}

	return nil
}

func (c *fastOpenConn) SetReadDeadline(t time.Time) error {
	c.connLock.RLock()
	defer c.connLock.RUnlock()

	c.readDeadline = &t

	if c.conn != nil {
		return c.conn.SetReadDeadline(t)
	}

	if c.isClosedBeforeReady() {
		return net.ErrClosed
	}

	return nil
}

func (c *fastOpenConn) SetWriteDeadline(t time.Time) error {
	c.connLock.RLock()
	defer c.connLock.RUnlock()

	c.writeDeadline = &t

	if c.conn != nil {
		return c.conn.SetWriteDeadline(t)
	}

	if c.isClosedBeforeReady() {
		return net.ErrClosed
	}

	return nil
}

var _ net.Conn = (*fastOpenConn)(nil)
