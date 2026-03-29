package udphop

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type stubPacketConn struct {
	mu                    sync.Mutex
	readResults           []readResult
	setDeadlineCalls      []time.Time
	setReadDeadlineCalls  []time.Time
	setWriteDeadlineCalls []time.Time
	closed                bool
}

type readResult struct {
	n    int
	addr net.Addr
	err  error
}

func (c *stubPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, nil, net.ErrClosed
	}
	if len(c.readResults) == 0 {
		return 0, nil, net.ErrClosed
	}
	r := c.readResults[0]
	c.readResults = c.readResults[1:]
	if r.n > 0 {
		copy(p, []byte("payload")[:r.n])
	}
	return r.n, r.addr, r.err
}

func (c *stubPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) { return len(p), nil }
func (c *stubPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *stubPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *stubPacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setDeadlineCalls = append(c.setDeadlineCalls, t)
	return nil
}

func (c *stubPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setReadDeadlineCalls = append(c.setReadDeadlineCalls, t)
	return nil
}

func (c *stubPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setWriteDeadlineCalls = append(c.setWriteDeadlineCalls, t)
	return nil
}

func TestRecvLoopTimeoutIsNotFatal(t *testing.T) {
	conn := &stubPacketConn{
		readResults: []readResult{
			{err: timeoutError{}},
			{n: 3, addr: &net.UDPAddr{}},
		},
	}
	u := &udpHopPacketConn{
		Addr:      &net.UDPAddr{},
		recvQueue: make(chan *udpPacket, 2),
		closeChan: make(chan struct{}),
		bufPool: sync.Pool{New: func() any {
			return make([]byte, udpBufferSize)
		}},
	}

	go u.recvLoop(conn)

	first := <-u.recvQueue
	require.Error(t, first.Err)
	require.True(t, errors.As(first.Err, new(net.Error)))

	second := <-u.recvQueue
	require.NoError(t, second.Err)
	require.Equal(t, 3, second.N)
	u.bufPool.Put(second.Buf)
}

func TestHopReappliesStoredDeadlines(t *testing.T) {
	firstConn := &stubPacketConn{}
	secondConn := &stubPacketConn{}
	listenCalls := 0
	u := &udpHopPacketConn{
		Addr:  &net.UDPAddr{},
		Addrs: []net.Addr{&net.UDPAddr{Port: 1}},
		ListenUDPFunc: func() (net.PacketConn, error) {
			listenCalls++
			if listenCalls == 1 {
				return secondConn, nil
			}
			return nil, errors.New("unexpected extra listen")
		},
		currentConn: firstConn,
		closeChan:   make(chan struct{}),
		bufPool: sync.Pool{New: func() any {
			return make([]byte, udpBufferSize)
		}},
	}

	deadline := time.Now().Add(time.Minute)
	readDeadline := time.Now().Add(2 * time.Minute)
	writeDeadline := time.Now().Add(3 * time.Minute)

	require.NoError(t, u.SetDeadline(deadline))
	require.NoError(t, u.SetReadDeadline(readDeadline))
	require.NoError(t, u.SetWriteDeadline(writeDeadline))

	u.hop()

	require.Empty(t, secondConn.setDeadlineCalls)
	require.Equal(t, []time.Time{readDeadline}, secondConn.setReadDeadlineCalls)
	require.Equal(t, []time.Time{writeDeadline}, secondConn.setWriteDeadlineCalls)
}
