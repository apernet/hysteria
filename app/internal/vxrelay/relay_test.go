package vxrelay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestRelayCarriesVNIs(t *testing.T) {
	vtepA := listenLoopback(t)
	vtepB := listenLoopback(t)
	vtepC := listenLoopback(t)

	relayA := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("10.200.0.2"),
		VNIs: []VNI{
			{ID: 500, VTEP: vtepA.LocalAddr().(*net.UDPAddr).AddrPort()},
			{ID: 600, VTEP: vtepA.LocalAddr().(*net.UDPAddr).AddrPort()},
		},
	})
	relayB := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.2"),
		Peer:    netip.MustParseAddr("10.200.0.1"),
		VNIs: []VNI{
			{ID: 500, VTEP: vtepB.LocalAddr().(*net.UDPAddr).AddrPort()},
			{ID: 600, VTEP: vtepC.LocalAddr().(*net.UDPAddr).AddrPort()},
		},
	})
	ab, ba := newPipe(), newPipe()
	serveRelay(t, relayA, memEnd{in: ba, out: ab})
	serveRelay(t, relayB, memEnd{in: ab, out: ba})
	t.Cleanup(func() {
		_ = relayA.Close()
		_ = relayB.Close()
		ab.Close()
		ba.Close()
	})

	frame500 := testVXLAN(500, innerFrame(10, 80))
	frame600 := testVXLAN(600, innerFrame(10, 81))
	sendVXLAN(t, vtepA, relayA.LocalAddr(), frame500)
	sendVXLAN(t, vtepA, relayA.LocalAddr(), frame600)
	if got := recvVXLAN(t, vtepB); string(got) != string(frame500) {
		t.Fatalf("vni 500 = %x", got)
	}
	if got := recvVXLAN(t, vtepC); string(got) != string(frame600) {
		t.Fatalf("vni 600 = %x", got)
	}

	sendVXLAN(t, vtepB, relayB.LocalAddr(), frame500)
	if got := recvVXLAN(t, vtepA); string(got) != string(frame500) {
		t.Fatalf("return = %x", got)
	}
}

func TestRelayDropsUnwanted(t *testing.T) {
	sender := listenLoopback(t)
	cap := newCapture()
	relay := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("10.200.0.2"),
		VNIs: []VNI{{
			ID:   500,
			VTEP: sender.LocalAddr().(*net.UDPAddr).AddrPort(),
		}},
	})
	serveRelay(t, relay, cap)
	t.Cleanup(func() {
		_ = relay.Close()
		cap.Close()
	})

	sendVXLAN(t, sender, relay.LocalAddr(), testVXLAN(9, innerFrame(1, 2)))
	oversized := make([]byte, maxPacket)
	oversized[0] = vxlanIBit
	oversized[5] = 0x01
	oversized[6] = 0xf4
	sendVXLAN(t, sender, relay.LocalAddr(), oversized)
	if cap.wait(200 * time.Millisecond) {
		t.Fatal("dropped datagram was forwarded")
	}

	open := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("10.200.0.2"),
		VNIs: []VNI{{
			ID:    500,
			VTEP:  netip.MustParseAddrPort("192.0.2.1:4789"),
			Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		}},
	})
	allowed := newCapture()
	serveRelay(t, open, allowed)
	t.Cleanup(func() {
		_ = open.Close()
		allowed.Close()
	})
	sendVXLAN(t, sender, open.LocalAddr(), testVXLAN(500, innerFrame(1, 2)))
	if !allowed.wait(2 * time.Second) {
		t.Fatal("allowed source was dropped")
	}
}

func TestRelayCloseUnblocksServe(t *testing.T) {
	relay := mustRelay(t, Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("10.200.0.2"),
		VNIs:    []VNI{{ID: 1, VTEP: netip.MustParseAddrPort("127.0.0.1:9")}},
	})
	errCh := make(chan error, 1)
	go func() { errCh <- relay.Serve(memEnd{in: newPipe(), out: newPipe()}) }()
	time.Sleep(20 * time.Millisecond)
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
	if err := relay.Serve(memEnd{in: newPipe(), out: newPipe()}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve after Close = %v", err)
	}
}

func TestNewRejectsBadTable(t *testing.T) {
	base := Config{
		Listen:  "127.0.0.1:0",
		Address: netip.MustParseAddr("10.200.0.1"),
		Peer:    netip.MustParseAddr("2001:db8::1"),
		VNIs:    []VNI{{ID: 1, VTEP: netip.MustParseAddrPort("127.0.0.1:1")}},
	}
	if _, err := New(base); err == nil {
		t.Fatal("mixed IP versions were accepted")
	}
	base.Peer = netip.MustParseAddr("10.200.0.2")
	base.VNIs = []VNI{
		{ID: 1, VTEP: netip.MustParseAddrPort("127.0.0.1:1")},
		{ID: 1, VTEP: netip.MustParseAddrPort("127.0.0.1:2")},
	}
	if _, err := New(base); err == nil {
		t.Fatal("duplicate vni was accepted")
	}
	base.VNIs = []VNI{{ID: 0, VTEP: netip.MustParseAddrPort("127.0.0.1:1")}}
	if _, err := New(base); err == nil {
		t.Fatal("vni 0 was accepted")
	}
}

func mustRelay(t *testing.T, cfg Config) *Relay {
	t.Helper()
	relay, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return relay
}

func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func serveRelay(t *testing.T, relay *Relay, conn L3Conn) {
	t.Helper()
	go func() { _ = relay.Serve(conn) }()
}

func sendVXLAN(t *testing.T, conn *net.UDPConn, dst net.Addr, payload []byte) {
	t.Helper()
	if _, err := conn.WriteTo(payload, dst); err != nil {
		t.Fatal(err)
	}
}

func recvVXLAN(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

type memPipe struct {
	ch   chan []byte
	done chan struct{}
	once sync.Once
}

func newPipe() *memPipe {
	return &memPipe{ch: make(chan []byte, 8), done: make(chan struct{})}
}

func (p *memPipe) Send(b []byte) error {
	select {
	case <-p.done:
		return net.ErrClosed
	case p.ch <- append([]byte(nil), b...):
		return nil
	}
}

func (p *memPipe) Receive() ([]byte, error) {
	select {
	case <-p.done:
		return nil, net.ErrClosed
	case b := <-p.ch:
		return b, nil
	}
}

func (p *memPipe) Close() { p.once.Do(func() { close(p.done) }) }

type memEnd struct{ in, out *memPipe }

func (e memEnd) Send(b []byte) error      { return e.out.Send(b) }
func (e memEnd) Receive() ([]byte, error) { return e.in.Receive() }

type capture struct {
	got  chan struct{}
	done chan struct{}
	once sync.Once
}

func newCapture() *capture {
	return &capture{got: make(chan struct{}, 1), done: make(chan struct{})}
}

func (c *capture) Send(b []byte) error {
	select {
	case c.got <- struct{}{}:
	default:
	}
	return nil
}

func (c *capture) Receive() ([]byte, error) {
	<-c.done
	return nil, net.ErrClosed
}

func (c *capture) wait(d time.Duration) bool {
	select {
	case <-c.got:
		return true
	case <-time.After(d):
		return false
	}
}

func (c *capture) Close() { c.once.Do(func() { close(c.done) }) }
