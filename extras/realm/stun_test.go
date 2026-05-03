package realm

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverSTUNIPv4(t *testing.T) {
	server := newFakeSTUNServer(t, "udp4", "127.0.0.1:0", []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.10:4433"),
	})
	defer server.Close()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()

	addrs, err := Discover(context.Background(), conn, STUNConfig{
		Servers: []string{server.Addr().String()},
		Timeout: time.Second,
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:4433")}, addrs)
}

func TestDiscoverSTUNDeduplicatesResponses(t *testing.T) {
	mappedAddr := netip.MustParseAddrPort("203.0.113.10:4433")
	server := newFakeSTUNServer(t, "udp4", "127.0.0.1:0", []netip.AddrPort{mappedAddr, mappedAddr})
	defer server.Close()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()

	addrs, err := Discover(context.Background(), conn, STUNConfig{
		Servers: []string{server.Addr().String()},
		Timeout: time.Second,
	})
	require.NoError(t, err)
	assert.Equal(t, []netip.AddrPort{mappedAddr}, addrs)
}

func TestDiscoverSTUNIPv6(t *testing.T) {
	server := newFakeSTUNServer(t, "udp6", "[::1]:0", []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::10]:4433"),
	})
	defer server.Close()

	conn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer conn.Close()

	addrs, err := Discover(context.Background(), conn, STUNConfig{
		Servers: []string{server.Addr().String()},
		Timeout: time.Second,
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::10]:4433")}, addrs)
}

func TestDiscoverSTUNWithDemux(t *testing.T) {
	server := newFakeSTUNServer(t, "udp4", "127.0.0.1:0", []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.10:4433"),
	})
	defer server.Close()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer conn.Close()
	wrapped, err := NewPunchPacketConn(conn, 4)
	require.NoError(t, err)
	go pumpPunchPacketConn(wrapped)

	addrs, err := DiscoverWithDemux(context.Background(), wrapped, STUNConfig{
		Servers: []string{server.Addr().String()},
		Timeout: time.Second,
	})
	require.NoError(t, err)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("203.0.113.10:4433")}, addrs)
}

func TestResolveSTUNServersUsesAllResolvedAddresses(t *testing.T) {
	resolver := fakeSTUNResolver{
		"stun.example.com": {
			{IP: net.ParseIP("192.0.2.1")},
			{IP: net.ParseIP("2001:db8::1")},
			{IP: net.ParseIP("192.0.2.1")},
		},
	}

	addrs, err := resolveSTUNServers(context.Background(), resolver, []string{"stun.example.com:19302"}, addrFamilyAny)
	require.NoError(t, err)
	require.Len(t, addrs, 2)
	assert.ElementsMatch(t, []string{"192.0.2.1:19302", "[2001:db8::1]:19302"}, udpAddrStrings(addrs))
}

func TestResolveSTUNServersFiltersByLocalFamily(t *testing.T) {
	resolver := fakeSTUNResolver{
		"stun.example.com": {
			{IP: net.ParseIP("192.0.2.1")},
			{IP: net.ParseIP("2001:db8::1")},
		},
	}

	addrs, err := resolveSTUNServers(context.Background(), resolver, []string{"stun.example.com"}, addrFamilyIPv4)
	require.NoError(t, err)
	assert.Equal(t, []string{"192.0.2.1:3478"}, udpAddrStrings(addrs))

	addrs, err = resolveSTUNServers(context.Background(), resolver, []string{"stun.example.com"}, addrFamilyIPv6)
	require.NoError(t, err)
	assert.Equal(t, []string{"[2001:db8::1]:3478"}, udpAddrStrings(addrs))
}

func TestParseSTUNBindingResponsePrefersXORMappedAddress(t *testing.T) {
	var txID [stun.TransactionIDSize]byte
	copy(txID[:], []byte("abcdefghijkl"))
	want := netip.MustParseAddrPort("[2001:db8::20]:5555")
	packet := buildSTUNBindingResponse(t, txID, netip.MustParseAddrPort("192.0.2.10:4444"), want)

	msg, got, err := parseSTUNBindingResponse(packet)
	require.NoError(t, err)
	assert.Equal(t, txID, msg.TransactionID)
	assert.Equal(t, want, got)
}

type fakeSTUNResolver map[string][]net.IPAddr

func (r fakeSTUNResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := r[host]
	if !ok {
		return nil, errors.New("host not found")
	}
	return append([]net.IPAddr(nil), ips...), nil
}

type fakeSTUNServer struct {
	conn      net.PacketConn
	responses []netip.AddrPort
}

func newFakeSTUNServer(t *testing.T, network, address string, responses []netip.AddrPort) *fakeSTUNServer {
	t.Helper()
	conn, err := net.ListenPacket(network, address)
	require.NoError(t, err)
	s := &fakeSTUNServer{conn: conn, responses: responses}
	go s.serve()
	return s
}

func (s *fakeSTUNServer) Addr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *fakeSTUNServer) Close() error {
	return s.conn.Close()
}

func (s *fakeSTUNServer) serve() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		msg := stun.New()
		if err := stun.Decode(buf[:n], msg); err != nil || msg.Type != stun.BindingRequest {
			continue
		}
		for _, response := range s.responses {
			_, _ = s.conn.WriteTo(buildSTUNBindingResponse(nil, msg.TransactionID, netip.AddrPort{}, response), addr)
		}
	}
}

func buildSTUNBindingResponse(t require.TestingT, txID [stun.TransactionIDSize]byte, mapped, xorMapped netip.AddrPort) []byte {
	setters := []stun.Setter{
		stun.BindingSuccess,
		stun.NewTransactionIDSetter(txID),
	}
	if mapped.IsValid() {
		setters = append(setters, &stun.MappedAddress{
			IP:   netIPFromAddr(mapped.Addr()),
			Port: int(mapped.Port()),
		})
	}
	if xorMapped.IsValid() {
		setters = append(setters, &stun.XORMappedAddress{
			IP:   netIPFromAddr(xorMapped.Addr()),
			Port: int(xorMapped.Port()),
		})
	}
	msg, err := stun.Build(setters...)
	if t != nil {
		require.NoError(t, err)
	} else if err != nil {
		return nil
	}
	return msg.Raw
}

func netIPFromAddr(addr netip.Addr) net.IP {
	if addr.Is4() {
		ip := addr.As4()
		return net.IPv4(ip[0], ip[1], ip[2], ip[3])
	}
	ip := addr.As16()
	return net.IP(append([]byte(nil), ip[:]...))
}

func udpAddrStrings(addrs []*net.UDPAddr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}
