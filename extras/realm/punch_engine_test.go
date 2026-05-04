package realm

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPunchBetweenTwoPeers(t *testing.T) {
	meta := testPunchMetadata()
	a := listenUDP4(t)
	defer a.Close()
	b := listenUDP4(t)
	defer b.Close()

	aAddr := packetConnAddrPort(t, a)
	bAddr := packetConnAddrPort(t, b)

	type result struct {
		r   PunchResult
		err error
	}
	aDone := make(chan result, 1)
	bDone := make(chan result, 1)
	go func() {
		r, err := Punch(context.Background(), a, []netip.AddrPort{aAddr}, []netip.AddrPort{bAddr}, meta, PunchConfig{
			Timeout:  time.Second,
			Interval: 10 * time.Millisecond,
		})
		aDone <- result{r: r, err: err}
	}()
	go func() {
		r, err := Punch(context.Background(), b, []netip.AddrPort{bAddr}, []netip.AddrPort{aAddr}, meta, PunchConfig{
			Timeout:  time.Second,
			Interval: 10 * time.Millisecond,
		})
		bDone <- result{r: r, err: err}
	}()

	aResult := <-aDone
	require.NoError(t, aResult.err)
	assert.Equal(t, bAddr, aResult.r.PeerAddr)
	assert.Contains(t, []PunchPacketType{PunchPacketHello, PunchPacketAck}, aResult.r.Packet.Type)

	bResult := <-bDone
	require.NoError(t, bResult.err)
	assert.Equal(t, aAddr, bResult.r.PeerAddr)
	assert.Contains(t, []PunchPacketType{PunchPacketHello, PunchPacketAck}, bResult.r.Packet.Type)
}

func TestPunchReturnsOnAck(t *testing.T) {
	meta := testPunchMetadata()
	client := listenUDP4(t)
	defer client.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	clientAddr := packetConnAddrPort(t, client)
	peerAddr := packetConnAddrPort(t, peer)

	ackDone := make(chan struct{})
	go func() {
		defer close(ackDone)
		buf := make([]byte, punchMaxWireLen)
		n, addr, err := peer.ReadFrom(buf)
		if err != nil {
			return
		}
		packet, err := DecodePunchPacket(buf[:n], meta)
		if err != nil || packet.Type != PunchPacketHello {
			return
		}
		ack, err := EncodePunchPacket(PunchPacketAck, meta)
		if err != nil {
			return
		}
		_, _ = peer.WriteTo(ack, addr)
	}()

	result, err := Punch(context.Background(), client, []netip.AddrPort{clientAddr}, []netip.AddrPort{peerAddr}, meta, PunchConfig{
		Timeout:  time.Second,
		Interval: 10 * time.Millisecond,
	})
	require.NoError(t, err)
	assert.Equal(t, peerAddr, result.PeerAddr)
	assert.Equal(t, PunchPacketAck, result.Packet.Type)
	<-ackDone
}

func TestCandidatePunchAddrsFiltersByFamily(t *testing.T) {
	local := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:1234"),
	}
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::1]:4433"),
		netip.MustParseAddrPort("198.51.100.20:4433"),
		netip.MustParseAddrPort("198.51.100.20:4433"),
	}

	candidates := candidatePunchAddrs(local, peer, addrFamilyAny)
	assert.Equal(t, []netip.AddrPort{netip.MustParseAddrPort("198.51.100.20:4433")}, candidates)
}

func TestCandidatePunchAddrsExpandsPredictableIPv4Ports(t *testing.T) {
	local := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")}
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:40003"),
	}

	candidates := candidatePunchAddrs(local, peer, addrFamilyAny)
	assert.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:40001"),
		netip.MustParseAddrPort("198.51.100.20:40002"),
		netip.MustParseAddrPort("198.51.100.20:40003"),
		netip.MustParseAddrPort("198.51.100.20:40004"),
		netip.MustParseAddrPort("198.51.100.20:40005"),
		netip.MustParseAddrPort("198.51.100.20:40006"),
		netip.MustParseAddrPort("198.51.100.20:40007"),
	}, candidates)
}

func TestCandidatePunchAddrsDoesNotExpandLargePortGaps(t *testing.T) {
	local := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")}
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:40000"),
		netip.MustParseAddrPort("198.51.100.20:40010"),
	}

	candidates := candidatePunchAddrs(local, peer, addrFamilyAny)
	assert.Equal(t, peer, candidates)
}

func TestCandidatePunchAddrsDoesNotExpandIPv6(t *testing.T) {
	local := []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::10]:1234")}
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::20]:40000"),
		netip.MustParseAddrPort("[2001:db8::20]:40001"),
	}

	candidates := candidatePunchAddrs(local, peer, addrFamilyAny)
	assert.Equal(t, peer, candidates)
}

func TestCandidatePunchAddrsExpansionHandlesPortBounds(t *testing.T) {
	local := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:1234")}
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:65534"),
		netip.MustParseAddrPort("198.51.100.20:65535"),
	}

	candidates := candidatePunchAddrs(local, peer, addrFamilyAny)
	assert.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:65534"),
		netip.MustParseAddrPort("198.51.100.20:65535"),
	}, candidates)
}

func TestPunchTimeout(t *testing.T) {
	meta := testPunchMetadata()
	client := listenUDP4(t)
	defer client.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	clientAddr := packetConnAddrPort(t, client)
	peerAddr := packetConnAddrPort(t, peer)

	_, err := Punch(context.Background(), client, []netip.AddrPort{clientAddr}, []netip.AddrPort{peerAddr}, meta, PunchConfig{
		Timeout:  50 * time.Millisecond,
		Interval: 10 * time.Millisecond,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPunchTimeout), "got %v", err)
}

func TestPunchRejectsBadMetadata(t *testing.T) {
	client := listenUDP4(t)
	defer client.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	_, err := Punch(context.Background(), client, []netip.AddrPort{packetConnAddrPort(t, client)}, []netip.AddrPort{packetConnAddrPort(t, peer)}, PunchMetadata{
		Nonce: "not-hex",
		Obfs:  testPunchMetadata().Obfs,
	}, PunchConfig{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket), "got %v", err)
}

func TestPunchIgnoresWrongMetadata(t *testing.T) {
	meta := testPunchMetadata()
	client := listenUDP4(t)
	defer client.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	clientAddr := packetConnAddrPort(t, client)
	peerAddr := packetConnAddrPort(t, peer)
	wrongMeta := PunchMetadata{
		Nonce: "ffffffffffffffffffffffffffffffff",
		Obfs:  meta.Obfs,
	}

	go func() {
		packet, err := EncodePunchPacket(PunchPacketAck, wrongMeta)
		if err != nil {
			return
		}
		_, _ = peer.WriteTo(packet, udpAddrFromAddrPort(clientAddr))
	}()

	_, err := Punch(context.Background(), client, []netip.AddrPort{clientAddr}, []netip.AddrPort{peerAddr}, meta, PunchConfig{
		Timeout:  50 * time.Millisecond,
		Interval: 10 * time.Millisecond,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPunchTimeout), "got %v", err)
}

func listenUDP4(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	return conn
}

func packetConnAddrPort(t *testing.T, conn net.PacketConn) netip.AddrPort {
	t.Helper()
	addr, ok := addrToAddrPort(conn.LocalAddr())
	require.True(t, ok)
	return addr
}
