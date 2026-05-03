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

func TestServerPuncherRespondsToHello(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	meta := testPunchMetadata()
	server, wrapped, puncher := newTestServerPuncher(t, ctx)
	defer server.Close()
	client := listenUDP4(t)
	defer client.Close()
	pumpPunchPacketConn(wrapped)

	serverAddr := packetConnAddrPort(t, server)
	clientAddr := packetConnAddrPort(t, client)
	done := make(chan punchResponse, 1)
	go func() {
		r, err := puncher.Respond(ctx, "attempt-1", []netip.AddrPort{serverAddr}, []netip.AddrPort{clientAddr}, meta, PunchConfig{
			Timeout:  50 * time.Millisecond,
			Interval: 10 * time.Millisecond,
		})
		done <- punchResponse{result: r, err: err}
	}()

	time.Sleep(10 * time.Millisecond)
	hello, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	_, err = client.WriteTo(hello, server.LocalAddr())
	require.NoError(t, err)

	ack := readPunchPacketFrom(t, client, meta, PunchPacketAck)
	assert.Equal(t, PunchPacketAck, ack.Type)

	resp := <-done
	require.NoError(t, resp.err)
	assert.Equal(t, clientAddr, resp.result.PeerAddr)
	assert.Equal(t, PunchPacketHello, resp.result.Packet.Type)
}

func TestServerPuncherSendsHelloAndSeesAck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	meta := testPunchMetadata()
	server, wrapped, puncher := newTestServerPuncher(t, ctx)
	defer server.Close()
	client := listenUDP4(t)
	defer client.Close()
	pumpPunchPacketConn(wrapped)

	serverAddr := packetConnAddrPort(t, server)
	clientAddr := packetConnAddrPort(t, client)
	done := make(chan punchResponse, 1)
	go func() {
		r, err := puncher.Respond(ctx, "attempt-1", []netip.AddrPort{serverAddr}, []netip.AddrPort{clientAddr}, meta, PunchConfig{
			Timeout:  50 * time.Millisecond,
			Interval: 10 * time.Millisecond,
		})
		done <- punchResponse{result: r, err: err}
	}()

	hello := readPunchPacketFrom(t, client, meta, PunchPacketHello)
	assert.Equal(t, PunchPacketHello, hello.Type)

	ack, err := EncodePunchPacket(PunchPacketAck, meta)
	require.NoError(t, err)
	_, err = client.WriteTo(ack, server.LocalAddr())
	require.NoError(t, err)

	resp := <-done
	require.NoError(t, resp.err)
	assert.Equal(t, clientAddr, resp.result.PeerAddr)
	assert.Equal(t, PunchPacketAck, resp.result.Packet.Type)
}

func TestServerPuncherTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	meta := testPunchMetadata()
	server, wrapped, puncher := newTestServerPuncher(t, ctx)
	defer server.Close()
	client := listenUDP4(t)
	defer client.Close()
	pumpPunchPacketConn(wrapped)

	_, err := puncher.Respond(ctx, "attempt-1", []netip.AddrPort{packetConnAddrPort(t, server)}, []netip.AddrPort{packetConnAddrPort(t, client)}, meta, PunchConfig{
		Timeout:  30 * time.Millisecond,
		Interval: 10 * time.Millisecond,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPunchTimeout), "got %v", err)
}

func TestServerPuncherConcurrentAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, wrapped, puncher := newTestServerPuncher(t, ctx)
	defer server.Close()
	clientA := listenUDP4(t)
	defer clientA.Close()
	clientB := listenUDP4(t)
	defer clientB.Close()
	pumpPunchPacketConn(wrapped)

	metaA := testPunchMetadata()
	metaB := PunchMetadata{
		Nonce: "11112233445566778899aabbccddeeff",
		Obfs:  "11112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
	serverAddr := packetConnAddrPort(t, server)
	clientAAddr := packetConnAddrPort(t, clientA)
	clientBAddr := packetConnAddrPort(t, clientB)

	doneA := make(chan punchResponse, 1)
	doneB := make(chan punchResponse, 1)
	go func() {
		r, err := puncher.Respond(ctx, "attempt-a", []netip.AddrPort{serverAddr}, []netip.AddrPort{clientAAddr}, metaA, PunchConfig{
			Timeout:  50 * time.Millisecond,
			Interval: 10 * time.Millisecond,
		})
		doneA <- punchResponse{result: r, err: err}
	}()
	go func() {
		r, err := puncher.Respond(ctx, "attempt-b", []netip.AddrPort{serverAddr}, []netip.AddrPort{clientBAddr}, metaB, PunchConfig{
			Timeout:  50 * time.Millisecond,
			Interval: 10 * time.Millisecond,
		})
		doneB <- punchResponse{result: r, err: err}
	}()

	time.Sleep(10 * time.Millisecond)
	sendHello(t, clientA, server.LocalAddr(), metaA)
	sendHello(t, clientB, server.LocalAddr(), metaB)
	readPunchPacketFrom(t, clientA, metaA, PunchPacketAck)
	readPunchPacketFrom(t, clientB, metaB, PunchPacketAck)

	respA := <-doneA
	require.NoError(t, respA.err)
	assert.Equal(t, clientAAddr, respA.result.PeerAddr)
	respB := <-doneB
	require.NoError(t, respB.err)
	assert.Equal(t, clientBAddr, respB.result.PeerAddr)
}

func TestServerPuncherRejectsDuplicateAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	meta := testPunchMetadata()
	server, _, puncher := newTestServerPuncher(t, ctx)
	defer server.Close()
	clientB := listenUDP4(t)
	defer clientB.Close()

	_, err := puncher.addAttempt("attempt-1", meta)
	require.NoError(t, err)
	defer puncher.removeAttempt("attempt-1")

	_, err = puncher.Respond(ctx, "attempt-1", []netip.AddrPort{packetConnAddrPort(t, server)}, []netip.AddrPort{packetConnAddrPort(t, clientB)}, meta, PunchConfig{
		Timeout:  10 * time.Millisecond,
		Interval: 10 * time.Millisecond,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchAttempt), "got %v", err)
}

type punchResponse struct {
	result PunchResult
	err    error
}

func newTestServerPuncher(t *testing.T, ctx context.Context) (net.PacketConn, *PunchPacketConn, *ServerPuncher) {
	t.Helper()
	server := listenUDP4(t)
	wrapped, err := NewPunchPacketConn(server, 8)
	require.NoError(t, err)
	puncher, err := NewServerPuncher(ctx, wrapped)
	require.NoError(t, err)
	return server, wrapped, puncher
}

func pumpPunchPacketConn(conn *PunchPacketConn) {
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := conn.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
}

func sendHello(t *testing.T, conn net.PacketConn, serverAddr net.Addr, meta PunchMetadata) {
	t.Helper()
	packet, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	_, err = conn.WriteTo(packet, serverAddr)
	require.NoError(t, err)
}

func readPunchPacketFrom(t *testing.T, conn net.PacketConn, meta PunchMetadata, want PunchPacketType) PunchPacket {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, punchMaxWireLen)
	for {
		n, _, err := conn.ReadFrom(buf)
		require.NoError(t, err)
		packet, err := DecodePunchPacket(buf[:n], meta)
		if err != nil {
			continue
		}
		if packet.Type == want {
			return packet
		}
	}
}
