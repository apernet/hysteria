package realm

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPunchPacketConnPassesThroughNonPunchPackets(t *testing.T) {
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)

	payload := []byte("not a punch packet")
	_, err = peer.WriteTo(payload, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, from, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])
	assert.Equal(t, peer.LocalAddr().String(), from.String())
}

func TestPunchPacketConnInterceptsRegisteredPunchPackets(t *testing.T) {
	meta := testPunchMetadata()
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)
	require.NoError(t, wrapped.AddPunchAttempt("attempt-1", meta))

	punchPacket, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	_, err = peer.WriteTo(punchPacket, server.LocalAddr())
	require.NoError(t, err)

	payload := []byte("quic packet")
	_, err = peer.WriteTo(payload, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])

	select {
	case ev := <-wrapped.Events():
		assert.Equal(t, "attempt-1", ev.AttemptID)
		assert.Equal(t, packetConnAddrPort(t, peer), ev.From)
		assert.Equal(t, PunchPacketHello, ev.Packet.Type)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for punch event")
	}
}

func TestPunchPacketConnRemovePunchAttempt(t *testing.T) {
	meta := testPunchMetadata()
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)
	require.NoError(t, wrapped.AddPunchAttempt("attempt-1", meta))
	wrapped.RemovePunchAttempt("attempt-1")

	punchPacket, err := EncodePunchPacket(PunchPacketAck, meta)
	require.NoError(t, err)
	_, err = peer.WriteTo(punchPacket, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, punchPacket, buf[:n])

	select {
	case ev := <-wrapped.Events():
		t.Fatalf("unexpected punch event: %+v", ev)
	default:
	}
}

func TestPunchPacketConnRejectsBadAttempts(t *testing.T) {
	server := listenUDP4(t)
	defer server.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)

	err = wrapped.AddPunchAttempt("", testPunchMetadata())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchAttempt), "got %v", err)

	err = wrapped.AddPunchAttempt("attempt-1", PunchMetadata{
		Nonce: "not-hex",
		Obfs:  testPunchMetadata().Obfs,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchPacket), "got %v", err)
}

func TestPunchPacketConnCloseClosesUnderlyingConn(t *testing.T) {
	server := listenUDP4(t)
	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)

	require.NoError(t, wrapped.Close())
	_, _, err = wrapped.ReadFrom(make([]byte, 1))
	require.Error(t, err)
}

func TestNewPunchPacketConnRejectsNilConn(t *testing.T) {
	_, err := NewPunchPacketConn(nil, 1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPunchAttempt), "got %v", err)
}

func TestPunchPacketConnDoesNotExposePunchBytesToReader(t *testing.T) {
	meta := testPunchMetadata()
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)
	require.NoError(t, wrapped.AddPunchAttempt("attempt-1", meta))

	punchPacket, err := EncodePunchPacket(PunchPacketHello, meta)
	require.NoError(t, err)
	_, err = peer.WriteTo(punchPacket, server.LocalAddr())
	require.NoError(t, err)

	payload := []byte("next packet")
	_, err = peer.WriteTo(payload, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(punchPacket, buf[:n]))
	assert.Equal(t, payload, buf[:n])
}

func TestPunchPacketConnInterceptsSTUNPackets(t *testing.T) {
	server := listenUDP4(t)
	defer server.Close()
	peer := listenUDP4(t)
	defer peer.Close()

	wrapped, err := NewPunchPacketConn(server, 1)
	require.NoError(t, err)

	txID := stun.NewTransactionID()
	mapped := netip.MustParseAddrPort("203.0.113.10:4433")
	response := buildSTUNBindingResponse(t, txID, netip.AddrPort{}, mapped)
	_, err = peer.WriteTo(response, server.LocalAddr())
	require.NoError(t, err)

	payload := []byte("quic packet")
	_, err = peer.WriteTo(payload, server.LocalAddr())
	require.NoError(t, err)

	buf := make([]byte, 1500)
	n, _, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])

	select {
	case ev := <-wrapped.STUNEvents():
		assert.Equal(t, txID, ev.Message.TransactionID)
		assert.Equal(t, mapped, ev.Addr)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for STUN event")
	}
}

var _ net.PacketConn = (*PunchPacketConn)(nil)
