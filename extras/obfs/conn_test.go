package obfs

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeUDPLikeConn satisfies udpLikePacketConn without being a *net.UDPConn,
// representing wrappers like realm.PunchPacketConn that proxy SyscallConn /
// Set{Read,Write}Buffer through to a real UDP socket.
type fakeUDPLikeConn struct{}

func (fakeUDPLikeConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (fakeUDPLikeConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (fakeUDPLikeConn) Close() error                           { return nil }
func (fakeUDPLikeConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (fakeUDPLikeConn) SetDeadline(time.Time) error            { return nil }
func (fakeUDPLikeConn) SetReadDeadline(time.Time) error        { return nil }
func (fakeUDPLikeConn) SetWriteDeadline(time.Time) error       { return nil }
func (fakeUDPLikeConn) SyscallConn() (syscall.RawConn, error)  { return nil, nil }
func (fakeUDPLikeConn) SetReadBuffer(int) error                { return nil }
func (fakeUDPLikeConn) SetWriteBuffer(int) error               { return nil }

type fakePlainConn struct{}

func (fakePlainConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (fakePlainConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (fakePlainConn) Close() error                           { return nil }
func (fakePlainConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (fakePlainConn) SetDeadline(time.Time) error            { return nil }
func (fakePlainConn) SetReadDeadline(time.Time) error        { return nil }
func (fakePlainConn) SetWriteDeadline(time.Time) error       { return nil }

type noopObfs struct{}

func (noopObfs) Obfuscate(in, out []byte) int   { return copy(out, in) }
func (noopObfs) Deobfuscate(in, out []byte) int { return copy(out, in) }

func TestWrapPacketConnUsesUDPVariantForUDPConn(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{})
	require.NoError(t, err)
	defer udp.Close()

	wrapped := WrapPacketConn(udp, noopObfs{})
	_, ok := wrapped.(*obfsPacketConnUDP)
	assert.True(t, ok, "wrapping a *net.UDPConn should return *obfsPacketConnUDP")
}

func TestWrapPacketConnUsesUDPVariantForUDPLikeWrapper(t *testing.T) {
	wrapped := WrapPacketConn(fakeUDPLikeConn{}, noopObfs{})
	_, ok := wrapped.(*obfsPacketConnUDP)
	assert.True(t, ok, "wrapping a udpLikePacketConn should return *obfsPacketConnUDP")
}

func TestWrapPacketConnFallsBackForPlainPacketConn(t *testing.T) {
	wrapped := WrapPacketConn(fakePlainConn{}, noopObfs{})
	_, isUDP := wrapped.(*obfsPacketConnUDP)
	assert.False(t, isUDP, "wrapping a plain net.PacketConn should not return *obfsPacketConnUDP")
}
