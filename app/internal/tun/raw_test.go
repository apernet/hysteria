package tun

import (
	"net/netip"
	"testing"
)

func TestPacketSource(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0] = 0x45
	copy(v4[12:16], []byte{10, 200, 0, 2})
	got, ok := packetSource(v4)
	if !ok || got != netip.MustParseAddr("10.200.0.2") {
		t.Fatalf("v4 source = %v %v", got, ok)
	}
	v6 := make([]byte, 40)
	v6[0] = 0x60
	addr := netip.MustParseAddr("2001:db8::1").As16()
	copy(v6[8:24], addr[:])
	got, ok = packetSource(v6)
	if !ok || got != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("v6 source = %v %v", got, ok)
	}
	if _, ok := packetSource([]byte{0x45, 0x00}); ok {
		t.Fatal("short ipv4 accepted")
	}
}

func TestNewRawRejectsBadPeer(t *testing.T) {
	_, err := NewRaw("hytun0", 1600, netip.MustParsePrefix("10.200.0.1/30"), netip.MustParseAddr("2001:db8::1"))
	if err == nil {
		t.Fatal("mixed IP versions were accepted")
	}
}
