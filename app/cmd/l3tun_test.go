package cmd

import (
	"strings"
	"testing"
)

func TestNewL3Relay(t *testing.T) {
	tunDev, err := newL3Device(l3TunConfig{
		Name:    "hytun0",
		Address: "10.200.0.2/30",
		Peer:    "10.200.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tunDev.Close(); err != nil {
		t.Fatal(err)
	}

	dev, err := newL3Device(l3TunConfig{
		Type:    "relay",
		Address: "10.200.0.2/30",
		Peer:    "10.200.0.1",
		Relay: l3RelayConfig{
			Listen: "127.0.0.1:0",
			VNIs: []l3RelayVNI{
				{VNI: 500, VTEP: "192.168.7.1"},
				{VNI: 600, VTEP: "192.168.7.20:4790", Allow: []string{"192.168.7.0/24"}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = newL3Device(l3TunConfig{
		Type:    "relay",
		Address: "10.200.0.2",
		Peer:    "2001:db8::1",
		Relay: l3RelayConfig{
			Listen: "127.0.0.1:0",
			VNIs:   []l3RelayVNI{{VNI: 1, VTEP: "127.0.0.1"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "l3tun") {
		t.Fatalf("mixed versions: %v", err)
	}

	cases := []l3TunConfig{
		{Type: "relay", Address: "10.200.0.2/30", Peer: "10.200.0.1"},
		{
			Type: "nope", Address: "10.200.0.2/30", Peer: "10.200.0.1",
		},
		{
			Type: "relay", Address: "10.200.0.2/30", Peer: "10.200.0.1",
			Relay: l3RelayConfig{
				Listen: "127.0.0.1:0",
				VNIs:   []l3RelayVNI{{VNI: 1, VTEP: "192.168.7.1"}, {VNI: 1, VTEP: "192.168.7.2"}},
			},
		},
		{
			Type: "relay", Address: "10.200.0.2/30", Peer: "10.200.0.1",
			Relay: l3RelayConfig{
				Listen: "127.0.0.1:0",
				VNIs:   []l3RelayVNI{{VNI: 0, VTEP: "192.168.7.1"}},
			},
		},
		{
			Type: "relay", Address: "10.200.0.2/30", Peer: "10.200.0.1",
			Relay: l3RelayConfig{
				Listen: "not an address",
				VNIs:   []l3RelayVNI{{VNI: 1, VTEP: "192.168.7.1"}},
			},
		},
	}
	for _, cfg := range cases {
		if _, err := newL3Device(cfg); err == nil {
			t.Fatalf("accepted %#v", cfg)
		}
	}
}

func TestParseVTEP(t *testing.T) {
	bare, err := parseVTEP("192.168.7.1")
	if err != nil || bare.Port() != 4789 || bare.Addr().String() != "192.168.7.1" {
		t.Fatalf("bare = %v %v", bare, err)
	}
	full, err := parseVTEP("192.168.7.20:4790")
	if err != nil || full.Port() != 4790 {
		t.Fatalf("full = %v %v", full, err)
	}
}
