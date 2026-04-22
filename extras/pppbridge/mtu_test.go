package pppbridge

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculatePPPMTU(t *testing.T) {
	tests := []struct {
		name        string
		wanMTU      int
		outerIPv6   bool
		salamander  bool
		dataStreams int
		multilink   bool
		want        int
	}{
		// Datagram mode: framing = 30 (QUIC(7)+AEAD(16)+DATAGRAM(3)+PPP(4))
		// maxQUIC = min(WAN-outerIP-UDP[-sal], 1452) - 21
		// PPP MTU = maxQUIC - framing
		{"datagram IPv4 no sal", 1500, false, false, 0, false, 1401},
		{"datagram IPv4 with sal", 1500, false, true, 0, false, 1401},
		{"datagram IPv6 no sal", 1500, true, false, 0, false, 1401},
		{"datagram IPv6 with sal", 1500, true, true, 0, false, 1393},
		// Multi-stream: framing = 38 (QUIC(7)+AEAD(16)+STREAM(9)+LenPfx(2)+PPP(4))
		{"multistream IPv4 no sal", 1500, false, false, 20, false, 1393},
		{"multistream IPv4 with sal", 1500, false, true, 20, false, 1393},
		{"multistream IPv6 no sal", 1500, true, false, 20, false, 1393},
		{"multistream IPv6 with sal", 1500, true, true, 20, false, 1385},
		// Multilink adds 4 bytes overhead
		{"datagram IPv4 multilink", 1500, false, false, 0, true, 1397},
		{"multistream IPv4 multilink", 1500, false, false, 20, true, 1389},
		{"datagram IPv6 sal multilink", 1500, true, true, 0, true, 1389},
		// Edge cases
		{"PPPoE WAN datagram", 1492, false, false, 0, false, 1401},
		{"tiny WAN clamp to min", 200, true, true, 0, false, 576},
		{"jumbo WAN clamp to max", 9000, false, false, 0, false, 1401},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePPPMTU(tt.wanMTU, tt.outerIPv6, tt.salamander, tt.dataStreams, tt.multilink)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDetectWANMTU(t *testing.T) {
	t.Run("loopback", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
		mtu, err := DetectWANMTU(addr)
		require.NoError(t, err)
		assert.NotEqual(t, 0, mtu)
	})

	t.Run("invalid address", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
		_, _ = DetectWANMTU(addr)
	})
}
