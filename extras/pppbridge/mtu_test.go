package pppbridge

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculatePPPMTU(t *testing.T) {
	tests := []struct {
		name        string
		wanMTU      int
		outerIPv6   bool
		salamander  bool
		dataStreams int
		want        int
	}{
		// Datagram mode: framing = 32 (QUIC(9)+AEAD(16)+DATAGRAM(3)+PPP(4))
		// maxQUIC = min(WAN-outerIP-UDP[-sal], 1452) - 21
		// PPP MTU = maxQUIC - framing
		{"datagram IPv4 no sal", 1500, false, false, 0, 1399},
		{"datagram IPv4 with sal", 1500, false, true, 0, 1399},
		{"datagram IPv6 no sal", 1500, true, false, 0, 1399},
		{"datagram IPv6 with sal", 1500, true, true, 0, 1391},
		// Multi-stream: framing = 40 (QUIC(9)+AEAD(16)+STREAM(9)+LenPfx(2)+PPP(4))
		{"multistream IPv4 no sal", 1500, false, false, 20, 1391},
		{"multistream IPv4 with sal", 1500, false, true, 20, 1391},
		{"multistream IPv6 no sal", 1500, true, false, 20, 1391},
		{"multistream IPv6 with sal", 1500, true, true, 20, 1383},
		// Multilink adds 4 bytes overhead
		// Edge cases
		{"PPPoE WAN datagram", 1492, false, false, 0, 1399},
		{"tiny WAN clamp to min", 200, true, true, 0, 576},
		{"jumbo WAN clamp to max", 9000, false, false, 0, 1399},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePPPMTU(tt.wanMTU, tt.outerIPv6, tt.salamander, tt.dataStreams)
			assert.Equal(t, tt.want, got)
		})
	}
}

// AutoPPPMTU is what sizes a link that has not been measured. It no longer asks
// the host anything, so unlike the version that probed the egress interface its
// answer is fully determined by the arguments -- which is what makes it worth
// pinning exactly rather than by inequalities.
func TestAutoPPPMTUAssumesAnEthernetPath(t *testing.T) {
	v4 := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
	v6 := &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}

	assert.Equal(t,
		CalculatePPPMTU(1500, false, false, 0),
		AutoPPPMTU(MTUParams{RemoteAddr: v4}),
		"an IPv4 peer is sized as a 1500-octet Ethernet path")

	assert.Equal(t,
		CalculatePPPMTU(1500, true, false, 0),
		AutoPPPMTU(MTUParams{RemoteAddr: v6}),
		"an IPv6 peer pays the larger outer header")
}

// With no destination at all the answer must be the smaller one. "We do not know"
// producing a larger MTU than a known path would size the link above something it
// then turns out not to fit.
func TestAutoPPPMTUFallsBackToTheWorstCase(t *testing.T) {
	known := AutoPPPMTU(MTUParams{
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443},
	})
	unknown := AutoPPPMTU(MTUParams{RemoteAddr: nil})

	assert.GreaterOrEqual(t, known, minPPPMTU)
	assert.LessOrEqual(t, known, maxPPPMTU)
	assert.Less(t, unknown, known,
		"not knowing the path must never produce a larger MTU than knowing it")

	// The unknown case is IPv6 plus Salamander, whatever the caller said about
	// obfuscation.
	assert.Equal(t, CalculatePPPMTU(1500, true, true, 0), unknown)
}

// A destination that is not a UDP address -- which is what the server side sees,
// since a client's remote address arrives as whatever the transport reports --
// is sized as IPv4 rather than treated as unknown.
func TestAutoPPPMTUHandlesANonUDPAddress(t *testing.T) {
	got := AutoPPPMTU(MTUParams{
		RemoteAddr:  &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 443},
		DataStreams: 4,
	})
	assert.Equal(t, CalculatePPPMTU(1500, false, false, 4), got)
}

// The one number in this file that cannot be derived from the others, pinned to
// its value rather than to a relationship. Every other multilink assertion is
// written as "ceiling minus MLPPPOverhead", so all of them would follow the
// constant quietly if it were changed back.
//
// Six is what pppd 2.5.2 can actually transmit: short sequence numbers on
// transmit need ho->neg_ssnhf, lcp.c:1784 refuses to set it unless
// ao->neg_ssnhf is set, and nothing in pppd ever sets that -- "mpshortseq"
// reaches lcp_wantoptions, which is the receive direction. See MLPPPOverhead.
//
// At 4 the bundle MTU is two octets too large. That is invisible while several
// links share the load and drops every full-size packet once one link is left,
// so it presents as the redundancy not working.
func TestMLPPPOverheadIsTheLongSequenceHeader(t *testing.T) {
	assert.Equal(t, 6, MLPPPOverhead,
		"pppd cannot negotiate short-sequence transmit, so the header is always 6 octets")
}

// AutoPPPMTU reports what one link carries. The bundle MTU is that minus the
// multilink header, and it is the caller that subtracts it -- keeping the two
// numbers distinct at the point where the difference is visible.
func TestAutoPPPMTUReportsTheLinkCeilingNotTheBundleMTU(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
	linkMRU := AutoPPPMTU(MTUParams{RemoteAddr: addr})

	assert.Equal(t, 1399, linkMRU, "the link ceiling on an ordinary 1500-octet path")
	assert.Equal(t, 1393, linkMRU-MLPPPOverhead, "what the bundle may advertise")
}
