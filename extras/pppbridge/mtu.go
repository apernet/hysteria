package pppbridge

import (
	"errors"
	"net"
)

// PPP over Hysteria2 MTU overhead breakdown:
//
// The max inner IP packet (PPP MTU) is constrained by the smallest bottleneck
// in the encapsulation chain. For datagram mode, the QUIC datagram must fit in
// a single QUIC packet whose size is limited by both the WAN path MTU and
// quic-go's internal MaxPacketBufferSize (1452, hardcoded for IPv6 worst case).
// PMTUD binary search adds further tolerance loss (up to maxMTUDiff+1 = 21 bytes).
//
// === Datagram mode (dataStreams == 0): ===
//
//   QUIC packet (UDP payload, after PMTUD):
//    |- QUIC short header:           7 B  (1 type + CID(4) + PN(2))
//    |- QUIC AEAD tag:              16 B
//    |- QUIC DATAGRAM frame header:  3 B  (type(1) + length varint(2))
//    |- PPP header (FF 03 + proto):  4 B
//    '- Inner IP packet:            <-- this is the PPP MTU
//
//   Framing overhead: 30 B = QUIC(7) + AEAD(16) + DATAGRAM(3) + PPP(4)
//
// === Multi-stream mode (dataStreams > 0): ===
//
//   QUIC packet (UDP payload, after PMTUD):
//    |- QUIC short header:           7 B
//    |- QUIC AEAD tag:              16 B
//    |- QUIC STREAM frame header:    9 B
//    |- Length prefix:                2 B
//    |- PPP header (FF 03 + proto):  4 B
//    '- Inner IP packet:            <-- this is the PPP MTU
//
//   Framing overhead: 38 B = QUIC(7) + AEAD(16) + STREAM(9) + LenPfx(2) + PPP(4)

const (
	// quic-go caps PMTUD at this value (1500 - 40 IPv6 - 8 UDP), even for IPv4.
	quicMaxPacketBufferSize = 1452
	// PMTUD binary search stops when max-min <= maxMTUDiff (20). Worst-case
	// convergence leaves the discovered size up to maxMTUDiff+1 below the true max.
	pmtudSafetyMargin = 21

	quicShortHeader       = 7  // 1 (type byte) + CID(4) + PN(2)
	quicAEADTag           = 16 // Poly1305
	datagramFrameOverhead = 3  // type(1) + length varint(2)
	streamFrameOverhead   = 9  // type(1) + stream ID(~4) + offset(~2) + length(~2)
	lengthPrefix          = 2
	pppHeader             = 4  // FF 03 + protocol(2)
	MLPPPOverhead         = 4  // MP protocol field (00 3D) + short-seq header (2 bytes)

	udpHeader      = 8
	ipv4Header     = 20
	ipv6Header     = 40
	salamanderCost = 8
	minPPPMTU      = 576
	maxPPPMTU      = 1500
)

// CalculatePPPMTU computes the PPP MTU given the WAN interface MTU,
// whether the outer connection uses IPv6, whether Salamander obfuscation is on,
// and the dataStreams count (0 = datagram mode, >0 = multi-stream mode).
//
// The calculation accounts for quic-go's MaxPacketBufferSize cap and PMTUD
// binary search convergence tolerance.
func CalculatePPPMTU(wanMTU int, outerIsIPv6 bool, salamander bool, dataStreams int, multilink bool) int {
	outerIP := ipv4Header
	if outerIsIPv6 {
		outerIP = ipv6Header
	}

	maxQUICPacket := wanMTU - outerIP - udpHeader
	if salamander {
		maxQUICPacket -= salamanderCost
	}
	if maxQUICPacket > quicMaxPacketBufferSize {
		maxQUICPacket = quicMaxPacketBufferSize
	}
	maxQUICPacket -= pmtudSafetyMargin

	var framingOverhead int
	if dataStreams > 0 {
		framingOverhead = quicShortHeader + quicAEADTag + streamFrameOverhead + lengthPrefix + pppHeader
	} else {
		framingOverhead = quicShortHeader + quicAEADTag + datagramFrameOverhead + pppHeader
	}
	if multilink {
		framingOverhead += MLPPPOverhead
	}

	mtu := maxQUICPacket - framingOverhead
	if mtu < minPPPMTU {
		mtu = minPPPMTU
	}
	if mtu > maxPPPMTU {
		mtu = maxPPPMTU
	}
	return mtu
}

// DetectWANMTU determines the MTU of the network interface that would be used
// to reach serverAddr, by performing a UDP dial (no data sent) and looking up
// the outbound interface.
func DetectWANMTU(serverAddr *net.UDPAddr) (int, error) {
	network := "udp4"
	if serverAddr.IP.To4() == nil {
		network = "udp6"
	}
	conn, err := net.Dial(network, serverAddr.String())
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(localAddr.IP) {
					return iface.MTU, nil
				}
			}
		}
	}
	return 0, errors.New("default interface not found")
}

// MTUParams configures auto PPP MTU calculation.
type MTUParams struct {
	RemoteAddr  net.Addr
	Salamander  bool
	DataStreams int
	Multilink   bool
}

// AutoPPPMTU detects the WAN MTU and calculates the optimal PPP MTU.
// Fallback chain: detect WAN MTU -> assume 1500 -> worst-case (IPv6+Salamander).
func AutoPPPMTU(p MTUParams) int {
	wanMTU := 1500
	isIPv6 := false

	if udpAddr, ok := p.RemoteAddr.(*net.UDPAddr); ok && udpAddr != nil {
		if detected, err := DetectWANMTU(udpAddr); err == nil {
			wanMTU = detected
		}
		isIPv6 = udpAddr.IP.To4() == nil
	} else if p.RemoteAddr == nil {
		// Unknown remote: assume worst case
		isIPv6 = true
		p.Salamander = true
	}

	return CalculatePPPMTU(wanMTU, isIPv6, p.Salamander, p.DataStreams, p.Multilink)
}
