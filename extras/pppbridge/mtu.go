package pppbridge

import (
	"errors"
	"net"
)

// PPP over Hysteria2 MTU overhead breakdown:
//
// === Current mode (HDLC stream, dataStreams irrelevant): ===
//
//   WAN frame (e.g. 1500 bytes Ethernet)
//    |- Outer IP header:           20 B (IPv4) or 40 B (IPv6)
//    |- UDP header:                 8 B
//    |- Salamander obfs (optional): 8 B
//    |- QUIC short header:         11 B
//    |- QUIC AEAD tag:             16 B
//    |- QUIC STREAM frame header:   9 B
//    |- PPP async HDLC framing:    12 B
//    '- Inner IP packet:           <-- this is the PPP MTU
//
//   Fixed overhead: 56 B = UDP(8) + QUIC(11) + AEAD(16) + STREAM(9) + HDLC(12)
//
// === Datagram mode (dataStreams == 0): ===
//
//   WAN frame (e.g. 1500 bytes Ethernet)
//    |- Outer IP header:            20 B (IPv4) or 40 B (IPv6)
//    |- UDP header:                  8 B
//    |- Salamander obfs (optional):  8 B
//    |- QUIC short header:          11 B
//    |- QUIC AEAD tag:              16 B
//    |- QUIC DATAGRAM frame header:  3 B
//    |- PPP header (FF 03 + proto):  4 B
//    '- Inner IP packet:            <-- this is the PPP MTU
//
//   Fixed overhead: 42 B = UDP(8) + QUIC(11) + AEAD(16) + DATAGRAM(3) + PPP(4)
//
// === Multi-stream mode (dataStreams > 0): ===
//
//   WAN frame (e.g. 1500 bytes Ethernet)
//    |- Outer IP header:            20 B (IPv4) or 40 B (IPv6)
//    |- UDP header:                  8 B
//    |- Salamander obfs (optional):  8 B
//    |- QUIC short header:          11 B
//    |- QUIC AEAD tag:              16 B
//    |- QUIC STREAM frame header:    9 B
//    |- Length prefix:                2 B
//    |- PPP header (FF 03 + proto):  4 B
//    '- Inner IP packet:            <-- this is the PPP MTU
//
//   Fixed overhead: 50 B = UDP(8) + QUIC(11) + AEAD(16) + STREAM(9) + LenPfx(2) + PPP(4)
//
//   PPP MTU = WAN MTU - outer IP - fixed overhead - salamander - safety margin

const (
	fixedOverheadDatagram    = 42 // UDP(8) + QUIC(11) + AEAD(16) + DATAGRAM(3) + PPP(4)
	fixedOverheadMultiStream = 50 // UDP(8) + QUIC(11) + AEAD(16) + STREAM(9) + LenPfx(2) + PPP(4)
	mlpppOverhead            = 4  // MP protocol field (00 3D) + short-seq header (2 bytes)
	ipv4Header               = 20
	ipv6Header               = 40
	salamanderCost           = 8
	safetyMargin             = 4
	minPPPMTU                = 576
	maxPPPMTU                = 1500
)

// CalculatePPPMTU computes the PPP MTU given the WAN interface MTU,
// whether the outer connection uses IPv6, whether Salamander obfuscation is on,
// and the dataStreams count (0 = datagram mode, >0 = multi-stream mode).
func CalculatePPPMTU(wanMTU int, outerIsIPv6 bool, salamander bool, dataStreams int, multilink bool) int {
	var fixed int
	if dataStreams > 0 {
		fixed = fixedOverheadMultiStream
	} else {
		fixed = fixedOverheadDatagram
	}
	overhead := fixed + safetyMargin
	if outerIsIPv6 {
		overhead += ipv6Header
	} else {
		overhead += ipv4Header
	}
	if salamander {
		overhead += salamanderCost
	}
	if multilink {
		overhead += mlpppOverhead
	}
	mtu := wanMTU - overhead
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
