package realm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	defaultPunchTimeout  = 10 * time.Second
	defaultPunchInterval = 100 * time.Millisecond
)

var (
	ErrInvalidPunchConfig = errors.New("invalid punch config")
	ErrPunchTimeout       = errors.New("punch timed out")
)

type PunchConfig struct {
	Timeout  time.Duration
	Interval time.Duration
}

type PunchResult struct {
	PeerAddr netip.AddrPort
	Packet   PunchPacket
}

// Punch performs pre-QUIC UDP hole punching. It owns conn reads until it
// returns, so it must run before handing the socket to QUIC.
func Punch(ctx context.Context, conn net.PacketConn, localAddrs, peerAddrs []netip.AddrPort, meta PunchMetadata, config PunchConfig) (PunchResult, error) {
	if conn == nil {
		return PunchResult{}, fmt.Errorf("%w: conn is nil", ErrInvalidPunchConfig)
	}
	if _, _, err := decodePunchMetadata(meta); err != nil {
		return PunchResult{}, err
	}
	candidates := candidatePunchAddrs(localAddrs, peerAddrs, localAddrFamily(conn.LocalAddr()))
	if len(candidates) == 0 {
		return PunchResult{}, fmt.Errorf("%w: no compatible peer addresses", ErrInvalidPunchConfig)
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultPunchTimeout
	}
	if timeout < 0 {
		return PunchResult{}, fmt.Errorf("%w: timeout must not be negative", ErrInvalidPunchConfig)
	}
	interval := config.Interval
	if interval == 0 {
		interval = defaultPunchInterval
	}
	if interval <= 0 {
		return PunchResult{}, fmt.Errorf("%w: interval must be positive", ErrInvalidPunchConfig)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer conn.SetReadDeadline(time.Time{})

	candidateSet := make(map[netip.AddrPort]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidateSet[candidate] = struct{}{}
	}

	nextSend := time.Now()
	buf := make([]byte, punchMaxWireLen)
	for {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return PunchResult{}, ErrPunchTimeout
			}
			return PunchResult{}, err
		}
		now := time.Now()
		if !now.Before(nextSend) {
			sendPunchPackets(conn, candidates, meta, PunchPacketHello)
			nextSend = now.Add(interval)
		}

		deadline := nextSend
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		_ = conn.SetReadDeadline(deadline)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return PunchResult{}, err
		}
		peerAddr, ok := addrToAddrPort(addr)
		if !ok {
			continue
		}
		if _, ok := candidateSet[peerAddr]; !ok {
			continue
		}
		packet, err := DecodePunchPacket(buf[:n], meta)
		if err != nil {
			continue
		}
		if packet.Type == PunchPacketHello {
			sendPunchPacket(conn, peerAddr, meta, PunchPacketAck)
		}
		return PunchResult{
			PeerAddr: peerAddr,
			Packet:   packet,
		}, nil
	}
}

func sendPunchPackets(conn net.PacketConn, addrs []netip.AddrPort, meta PunchMetadata, packetType PunchPacketType) {
	for _, addr := range addrs {
		sendPunchPacket(conn, addr, meta, packetType)
	}
}

func sendPunchPacket(conn net.PacketConn, addr netip.AddrPort, meta PunchMetadata, packetType PunchPacketType) {
	packet, err := EncodePunchPacket(packetType, meta)
	if err != nil {
		return
	}
	_, _ = conn.WriteTo(packet, udpAddrFromAddrPort(addr))
}

func candidatePunchAddrs(localAddrs, peerAddrs []netip.AddrPort, connFamily addrFamily) []netip.AddrPort {
	allowedFamilies := punchFamilies(localAddrs, connFamily)
	seen := make(map[netip.AddrPort]struct{})
	var candidates []netip.AddrPort
	for _, addr := range peerAddrs {
		if !addr.IsValid() || addr.Port() == 0 {
			continue
		}
		if !allowedFamilies.allows(addr.Addr()) {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		candidates = append(candidates, addr)
	}
	slices.SortFunc(candidates, func(a, b netip.AddrPort) int {
		return strings.Compare(a.String(), b.String())
	})
	return candidates
}

type punchFamilySet struct {
	v4 bool
	v6 bool
}

func punchFamilies(localAddrs []netip.AddrPort, connFamily addrFamily) punchFamilySet {
	var families punchFamilySet
	for _, addr := range localAddrs {
		if !addr.IsValid() {
			continue
		}
		if addr.Addr().Is4() {
			families.v4 = true
		} else if addr.Addr().Is6() {
			families.v6 = true
		}
	}
	if families.v4 || families.v6 {
		return families
	}
	switch connFamily {
	case addrFamilyIPv4:
		families.v4 = true
	case addrFamilyIPv6:
		families.v6 = true
	default:
		families.v4 = true
		families.v6 = true
	}
	return families
}

func (s punchFamilySet) allows(addr netip.Addr) bool {
	if addr.Is4() {
		return s.v4
	}
	if addr.Is6() {
		return s.v6
	}
	return false
}

func addrToAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ipAddr, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok || udpAddr.Port <= 0 || udpAddr.Port > 65535 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ipAddr.Unmap(), uint16(udpAddr.Port)), true
}

func udpAddrFromAddrPort(addr netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP(addr.Addr().AsSlice()),
		Port: int(addr.Port()),
	}
}
