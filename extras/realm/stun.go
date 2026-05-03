package realm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pion/stun/v3"
)

const (
	defaultSTUNPort    = "3478"
	defaultSTUNTimeout = 4 * time.Second
)

var ErrInvalidSTUNConfig = errors.New("invalid STUN config")

type STUNResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type STUNConfig struct {
	Servers  []string
	Timeout  time.Duration
	Resolver STUNResolver
}

// Discover queries the configured STUN servers using conn and returns the
// externally observed addresses for that same socket.
func Discover(ctx context.Context, conn net.PacketConn, config STUNConfig) ([]netip.AddrPort, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: conn is nil", ErrInvalidSTUNConfig)
	}
	if len(config.Servers) == 0 {
		return nil, fmt.Errorf("%w: at least one STUN server is required", ErrInvalidSTUNConfig)
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultSTUNTimeout
	}
	if timeout < 0 {
		return nil, fmt.Errorf("%w: timeout must not be negative", ErrInvalidSTUNConfig)
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stunAddrs, err := resolveSTUNServers(ctx, resolver, config.Servers, localAddrFamily(conn.LocalAddr()))
	if err != nil {
		return nil, err
	}
	transactions, err := sendSTUNRequests(conn, stunAddrs)
	if err != nil {
		return nil, err
	}

	defer conn.SetReadDeadline(time.Time{})
	results := make(map[netip.AddrPort]struct{})
	buf := make([]byte, 1500)
	for len(transactions) > 0 {
		deadline, ok := ctx.Deadline()
		if ok {
			_ = conn.SetReadDeadline(deadline)
		}
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || isTimeout(err) {
				break
			}
			return nil, err
		}
		msg, addr, err := parseSTUNBindingResponse(buf[:n])
		if err != nil {
			continue
		}
		if _, ok := transactions[msg.TransactionID]; !ok {
			continue
		}
		delete(transactions, msg.TransactionID)
		results[addr] = struct{}{}
	}
	return finishSTUNResults(results, ctx.Err())
}

func DiscoverWithDemux(ctx context.Context, conn *PunchPacketConn, config STUNConfig) ([]netip.AddrPort, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: conn is nil", ErrInvalidSTUNConfig)
	}
	if len(config.Servers) == 0 {
		return nil, fmt.Errorf("%w: at least one STUN server is required", ErrInvalidSTUNConfig)
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultSTUNTimeout
	}
	if timeout < 0 {
		return nil, fmt.Errorf("%w: timeout must not be negative", ErrInvalidSTUNConfig)
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stunAddrs, err := resolveSTUNServers(ctx, resolver, config.Servers, localAddrFamily(conn.LocalAddr()))
	if err != nil {
		return nil, err
	}
	transactions, err := sendSTUNRequests(conn, stunAddrs)
	if err != nil {
		return nil, err
	}

	results := make(map[netip.AddrPort]struct{})
	for len(transactions) > 0 {
		select {
		case <-ctx.Done():
			return finishSTUNResults(results, ctx.Err())
		case ev := <-conn.STUNEvents():
			if _, ok := transactions[ev.Message.TransactionID]; !ok {
				continue
			}
			delete(transactions, ev.Message.TransactionID)
			results[ev.Addr] = struct{}{}
		}
	}
	return finishSTUNResults(results, nil)
}

func resolveSTUNServers(ctx context.Context, resolver STUNResolver, servers []string, family addrFamily) ([]*net.UDPAddr, error) {
	var out []*net.UDPAddr
	seen := make(map[string]struct{})
	for _, server := range servers {
		host, port, err := splitSTUNServer(server)
		if err != nil {
			return nil, err
		}
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ipAddr := range ips {
			ip := ipAddr.IP
			if ip == nil || !family.allows(ip) {
				continue
			}
			key := net.JoinHostPort(ip.String(), port)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			portNum, _ := strconv.Atoi(port)
			out = append(out, &net.UDPAddr{IP: ip, Port: portNum})
		}
	}
	return out, nil
}

func sendSTUNRequests(conn net.PacketConn, addrs []*net.UDPAddr) (map[[stun.TransactionIDSize]byte]*net.UDPAddr, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: no STUN server addresses match the local socket family", ErrInvalidSTUNConfig)
	}
	transactions := make(map[[stun.TransactionIDSize]byte]*net.UDPAddr, len(addrs))
	for _, addr := range addrs {
		msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
		if err != nil {
			return nil, err
		}
		if _, err := conn.WriteTo(msg.Raw, addr); err != nil {
			continue
		}
		transactions[msg.TransactionID] = addr
	}
	if len(transactions) == 0 {
		return nil, fmt.Errorf("%w: failed to send STUN binding requests", ErrInvalidSTUNConfig)
	}
	return transactions, nil
}

func finishSTUNResults(results map[netip.AddrPort]struct{}, err error) ([]netip.AddrPort, error) {
	if len(results) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: no STUN responses received", ErrInvalidSTUNConfig)
	}
	addrs := make([]netip.AddrPort, 0, len(results))
	for addr := range results {
		addrs = append(addrs, addr)
	}
	slices.SortFunc(addrs, func(a, b netip.AddrPort) int {
		return strings.Compare(a.String(), b.String())
	})
	return addrs, nil
}

func splitSTUNServer(server string) (host, port string, err error) {
	if server == "" {
		return "", "", fmt.Errorf("%w: STUN server is empty", ErrInvalidSTUNConfig)
	}
	host, port, err = net.SplitHostPort(server)
	if err == nil {
		if host == "" {
			return "", "", fmt.Errorf("%w: STUN server host is required", ErrInvalidSTUNConfig)
		}
		if err := validatePort(port); err != nil {
			return "", "", err
		}
		return host, port, nil
	}
	if strings.Count(server, ":") > 1 {
		if _, parseErr := netip.ParseAddr(server); parseErr != nil {
			return "", "", fmt.Errorf("%w: invalid STUN server address", ErrInvalidSTUNConfig)
		}
		return server, defaultSTUNPort, nil
	}
	if strings.Contains(server, ":") {
		host, port, err = net.SplitHostPort(server)
		if err != nil {
			return "", "", fmt.Errorf("%w: invalid STUN server address", ErrInvalidSTUNConfig)
		}
		return host, port, nil
	}
	return server, defaultSTUNPort, nil
}

func parseSTUNBindingResponse(packet []byte) (*stun.Message, netip.AddrPort, error) {
	msg := stun.New()
	if err := stun.Decode(packet, msg); err != nil {
		return nil, netip.AddrPort{}, err
	}
	if msg.Type != stun.BindingSuccess {
		return nil, netip.AddrPort{}, errors.New("not a STUN binding success response")
	}

	var xorMapped stun.XORMappedAddress
	if err := xorMapped.GetFrom(msg); err == nil {
		addr, err := netIPPortToAddrPort(xorMapped.IP, xorMapped.Port)
		return msg, addr, err
	}

	var mapped stun.MappedAddress
	if err := mapped.GetFrom(msg); err == nil {
		addr, err := netIPPortToAddrPort(mapped.IP, mapped.Port)
		return msg, addr, err
	}

	return nil, netip.AddrPort{}, errors.New("STUN mapped address not found")
}

func netIPPortToAddrPort(ip net.IP, port int) (netip.AddrPort, error) {
	if port <= 0 || port > 65535 {
		return netip.AddrPort{}, errors.New("invalid STUN mapped port")
	}
	if ip4 := ip.To4(); ip4 != nil {
		var addr [4]byte
		copy(addr[:], ip4)
		return netip.AddrPortFrom(netip.AddrFrom4(addr), uint16(port)), nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return netip.AddrPort{}, errors.New("invalid STUN mapped IP")
	}
	var addr [16]byte
	copy(addr[:], ip16)
	return netip.AddrPortFrom(netip.AddrFrom16(addr), uint16(port)), nil
}

type addrFamily uint8

const (
	addrFamilyAny addrFamily = iota
	addrFamilyIPv4
	addrFamilyIPv6
)

func localAddrFamily(addr net.Addr) addrFamily {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr.IP == nil || udpAddr.IP.IsUnspecified() {
		return addrFamilyAny
	}
	if udpAddr.IP.To4() != nil {
		return addrFamilyIPv4
	}
	return addrFamilyIPv6
}

func (f addrFamily) allows(ip net.IP) bool {
	is4 := ip.To4() != nil
	switch f {
	case addrFamilyIPv4:
		return is4
	case addrFamilyIPv6:
		return !is4
	default:
		return true
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
