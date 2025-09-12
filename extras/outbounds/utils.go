package outbounds

import "net"

// splitIPv4IPv6 gets the first IPv4 and IPv6 address from a list of IP addresses.
// Both of the return values can be nil when no IPv4 or IPv6 address is found.
func splitIPv4IPv6(ips []net.IP) (ipv4, ipv6 net.IP) {
	for _, ip := range ips {
		if ip.To4() != nil {
			if ipv4 == nil {
				ipv4 = ip
			}
		} else {
			if ipv6 == nil {
				ipv6 = ip
			}
		}
		if ipv4 != nil && ipv6 != nil {
			// We have everything we need.
			break
		}
	}
	return ipv4, ipv6
}

// tryParseIP tries to parse the host string in the AddrEx as an IP address.
// If the host is indeed an IP address, it will fill the ResolveInfo with the
// parsed IP address and return true. Otherwise, it will return false.
func tryParseIP(addr *AddrEx) bool {
	if ip := net.ParseIP(addr.Host); ip != nil {
		addr.ResolveInfo = &ResolveInfo{}
		if ip.To4() != nil {
			addr.ResolveInfo.IPv4 = ip
		} else {
			addr.ResolveInfo.IPv6 = ip
		}
		return true
	}
	return false
}
