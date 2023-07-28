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
	return
}
