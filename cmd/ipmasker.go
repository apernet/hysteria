package main

import (
	"net"
)

type ipMasker struct {
	IPv4Mask net.IPMask
	IPv6Mask net.IPMask
}

// Mask masks an address with the configured CIDR.
// addr can be "host:port" or just host.
func (m *ipMasker) Mask(addr string) string {
	if m.IPv4Mask == nil && m.IPv6Mask == nil {
		return addr
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// just host
		host, port = addr, ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// not an IP address, return as is
		return addr
	}
	if ip4 := ip.To4(); ip4 != nil && m.IPv4Mask != nil {
		// IPv4
		host = ip4.Mask(m.IPv4Mask).String()
	} else if ip6 := ip.To16(); ip6 != nil && m.IPv6Mask != nil {
		// IPv6
		host = ip6.Mask(m.IPv6Mask).String()
	}
	if port != "" {
		return net.JoinHostPort(host, port)
	} else {
		return host
	}
}

var defaultIPMasker = &ipMasker{}
