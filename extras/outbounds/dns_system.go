package outbounds

import (
	"net"
)

// systemResolver is a PluggableOutbound DNS resolver that resolves hostnames
// using the default system DNS server.
// Outbounds typically don't require a resolver, as they can do DNS resolution
// themselves. However, when using ACL, it's necessary to place a resolver in
// front of it in the pipeline (for IP rules to work on domain requests).
type systemResolver struct {
	Next PluggableOutbound
}

func NewSystemResolver(next PluggableOutbound) PluggableOutbound {
	return &systemResolver{
		Next: next,
	}
}

func (r *systemResolver) resolve(reqAddr *AddrEx) {
	ips, err := net.LookupIP(reqAddr.Host)
	if err != nil {
		reqAddr.ResolveInfo = &ResolveInfo{Err: err}
		return
	}
	info := &ResolveInfo{}
	info.IPv4, info.IPv6 = splitIPv4IPv6(ips)
	reqAddr.ResolveInfo = info
}

func (r *systemResolver) TCP(reqAddr *AddrEx) (net.Conn, error) {
	r.resolve(reqAddr)
	return r.Next.TCP(reqAddr)
}

func (r *systemResolver) UDP(reqAddr *AddrEx) (UDPConn, error) {
	r.resolve(reqAddr)
	return r.Next.UDP(reqAddr)
}
