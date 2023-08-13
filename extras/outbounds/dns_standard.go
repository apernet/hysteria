package outbounds

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	resolverDefaultTimeout     = 2 * time.Second
	standardResolverRetryTimes = 2
)

// standardResolver is a PluggableOutbound DNS resolver that resolves hostnames
// using the user-provided DNS server.
// Based on "github.com/miekg/dns", it supports UDP, TCP & DNS-over-TLS (TCP).
type standardResolver struct {
	Addr   string
	Client *dns.Client
	Next   PluggableOutbound
}

func NewStandardResolverUDP(addr string, timeout time.Duration, next PluggableOutbound) PluggableOutbound {
	return &standardResolver{
		Addr: addDefaultPort(addr),
		Client: &dns.Client{
			Timeout: timeoutOrDefault(timeout),
		},
		Next: next,
	}
}

func NewStandardResolverTCP(addr string, timeout time.Duration, next PluggableOutbound) PluggableOutbound {
	return &standardResolver{
		Addr: addDefaultPort(addr),
		Client: &dns.Client{
			Net:     "tcp",
			Timeout: timeoutOrDefault(timeout),
		},
		Next: next,
	}
}

func NewStandardResolverTLS(addr string, timeout time.Duration, sni string, insecure bool, next PluggableOutbound) PluggableOutbound {
	return &standardResolver{
		Addr: addDefaultPortTLS(addr),
		Client: &dns.Client{
			Net:     "tcp-tls",
			Timeout: timeoutOrDefault(timeout),
			TLSConfig: &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: insecure,
			},
		},
		Next: next,
	}
}

// addDefaultPort adds the default DNS port (53) to the address if not present.
func addDefaultPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "53")
	}
	return addr
}

// addDefaultPortTLS adds the default DNS-over-TLS port (853) to the address if not present.
func addDefaultPortTLS(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "853")
	}
	return addr
}

func timeoutOrDefault(timeout time.Duration) time.Duration {
	if timeout == 0 {
		return resolverDefaultTimeout
	}
	return timeout
}

// skipCNAMEChain skips the CNAME chain and returns the last CNAME target.
// Sometimes the DNS server returns a CNAME chain like this, in one packet:
// domain1.com. CNAME domain2.com.
// domain2.com. CNAME domain3.com.
// In this case, we should avoid sending a query for domain2.com and go
// straight to domain3.com.
func (r *standardResolver) skipCNAMEChain(answers []dns.RR) string {
	var lastCNAME string
	for _, a := range answers {
		if cname, ok := a.(*dns.CNAME); ok {
			if lastCNAME == "" {
				// First CNAME
				lastCNAME = cname.Target
			} else if cname.Hdr.Name == lastCNAME {
				// CNAME chain
				lastCNAME = cname.Target
			} else {
				// CNAME chain ends
				return lastCNAME
			}
		}
	}
	return lastCNAME
}

// lookup4 resolves a hostname to an IPv4 address.
// If there's no IPv4 address, it returns (nil, nil), no error.
func (r *standardResolver) lookup4(host string) (net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true
	resp, _, err := r.Client.Exchange(m, r.Addr)
	if err != nil {
		return nil, err
	}
	if len(resp.Answer) == 0 {
		return nil, nil
	}
	// Sometimes the DNS server returns both CNAME and A records in one packet.
	hasCNAME := false
	for _, a := range resp.Answer {
		if aa, ok := a.(*dns.A); ok {
			return aa.A.To4(), nil
		} else if _, ok := a.(*dns.CNAME); ok {
			hasCNAME = true
		}
	}
	if hasCNAME {
		return r.lookup4(r.skipCNAMEChain(resp.Answer))
	} else {
		// Should not happen
		return nil, nil
	}
}

// lookup6 resolves a hostname to an IPv6 address.
// If there's no IPv6 address, it returns (nil, nil), no error.
func (r *standardResolver) lookup6(host string) (net.IP, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
	m.RecursionDesired = true
	resp, _, err := r.Client.Exchange(m, r.Addr)
	if err != nil {
		return nil, err
	}
	if len(resp.Answer) == 0 {
		return nil, nil
	}
	// Sometimes the DNS server returns both CNAME and AAAA records in one packet.
	hasCNAME := false
	for _, a := range resp.Answer {
		if aa, ok := a.(*dns.AAAA); ok {
			return aa.AAAA.To16(), nil
		} else if _, ok := a.(*dns.CNAME); ok {
			hasCNAME = true
		}
	}
	if hasCNAME {
		return r.lookup6(r.skipCNAMEChain(resp.Answer))
	} else {
		// Should not happen
		return nil, nil
	}
}

func (r *standardResolver) resolve(reqAddr *AddrEx) {
	if tryParseIP(reqAddr) {
		// The host is already an IP address, we don't need to resolve it.
		return
	}
	type lookupResult struct {
		ip  net.IP
		err error
	}
	ch4, ch6 := make(chan lookupResult, 1), make(chan lookupResult, 1)
	go func() {
		var ip net.IP
		var err error
		for i := 0; i < standardResolverRetryTimes; i++ {
			ip, err = r.lookup4(reqAddr.Host)
			if err == nil {
				break
			}
		}
		ch4 <- lookupResult{ip, err}
	}()
	go func() {
		var ip net.IP
		var err error
		for i := 0; i < standardResolverRetryTimes; i++ {
			ip, err = r.lookup6(reqAddr.Host)
			if err == nil {
				break
			}
		}
		ch6 <- lookupResult{ip, err}
	}()
	result4, result6 := <-ch4, <-ch6
	reqAddr.ResolveInfo = &ResolveInfo{
		IPv4: result4.ip,
		IPv6: result6.ip,
	}
	if result4.err != nil {
		reqAddr.ResolveInfo.Err = result4.err
	} else if result6.err != nil {
		reqAddr.ResolveInfo.Err = result6.err
	}
}

func (r *standardResolver) TCP(reqAddr *AddrEx) (net.Conn, error) {
	r.resolve(reqAddr)
	return r.Next.TCP(reqAddr)
}

func (r *standardResolver) UDP(reqAddr *AddrEx) (UDPConn, error) {
	r.resolve(reqAddr)
	return r.Next.UDP(reqAddr)
}
