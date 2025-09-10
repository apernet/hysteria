package outbounds

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/apernet/hysteria/extras/v2/outbounds/tinydoh"
)

// dohResolver is a PluggableOutbound DNS resolver that resolves hostnames
// using the user-provided DNS-over-HTTPS server.
type dohResolver struct {
	Resolver *tinydoh.Resolver
	Next     PluggableOutbound
}

func NewDoHResolver(addr string, timeout time.Duration, sni string, insecure bool, next PluggableOutbound) PluggableOutbound {
	// User may provide just the IP address or full URL
	if !strings.HasSuffix(addr, "https://") {
		addr = fmt.Sprintf("https://%s/dns-query", addr)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
	}
	return &dohResolver{
		Resolver: &tinydoh.Resolver{
			URL: addr,
			HTTPClient: &http.Client{
				Transport: tr,
				Timeout:   timeoutOrDefault(timeout),
			},
		},
		Next: next,
	}
}

func (r *dohResolver) resolve(reqAddr *AddrEx) {
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
		ips, err := r.Resolver.LookupA(reqAddr.Host)
		var ip net.IP
		if err == nil && len(ips) > 0 {
			ip = ips[0]
		}
		ch4 <- lookupResult{ip, err}
	}()
	go func() {
		ips, err := r.Resolver.LookupAAAA(reqAddr.Host)
		var ip net.IP
		if err == nil && len(ips) > 0 {
			ip = ips[0]
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

func (r *dohResolver) TCP(reqAddr *AddrEx) (net.Conn, error) {
	r.resolve(reqAddr)
	return r.Next.TCP(reqAddr)
}

func (r *dohResolver) UDP(reqAddr *AddrEx) (UDPConn, error) {
	r.resolve(reqAddr)
	return r.Next.UDP(reqAddr)
}
