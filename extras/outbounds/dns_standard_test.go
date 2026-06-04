package outbounds

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStandardResolverRejectsCNAMECycle(t *testing.T) {
	var queries atomic.Int32
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		queries.Add(1)
		q := req.Question[0]
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = append(resp.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1},
			Target: q.Name,
		})
		_ = w.WriteMsg(resp)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	defer server.Shutdown()

	r := &standardResolver{Addr: pc.LocalAddr().String(), Client: &dns.Client{Timeout: time.Second}}
	_, err = r.lookup4("loop.example")
	if !errors.Is(err, errCNAMEChainTooLong) {
		t.Fatalf("lookup4 error = %v, want %v", err, errCNAMEChainTooLong)
	}
	if got := queries.Load(); got > 2 {
		t.Fatalf("lookup4 followed CNAME cycle for %d queries", got)
	}
}
