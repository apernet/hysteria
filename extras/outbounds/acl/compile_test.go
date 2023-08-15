package acl

import (
	"net"
	"testing"

	"github.com/oschwald/geoip2-golang"
	"github.com/stretchr/testify/assert"
)

func TestCompile(t *testing.T) {
	ob1, ob2, ob3 := 1, 2, 3
	rules := []TextRule{
		{
			Outbound:      "ob1",
			Address:       "1.2.3.4",
			ProtoPort:     "",
			HijackAddress: "",
		},
		{
			Outbound:      "ob2",
			Address:       "8.8.8.0/24",
			ProtoPort:     "*",
			HijackAddress: "1.1.1.1",
		},
		{
			Outbound:      "ob3",
			Address:       "all",
			ProtoPort:     "udp/443",
			HijackAddress: "",
		},
		{
			Outbound:      "ob1",
			Address:       "2606:4700::6810:85e5",
			ProtoPort:     "tcp",
			HijackAddress: "2606:4700::6810:85e6",
		},
		{
			Outbound:      "ob2",
			Address:       "2606:4700::/44",
			ProtoPort:     "*/8888",
			HijackAddress: "",
		},
		{
			Outbound:      "ob3",
			Address:       "*.v2ex.com",
			ProtoPort:     "udp",
			HijackAddress: "",
		},
		{
			Outbound:      "ob1",
			Address:       "crap.v2ex.com",
			ProtoPort:     "tcp/80",
			HijackAddress: "2.2.2.2",
		},
		{
			Outbound:      "ob2",
			Address:       "geoip:JP",
			ProtoPort:     "*/*",
			HijackAddress: "",
		},
	}
	reader, err := geoip2.Open("GeoLite2-Country.mmdb")
	assert.NoError(t, err)
	comp, err := Compile[int](rules, map[string]int{"ob1": ob1, "ob2": ob2, "ob3": ob3}, 100, func() *geoip2.Reader {
		return reader
	})
	assert.NoError(t, err)

	tests := []struct {
		host         HostInfo
		proto        Protocol
		port         uint16
		wantOutbound int
		wantIP       net.IP
	}{
		{
			host: HostInfo{
				IPv4: net.ParseIP("1.2.3.4"),
			},
			proto:        ProtocolTCP,
			port:         1234,
			wantOutbound: ob1,
			wantIP:       nil,
		},
		{
			host: HostInfo{
				IPv4: net.ParseIP("8.8.8.4"),
			},
			proto:        ProtocolUDP,
			port:         5353,
			wantOutbound: ob2,
			wantIP:       net.ParseIP("1.1.1.1"),
		},
		{
			host: HostInfo{
				Name: "lean.delicious.com",
			},
			proto:        ProtocolUDP,
			port:         443,
			wantOutbound: ob3,
			wantIP:       nil,
		},
		{
			host: HostInfo{
				IPv6: net.ParseIP("2606:4700::6810:85e5"),
			},
			proto:        ProtocolTCP,
			port:         80,
			wantOutbound: ob1,
			wantIP:       net.ParseIP("2606:4700::6810:85e6"),
		},
		{
			host: HostInfo{
				IPv6: net.ParseIP("2606:4700:0:0:0:0:0:1"),
			},
			proto:        ProtocolUDP,
			port:         8888,
			wantOutbound: ob2,
			wantIP:       nil,
		},
		{
			host: HostInfo{
				Name: "www.v2ex.com",
			},
			proto:        ProtocolUDP,
			port:         1234,
			wantOutbound: ob3,
			wantIP:       nil,
		},
		{
			host: HostInfo{
				Name: "crap.v2ex.com",
			},
			proto:        ProtocolTCP,
			port:         80,
			wantOutbound: ob1,
			wantIP:       net.ParseIP("2.2.2.2"),
		},
		{
			host: HostInfo{
				IPv4: net.ParseIP("210.140.92.187"),
			},
			proto:        ProtocolTCP,
			port:         25,
			wantOutbound: ob2,
			wantIP:       nil,
		},
	}

	for _, test := range tests {
		gotOutbound, gotIP := comp.Match(test.host, test.proto, test.port)
		assert.Equal(t, test.wantOutbound, gotOutbound)
		assert.Equal(t, test.wantIP, gotIP)
	}
}
