package acl

import (
	"net"
	"testing"

	"github.com/oschwald/geoip2-golang"
	"github.com/stretchr/testify/assert"
)

func Test_ipMatcher_Match(t *testing.T) {
	tests := []struct {
		name string
		IP   net.IP
		host HostInfo
		want bool
	}{
		{
			name: "ipv4 match",
			IP:   net.IPv4(127, 0, 0, 1),
			host: HostInfo{
				IPv4: net.IPv4(127, 0, 0, 1),
				IPv6: nil,
			},
			want: true,
		},
		{
			name: "ipv6 match",
			IP:   net.IPv6loopback,
			host: HostInfo{
				IPv4: nil,
				IPv6: net.IPv6loopback,
			},
			want: true,
		},
		{
			name: "no match",
			IP:   net.IPv4(127, 0, 0, 1),
			host: HostInfo{
				IPv4: net.IPv4(127, 0, 0, 2),
				IPv6: net.IPv6loopback,
			},
			want: false,
		},
		{
			name: "both nil",
			IP:   net.IPv4(127, 0, 0, 1),
			host: HostInfo{
				IPv4: nil,
				IPv6: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ipMatcher{
				IP: tt.IP,
			}
			if got := m.Match(tt.host); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_cidrMatcher_Match(t *testing.T) {
	_, cidr1, _ := net.ParseCIDR("192.168.1.0/24")
	_, cidr2, _ := net.ParseCIDR("::1/128")
	_, cidr3, _ := net.ParseCIDR("0.0.0.0/0")
	_, cidr4, _ := net.ParseCIDR("::/0")

	tests := []struct {
		name  string
		IPNet *net.IPNet
		host  HostInfo
		want  bool
	}{
		{
			name:  "ipv4 match",
			IPNet: cidr1,
			host: HostInfo{
				IPv4: net.ParseIP("192.168.1.100"),
				IPv6: net.ParseIP("::1"),
			},
			want: true,
		},
		{
			name:  "ipv6 match",
			IPNet: cidr2,
			host: HostInfo{
				IPv4: net.ParseIP("10.0.0.1"),
				IPv6: net.ParseIP("::1"),
			},
			want: true,
		},
		{
			name:  "no match",
			IPNet: cidr1,
			host: HostInfo{
				IPv4: net.ParseIP("10.0.0.1"),
				IPv6: net.ParseIP("2001:db8::2:1"),
			},
			want: false,
		},
		{
			name:  "ipv4 broad",
			IPNet: cidr3,
			host: HostInfo{
				IPv4: net.ParseIP("10.0.0.1"),
				IPv6: net.ParseIP("::1"),
			},
			want: true,
		},
		{
			name:  "ipv6 broad",
			IPNet: cidr4,
			host: HostInfo{
				IPv4: net.ParseIP("10.0.0.1"),
				IPv6: net.ParseIP("2001:db8::2:1"),
			},
			want: true,
		},
		{
			name:  "both nil",
			IPNet: cidr1,
			host: HostInfo{
				IPv4: nil,
				IPv6: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &cidrMatcher{
				IPNet: tt.IPNet,
			}
			if got := m.Match(tt.host); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_domainMatcher_Match(t *testing.T) {
	type fields struct {
		Pattern  string
		Wildcard bool
	}
	tests := []struct {
		name   string
		fields fields
		host   HostInfo
		want   bool
	}{
		{
			name: "non-wildcard match",
			fields: fields{
				Pattern:  "example.com",
				Wildcard: false,
			},
			host: HostInfo{
				Name: "example.com",
			},
			want: true,
		},
		{
			name: "non-wildcard no match",
			fields: fields{
				Pattern:  "example.com",
				Wildcard: false,
			},
			host: HostInfo{
				Name: "example.org",
			},
			want: false,
		},
		{
			name: "wildcard match 1",
			fields: fields{
				Pattern:  "*.example.com",
				Wildcard: true,
			},
			host: HostInfo{
				Name: "www.example.com",
			},
			want: true,
		},
		{
			name: "wildcard match 2",
			fields: fields{
				Pattern:  "example*.com",
				Wildcard: true,
			},
			host: HostInfo{
				Name: "example2.com",
			},
			want: true,
		},
		{
			name: "wildcard no match",
			fields: fields{
				Pattern:  "*.example.com",
				Wildcard: true,
			},
			host: HostInfo{
				Name: "example.com",
			},
			want: false,
		},
		{
			name: "empty",
			fields: fields{
				Pattern:  "*.example.com",
				Wildcard: true,
			},
			host: HostInfo{
				Name: "",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &domainMatcher{
				Pattern:  tt.fields.Pattern,
				Wildcard: tt.fields.Wildcard,
			}
			if got := m.Match(tt.host); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_geoipMatcher_Match(t *testing.T) {
	db, err := geoip2.Open("GeoLite2-Country.mmdb")
	assert.NoError(t, err)
	defer db.Close()

	type fields struct {
		DB      *geoip2.Reader
		Country string
	}
	tests := []struct {
		name   string
		fields fields
		host   HostInfo
		want   bool
	}{
		{
			name: "ipv4 match",
			fields: fields{
				DB:      db,
				Country: "JP",
			},
			host: HostInfo{
				IPv4: net.ParseIP("210.140.92.181"),
			},
			want: true,
		},
		{
			name: "ipv6 match",
			fields: fields{
				DB:      db,
				Country: "US",
			},
			host: HostInfo{
				IPv6: net.ParseIP("2606:4700::6810:85e5"),
			},
			want: true,
		},
		{
			name: "no match",
			fields: fields{
				DB:      db,
				Country: "AU",
			},
			host: HostInfo{
				IPv4: net.ParseIP("210.140.92.181"),
				IPv6: net.ParseIP("2606:4700::6810:85e5"),
			},
			want: false,
		},
		{
			name: "both nil",
			fields: fields{
				DB:      db,
				Country: "KR",
			},
			host: HostInfo{
				IPv4: nil,
				IPv6: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &geoipMatcher{
				DB:      tt.fields.DB,
				Country: tt.fields.Country,
			}
			if got := m.Match(tt.host); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}
