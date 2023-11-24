package acl

import (
	"net"
	"testing"
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
		Pattern string
		Mode    uint8
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
				Pattern: "example.com",
				Mode:    domainMatchExact,
			},
			host: HostInfo{
				Name: "example.com",
			},
			want: true,
		},
		{
			name: "non-wildcard IDN match",
			fields: fields{
				Pattern: "政府.中国",
				Mode:    domainMatchExact,
			},
			host: HostInfo{
				Name: "xn--mxtq1m.xn--fiqs8s",
			},
			want: true,
		},
		{
			name: "non-wildcard no match",
			fields: fields{
				Pattern: "example.com",
				Mode:    domainMatchExact,
			},
			host: HostInfo{
				Name: "example.org",
			},
			want: false,
		},
		{
			name: "non-wildcard IDN no match",
			fields: fields{
				Pattern: "政府.中国",
				Mode:    domainMatchExact,
			},
			host: HostInfo{
				Name: "xn--mxtq1m.xn--yfro4i67o",
			},
			want: false,
		},
		{
			name: "wildcard match 1",
			fields: fields{
				Pattern: "*.example.com",
				Mode:    domainMatchWildcard,
			},
			host: HostInfo{
				Name: "www.example.com",
			},
			want: true,
		},
		{
			name: "wildcard match 2",
			fields: fields{
				Pattern: "example*.com",
				Mode:    domainMatchWildcard,
			},
			host: HostInfo{
				Name: "example2.com",
			},
			want: true,
		},
		{
			name: "wildcard IDN match 1",
			fields: fields{
				Pattern: "战狼*.com",
				Mode:    domainMatchWildcard,
			},
			host: HostInfo{
				Name: "xn--2-x14by21c.com",
			},
			want: true,
		},
		{
			name: "wildcard IDN match 2",
			fields: fields{
				Pattern: "*大学*",
				Mode:    domainMatchWildcard,
			},
			host: HostInfo{
				Name: "xn--xkry9kk1bz66a.xn--ses554g",
			},
			want: true,
		},
		{
			name: "wildcard no match",
			fields: fields{
				Pattern: "*.example.com",
				Mode:    domainMatchWildcard,
			},
			host: HostInfo{
				Name: "example.com",
			},
			want: false,
		},
		{
			name: "wildcard IDN no match",
			fields: fields{
				Pattern: "*呵呵*",
				Mode:    domainMatchWildcard,
			},
			host: HostInfo{
				Name: "xn--6qqt7juua.cn",
			},
			want: false,
		},
		{
			name: "suffix match 1",
			fields: fields{
				Pattern: "apple.com",
				Mode:    domainMatchSuffix,
			},
			host: HostInfo{
				Name: "apple.com",
			},
			want: true,
		},
		{
			name: "suffix match 2",
			fields: fields{
				Pattern: "apple.com",
				Mode:    domainMatchSuffix,
			},
			host: HostInfo{
				Name: "store.apple.com",
			},
			want: true,
		},
		{
			name: "suffix IDN match 1",
			fields: fields{
				Pattern: "中国",
				Mode:    domainMatchSuffix,
			},
			host: HostInfo{
				Name: "中国",
			},
			want: true,
		},
		{
			name: "suffix IDN match 2",
			fields: fields{
				Pattern: "中国",
				Mode:    domainMatchSuffix,
			},
			host: HostInfo{
				Name: "天安门.中国",
			},
			want: true,
		},
		{
			name: "suffix no match",
			fields: fields{
				Pattern: "news.com",
			},
			host: HostInfo{
				Name: "fakenews.com",
			},
			want: false,
		},
		{
			name: "suffix IDN no match",
			fields: fields{
				Pattern: "冲浪",
			},
			host: HostInfo{
				Name: "666.网上冲浪",
			},
			want: false,
		},
		{
			name: "empty",
			fields: fields{
				Pattern: "*.example.com",
				Mode:    domainMatchWildcard,
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
				Pattern: tt.fields.Pattern,
				Mode:    tt.fields.Mode,
			}
			if got := m.Match(tt.host); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}
