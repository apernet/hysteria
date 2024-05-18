package acl

import (
	"net"
	"testing"

	"github.com/apernet/hysteria/extras/v2/outbounds/acl/v2geo"
	"github.com/stretchr/testify/assert"
)

func Test_geoipMatcher_Match(t *testing.T) {
	geoipMap, err := v2geo.LoadGeoIP("v2geo/geoip.dat")
	assert.NoError(t, err)
	m, err := newGeoIPMatcher(geoipMap["us"])
	assert.NoError(t, err)

	tests := []struct {
		name string
		host HostInfo
		want bool
	}{
		{
			name: "IPv4 match",
			host: HostInfo{
				IPv4: net.ParseIP("73.222.1.100"),
			},
			want: true,
		},
		{
			name: "IPv4 no match",
			host: HostInfo{
				IPv4: net.ParseIP("123.123.123.123"),
			},
			want: false,
		},
		{
			name: "IPv6 match",
			host: HostInfo{
				IPv6: net.ParseIP("2607:f8b0:4005:80c::2004"),
			},
			want: true,
		},
		{
			name: "IPv6 no match",
			host: HostInfo{
				IPv6: net.ParseIP("240e:947:6001::1f8"),
			},
			want: false,
		},
		{
			name: "both nil",
			host: HostInfo{
				IPv4: nil,
				IPv6: nil,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, m.Match(tt.host), "Match(%v)", tt.host)
		})
	}
}

func Test_geositeMatcher_Match(t *testing.T) {
	geositeMap, err := v2geo.LoadGeoSite("v2geo/geosite.dat")
	assert.NoError(t, err)
	m, err := newGeositeMatcher(geositeMap["apple"], nil)
	assert.NoError(t, err)

	tests := []struct {
		name  string
		attrs []string
		host  HostInfo
		want  bool
	}{
		{
			name:  "subdomain",
			attrs: nil,
			host: HostInfo{
				Name: "poop.i-book.com",
			},
			want: true,
		},
		{
			name:  "subdomain root",
			attrs: nil,
			host: HostInfo{
				Name: "applepaycash.net",
			},
			want: true,
		},
		{
			name:  "full",
			attrs: nil,
			host: HostInfo{
				Name: "courier-push-apple.com.akadns.net",
			},
			want: true,
		},
		{
			name:  "regexp",
			attrs: nil,
			host: HostInfo{
				Name: "cdn4.apple-mapkit.com",
			},
			want: true,
		},
		{
			name:  "attr match",
			attrs: []string{"cn"},
			host: HostInfo{
				Name: "bag.itunes.apple.com",
			},
			want: true,
		},
		{
			name:  "attr multi no match",
			attrs: []string{"cn", "haha"},
			host: HostInfo{
				Name: "bag.itunes.apple.com",
			},
			want: false,
		},
		{
			name:  "attr no match",
			attrs: []string{"cn"},
			host: HostInfo{
				Name: "mr-apple.com.tw",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.Attrs = tt.attrs
			assert.Equalf(t, tt.want, m.Match(tt.host), "Match(%v)", tt.host)
		})
	}
}
