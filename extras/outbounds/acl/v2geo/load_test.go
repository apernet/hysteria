package v2geo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadGeoIP(t *testing.T) {
	m, err := LoadGeoIP("geoip.dat")
	assert.NoError(t, err)

	// Exact checks since we know the data.
	assert.Len(t, m, 252)
	assert.Equal(t, m["cn"].CountryCode, "CN")
	assert.Len(t, m["cn"].Cidr, 10407)
	assert.Equal(t, m["us"].CountryCode, "US")
	assert.Len(t, m["us"].Cidr, 193171)
	assert.Equal(t, m["private"].CountryCode, "PRIVATE")
	assert.Len(t, m["private"].Cidr, 18)
	assert.Contains(t, m["private"].Cidr, &CIDR{
		Ip:     []byte("\xc0\xa8\x00\x00"),
		Prefix: 16,
	})
}

func TestLoadGeoSite(t *testing.T) {
	m, err := LoadGeoSite("geosite.dat")
	assert.NoError(t, err)

	// Exact checks since we know the data.
	assert.Len(t, m, 1204)
	assert.Equal(t, m["netflix"].CountryCode, "NETFLIX")
	assert.Len(t, m["netflix"].Domain, 25)
	assert.Contains(t, m["netflix"].Domain, &Domain{
		Type:  Domain_Full,
		Value: "netflix.com.edgesuite.net",
	})
	assert.Contains(t, m["netflix"].Domain, &Domain{
		Type:  Domain_RootDomain,
		Value: "fast.com",
	})
	assert.Len(t, m["google"].Domain, 1066)
	assert.Contains(t, m["google"].Domain, &Domain{
		Type:  Domain_RootDomain,
		Value: "ggpht.cn",
		Attribute: []*Domain_Attribute{
			{
				Key:        "cn",
				TypedValue: &Domain_Attribute_BoolValue{BoolValue: true},
			},
		},
	})
}
