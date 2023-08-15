package outbounds

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestACLEngine(t *testing.T) {
	ob1, ob2, ob3 := &mockPluggableOutbound{}, &mockPluggableOutbound{}, &mockPluggableOutbound{}
	obs := []OutboundEntry{
		{"ob1", ob1},
		{"ob2", ob2},
		{"ob3", ob3},
		{"direct", ob2},
	}
	acl, err := NewACLEngineFromString(`
ob2(google.com,tcp)
ob3(youtube.com,udp)
ob1 (1.1.1.1/24,*,8.8.8.8)
Direct(cia.gov)
reJect(nsa.gov)
`, obs, nil)
	assert.NoError(t, err)

	// No match, default, should be the first (ob1)
	ob1.EXPECT().TCP(&AddrEx{Host: "example.com"}).Return(nil, nil).Once()
	conn, err := acl.TCP(&AddrEx{Host: "example.com"})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// Match ob2
	ob2.EXPECT().TCP(&AddrEx{Host: "google.com"}).Return(nil, nil).Once()
	conn, err = acl.TCP(&AddrEx{Host: "google.com"})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// Match ob3
	ob3.EXPECT().UDP(&AddrEx{Host: "youtube.com"}).Return(nil, nil).Once()
	udpConn, err := acl.UDP(&AddrEx{Host: "youtube.com"})
	assert.NoError(t, err)
	assert.Nil(t, udpConn)

	// Match ob1 hijack IP
	ob1.EXPECT().TCP(&AddrEx{Host: "8.8.8.8", ResolveInfo: &ResolveInfo{IPv4: net.ParseIP("8.8.8.8").To4()}}).Return(nil, nil).Once()
	conn, err = acl.TCP(&AddrEx{ResolveInfo: &ResolveInfo{IPv4: net.ParseIP("1.1.1.22")}})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// direct should be ob2 as we override it
	ob2.EXPECT().TCP(&AddrEx{Host: "cia.gov"}).Return(nil, nil).Once()
	conn, err = acl.TCP(&AddrEx{Host: "cia.gov"})
	assert.NoError(t, err)
	assert.Nil(t, conn)

	// reject
	conn, err = acl.TCP(&AddrEx{Host: "nsa.gov"})
	assert.Error(t, err)
	assert.Nil(t, conn)
}
