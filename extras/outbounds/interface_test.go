package outbounds

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestPluggableOutboundAdapter(t *testing.T) {
	ob := newMockPluggableOutbound(t)
	adapter := &PluggableOutboundAdapter{ob}

	ob.EXPECT().TCP(&AddrEx{
		Host: "only.fans",
		Port: 443,
	}).Return(nil, nil).Once()
	conn, err := adapter.TCP("only.fans:443")
	assert.Nil(t, conn)
	assert.Nil(t, err)

	mc := newMockUDPConn(t)
	mc.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(bs []byte) (int, *AddrEx, error) {
		return copy(bs, "gura"), &AddrEx{
			Host: "gura.com",
			Port: 2333,
		}, nil
	}).Once()
	mc.EXPECT().WriteTo([]byte("gawr"), &AddrEx{
		Host: "another.hololive.tv",
		Port: 1551,
	}).Return(4, nil).Once()
	ob.EXPECT().UDP(&AddrEx{
		Host: "hololive.tv",
		Port: 8999,
	}).Return(mc, nil).Once()

	uConn, err := adapter.UDP("hololive.tv:8999")
	assert.Nil(t, err)
	assert.NotNil(t, uConn)
	n, err := uConn.WriteTo([]byte("gawr"), "another.hololive.tv:1551")
	assert.Nil(t, err)
	assert.Equal(t, 4, n)
	bs := make([]byte, 1024)
	n, addr, err := uConn.ReadFrom(bs)
	assert.Nil(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, "gura", string(bs[:n]))
	assert.Equal(t, "gura.com:2333", addr)
}
