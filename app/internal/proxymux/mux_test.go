package proxymux

import (
	"net"
	"testing"
	"time"

	"github.com/apernet/hysteria/app/internal/proxymux/internal/mocks"
	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/assert"
)

//go:generate mockery

func testMockListener(t *testing.T, firstByte byte) net.Listener {
	mockConn := mocks.NewMockConn(t)
	mockConn.EXPECT().Read(mock.Anything).RunAndReturn(func(b []byte) (int, error) {
		b[0] = firstByte
		return 1, nil
	})
	mockConn.EXPECT().Close().Return(nil)
	mockListener := mocks.NewMockListener(t)
	mockListener.EXPECT().Accept().RunAndReturn(func() (net.Conn, error) {
		// Wait for all listener set up
		time.Sleep(200 * time.Millisecond)
		return mockConn, nil
	})
	mockListener.EXPECT().Close().Return(nil)
	return mockListener
}

func TestMuxHTTP(t *testing.T) {
	mockListener := testMockListener(t, 'C')

	mux := newMuxListener(mockListener, func() {})
	hl, err := mux.ListenHTTP()
	if !assert.NoError(t, err) {
		return
	}
	sl, err := mux.ListenSOCKS()
	if !assert.NoError(t, err) {
		return
	}

	var socksConn, httpConn net.Conn
	var socksErr, httpErr error

	go func() {
		socksConn, socksErr = sl.Accept()
	}()

	go func() {
		httpConn, httpErr = hl.Accept()
	}()

	time.Sleep(1 * time.Second)
	sl.Close()
	hl.Close()
	// Wait for unmatched handler error
	time.Sleep(1 * time.Second)

	assert.Nil(t, socksConn)
	assert.ErrorIs(t, socksErr, net.ErrClosed)
	assert.NotNil(t, httpConn)
	httpConn.Close()
	assert.NoError(t, httpErr)

	// Wait for muxListener released
	time.Sleep(time.Second)
}

func TestMuxSOCKS(t *testing.T) {
	mockListener := testMockListener(t, '\x05')

	mux := newMuxListener(mockListener, func() {})
	hl, err := mux.ListenHTTP()
	if !assert.NoError(t, err) {
		return
	}
	sl, err := mux.ListenSOCKS()
	if !assert.NoError(t, err) {
		return
	}

	var socksConn, httpConn net.Conn
	var socksErr, httpErr error

	go func() {
		socksConn, socksErr = sl.Accept()
	}()

	go func() {
		httpConn, httpErr = hl.Accept()
	}()

	time.Sleep(1 * time.Second)
	sl.Close()
	hl.Close()
	// Wait for unmatched handler error
	time.Sleep(1 * time.Second)

	assert.NotNil(t, socksConn)
	socksConn.Close()
	assert.NoError(t, socksErr)
	assert.Nil(t, httpConn)
	assert.ErrorIs(t, httpErr, net.ErrClosed)

	// Wait for muxListener released
	time.Sleep(time.Second)
}
