package proxymux

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestListenSOCKS(t *testing.T) {
	address := "127.2.39.129:11081"

	sl, err := ListenSOCKS(address)
	if !assert.NoError(t, err) {
		return
	}
	defer func() {
		sl.Close()
	}()

	hl, err := ListenHTTP(address)
	if !assert.NoError(t, err) {
		return
	}
	defer hl.Close()

	_, err = ListenSOCKS(address)
	if !assert.ErrorIs(t, err, ErrProtocolInUse) {
		return
	}
	sl.Close()

	sl, err = ListenSOCKS(address)
	if !assert.NoError(t, err) {
		return
	}
}

func TestListenHTTP(t *testing.T) {
	address := "127.2.39.129:11082"

	hl, err := ListenHTTP(address)
	if !assert.NoError(t, err) {
		return
	}
	defer func() {
		hl.Close()
	}()

	sl, err := ListenSOCKS(address)
	if !assert.NoError(t, err) {
		return
	}
	defer sl.Close()

	_, err = ListenHTTP(address)
	if !assert.ErrorIs(t, err, ErrProtocolInUse) {
		return
	}
	hl.Close()

	hl, err = ListenHTTP(address)
	if !assert.NoError(t, err) {
		return
	}
}

func TestRelease(t *testing.T) {
	address := "127.2.39.129:11083"

	hl, err := ListenHTTP(address)
	if !assert.NoError(t, err) {
		return
	}
	sl, err := ListenSOCKS(address)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.True(t, globalMuxManager.testAddressExists(address)) {
		return
	}
	_, err = net.Listen("tcp", address)
	if !assert.Error(t, err) {
		return
	}

	hl.Close()
	sl.Close()

	// Wait for muxListener released
	time.Sleep(time.Second)
	if !assert.False(t, globalMuxManager.testAddressExists(address)) {
		return
	}
	lis, err := net.Listen("tcp", address)
	if !assert.NoError(t, err) {
		return
	}
	defer lis.Close()
}

func (m *muxManager) testAddressExists(address string) bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	_, ok := m.listeners[address]
	return ok
}
