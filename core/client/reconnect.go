package client

import (
	"net"
	"sync"

	coreErrs "github.com/apernet/hysteria/core/errors"
)

// reconnectableClientImpl is a wrapper of Client, which can reconnect when the connection is closed,
// except when the caller explicitly calls Close() to permanently close this client.
type reconnectableClientImpl struct {
	config        *Config
	client        Client
	count         int
	connectedFunc func(Client, int) // called when successfully connected
	m             sync.Mutex
	closed        bool // permanent close
}

func NewReconnectableClient(config *Config, connectedFunc func(Client, int), lazy bool) (Client, error) {
	// Make sure we capture any error in config and return it here,
	// so that the caller doesn't have to wait until the first call
	// to TCP() or UDP() to get the error (when lazy is true).
	if err := config.verifyAndFill(); err != nil {
		return nil, err
	}
	rc := &reconnectableClientImpl{
		config:        config,
		connectedFunc: connectedFunc,
	}
	if !lazy {
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
	}
	return rc, nil
}

func (rc *reconnectableClientImpl) reconnect() error {
	if rc.client != nil {
		_ = rc.client.Close()
	}
	var err error
	rc.client, err = NewClient(rc.config)
	if err != nil {
		return err
	} else {
		rc.count++
		if rc.connectedFunc != nil {
			rc.connectedFunc(rc, rc.count)
		}
		return nil
	}
}

func (rc *reconnectableClientImpl) TCP(addr string) (net.Conn, error) {
	rc.m.Lock()
	defer rc.m.Unlock()
	if rc.closed {
		return nil, coreErrs.ClosedError{}
	}
	if rc.client == nil {
		// No active connection, connect first
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
	}
	conn, err := rc.client.TCP(addr)
	if _, ok := err.(coreErrs.ClosedError); ok {
		// Connection closed, reconnect
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
		return rc.client.TCP(addr)
	} else {
		// OK or some other temporary error
		return conn, err
	}
}

func (rc *reconnectableClientImpl) UDP() (HyUDPConn, error) {
	rc.m.Lock()
	defer rc.m.Unlock()
	if rc.closed {
		return nil, coreErrs.ClosedError{}
	}
	if rc.client == nil {
		// No active connection, connect first
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
	}
	conn, err := rc.client.UDP()
	if _, ok := err.(coreErrs.ClosedError); ok {
		// Connection closed, reconnect
		if err := rc.reconnect(); err != nil {
			return nil, err
		}
		return rc.client.UDP()
	} else {
		// OK or some other temporary error
		return conn, err
	}
}

func (rc *reconnectableClientImpl) Close() error {
	rc.m.Lock()
	defer rc.m.Unlock()
	rc.closed = true
	if rc.client != nil {
		return rc.client.Close()
	}
	return nil
}
