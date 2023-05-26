package client

import (
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

// autoReconnectConn is a wrapper of quic.Connection that automatically reconnects
// when a non-temporary error (usually a timeout) occurs.
type autoReconnectConn struct {
	// Connect is called whenever a new QUIC connection is needed.
	// It should return a new QUIC connection, a function to close the connection
	// (and potentially other underlying resources), and an error if one occurred.
	Connect func() (quic.Connection, func(), error)

	conn      quic.Connection
	closeFunc func()
	connMutex sync.RWMutex
}

func (c *autoReconnectConn) OpenStream() (quic.Connection, quic.Stream, error) {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	// First time?
	if c.conn == nil {
		conn, closeFunc, err := c.Connect()
		if err != nil {
			return nil, nil, err
		}
		c.conn = conn
		c.closeFunc = closeFunc
	}
	stream, err := c.conn.OpenStream()
	if err == nil {
		// All is good
		return c.conn, stream, nil
	} else if nErr, ok := err.(net.Error); ok && nErr.Temporary() {
		// Temporary error, just pass the error to the caller
		return nil, nil, err
	} else {
		// Permanent error
		// Close the previous connection,
		// reconnect and try again (only once)
		c.closeFunc()
		conn, closeFunc, err := c.Connect()
		if err != nil {
			return nil, nil, err
		}
		c.conn = conn
		c.closeFunc = closeFunc
		stream, err = c.conn.OpenStream()
		return c.conn, stream, err
	}
}

func (c *autoReconnectConn) Close() error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	if c.conn == nil {
		return nil
	}
	c.closeFunc()
	c.conn = nil
	c.closeFunc = nil
	return nil
}
