//go:build !linux

package outbounds

import (
	"errors"
	"net"
)

// NewDirectOutboundBindToDevice creates a new directOutbound with the given mode,
// and binds to the given device. This doesn't work on non-Linux platforms, so this
// is just a stub function that always returns an error.
func NewDirectOutboundBindToDevice(mode DirectOutboundMode, deviceName string) (PluggableOutbound, error) {
	return nil, errors.New("binding to device is not supported on this platform")
}

func udpConnBindToDevice(conn *net.UDPConn, deviceName string) error {
	return errors.New("binding to device is not supported on this platform")
}
