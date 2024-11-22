//go:build !linux

package outbounds

import (
	"errors"
	"net"
)

func dialerBindToDevice(dialer *net.Dialer, deviceName string) error {
	return errors.New("binding to device is not supported on this platform")
}

func udpConnBindToDevice(conn *net.UDPConn, deviceName string) error {
	return errors.New("binding to device is not supported on this platform")
}
