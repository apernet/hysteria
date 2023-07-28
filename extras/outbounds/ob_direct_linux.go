package outbounds

import (
	"errors"
	"net"
	"syscall"
)

// NewDirectOutboundBindToDevice creates a new directOutbound with the given mode,
// and binds to the given device. Only works on Linux.
func NewDirectOutboundBindToDevice(mode DirectOutboundMode, deviceName string) (PluggableOutbound, error) {
	if err := verifyDeviceName(deviceName); err != nil {
		return nil, err
	}
	d := &net.Dialer{
		Timeout: defaultDialerTimeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var errBind error
			err := c.Control(func(fd uintptr) {
				errBind = syscall.BindToDevice(int(fd), deviceName)
			})
			if err != nil {
				return err
			}
			return errBind
		},
	}
	return &directOutbound{
		Mode:       mode,
		Dialer4:    d,
		Dialer6:    d,
		DeviceName: deviceName,
	}, nil
}

func verifyDeviceName(deviceName string) error {
	if deviceName == "" {
		return errors.New("device name cannot be empty")
	}
	_, err := net.InterfaceByName(deviceName)
	return err
}

func udpConnBindToDevice(conn *net.UDPConn, deviceName string) error {
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var errBind error
	err = sc.Control(func(fd uintptr) {
		errBind = syscall.BindToDevice(int(fd), deviceName)
	})
	if err != nil {
		return err
	}
	return errBind
}
