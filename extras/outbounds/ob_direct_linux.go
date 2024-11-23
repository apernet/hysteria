package outbounds

import (
	"errors"
	"net"
	"syscall"
)

func dialerBindToDevice(dialer *net.Dialer, deviceName string) error {
	if err := verifyDeviceName(deviceName); err != nil {
		return err
	}

	originControl := dialer.Control
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		if originControl != nil {
			// Chaining other control function
			err := originControl(network, address, c)
			if err != nil {
				return err
			}
		}

		var errBind error
		err := c.Control(func(fd uintptr) {
			errBind = syscall.BindToDevice(int(fd), deviceName)
		})
		if err != nil {
			return err
		}
		return errBind
	}
	return nil
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
