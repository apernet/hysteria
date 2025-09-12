package sockopts

import (
	"fmt"
	"net"
)

type SocketOptions struct {
	BindInterface       *string
	FirewallMark        *uint32
	FdControlUnixSocket *string
}

// implemented in platform-specific files
var (
	bindInterfaceFunc       func(c *net.UDPConn, device string) error
	firewallMarkFunc        func(c *net.UDPConn, fwmark uint32) error
	fdControlUnixSocketFunc func(c *net.UDPConn, path string) error
)

func (o *SocketOptions) CheckSupported() (err error) {
	if o.BindInterface != nil && bindInterfaceFunc == nil {
		return &UnsupportedError{"bindInterface"}
	}
	if o.FirewallMark != nil && firewallMarkFunc == nil {
		return &UnsupportedError{"fwmark"}
	}
	if o.FdControlUnixSocket != nil && fdControlUnixSocketFunc == nil {
		return &UnsupportedError{"fdControlUnixSocket"}
	}
	return nil
}

type UnsupportedError struct {
	Field string
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("%s is not supported on this platform", e.Field)
}

func (o *SocketOptions) ListenUDP() (uconn net.PacketConn, err error) {
	uconn, err = net.ListenUDP("udp", nil)
	if err != nil {
		return uconn, err
	}
	err = o.applyToUDPConn(uconn.(*net.UDPConn))
	if err != nil {
		uconn.Close()
		uconn = nil
		return uconn, err
	}
	return uconn, err
}

func (o *SocketOptions) applyToUDPConn(c *net.UDPConn) error {
	if o.BindInterface != nil && bindInterfaceFunc != nil {
		err := bindInterfaceFunc(c, *o.BindInterface)
		if err != nil {
			return fmt.Errorf("failed to bind to interface: %w", err)
		}
	}
	if o.FirewallMark != nil && firewallMarkFunc != nil {
		err := firewallMarkFunc(c, *o.FirewallMark)
		if err != nil {
			return fmt.Errorf("failed to set fwmark: %w", err)
		}
	}
	if o.FdControlUnixSocket != nil && fdControlUnixSocketFunc != nil {
		err := fdControlUnixSocketFunc(c, *o.FdControlUnixSocket)
		if err != nil {
			return fmt.Errorf("failed to send fd to control unix socket: %w", err)
		}
	}
	return nil
}
