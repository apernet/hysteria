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

func (o *SocketOptions) ListenUDP() (net.PacketConn, error) {
	return o.ListenUDPAddr(nil)
}

// ListenUDPAddr is like ListenUDP but binds to a specific local UDP address.
// Pass nil to use an ephemeral port (same as ListenUDP).
func (o *SocketOptions) ListenUDPAddr(addr *net.UDPAddr) (net.PacketConn, error) {
	uconn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	if err := o.applyToUDPConn(uconn); err != nil {
		uconn.Close()
		return nil, err
	}
	return uconn, nil
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
