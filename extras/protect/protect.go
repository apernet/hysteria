// Package protect set VPN protect for every conns to bypass route.
package protect

import (
	"net"
)

// ListenUDPFunc listen UDP with VPN protect.
type ListenUDPFunc func() (net.PacketConn, error)
