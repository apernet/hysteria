//go:build !linux

package tproxy

import (
	"errors"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

type UDPTProxy struct {
	HyClient    client.Client
	Timeout     time.Duration
	EventLogger UDPEventLogger
}

type UDPEventLogger interface {
	Connect(addr, reqAddr net.Addr)
	Error(addr, reqAddr net.Addr, err error)
}

func (r *UDPTProxy) ListenAndServe(laddr *net.UDPAddr) error {
	return errors.New("not supported on this platform")
}
