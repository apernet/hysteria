//go:build !linux
// +build !linux

package tproxy

import (
	"errors"
	"net"
	"time"

	"github.com/HyNetwork/hysteria/pkg/core"
)

type TCPTProxy struct{}

func NewTCPTProxy(hyClient *core.Client, listen string, timeout time.Duration,
	connFunc func(addr, reqAddr net.Addr),
	errorFunc func(addr, reqAddr net.Addr, err error),
) (*TCPTProxy, error) {
	return nil, errors.New("not supported on the current system")
}

func (r *TCPTProxy) ListenAndServe() error {
	return nil
}
