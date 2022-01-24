//go:build !cgo
// +build !cgo

package tun

import (
	"errors"
	"github.com/tobyxdd/hysteria/pkg/core"
	"io"
	"net"
	"time"
)

type Server struct {
	HyClient *core.Client
	Timeout  time.Duration
	TunDev   io.ReadWriteCloser

	RequestFunc func(addr net.Addr, reqAddr string)
	ErrorFunc   func(addr net.Addr, reqAddr string, err error)
}

const (
	MTU = 1500
)

func NewServerWithTunDev(hyClient *core.Client, timeout time.Duration, tunDev io.ReadWriteCloser) (*Server, error) {
	return nil, errors.New("TUN mode is not available in this build")
}

func NewServer(hyClient *core.Client, timeout time.Duration,
	name, address, gateway, mask string, dnsServers []string, persist bool) (*Server, error) {
	return nil, errors.New("TUN mode is not available in this build")
}

func (s *Server) ListenAndServe() error {
	panic("not implemented!")
}
