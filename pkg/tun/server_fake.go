// +build !cgo

package tun

import (
	"errors"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"io"
	"net"
	"time"
)

type Server struct {
	HyClient  *core.Client
	Timeout   time.Duration
	TunDev    io.ReadWriteCloser
	Transport transport.Transport
	ACLEngine *acl.Engine

	RequestFunc func(addr net.Addr, reqAddr string, action acl.Action, arg string)
	ErrorFunc   func(addr net.Addr, reqAddr string, err error)
}

const (
	MTU = 1500
)

func NewServerWithTunDev(hyClient *core.Client, transport transport.Transport,
	timeout time.Duration,
	tunDev io.ReadWriteCloser) (*Server, error) {
	return nil, errors.New("TUN mode is not available when build with CGO_ENABLED=0")
}

func NewServer(hyClient *core.Client, transport transport.Transport,
	timeout time.Duration,
	name, address, gateway, mask string, dnsServers []string, persist bool) (*Server, error) {
	return nil, errors.New("TUN mode is not available when build with CGO_ENABLED=0")
}

func (s *Server) ListenAndServe() error {
	panic("not implemented!")
}
