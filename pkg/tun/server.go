// +build cgo

package tun

import (
	tun2socks "github.com/eycorsican/go-tun2socks/core"
	"github.com/eycorsican/go-tun2socks/tun"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"io"
	"net"
	"sync"
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

	udpConnMap     map[tun2socks.UDPConn]*udpConnInfo
	udpConnMapLock sync.RWMutex
}

const (
	MTU = 1500
)

func NewServerWithTunDev(hyClient *core.Client, transport transport.Transport,
	timeout time.Duration,
	tunDev io.ReadWriteCloser) (*Server, error) {
	s := &Server{
		HyClient:   hyClient,
		Transport:  transport,
		Timeout:    timeout,
		TunDev:     tunDev,
		udpConnMap: make(map[tun2socks.UDPConn]*udpConnInfo),
	}
	return s, nil
}

func NewServer(hyClient *core.Client, transport transport.Transport,
	timeout time.Duration,
	name, address, gateway, mask string, dnsServers []string, persist bool) (*Server, error) {
	tunDev, err := tun.OpenTunDevice(name, address, gateway, mask, dnsServers, persist)
	if err != nil {
		return nil, err
	}
	return NewServerWithTunDev(hyClient, transport, timeout, tunDev)
}

func (s *Server) ListenAndServe() error {
	lwipWriter := tun2socks.NewLWIPStack().(io.Writer)

	tun2socks.RegisterTCPConnHandler(s)
	tun2socks.RegisterUDPConnHandler(s)
	tun2socks.RegisterOutputFn(func(data []byte) (int, error) {
		return s.TunDev.Write(data)
	})

	_, err := io.CopyBuffer(lwipWriter, s.TunDev, make([]byte, MTU))
	if err != nil {
		return err
	}
	return nil
}
