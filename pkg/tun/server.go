package tun

import (
	"github.com/sirupsen/logrus"
	"github.com/tobyxdd/hysteria/pkg/core"
	t2score "github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var _ adapter.TransportHandler = (*Server)(nil)

type Server struct {
	HyClient  *core.Client
	Timeout   time.Duration
	TunDevice device.Device

	RequestFunc func(addr net.Addr, reqAddr string)
	ErrorFunc   func(addr net.Addr, reqAddr string, err error)
}

const (
	MTU = 1500
)

func NewServerWithTunFd(hyClient *core.Client, timeout time.Duration, tunFd int, mtu uint32) (*Server, error) {
	if mtu == 0 {
		mtu = MTU
	}
	dev, err := fdbased.Open(strconv.Itoa(tunFd), mtu)
	if err != nil {
		return nil, err
	}
	s := &Server{
		HyClient:  hyClient,
		Timeout:   timeout,
		TunDevice: dev,
	}
	return s, nil
}

func NewServer(hyClient *core.Client, timeout time.Duration, name string, mtu uint32) (*Server, error) {
	if mtu == 0 {
		mtu = MTU
	}
	dev, err := tun.Open(name, mtu)
	if err != nil {
		return nil, err
	}
	s := &Server{
		HyClient:  hyClient,
		Timeout:   timeout,
		TunDevice: dev,
	}
	return s, nil
}

func (s *Server) ListenAndServe() error {
	t2sconf := t2score.Config{
		LinkEndpoint:     s.TunDevice,
		TransportHandler: s,
		PrintFunc: func(format string, v ...interface{}) {
			logrus.Warnf(format, v...)
		},
		Options: nil,
	}

	stack, err := t2score.CreateStack(&t2sconf)
	if err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	stack.Close()
	stack.Wait()

	return nil
}
