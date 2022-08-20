//go:build gpl
// +build gpl

package tun

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/HyNetwork/hysteria/pkg/core"
	"github.com/sirupsen/logrus"
	t2score "github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ adapter.TransportHandler = (*Server)(nil)

type Server struct {
	HyClient   *core.Client
	Timeout    time.Duration
	DeviceInfo DeviceInfo

	RequestFunc func(addr net.Addr, reqAddr string)
	ErrorFunc   func(addr net.Addr, reqAddr string, err error)
}

const (
	MTU = 1500
)

const (
	DeviceTypeFd = iota
	DeviceTypeName
)

type DeviceInfo struct {
	Type int
	Fd   int
	Name string
	MTU  uint32
}

func (d *DeviceInfo) Open() (dev device.Device, err error) {
	switch d.Type {
	case DeviceTypeFd:
		dev, err = fdbased.Open(strconv.Itoa(d.Fd), d.MTU)
	case DeviceTypeName:
		dev, err = tun.Open(d.Name, d.MTU)
	default:
		err = fmt.Errorf("unknown device type: %d", d.Type)
	}
	return
}

func NewServerWithTunFd(hyClient *core.Client, timeout time.Duration, tunFd int, mtu uint32) (*Server, error) {
	if mtu == 0 {
		mtu = MTU
	}
	s := &Server{
		HyClient: hyClient,
		Timeout:  timeout,
		DeviceInfo: DeviceInfo{
			Type: DeviceTypeFd,
			Fd:   tunFd,
			MTU:  mtu,
		},
	}
	return s, nil
}

func NewServer(hyClient *core.Client, timeout time.Duration, name string, mtu uint32) (*Server, error) {
	if mtu == 0 {
		mtu = MTU
	}
	s := &Server{
		HyClient: hyClient,
		Timeout:  timeout,
		DeviceInfo: DeviceInfo{
			Type: DeviceTypeName,
			Name: name,
			MTU:  mtu,
		},
	}
	return s, nil
}

func (s *Server) ListenAndServe() error {
	var dev device.Device
	var st *stack.Stack

	defer func() {
		if dev != nil {
			_ = dev.Close()
		}
		if st != nil {
			st.Close()
			st.Wait()
		}
	}()

	dev, err := s.DeviceInfo.Open()
	if err != nil {
		return err
	}

	t2sconf := t2score.Config{
		LinkEndpoint:     dev,
		TransportHandler: s,
		PrintFunc: func(format string, v ...interface{}) {
			logrus.Infof(format, v...)
		},
		Options: nil,
	}

	st, err = t2score.CreateStack(&t2sconf)
	if err != nil {
		return err
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	return nil
}
