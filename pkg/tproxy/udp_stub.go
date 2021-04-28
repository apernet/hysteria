// +build !linux

package tproxy

import (
	"errors"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"net"
	"time"
)

var ErrTimeout = errors.New("inactivity timeout")

type UDPTProxy struct{}

func NewUDPTProxy(hyClient *core.Client, transport transport.Transport, listen string, timeout time.Duration,
	aclEngine *acl.Engine,
	connFunc func(addr net.Addr), errorFunc func(addr net.Addr, err error)) (*UDPTProxy, error) {
	return nil, errors.New("not supported on the current system")
}

func (r *UDPTProxy) ListenAndServe() error {
	return nil
}
