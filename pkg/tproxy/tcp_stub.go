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

type TCPTProxy struct{}

func NewTCPTProxy(hyClient *core.Client, transport transport.Transport, listen string, timeout time.Duration,
	aclEngine *acl.Engine,
	connFunc func(addr, reqAddr net.Addr, action acl.Action, arg string),
	errorFunc func(addr, reqAddr net.Addr, err error)) (*TCPTProxy, error) {
	return nil, errors.New("not supported on the current system")
}

func (r *TCPTProxy) ListenAndServe() error {
	return nil
}
