//go:build !linux
// +build !linux

package redirect

import (
	"errors"
	"net"
	"time"

	"github.com/apernet/hysteria/pkg/core"
)

type TCPRedirect struct{}

func NewTCPRedirect(hyClient *core.Client, listen string, timeout time.Duration,
	connFunc func(addr, reqAddr net.Addr),
	errorFunc func(addr, reqAddr net.Addr, err error),
) (*TCPRedirect, error) {
	return nil, errors.New("not supported on the current system")
}

func (r *TCPRedirect) ListenAndServe() error {
	return nil
}
