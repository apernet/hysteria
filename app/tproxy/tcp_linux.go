package tproxy

import (
	"net"
	"time"

	"github.com/LiamHaworth/go-tproxy"
	"github.com/apernet/hysteria/core/cs"
	"github.com/apernet/hysteria/core/utils"
)

type TCPTProxy struct {
	HyClient   *cs.Client
	ListenAddr *net.TCPAddr
	Timeout    time.Duration

	ConnFunc  func(addr, reqAddr net.Addr)
	ErrorFunc func(addr, reqAddr net.Addr, err error)
}

func NewTCPTProxy(hyClient *cs.Client, listen string, timeout time.Duration,
	connFunc func(addr, reqAddr net.Addr),
	errorFunc func(addr, reqAddr net.Addr, err error),
) (*TCPTProxy, error) {
	tAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		return nil, err
	}
	r := &TCPTProxy{
		HyClient:   hyClient,
		ListenAddr: tAddr,
		Timeout:    timeout,
		ConnFunc:   connFunc,
		ErrorFunc:  errorFunc,
	}
	return r, nil
}

func (r *TCPTProxy) ListenAndServe() error {
	listener, err := tproxy.ListenTCP("tcp", r.ListenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		c, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			// Under TPROXY mode, we are effectively acting as the remote server
			// So our LocalAddr is actually the target to which the user is trying to connect
			// and our RemoteAddr is the local address where the user initiates the connection
			r.ConnFunc(c.RemoteAddr(), c.LocalAddr())
			rc, err := r.HyClient.DialTCP(c.LocalAddr().String())
			if err != nil {
				r.ErrorFunc(c.RemoteAddr(), c.LocalAddr(), err)
				return
			}
			defer rc.Close()
			err = utils.PipePairWithTimeout(c, rc, r.Timeout)
			r.ErrorFunc(c.RemoteAddr(), c.LocalAddr(), err)
		}()
	}
}
