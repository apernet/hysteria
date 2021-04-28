package relay

import (
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"time"
)

type TCPRelay struct {
	HyClient   *core.Client
	Transport  transport.Transport
	ListenAddr *net.TCPAddr
	Remote     string
	Timeout    time.Duration

	ConnFunc  func(addr net.Addr)
	ErrorFunc func(addr net.Addr, err error)
}

func NewTCPRelay(hyClient *core.Client, transport transport.Transport, listen, remote string, timeout time.Duration,
	connFunc func(addr net.Addr), errorFunc func(addr net.Addr, err error)) (*TCPRelay, error) {
	tAddr, err := transport.LocalResolveTCPAddr(listen)
	if err != nil {
		return nil, err
	}
	r := &TCPRelay{
		HyClient:   hyClient,
		Transport:  transport,
		ListenAddr: tAddr,
		Remote:     remote,
		Timeout:    timeout,
		ConnFunc:   connFunc,
		ErrorFunc:  errorFunc,
	}
	return r, nil
}

func (r *TCPRelay) ListenAndServe() error {
	listener, err := r.Transport.LocalListenTCP(r.ListenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	for {
		c, err := listener.AcceptTCP()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			r.ConnFunc(c.RemoteAddr())
			rc, err := r.HyClient.DialTCP(r.Remote)
			if err != nil {
				r.ErrorFunc(c.RemoteAddr(), err)
				return
			}
			defer rc.Close()
			err = utils.PipePairWithTimeout(c, rc, r.Timeout)
			r.ErrorFunc(c.RemoteAddr(), err)
		}()
	}
}
