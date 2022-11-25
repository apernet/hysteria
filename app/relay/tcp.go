package relay

import (
	"net"
	"time"

	"github.com/apernet/hysteria/core/cs"
	"github.com/apernet/hysteria/core/utils"
)

type TCPRelay struct {
	HyClient   *cs.Client
	ListenAddr *net.TCPAddr
	Remote     string
	Timeout    time.Duration

	ConnFunc  func(addr net.Addr)
	ErrorFunc func(addr net.Addr, err error)
}

func NewTCPRelay(hyClient *cs.Client, listen, remote string, timeout time.Duration,
	connFunc func(addr net.Addr), errorFunc func(addr net.Addr, err error),
) (*TCPRelay, error) {
	tAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		return nil, err
	}
	r := &TCPRelay{
		HyClient:   hyClient,
		ListenAddr: tAddr,
		Remote:     remote,
		Timeout:    timeout,
		ConnFunc:   connFunc,
		ErrorFunc:  errorFunc,
	}
	return r, nil
}

func (r *TCPRelay) ListenAndServe() error {
	listener, err := net.ListenTCP("tcp", r.ListenAddr)
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
