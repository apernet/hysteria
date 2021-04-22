package relay

import (
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"time"
)

type Relay struct {
	HyClient   *core.Client
	ListenAddr *net.TCPAddr
	Remote     string
	Timeout    time.Duration

	ConnFunc  func(addr net.Addr)
	ErrorFunc func(addr net.Addr, err error)

	tcpListener *net.TCPListener
}

func NewRelay(hyClient *core.Client, listen, remote string, timeout time.Duration,
	connFunc func(addr net.Addr), errorFunc func(addr net.Addr, err error)) (*Relay, error) {
	tAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		return nil, err
	}
	r := &Relay{
		HyClient:   hyClient,
		ListenAddr: tAddr,
		Remote:     remote,
		Timeout:    timeout,
		ConnFunc:   connFunc,
		ErrorFunc:  errorFunc,
	}
	return r, nil
}

func (r *Relay) ListenAndServe() error {
	var err error
	r.tcpListener, err = net.ListenTCP("tcp", r.ListenAddr)
	if err != nil {
		return err
	}
	defer r.tcpListener.Close()
	for {
		c, err := r.tcpListener.AcceptTCP()
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
