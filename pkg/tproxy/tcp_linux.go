package tproxy

import (
	"errors"
	"fmt"
	"github.com/LiamHaworth/go-tproxy"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"strconv"
	"time"
)

type TCPTProxy struct {
	HyClient   *core.Client
	Transport  transport.Transport
	ListenAddr *net.TCPAddr
	Timeout    time.Duration
	ACLEngine  *acl.Engine

	ConnFunc  func(addr, reqAddr net.Addr, action acl.Action, arg string)
	ErrorFunc func(addr, reqAddr net.Addr, err error)
}

func NewTCPTProxy(hyClient *core.Client, transport transport.Transport, listen string, timeout time.Duration,
	aclEngine *acl.Engine,
	connFunc func(addr, reqAddr net.Addr, action acl.Action, arg string),
	errorFunc func(addr, reqAddr net.Addr, err error)) (*TCPTProxy, error) {
	tAddr, err := transport.LocalResolveTCPAddr(listen)
	if err != nil {
		return nil, err
	}
	r := &TCPTProxy{
		HyClient:   hyClient,
		Transport:  transport,
		ListenAddr: tAddr,
		Timeout:    timeout,
		ACLEngine:  aclEngine,
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
			host, port, err := utils.SplitHostPort(c.LocalAddr().String())
			if err != nil {
				return
			}
			action, arg := acl.ActionProxy, ""
			var ipAddr *net.IPAddr
			var resErr error
			if r.ACLEngine != nil {
				action, arg, ipAddr, resErr = r.ACLEngine.ResolveAndMatch(host)
				// Doesn't always matter if the resolution fails, as we may send it through HyClient
			}
			r.ConnFunc(c.RemoteAddr(), c.LocalAddr(), action, arg)
			var closeErr error
			defer func() {
				r.ErrorFunc(c.RemoteAddr(), c.LocalAddr(), closeErr)
			}()
			// Handle according to the action
			switch action {
			case acl.ActionDirect:
				if resErr != nil {
					closeErr = resErr
					return
				}
				rc, err := r.Transport.LocalDialTCP(nil, &net.TCPAddr{
					IP:   ipAddr.IP,
					Port: int(port),
					Zone: ipAddr.Zone,
				})
				if err != nil {
					closeErr = err
					return
				}
				defer rc.Close()
				closeErr = utils.PipePairWithTimeout(c, rc, r.Timeout)
				return
			case acl.ActionProxy:
				rc, err := r.HyClient.DialTCP(c.LocalAddr().String())
				if err != nil {
					closeErr = err
					return
				}
				defer rc.Close()
				closeErr = utils.PipePairWithTimeout(c, rc, r.Timeout)
				return
			case acl.ActionBlock:
				closeErr = errors.New("blocked in ACL")
				return
			case acl.ActionHijack:
				rc, err := r.Transport.LocalDial("tcp", net.JoinHostPort(arg, strconv.Itoa(int(port))))
				if err != nil {
					closeErr = err
					return
				}
				defer rc.Close()
				closeErr = utils.PipePairWithTimeout(c, rc, r.Timeout)
				return
			default:
				closeErr = fmt.Errorf("unknown action %d", action)
				return
			}
		}()
	}
}
