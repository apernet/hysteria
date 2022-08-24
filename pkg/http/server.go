package http

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/HyNetwork/hysteria/pkg/transport"
	"github.com/HyNetwork/hysteria/pkg/utils"

	"github.com/elazarl/goproxy/ext/auth"

	"github.com/HyNetwork/hysteria/pkg/acl"
	"github.com/HyNetwork/hysteria/pkg/core"
	"github.com/elazarl/goproxy"
)

func NewProxyHTTPServer(hyClient *core.Client, transport *transport.ClientTransport, idleTimeout time.Duration,
	aclEngine *acl.Engine,
	basicAuthFunc func(user, password string) bool,
	newDialFunc func(reqAddr string, action acl.Action, arg string),
	proxyErrorFunc func(reqAddr string, err error),
) (*goproxy.ProxyHttpServer, error) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = &nopLogger{}
	proxy.NonproxyHandler = http.NotFoundHandler()
	proxy.Tr = &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			// Parse addr string
			host, port, err := utils.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// ACL
			action, arg := acl.ActionProxy, ""
			var ipAddr *net.IPAddr
			var resErr error
			if aclEngine != nil {
				action, arg, _, ipAddr, resErr = aclEngine.ResolveAndMatch(host, port, false)
				// Doesn't always matter if the resolution fails, as we may send it through HyClient
			}
			newDialFunc(addr, action, arg)
			// Handle according to the action
			switch action {
			case acl.ActionDirect:
				if resErr != nil {
					return nil, resErr
				}
				conn, err := transport.DialTCP(&net.TCPAddr{
					IP:   ipAddr.IP,
					Port: int(port),
					Zone: ipAddr.Zone,
				})
				if err != nil {
					proxyErrorFunc(addr, err)
				}
				return conn, err
			case acl.ActionProxy:
				conn, err := hyClient.DialTCP(addr)
				if err != nil {
					proxyErrorFunc(addr, err)
				}
				return conn, err
			case acl.ActionBlock:
				err := errors.New("blocked by ACL")
				proxyErrorFunc(addr, err)
				return nil, err
			case acl.ActionHijack:
				hijackIPAddr, err := transport.ResolveIPAddr(arg)
				if err != nil {
					proxyErrorFunc(addr, err)
					return nil, err
				}
				conn, err := transport.DialTCP(&net.TCPAddr{
					IP:   hijackIPAddr.IP,
					Port: int(port),
					Zone: hijackIPAddr.Zone,
				})
				if err != nil {
					proxyErrorFunc(addr, err)
				}
				return conn, err
			default:
				err := fmt.Errorf("unknown action %d", action)
				proxyErrorFunc(addr, err)
				return nil, err
			}
		},
		IdleConnTimeout: idleTimeout,
		// Disable HTTP2 support? ref: https://github.com/elazarl/goproxy/issues/361
	}
	proxy.ConnectDial = nil
	if basicAuthFunc != nil {
		auth.ProxyBasic(proxy, "hysteria client", basicAuthFunc)
	}
	return proxy, nil
}

type nopLogger struct{}

func (n *nopLogger) Printf(format string, v ...interface{}) {}
