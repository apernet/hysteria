package http

import (
	"errors"
	"fmt"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/elazarl/goproxy/ext/auth"

	"github.com/elazarl/goproxy"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/core"
)

func NewProxyHTTPServer(hyClient *core.Client, transport transport.Transport, idleTimeout time.Duration, aclEngine *acl.Engine,
	newDialFunc func(reqAddr string, action acl.Action, arg string),
	basicAuthFunc func(user, password string) bool) (*goproxy.ProxyHttpServer, error) {
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
				action, arg, ipAddr, resErr = aclEngine.ResolveAndMatch(host)
				// Doesn't always matter if the resolution fails, as we may send it through HyClient
			}
			newDialFunc(addr, action, arg)
			// Handle according to the action
			switch action {
			case acl.ActionDirect:
				if resErr != nil {
					return nil, resErr
				}
				return transport.LocalDialTCP(nil, &net.TCPAddr{
					IP:   ipAddr.IP,
					Port: int(port),
					Zone: ipAddr.Zone,
				})
			case acl.ActionProxy:
				return hyClient.DialTCP(addr)
			case acl.ActionBlock:
				return nil, errors.New("blocked by ACL")
			case acl.ActionHijack:
				return transport.LocalDial(network, net.JoinHostPort(arg, strconv.Itoa(int(port))))
			default:
				return nil, fmt.Errorf("unknown action %d", action)
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
