package http

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/elazarl/goproxy/ext/auth"

	"github.com/elazarl/goproxy"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/core"
)

func NewProxyHTTPServer(hyClient *core.Client, idleTimeout time.Duration, aclEngine *acl.Engine,
	newDialFunc func(reqAddr string, action acl.Action, arg string),
	basicAuthFunc func(user, password string) bool) (*goproxy.ProxyHttpServer, error) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = &nopLogger{}
	proxy.NonproxyHandler = http.NotFoundHandler()
	proxy.Tr = &http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			// Parse addr string
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// ACL
			action, arg := acl.ActionProxy, ""
			if aclEngine != nil {
				ip := net.ParseIP(host)
				if ip != nil {
					host = ""
				}
				action, arg = aclEngine.Lookup(host, ip)
			}
			newDialFunc(addr, action, arg)
			// Handle according to the action
			switch action {
			case acl.ActionDirect:
				return net.Dial(network, addr)
			case acl.ActionProxy:
				return hyClient.DialTCP(addr)
			case acl.ActionBlock:
				return nil, errors.New("blocked by ACL")
			case acl.ActionHijack:
				return net.Dial(network, net.JoinHostPort(arg, port))
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
