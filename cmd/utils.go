package main

import (
	"context"
	"net"
)

func setResolver(addr string) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		// Append the default DNS port
		addr = net.JoinHostPort(addr, "53")
	}
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, "udp", addr)
	}
}
