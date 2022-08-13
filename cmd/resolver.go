package main

import (
	"errors"
	"net"
	"strings"

	rdns "github.com/folbricht/routedns"
	"github.com/tobyxdd/hysteria/pkg/utils"
)

var errInvalidSyntax = errors.New("invalid syntax")

func setResolver(dns string) error {
	if net.ParseIP(dns) != nil {
		// Just an IP address, treat as UDP 53
		dns = "udp://" + net.JoinHostPort(dns, "53")
	}
	var r rdns.Resolver
	if strings.HasPrefix(dns, "udp://") {
		// Standard UDP DNS resolver
		dns = strings.TrimPrefix(dns, "udp://")
		if dns == "" {
			return errInvalidSyntax
		}
		if _, _, err := utils.SplitHostPort(dns); err != nil {
			// Append the default DNS port
			dns = net.JoinHostPort(dns, "53")
		}
		client, err := rdns.NewDNSClient("dns-udp", dns, "udp", rdns.DNSClientOptions{})
		if err != nil {
			return err
		}
		r = client
	} else if strings.HasPrefix(dns, "tcp://") {
		// Standard TCP DNS resolver
		dns = strings.TrimPrefix(dns, "tcp://")
		if dns == "" {
			return errInvalidSyntax
		}
		if _, _, err := utils.SplitHostPort(dns); err != nil {
			// Append the default DNS port
			dns = net.JoinHostPort(dns, "53")
		}
		client, err := rdns.NewDNSClient("dns-tcp", dns, "tcp", rdns.DNSClientOptions{})
		if err != nil {
			return err
		}
		r = client
	} else if strings.HasPrefix(dns, "https://") {
		// DoH resolver
		client, err := rdns.NewDoHClient("doh", dns, rdns.DoHClientOptions{})
		if err != nil {
			return err
		}
		r = client
	} else if strings.HasPrefix(dns, "tls://") {
		// DoT resolver
		dns = strings.TrimPrefix(dns, "tls://")
		if dns == "" {
			return errInvalidSyntax
		}
		if _, _, err := utils.SplitHostPort(dns); err != nil {
			// Append the default DoT port
			dns = net.JoinHostPort(dns, "853")
		}
		client, err := rdns.NewDoTClient("dot", dns, rdns.DoTClientOptions{})
		if err != nil {
			return err
		}
		r = client
	} else if strings.HasPrefix(dns, "quic://") {
		// DoQ resolver
		dns = strings.TrimPrefix(dns, "quic://")
		if dns == "" {
			return errInvalidSyntax
		}
		client, err := rdns.NewDoQClient("doq", dns, rdns.DoQClientOptions{})
		if err != nil {
			return err
		}
		r = client
	} else {
		return errInvalidSyntax
	}
	cache := rdns.NewCache("cache", r, rdns.CacheOptions{})
	net.DefaultResolver = rdns.NewNetResolver(cache)
	return nil
}
