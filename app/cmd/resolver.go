package main

import (
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/apernet/hysteria/core/utils"
	rdns "github.com/folbricht/routedns"
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
		if dohURL, err := url.Parse(dns); err != nil {
			return err
		} else {
			// Need to set bootstrap address to avoid loopback DNS lookup
			dohIPAddr, err := net.ResolveIPAddr("ip", dohURL.Hostname())
			if err != nil {
				return err
			}
			client, err := rdns.NewDoHClient("doh", dns, rdns.DoHClientOptions{
				BootstrapAddr: dohIPAddr.String(),
			})
			if err != nil {
				return err
			}
			r = client
		}
	} else if strings.HasPrefix(dns, "tls://") {
		// DoT resolver
		dns = strings.TrimPrefix(dns, "tls://")
		if dns == "" {
			return errInvalidSyntax
		}
		dotHost, _, err := utils.SplitHostPort(dns)
		if err != nil {
			// Append the default DNS port
			dns = net.JoinHostPort(dns, "853")
		}
		// Need to set bootstrap address to avoid loopback DNS lookup
		dotIPAddr, err := net.ResolveIPAddr("ip", dotHost)
		if err != nil {
			return err
		}
		client, err := rdns.NewDoTClient("dot", dns, rdns.DoTClientOptions{
			BootstrapAddr: dotIPAddr.String(),
			TLSConfig:     new(tls.Config),
		})
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
		doqHost, _, err := utils.SplitHostPort(dns)
		if err != nil {
			// Append the default DNS port
			dns = net.JoinHostPort(dns, "853")
		}
		// Need to set bootstrap address to avoid loopback DNS lookup
		doqIPAddr, err := net.ResolveIPAddr("ip", doqHost)
		if err != nil {
			return err
		}
		client, err := rdns.NewDoQClient("doq", dns, rdns.DoQClientOptions{
			BootstrapAddr: doqIPAddr.String(),
		})
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
