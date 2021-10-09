package main

import (
	"context"
	"crypto/tls"
	"github.com/caddyserver/certmagic"
)

func acmeTLSConfig(domains []string, email string, disableHTTP bool, disableTLSALPN bool,
	altHTTPPort int, altTLSALPNPort int) (*tls.Config, error) {
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = email
	certmagic.DefaultACME.DisableHTTPChallenge = disableHTTP
	certmagic.DefaultACME.DisableTLSALPNChallenge = disableTLSALPN
	certmagic.DefaultACME.AltHTTPPort = altHTTPPort
	certmagic.DefaultACME.AltTLSALPNPort = altTLSALPNPort
	cfg := certmagic.NewDefault()
	return cfg.TLSConfig(), cfg.ManageSync(context.Background(), domains)
}
