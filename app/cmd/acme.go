package main

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"

	"go.uber.org/zap"

	"github.com/caddyserver/certmagic"
)

func acmeTLSConfig(domains []string, email string, disableHTTP, disableTLSALPN bool,
	altHTTPPort, altTLSALPNPort int,
) (*tls.Config, error) {
	cfg := &certmagic.Config{
		RenewalWindowRatio: certmagic.DefaultRenewalWindowRatio,
		KeySource:          certmagic.DefaultKeyGenerator,
		Storage:            &certmagic.FileStorage{Path: dataDir()},
		Logger:             zap.NewNop(),
	}
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:                      certmagic.LetsEncryptProductionCA,
		TestCA:                  certmagic.LetsEncryptStagingCA,
		Email:                   email,
		Agreed:                  true,
		DisableHTTPChallenge:    disableHTTP,
		DisableTLSALPNChallenge: disableTLSALPN,
		AltHTTPPort:             altHTTPPort,
		AltTLSALPNPort:          altTLSALPNPort,
		Logger:                  zap.NewNop(),
	})
	cfg.Issuers = []certmagic.Issuer{issuer}

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return cfg, nil
		},
		Logger: zap.NewNop(),
	})
	cfg = certmagic.New(cache, *cfg)

	err := cfg.ManageSync(context.Background(), domains)
	if err != nil {
		return nil, err
	}
	return cfg.TLSConfig(), nil
}

func homeDir() string {
	home := os.Getenv("HOME")
	if home == "" && runtime.GOOS == "windows" {
		drive := os.Getenv("HOMEDRIVE")
		path := os.Getenv("HOMEPATH")
		home = drive + path
		if drive == "" || path == "" {
			home = os.Getenv("USERPROFILE")
		}
	}
	if home == "" {
		home = "."
	}
	return home
}

func dataDir() string {
	baseDir := filepath.Join(homeDir(), ".local", "share")
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		baseDir = xdgData
	}
	return filepath.Join(baseDir, "certmagic")
}
