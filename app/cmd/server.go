package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"

	"github.com/apernet/hysteria/core/server"
	"github.com/apernet/hysteria/extras/auth"

	"github.com/caddyserver/certmagic"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Server mode",
	Run:   runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)
	initServerConfigDefaults()
}

func initServerConfigDefaults() {
	viper.SetDefault("listen", ":443")
}

func runServer(cmd *cobra.Command, args []string) {
	logger.Info("server mode")

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read server config", zap.Error(err))
	}
	config, err := viperToServerConfig()
	if err != nil {
		logger.Fatal("failed to parse server config", zap.Error(err))
	}

	s, err := server.NewServer(config)
	if err != nil {
		logger.Fatal("failed to initialize server", zap.Error(err))
	}
	logger.Info("server up and running")

	if err := s.Serve(); err != nil {
		logger.Fatal("failed to serve", zap.Error(err))
	}
}

func viperToServerConfig() (*server.Config, error) {
	// Conn
	conn, err := viperToServerConn()
	if err != nil {
		return nil, err
	}
	// TLS
	tlsConfig, err := viperToServerTLSConfig()
	if err != nil {
		return nil, err
	}
	// QUIC
	quicConfig := viperToServerQUICConfig()
	// Bandwidth
	bwConfig, err := viperToServerBandwidthConfig()
	if err != nil {
		return nil, err
	}
	// Disable UDP
	disableUDP := viper.GetBool("disableUDP")
	// Authenticator
	authenticator, err := viperToAuthenticator()
	if err != nil {
		return nil, err
	}
	// Config
	config := &server.Config{
		TLSConfig:       tlsConfig,
		QUICConfig:      quicConfig,
		Conn:            conn,
		Outbound:        nil, // TODO
		BandwidthConfig: bwConfig,
		DisableUDP:      disableUDP,
		Authenticator:   authenticator,
		EventLogger:     &serverLogger{},
		MasqHandler:     nil, // TODO
	}
	return config, nil
}

func viperToServerConn() (net.PacketConn, error) {
	listen := viper.GetString("listen")
	if listen == "" {
		return nil, configError{Field: "listen", Err: errors.New("empty listen address")}
	}
	uAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, configError{Field: "listen", Err: err}
	}
	conn, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		return nil, configError{Field: "listen", Err: err}
	}
	return conn, nil
}

func viperToServerTLSConfig() (server.TLSConfig, error) {
	vTLS, vACME := viper.Sub("tls"), viper.Sub("acme")
	if vTLS == nil && vACME == nil {
		return server.TLSConfig{}, configError{Field: "tls", Err: errors.New("must set either tls or acme")}
	}
	if vTLS != nil && vACME != nil {
		return server.TLSConfig{}, configError{Field: "tls", Err: errors.New("cannot set both tls and acme")}
	}
	if vTLS != nil {
		return viperToServerTLSConfigLocal(vTLS)
	} else {
		return viperToServerTLSConfigACME(vACME)
	}
}

func viperToServerTLSConfigLocal(v *viper.Viper) (server.TLSConfig, error) {
	certPath, keyPath := v.GetString("cert"), v.GetString("key")
	if certPath == "" || keyPath == "" {
		return server.TLSConfig{}, configError{Field: "tls", Err: errors.New("empty cert or key path")}
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return server.TLSConfig{}, configError{Field: "tls", Err: err}
	}
	return server.TLSConfig{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func viperToServerTLSConfigACME(v *viper.Viper) (server.TLSConfig, error) {
	dataDir := v.GetString("dir")
	if dataDir == "" {
		dataDir = "acme"
	}

	cfg := &certmagic.Config{
		RenewalWindowRatio: certmagic.DefaultRenewalWindowRatio,
		KeySource:          certmagic.DefaultKeyGenerator,
		Storage:            &certmagic.FileStorage{Path: dataDir},
		Logger:             logger,
	}
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		Email:                   v.GetString("email"),
		Agreed:                  true,
		DisableHTTPChallenge:    v.GetBool("disableHTTP"),
		DisableTLSALPNChallenge: v.GetBool("disableTLSALPN"),
		AltHTTPPort:             v.GetInt("altHTTPPort"),
		AltTLSALPNPort:          v.GetInt("altTLSALPNPort"),
		Logger:                  logger,
	})
	switch strings.ToLower(v.GetString("ca")) {
	case "letsencrypt", "le", "":
		// Default to Let's Encrypt
		issuer.CA = certmagic.LetsEncryptProductionCA
	case "zerossl", "zero":
		issuer.CA = certmagic.ZeroSSLProductionCA
	default:
		return server.TLSConfig{}, configError{Field: "acme.ca", Err: errors.New("unknown CA")}
	}
	cfg.Issuers = []certmagic.Issuer{issuer}

	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return cfg, nil
		},
		Logger: logger,
	})
	cfg = certmagic.New(cache, *cfg)

	domains := v.GetStringSlice("domains")
	if len(domains) == 0 {
		return server.TLSConfig{}, configError{Field: "acme.domains", Err: errors.New("empty domains")}
	}
	err := cfg.ManageSync(context.Background(), domains)
	if err != nil {
		return server.TLSConfig{}, configError{Field: "acme", Err: err}
	}
	return server.TLSConfig{
		GetCertificate: cfg.GetCertificate,
	}, nil
}

func viperToServerQUICConfig() server.QUICConfig {
	return server.QUICConfig{
		InitialStreamReceiveWindow:     viper.GetUint64("quic.initStreamReceiveWindow"),
		MaxStreamReceiveWindow:         viper.GetUint64("quic.maxStreamReceiveWindow"),
		InitialConnectionReceiveWindow: viper.GetUint64("quic.initConnReceiveWindow"),
		MaxConnectionReceiveWindow:     viper.GetUint64("quic.maxConnReceiveWindow"),
		MaxIdleTimeout:                 viper.GetDuration("quic.maxIdleTimeout"),
		MaxIncomingStreams:             viper.GetInt64("quic.maxIncomingStreams"),
		DisablePathMTUDiscovery:        viper.GetBool("quic.disablePathMTUDiscovery"),
	}
}

func viperToServerBandwidthConfig() (server.BandwidthConfig, error) {
	bw := server.BandwidthConfig{}
	upStr, downStr := viper.GetString("bandwidth.up"), viper.GetString("bandwidth.down")
	if upStr != "" {
		up, err := convBandwidth(upStr)
		if err != nil {
			return server.BandwidthConfig{}, configError{Field: "bandwidth.up", Err: err}
		}
		bw.MaxTx = up
	}
	if downStr != "" {
		down, err := convBandwidth(downStr)
		if err != nil {
			return server.BandwidthConfig{}, configError{Field: "bandwidth.down", Err: err}
		}
		bw.MaxRx = down
	}
	return bw, nil
}

func viperToAuthenticator() (server.Authenticator, error) {
	authType := viper.GetString("auth.type")
	if authType == "" {
		return nil, configError{Field: "auth.type", Err: errors.New("empty auth type")}
	}
	switch authType {
	case "password":
		pw := viper.GetString("auth.password")
		if pw == "" {
			return nil, configError{Field: "auth.password", Err: errors.New("empty auth password")}
		}
		return &auth.PasswordAuthenticator{Password: pw}, nil
	default:
		return nil, configError{Field: "auth.type", Err: errors.New("unsupported auth type")}
	}
}

type serverLogger struct{}

func (l *serverLogger) Connect(addr net.Addr, id string, tx uint64) {
	logger.Info("client connected", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint64("tx", tx))
}

func (l *serverLogger) Disconnect(addr net.Addr, id string, err error) {
	logger.Info("client disconnected", zap.String("addr", addr.String()), zap.String("id", id), zap.Error(err))
}

func (l *serverLogger) TCPRequest(addr net.Addr, id, reqAddr string) {
	logger.Debug("TCP request", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr))
}

func (l *serverLogger) TCPError(addr net.Addr, id, reqAddr string, err error) {
	if err == nil {
		logger.Debug("TCP closed", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr))
	} else {
		logger.Error("TCP error", zap.String("addr", addr.String()), zap.String("id", id), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *serverLogger) UDPRequest(addr net.Addr, id string, sessionID uint32) {
	logger.Debug("UDP request", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID))
}

func (l *serverLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	if err == nil {
		logger.Debug("UDP closed", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID))
	} else {
		logger.Error("UDP error", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID), zap.Error(err))
	}
}
