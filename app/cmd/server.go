package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/core/server"
	"github.com/apernet/hysteria/extras/auth"
	"github.com/apernet/hysteria/extras/obfs"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Server mode",
	Run:   runServer,
}

func init() {
	rootCmd.AddCommand(serverCmd)
}

type serverConfig struct {
	Listen         string                 `mapstructure:"listen"`
	Obfs           serverConfigObfs       `mapstructure:"obfs"`
	TLS            *serverConfigTLS       `mapstructure:"tls"`
	ACME           *serverConfigACME      `mapstructure:"acme"`
	QUIC           serverConfigQUIC       `mapstructure:"quic"`
	Bandwidth      serverConfigBandwidth  `mapstructure:"bandwidth"`
	DisableUDP     bool                   `mapstructure:"disableUDP"`
	UDPIdleTimeout time.Duration          `mapstructure:"udpIdleTimeout"`
	Auth           serverConfigAuth       `mapstructure:"auth"`
	Masquerade     serverConfigMasquerade `mapstructure:"masquerade"`
}

type serverConfigObfsSalamander struct {
	Password string `mapstructure:"password"`
}

type serverConfigObfs struct {
	Type       string                     `mapstructure:"type"`
	Salamander serverConfigObfsSalamander `mapstructure:"salamander"`
}

type serverConfigTLS struct {
	Cert string `mapstructure:"cert"`
	Key  string `mapstructure:"key"`
}

type serverConfigACME struct {
	Domains        []string `mapstructure:"domains"`
	Email          string   `mapstructure:"email"`
	CA             string   `mapstructure:"ca"`
	DisableHTTP    bool     `mapstructure:"disableHTTP"`
	DisableTLSALPN bool     `mapstructure:"disableTLSALPN"`
	AltHTTPPort    int      `mapstructure:"altHTTPPort"`
	AltTLSALPNPort int      `mapstructure:"altTLSALPNPort"`
	Dir            string   `mapstructure:"dir"`
}

type serverConfigQUIC struct {
	InitStreamReceiveWindow     uint64        `mapstructure:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64        `mapstructure:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64        `mapstructure:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64        `mapstructure:"maxConnReceiveWindow"`
	MaxIdleTimeout              time.Duration `mapstructure:"maxIdleTimeout"`
	MaxIncomingStreams          int64         `mapstructure:"maxIncomingStreams"`
	DisablePathMTUDiscovery     bool          `mapstructure:"disablePathMTUDiscovery"`
}

type serverConfigBandwidth struct {
	Up   string `mapstructure:"up"`
	Down string `mapstructure:"down"`
}

type serverConfigAuth struct {
	Type     string `mapstructure:"type"`
	Password string `mapstructure:"password"`
}

type serverConfigMasqueradeFile struct {
	Dir string `mapstructure:"dir"`
}

type serverConfigMasqueradeProxy struct {
	URL         string `mapstructure:"url"`
	RewriteHost bool   `mapstructure:"rewriteHost"`
}

type serverConfigMasquerade struct {
	Type  string                      `mapstructure:"type"`
	File  serverConfigMasqueradeFile  `mapstructure:"file"`
	Proxy serverConfigMasqueradeProxy `mapstructure:"proxy"`
}

func (c *serverConfig) fillConn(hyConfig *server.Config) error {
	listenAddr := c.Listen
	if listenAddr == "" {
		listenAddr = ":443"
	}
	uAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	conn, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	switch strings.ToLower(c.Obfs.Type) {
	case "", "plain":
		hyConfig.Conn = conn
		return nil
	case "salamander":
		ob, err := obfs.NewSalamanderObfuscator([]byte(c.Obfs.Salamander.Password))
		if err != nil {
			return configError{Field: "obfs.salamander.password", Err: err}
		}
		hyConfig.Conn = obfs.WrapPacketConn(conn, ob)
		return nil
	default:
		return configError{Field: "obfs.type", Err: errors.New("unsupported obfuscation type")}
	}
}

func (c *serverConfig) fillTLSConfig(hyConfig *server.Config) error {
	if c.TLS == nil && c.ACME == nil {
		return configError{Field: "tls", Err: errors.New("must set either tls or acme")}
	}
	if c.TLS != nil && c.ACME != nil {
		return configError{Field: "tls", Err: errors.New("cannot set both tls and acme")}
	}
	if c.TLS != nil {
		// Local TLS cert
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return configError{Field: "tls", Err: errors.New("empty cert or key path")}
		}
		cert, err := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
		if err != nil {
			return configError{Field: "tls", Err: err}
		}
		hyConfig.TLSConfig.Certificates = []tls.Certificate{cert}
	} else {
		// ACME
		dataDir := c.ACME.Dir
		if dataDir == "" {
			dataDir = "acme"
		}
		cmCfg := &certmagic.Config{
			RenewalWindowRatio: certmagic.DefaultRenewalWindowRatio,
			KeySource:          certmagic.DefaultKeyGenerator,
			Storage:            &certmagic.FileStorage{Path: dataDir},
			Logger:             logger,
		}
		cmIssuer := certmagic.NewACMEIssuer(cmCfg, certmagic.ACMEIssuer{
			Email:                   c.ACME.Email,
			Agreed:                  true,
			DisableHTTPChallenge:    c.ACME.DisableHTTP,
			DisableTLSALPNChallenge: c.ACME.DisableTLSALPN,
			AltHTTPPort:             c.ACME.AltHTTPPort,
			AltTLSALPNPort:          c.ACME.AltTLSALPNPort,
			Logger:                  logger,
		})
		switch strings.ToLower(c.ACME.CA) {
		case "letsencrypt", "le", "":
			// Default to Let's Encrypt
			cmIssuer.CA = certmagic.LetsEncryptProductionCA
		case "zerossl", "zero":
			cmIssuer.CA = certmagic.ZeroSSLProductionCA
		default:
			return configError{Field: "acme.ca", Err: errors.New("unknown CA")}
		}
		cmCfg.Issuers = []certmagic.Issuer{cmIssuer}
		cmCache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
				return cmCfg, nil
			},
			Logger: logger,
		})
		cmCfg = certmagic.New(cmCache, *cmCfg)

		if len(c.ACME.Domains) == 0 {
			return configError{Field: "acme.domains", Err: errors.New("empty domains")}
		}
		err := cmCfg.ManageSync(context.Background(), c.ACME.Domains)
		if err != nil {
			return configError{Field: "acme.domains", Err: err}
		}
		hyConfig.TLSConfig.GetCertificate = cmCfg.GetCertificate
	}
	return nil
}

func (c *serverConfig) fillQUICConfig(hyConfig *server.Config) error {
	hyConfig.QUICConfig = server.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		MaxIncomingStreams:             c.QUIC.MaxIncomingStreams,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
	}
	return nil
}

func (c *serverConfig) fillBandwidthConfig(hyConfig *server.Config) error {
	var err error
	if c.Bandwidth.Up != "" {
		hyConfig.BandwidthConfig.MaxTx, err = convBandwidth(c.Bandwidth.Up)
		if err != nil {
			return configError{Field: "bandwidth.up", Err: err}
		}
	}
	if c.Bandwidth.Down != "" {
		hyConfig.BandwidthConfig.MaxRx, err = convBandwidth(c.Bandwidth.Down)
		if err != nil {
			return configError{Field: "bandwidth.down", Err: err}
		}
	}
	return nil
}

func (c *serverConfig) fillDisableUDP(hyConfig *server.Config) error {
	hyConfig.DisableUDP = c.DisableUDP
	return nil
}

func (c *serverConfig) fillUDPIdleTimeout(hyConfig *server.Config) error {
	hyConfig.UDPIdleTimeout = c.UDPIdleTimeout
	return nil
}

func (c *serverConfig) fillAuthenticator(hyConfig *server.Config) error {
	if c.Auth.Type == "" {
		return configError{Field: "auth.type", Err: errors.New("empty auth type")}
	}
	switch strings.ToLower(c.Auth.Type) {
	case "password":
		if c.Auth.Password == "" {
			return configError{Field: "auth.password", Err: errors.New("empty auth password")}
		}
		hyConfig.Authenticator = &auth.PasswordAuthenticator{Password: c.Auth.Password}
		return nil
	default:
		return configError{Field: "auth.type", Err: errors.New("unsupported auth type")}
	}
}

func (c *serverConfig) fillEventLogger(hyConfig *server.Config) error {
	hyConfig.EventLogger = &serverLogger{}
	return nil
}

func (c *serverConfig) fillMasqHandler(hyConfig *server.Config) error {
	switch strings.ToLower(c.Masquerade.Type) {
	case "", "404":
		hyConfig.MasqHandler = http.NotFoundHandler()
		return nil
	case "file":
		if c.Masquerade.File.Dir == "" {
			return configError{Field: "masquerade.file.dir", Err: errors.New("empty file directory")}
		}
		hyConfig.MasqHandler = http.FileServer(http.Dir(c.Masquerade.File.Dir))
		return nil
	case "proxy":
		if c.Masquerade.Proxy.URL == "" {
			return configError{Field: "masquerade.proxy.url", Err: errors.New("empty proxy url")}
		}
		u, err := url.Parse(c.Masquerade.Proxy.URL)
		if err != nil {
			return configError{Field: "masquerade.proxy.url", Err: err}
		}
		hyConfig.MasqHandler = &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(u)
				// SetURL rewrites the Host header,
				// but we don't want that if rewriteHost is false
				if !c.Masquerade.Proxy.RewriteHost {
					r.Out.Host = r.In.Host
				}
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				logger.Error("HTTP reverse proxy error", zap.Error(err))
				w.WriteHeader(http.StatusBadGateway)
			},
		}
		return nil
	default:
		return configError{Field: "masquerade.type", Err: errors.New("unsupported masquerade type")}
	}
}

// Config validates the fields and returns a ready-to-use Hysteria server config
func (c *serverConfig) Config() (*server.Config, error) {
	hyConfig := &server.Config{}
	fillers := []func(*server.Config) error{
		c.fillConn,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillBandwidthConfig,
		c.fillDisableUDP,
		c.fillUDPIdleTimeout,
		c.fillAuthenticator,
		c.fillEventLogger,
		c.fillMasqHandler,
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}
	return hyConfig, nil
}

func runServer(cmd *cobra.Command, args []string) {
	logger.Info("server mode")

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read server config", zap.Error(err))
	}
	var config serverConfig
	if err := viper.Unmarshal(&config); err != nil {
		logger.Fatal("failed to parse server config", zap.Error(err))
	}
	hyConfig, err := config.Config()
	if err != nil {
		logger.Fatal("failed to load server config", zap.Error(err))
	}

	s, err := server.NewServer(hyConfig)
	if err != nil {
		logger.Fatal("failed to initialize server", zap.Error(err))
	}
	logger.Info("server up and running")

	if err := s.Serve(); err != nil {
		logger.Fatal("failed to serve", zap.Error(err))
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

func (l *serverLogger) UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string) {
	logger.Debug("UDP request", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID), zap.String("reqAddr", reqAddr))
}

func (l *serverLogger) UDPError(addr net.Addr, id string, sessionID uint32, err error) {
	if err == nil {
		logger.Debug("UDP closed", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID))
	} else {
		logger.Error("UDP error", zap.String("addr", addr.String()), zap.String("id", id), zap.Uint32("sessionID", sessionID), zap.Error(err))
	}
}
