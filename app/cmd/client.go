package cmd

import (
	"crypto/x509"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/app/internal/http"
	"github.com/apernet/hysteria/app/internal/socks5"
	"github.com/apernet/hysteria/core/client"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Client mode",
	Run:   runClient,
}

func init() {
	rootCmd.AddCommand(clientCmd)
}

type clientConfig struct {
	Server string `mapstructure:"server"`
	Auth   string `mapstructure:"auth"`
	TLS    struct {
		SNI      string `mapstructure:"sni"`
		Insecure bool   `mapstructure:"insecure"`
		CA       string `mapstructure:"ca"`
	} `mapstructure:"tls"`
	QUIC struct {
		InitStreamReceiveWindow     uint64        `mapstructure:"initStreamReceiveWindow"`
		MaxStreamReceiveWindow      uint64        `mapstructure:"maxStreamReceiveWindow"`
		InitConnectionReceiveWindow uint64        `mapstructure:"initConnReceiveWindow"`
		MaxConnectionReceiveWindow  uint64        `mapstructure:"maxConnReceiveWindow"`
		MaxIdleTimeout              time.Duration `mapstructure:"maxIdleTimeout"`
		KeepAlivePeriod             time.Duration `mapstructure:"keepAlivePeriod"`
		DisablePathMTUDiscovery     bool          `mapstructure:"disablePathMTUDiscovery"`
	} `mapstructure:"quic"`
	Bandwidth struct {
		Up   string `mapstructure:"up"`
		Down string `mapstructure:"down"`
	} `mapstructure:"bandwidth"`
	FastOpen bool          `mapstructure:"fastOpen"`
	SOCKS5   *socks5Config `mapstructure:"socks5"`
	HTTP     *httpConfig   `mapstructure:"http"`
}

type socks5Config struct {
	Listen     string `mapstructure:"listen"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
	DisableUDP bool   `mapstructure:"disableUDP"`
}

type httpConfig struct {
	Listen   string `mapstructure:"listen"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Realm    string `mapstructure:"realm"`
}

// Config validates the fields and returns a ready-to-use Hysteria client config
func (c *clientConfig) Config() (*client.Config, error) {
	hyConfig := &client.Config{}
	// ServerAddr
	if c.Server == "" {
		return nil, configError{Field: "server", Err: errors.New("server address is empty")}
	}
	host, hostPort := parseServerAddrString(c.Server)
	addr, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return nil, configError{Field: "server", Err: err}
	}
	hyConfig.ServerAddr = addr
	// Auth
	hyConfig.Auth = c.Auth
	// TLSConfig
	if c.TLS.SNI == "" {
		// Use server hostname as SNI
		hyConfig.TLSConfig.ServerName = host
	} else {
		hyConfig.TLSConfig.ServerName = c.TLS.SNI
	}
	hyConfig.TLSConfig.InsecureSkipVerify = c.TLS.Insecure
	if c.TLS.CA != "" {
		ca, err := os.ReadFile(c.TLS.CA)
		if err != nil {
			return nil, configError{Field: "tls.ca", Err: err}
		}
		cPool := x509.NewCertPool()
		if !cPool.AppendCertsFromPEM(ca) {
			return nil, configError{Field: "tls.ca", Err: errors.New("failed to parse CA certificate")}
		}
		hyConfig.TLSConfig.RootCAs = cPool
	}
	// QUICConfig
	hyConfig.QUICConfig = client.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		KeepAlivePeriod:                c.QUIC.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
	}
	// BandwidthConfig
	if c.Bandwidth.Up == "" || c.Bandwidth.Down == "" {
		return nil, configError{Field: "bandwidth", Err: errors.New("both up and down bandwidth must be set")}
	}
	hyConfig.BandwidthConfig.MaxTx, err = convBandwidth(c.Bandwidth.Up)
	if err != nil {
		return nil, configError{Field: "bandwidth.up", Err: err}
	}
	hyConfig.BandwidthConfig.MaxRx, err = convBandwidth(c.Bandwidth.Down)
	if err != nil {
		return nil, configError{Field: "bandwidth.down", Err: err}
	}
	// FastOpen
	hyConfig.FastOpen = c.FastOpen

	return hyConfig, nil
}

func runClient(cmd *cobra.Command, args []string) {
	logger.Info("client mode")

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read client config", zap.Error(err))
	}
	var config clientConfig
	if err := viper.Unmarshal(&config); err != nil {
		logger.Fatal("failed to parse client config", zap.Error(err))
	}
	hyConfig, err := config.Config()
	if err != nil {
		logger.Fatal("failed to load client config", zap.Error(err))
	}

	c, err := client.NewClient(hyConfig)
	if err != nil {
		logger.Fatal("failed to initialize client", zap.Error(err))
	}
	defer c.Close()

	// Modes
	var wg sync.WaitGroup
	hasMode := false

	if config.SOCKS5 != nil {
		hasMode = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := clientSOCKS5(*config.SOCKS5, c); err != nil {
				logger.Fatal("failed to run SOCKS5 server", zap.Error(err))
			}
		}()
	}
	if config.HTTP != nil {
		hasMode = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := clientHTTP(*config.HTTP, c); err != nil {
				logger.Fatal("failed to run HTTP proxy server", zap.Error(err))
			}
		}()
	}

	if !hasMode {
		logger.Fatal("no mode specified")
	}
	wg.Wait()
}

func clientSOCKS5(config socks5Config, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	l, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	var authFunc func(username, password string) bool
	username, password := config.Username, config.Password
	if username != "" && password != "" {
		authFunc = func(u, p string) bool {
			return u == username && p == password
		}
	}
	s := socks5.Server{
		HyClient:    c,
		AuthFunc:    authFunc,
		DisableUDP:  config.DisableUDP,
		EventLogger: &socks5Logger{},
	}
	logger.Info("SOCKS5 server listening", zap.String("addr", config.Listen))
	return s.Serve(l)
}

func clientHTTP(config httpConfig, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	l, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	var authFunc func(username, password string) bool
	username, password := config.Username, config.Password
	if username != "" && password != "" {
		authFunc = func(u, p string) bool {
			return u == username && p == password
		}
	}
	if config.Realm == "" {
		config.Realm = "Hysteria"
	}
	h := http.Server{
		HyClient:    c,
		AuthFunc:    authFunc,
		AuthRealm:   config.Realm,
		EventLogger: &httpLogger{},
	}
	logger.Info("HTTP proxy server listening", zap.String("addr", config.Listen))
	return h.Serve(l)
}

// parseServerAddrString parses server address string.
// Server address can be in either "host:port" or "host" format (in which case we assume port 443).
func parseServerAddrString(addrStr string) (host, hostPort string) {
	h, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr, net.JoinHostPort(addrStr, "443")
	}
	return h, addrStr
}

type socks5Logger struct{}

func (l *socks5Logger) TCPRequest(addr net.Addr, reqAddr string) {
	logger.Debug("SOCKS5 TCP request", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
}

func (l *socks5Logger) TCPError(addr net.Addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("SOCKS5 TCP closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
	} else {
		logger.Error("SOCKS5 TCP error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *socks5Logger) UDPRequest(addr net.Addr) {
	logger.Debug("SOCKS5 UDP request", zap.String("addr", addr.String()))
}

func (l *socks5Logger) UDPError(addr net.Addr, err error) {
	if err == nil {
		logger.Debug("SOCKS5 UDP closed", zap.String("addr", addr.String()))
	} else {
		logger.Error("SOCKS5 UDP error", zap.String("addr", addr.String()), zap.Error(err))
	}
}

type httpLogger struct{}

func (l *httpLogger) ConnectRequest(addr net.Addr, reqAddr string) {
	logger.Debug("HTTP CONNECT request", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
}

func (l *httpLogger) ConnectError(addr net.Addr, reqAddr string, err error) {
	if err == nil {
		logger.Debug("HTTP CONNECT closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr))
	} else {
		logger.Error("HTTP CONNECT error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr), zap.Error(err))
	}
}

func (l *httpLogger) HTTPRequest(addr net.Addr, reqURL string) {
	logger.Debug("HTTP request", zap.String("addr", addr.String()), zap.String("reqURL", reqURL))
}

func (l *httpLogger) HTTPError(addr net.Addr, reqURL string, err error) {
	if err == nil {
		logger.Debug("HTTP closed", zap.String("addr", addr.String()), zap.String("reqURL", reqURL))
	} else {
		logger.Error("HTTP error", zap.String("addr", addr.String()), zap.String("reqURL", reqURL), zap.Error(err))
	}
}
