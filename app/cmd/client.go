package cmd

import (
	"crypto/x509"
	"errors"
	"net"
	"os"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/app/internal/socks5"
	"github.com/apernet/hysteria/core/client"
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Client mode",
	Run:   runClient,
}

var modeMap = map[string]func(*viper.Viper, client.Client) error{
	"socks5": clientSOCKS5,
}

func init() {
	rootCmd.AddCommand(clientCmd)
}

func runClient(cmd *cobra.Command, args []string) {
	logger.Info("client mode")

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read client config", zap.Error(err))
	}
	config, err := viperToClientConfig()
	if err != nil {
		logger.Fatal("failed to parse client config", zap.Error(err))
	}

	c, err := client.NewClient(config)
	if err != nil {
		logger.Fatal("failed to initialize client", zap.Error(err))
	}
	defer c.Close()

	var wg sync.WaitGroup
	hasMode := false
	for mode, f := range modeMap {
		v := viper.Sub(mode)
		if v != nil {
			hasMode = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := f(v, c); err != nil {
					logger.Fatal("failed to run mode", zap.String("mode", mode), zap.Error(err))
				}
			}()
		}
	}
	if !hasMode {
		logger.Fatal("no mode specified")
	}
	wg.Wait()
}

func viperToClientConfig() (*client.Config, error) {
	// Conn and address
	addrStr := viper.GetString("server")
	if addrStr == "" {
		return nil, configError{Field: "server", Err: errors.New("server address is empty")}
	}
	host, hostPort := parseServerAddrString(addrStr)
	addr, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return nil, configError{Field: "server", Err: err}
	}
	// TLS
	tlsConfig, err := viperToClientTLSConfig(host)
	if err != nil {
		return nil, err
	}
	// QUIC
	quicConfig := viperToClientQUICConfig()
	// Bandwidth
	bwConfig, err := viperToClientBandwidthConfig()
	if err != nil {
		return nil, err
	}
	return &client.Config{
		ConnFactory:     nil, // TODO
		ServerAddr:      addr,
		Auth:            viper.GetString("auth"),
		TLSConfig:       tlsConfig,
		QUICConfig:      quicConfig,
		BandwidthConfig: bwConfig,
		FastOpen:        viper.GetBool("fastOpen"),
	}, nil
}

func viperToClientTLSConfig(host string) (client.TLSConfig, error) {
	config := client.TLSConfig{
		ServerName:         viper.GetString("tls.sni"),
		InsecureSkipVerify: viper.GetBool("tls.insecure"),
	}
	if config.ServerName == "" {
		// The user didn't specify a server name, fallback to the host part of the server address
		config.ServerName = host
	}
	caPath := viper.GetString("tls.ca")
	if caPath != "" {
		ca, err := os.ReadFile(caPath)
		if err != nil {
			return client.TLSConfig{}, configError{Field: "tls.ca", Err: err}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return client.TLSConfig{}, configError{Field: "tls.ca", Err: errors.New("failed to parse CA certificate")}
		}
		config.RootCAs = pool
	}
	return config, nil
}

func viperToClientQUICConfig() client.QUICConfig {
	return client.QUICConfig{
		InitialStreamReceiveWindow:     viper.GetUint64("quic.initStreamReceiveWindow"),
		MaxStreamReceiveWindow:         viper.GetUint64("quic.maxStreamReceiveWindow"),
		InitialConnectionReceiveWindow: viper.GetUint64("quic.initConnReceiveWindow"),
		MaxConnectionReceiveWindow:     viper.GetUint64("quic.maxConnReceiveWindow"),
		MaxIdleTimeout:                 viper.GetDuration("quic.maxIdleTimeout"),
		KeepAlivePeriod:                viper.GetDuration("quic.keepAlivePeriod"),
		DisablePathMTUDiscovery:        viper.GetBool("quic.disablePathMTUDiscovery"),
	}
}

func viperToClientBandwidthConfig() (client.BandwidthConfig, error) {
	bw := client.BandwidthConfig{}
	upStr, downStr := viper.GetString("bandwidth.up"), viper.GetString("bandwidth.down")
	if upStr == "" || downStr == "" {
		return client.BandwidthConfig{}, configError{Field: "bandwidth", Err: errors.New("bandwidth.up and bandwidth.down must be set")}
	}
	up, err := convBandwidth(upStr)
	if err != nil {
		return client.BandwidthConfig{}, configError{Field: "bandwidth.up", Err: err}
	}
	down, err := convBandwidth(downStr)
	if err != nil {
		return client.BandwidthConfig{}, configError{Field: "bandwidth.down", Err: err}
	}
	bw.MaxTx, bw.MaxRx = up, down
	return bw, nil
}

func clientSOCKS5(v *viper.Viper, c client.Client) error {
	listenAddr := v.GetString("listen")
	if listenAddr == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	var authFunc func(username, password string) bool
	username, password := v.GetString("username"), v.GetString("password")
	if username != "" && password != "" {
		authFunc = func(username, password string) bool {
			return username == username && password == password
		}
	}
	s := socks5.Server{
		HyClient:    c,
		AuthFunc:    authFunc,
		DisableUDP:  viper.GetBool("disableUDP"),
		EventLogger: &socks5Logger{},
	}
	logger.Info("SOCKS5 server listening", zap.String("addr", listenAddr))
	return s.Serve(l)
}

func parseServerAddrString(addrStr string) (host, hostPort string) {
	h, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		// No port provided, use default HTTPS port
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
