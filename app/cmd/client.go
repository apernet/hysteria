package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/app/internal/forwarding"
	"github.com/apernet/hysteria/app/internal/http"
	"github.com/apernet/hysteria/app/internal/redirect"
	"github.com/apernet/hysteria/app/internal/socks5"
	"github.com/apernet/hysteria/app/internal/tproxy"
	"github.com/apernet/hysteria/app/internal/url"
	"github.com/apernet/hysteria/app/internal/utils"
	"github.com/apernet/hysteria/core/client"
	"github.com/apernet/hysteria/extras/obfs"
	"github.com/apernet/hysteria/extras/transport/udphop"
)

// Client flags
var (
	showQR bool
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Client mode",
	Run:   runClient,
}

func init() {
	initClientFlags()
	rootCmd.AddCommand(clientCmd)
}

func initClientFlags() {
	clientCmd.Flags().BoolVar(&showQR, "qr", false, "show QR code for server config sharing")
}

type clientConfig struct {
	Server        string                `mapstructure:"server"`
	Auth          string                `mapstructure:"auth"`
	Transport     clientConfigTransport `mapstructure:"transport"`
	Obfs          clientConfigObfs      `mapstructure:"obfs"`
	TLS           clientConfigTLS       `mapstructure:"tls"`
	QUIC          clientConfigQUIC      `mapstructure:"quic"`
	Bandwidth     clientConfigBandwidth `mapstructure:"bandwidth"`
	FastOpen      bool                  `mapstructure:"fastOpen"`
	Lazy          bool                  `mapstructure:"lazy"`
	SOCKS5        *socks5Config         `mapstructure:"socks5"`
	HTTP          *httpConfig           `mapstructure:"http"`
	TCPForwarding []tcpForwardingEntry  `mapstructure:"tcpForwarding"`
	UDPForwarding []udpForwardingEntry  `mapstructure:"udpForwarding"`
	TCPTProxy     *tcpTProxyConfig      `mapstructure:"tcpTProxy"`
	UDPTProxy     *udpTProxyConfig      `mapstructure:"udpTProxy"`
	TCPRedirect   *tcpRedirectConfig    `mapstructure:"tcpRedirect"`
}

type clientConfigTransportUDP struct {
	HopInterval time.Duration `mapstructure:"hopInterval"`
}

type clientConfigTransport struct {
	Type string                   `mapstructure:"type"`
	UDP  clientConfigTransportUDP `mapstructure:"udp"`
}

type clientConfigObfsSalamander struct {
	Password string `mapstructure:"password"`
}

type clientConfigObfs struct {
	Type       string                     `mapstructure:"type"`
	Salamander clientConfigObfsSalamander `mapstructure:"salamander"`
}

type clientConfigTLS struct {
	SNI       string `mapstructure:"sni"`
	Insecure  bool   `mapstructure:"insecure"`
	PinSHA256 string `mapstructure:"pinSHA256"`
	CA        string `mapstructure:"ca"`
}

type clientConfigQUIC struct {
	InitStreamReceiveWindow     uint64        `mapstructure:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow      uint64        `mapstructure:"maxStreamReceiveWindow"`
	InitConnectionReceiveWindow uint64        `mapstructure:"initConnReceiveWindow"`
	MaxConnectionReceiveWindow  uint64        `mapstructure:"maxConnReceiveWindow"`
	MaxIdleTimeout              time.Duration `mapstructure:"maxIdleTimeout"`
	KeepAlivePeriod             time.Duration `mapstructure:"keepAlivePeriod"`
	DisablePathMTUDiscovery     bool          `mapstructure:"disablePathMTUDiscovery"`
}

type clientConfigBandwidth struct {
	Up   string `mapstructure:"up"`
	Down string `mapstructure:"down"`
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

type tcpForwardingEntry struct {
	Listen string `mapstructure:"listen"`
	Remote string `mapstructure:"remote"`
}

type udpForwardingEntry struct {
	Listen  string        `mapstructure:"listen"`
	Remote  string        `mapstructure:"remote"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type tcpTProxyConfig struct {
	Listen string `mapstructure:"listen"`
}

type udpTProxyConfig struct {
	Listen  string        `mapstructure:"listen"`
	Timeout time.Duration `mapstructure:"timeout"`
}

type tcpRedirectConfig struct {
	Listen string `mapstructure:"listen"`
}

func (c *clientConfig) fillServerAddr(hyConfig *client.Config) error {
	if c.Server == "" {
		return configError{Field: "server", Err: errors.New("server address is empty")}
	}
	var addr net.Addr
	var err error
	host, port, hostPort := parseServerAddrString(c.Server)
	if !isPortHoppingPort(port) {
		addr, err = net.ResolveUDPAddr("udp", hostPort)
	} else {
		addr, err = udphop.ResolveUDPHopAddr(hostPort)
	}
	if err != nil {
		return configError{Field: "server", Err: err}
	}
	hyConfig.ServerAddr = addr
	// Special handling for SNI
	if c.TLS.SNI == "" {
		// Use server hostname as SNI
		hyConfig.TLSConfig.ServerName = host
	}
	return nil
}

// fillConnFactory must be called after fillServerAddr, as we have different logic
// for ConnFactory depending on whether we have a port hopping address.
func (c *clientConfig) fillConnFactory(hyConfig *client.Config) error {
	// Inner PacketConn
	var newFunc func(addr net.Addr) (net.PacketConn, error)
	switch strings.ToLower(c.Transport.Type) {
	case "", "udp":
		if hyConfig.ServerAddr.Network() == "udphop" {
			hopAddr := hyConfig.ServerAddr.(*udphop.UDPHopAddr)
			newFunc = func(addr net.Addr) (net.PacketConn, error) {
				return udphop.NewUDPHopPacketConn(hopAddr, c.Transport.UDP.HopInterval)
			}
		} else {
			newFunc = func(addr net.Addr) (net.PacketConn, error) {
				return net.ListenUDP("udp", nil)
			}
		}
	default:
		return configError{Field: "transport.type", Err: errors.New("unsupported transport type")}
	}
	// Obfuscation
	var ob obfs.Obfuscator
	var err error
	switch strings.ToLower(c.Obfs.Type) {
	case "", "plain":
		// Keep it nil
	case "salamander":
		ob, err = obfs.NewSalamanderObfuscator([]byte(c.Obfs.Salamander.Password))
		if err != nil {
			return configError{Field: "obfs.salamander.password", Err: err}
		}
	default:
		return configError{Field: "obfs.type", Err: errors.New("unsupported obfuscation type")}
	}
	hyConfig.ConnFactory = &adaptiveConnFactory{
		NewFunc:    newFunc,
		Obfuscator: ob,
	}
	return nil
}

func (c *clientConfig) fillAuth(hyConfig *client.Config) error {
	hyConfig.Auth = c.Auth
	return nil
}

func (c *clientConfig) fillTLSConfig(hyConfig *client.Config) error {
	if c.TLS.SNI != "" {
		hyConfig.TLSConfig.ServerName = c.TLS.SNI
	}
	hyConfig.TLSConfig.InsecureSkipVerify = c.TLS.Insecure
	if c.TLS.PinSHA256 != "" {
		nHash := normalizeCertHash(c.TLS.PinSHA256)
		hyConfig.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, cert := range rawCerts {
				hash := sha256.Sum256(cert)
				hashHex := hex.EncodeToString(hash[:])
				if hashHex == nHash {
					return nil
				}
			}
			// No match
			return errors.New("no certificate matches the pinned hash")
		}
	}
	if c.TLS.CA != "" {
		ca, err := os.ReadFile(c.TLS.CA)
		if err != nil {
			return configError{Field: "tls.ca", Err: err}
		}
		cPool := x509.NewCertPool()
		if !cPool.AppendCertsFromPEM(ca) {
			return configError{Field: "tls.ca", Err: errors.New("failed to parse CA certificate")}
		}
		hyConfig.TLSConfig.RootCAs = cPool
	}
	return nil
}

func (c *clientConfig) fillQUICConfig(hyConfig *client.Config) error {
	hyConfig.QUICConfig = client.QUICConfig{
		InitialStreamReceiveWindow:     c.QUIC.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.QUIC.InitConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.QUIC.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.QUIC.MaxIdleTimeout,
		KeepAlivePeriod:                c.QUIC.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.QUIC.DisablePathMTUDiscovery,
	}
	return nil
}

func (c *clientConfig) fillBandwidthConfig(hyConfig *client.Config) error {
	// New core now allows users to omit bandwidth values and use built-in congestion control
	var err error
	if c.Bandwidth.Up != "" {
		hyConfig.BandwidthConfig.MaxTx, err = utils.ConvBandwidth(c.Bandwidth.Up)
		if err != nil {
			return configError{Field: "bandwidth.up", Err: err}
		}
	}
	if c.Bandwidth.Down != "" {
		hyConfig.BandwidthConfig.MaxRx, err = utils.ConvBandwidth(c.Bandwidth.Down)
		if err != nil {
			return configError{Field: "bandwidth.down", Err: err}
		}
	}
	return nil
}

func (c *clientConfig) fillFastOpen(hyConfig *client.Config) error {
	hyConfig.FastOpen = c.FastOpen
	return nil
}

// URI generates a URI for sharing the config with others.
// Note that only the bare minimum of information required to
// connect to the server is included in the URI, specifically:
// - server address
// - authentication
// - obfuscation type
// - obfuscation password
// - TLS SNI
// - TLS insecure
// - TLS pinned SHA256 hash (normalized)
func (c *clientConfig) URI() string {
	q := url.Values{}
	switch strings.ToLower(c.Obfs.Type) {
	case "salamander":
		q.Set("obfs", "salamander")
		q.Set("obfs-password", c.Obfs.Salamander.Password)
	}
	if c.TLS.SNI != "" {
		q.Set("sni", c.TLS.SNI)
	}
	if c.TLS.Insecure {
		q.Set("insecure", "1")
	}
	if c.TLS.PinSHA256 != "" {
		q.Set("pinSHA256", normalizeCertHash(c.TLS.PinSHA256))
	}
	var user *url.Userinfo
	if c.Auth != "" {
		// We need to handle the special case of user:pass pairs
		rs := strings.SplitN(c.Auth, ":", 2)
		if len(rs) == 2 {
			user = url.UserPassword(rs[0], rs[1])
		} else {
			user = url.User(c.Auth)
		}
	}
	u := url.URL{
		Scheme:   "hysteria2",
		User:     user,
		Host:     c.Server,
		Path:     "/",
		RawQuery: q.Encode(),
	}
	return u.String()
}

// parseURI tries to parse the server address field as a URI,
// and fills the config with the information contained in the URI.
// Returns whether the server address field is a valid URI.
// This allows a user to use put a URI as the server address and
// omit the fields that are already contained in the URI.
func (c *clientConfig) parseURI() bool {
	u, err := url.Parse(c.Server)
	if err != nil {
		return false
	}
	if u.Scheme != "hysteria2" && u.Scheme != "hy2" {
		return false
	}
	if u.User != nil {
		c.Auth = u.User.String()
	}
	c.Server = u.Host
	q := u.Query()
	if obfsType := q.Get("obfs"); obfsType != "" {
		c.Obfs.Type = obfsType
		switch strings.ToLower(obfsType) {
		case "salamander":
			c.Obfs.Salamander.Password = q.Get("obfs-password")
		}
	}
	if sni := q.Get("sni"); sni != "" {
		c.TLS.SNI = sni
	}
	if insecure, err := strconv.ParseBool(q.Get("insecure")); err == nil {
		c.TLS.Insecure = insecure
	}
	if pinSHA256 := q.Get("pinSHA256"); pinSHA256 != "" {
		c.TLS.PinSHA256 = pinSHA256
	}
	return true
}

// Config validates the fields and returns a ready-to-use Hysteria client config
func (c *clientConfig) Config() (*client.Config, error) {
	c.parseURI()
	hyConfig := &client.Config{}
	fillers := []func(*client.Config) error{
		c.fillServerAddr,
		c.fillConnFactory,
		c.fillAuth,
		c.fillTLSConfig,
		c.fillQUICConfig,
		c.fillBandwidthConfig,
		c.fillFastOpen,
	}
	for _, f := range fillers {
		if err := f(hyConfig); err != nil {
			return nil, err
		}
	}
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

	c, err := client.NewReconnectableClient(hyConfig, func(c client.Client, count int) {
		connectLog(count)
		// On the client side, we start checking for updates after we successfully connect
		// to the server, which, depending on whether lazy mode is enabled, may or may not
		// be immediately after the client starts. We don't want the update check request
		// to interfere with the lazy mode option.
		if count == 1 && !disableUpdateCheck {
			go runCheckUpdateClient(c)
		}
	}, config.Lazy)
	if err != nil {
		logger.Fatal("failed to initialize client", zap.Error(err))
	}
	defer c.Close()

	uri := config.URI()
	logger.Info("use this URI to share your server", zap.String("uri", uri))
	if showQR {
		utils.PrintQR(uri)
	}

	// Register modes
	var runner clientModeRunner
	if config.SOCKS5 != nil {
		runner.Add("SOCKS5 server", func() error {
			return clientSOCKS5(*config.SOCKS5, c)
		})
	}
	if config.HTTP != nil {
		runner.Add("HTTP proxy server", func() error {
			return clientHTTP(*config.HTTP, c)
		})
	}
	if len(config.TCPForwarding) > 0 {
		runner.Add("TCP forwarding", func() error {
			return clientTCPForwarding(config.TCPForwarding, c)
		})
	}
	if len(config.UDPForwarding) > 0 {
		runner.Add("UDP forwarding", func() error {
			return clientUDPForwarding(config.UDPForwarding, c)
		})
	}
	if config.TCPTProxy != nil {
		runner.Add("TCP transparent proxy", func() error {
			return clientTCPTProxy(*config.TCPTProxy, c)
		})
	}
	if config.UDPTProxy != nil {
		runner.Add("UDP transparent proxy", func() error {
			return clientUDPTProxy(*config.UDPTProxy, c)
		})
	}
	if config.TCPRedirect != nil {
		runner.Add("TCP redirect", func() error {
			return clientTCPRedirect(*config.TCPRedirect, c)
		})
	}

	runner.Run()
}

type clientModeRunner struct {
	ModeMap map[string]func() error
}

func (r *clientModeRunner) Add(name string, f func() error) {
	if r.ModeMap == nil {
		r.ModeMap = make(map[string]func() error)
	}
	r.ModeMap[name] = f
}

func (r *clientModeRunner) Run() {
	if len(r.ModeMap) == 0 {
		logger.Fatal("no mode specified")
	}

	type modeError struct {
		Name string
		Err  error
	}
	errChan := make(chan modeError, len(r.ModeMap))
	for name, f := range r.ModeMap {
		go func(name string, f func() error) {
			err := f()
			errChan <- modeError{name, err}
		}(name, f)
	}
	// Fatal if any one of the modes fails
	for i := 0; i < len(r.ModeMap); i++ {
		e := <-errChan
		if e.Err != nil {
			logger.Fatal("failed to run "+e.Name, zap.Error(e.Err))
		}
	}
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

func clientTCPForwarding(entries []tcpForwardingEntry, c client.Client) error {
	errChan := make(chan error, len(entries))
	for _, e := range entries {
		if e.Listen == "" {
			return configError{Field: "listen", Err: errors.New("listen address is empty")}
		}
		if e.Remote == "" {
			return configError{Field: "remote", Err: errors.New("remote address is empty")}
		}
		l, err := net.Listen("tcp", e.Listen)
		if err != nil {
			return configError{Field: "listen", Err: err}
		}
		logger.Info("TCP forwarding listening", zap.String("addr", e.Listen), zap.String("remote", e.Remote))
		go func(remote string) {
			t := &forwarding.TCPTunnel{
				HyClient:    c,
				Remote:      remote,
				EventLogger: &tcpLogger{},
			}
			errChan <- t.Serve(l)
		}(e.Remote)
	}
	// Return if any one of the forwarding fails
	return <-errChan
}

func clientUDPForwarding(entries []udpForwardingEntry, c client.Client) error {
	errChan := make(chan error, len(entries))
	for _, e := range entries {
		if e.Listen == "" {
			return configError{Field: "listen", Err: errors.New("listen address is empty")}
		}
		if e.Remote == "" {
			return configError{Field: "remote", Err: errors.New("remote address is empty")}
		}
		l, err := net.ListenPacket("udp", e.Listen)
		if err != nil {
			return configError{Field: "listen", Err: err}
		}
		logger.Info("UDP forwarding listening", zap.String("addr", e.Listen), zap.String("remote", e.Remote))
		go func(remote string, timeout time.Duration) {
			u := &forwarding.UDPTunnel{
				HyClient:    c,
				Remote:      remote,
				Timeout:     timeout,
				EventLogger: &udpLogger{},
			}
			errChan <- u.Serve(l)
		}(e.Remote, e.Timeout)
	}
	// Return if any one of the forwarding fails
	return <-errChan
}

func clientTCPTProxy(config tcpTProxyConfig, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	laddr, err := net.ResolveTCPAddr("tcp", config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	p := &tproxy.TCPTProxy{
		HyClient:    c,
		EventLogger: &tcpTProxyLogger{},
	}
	logger.Info("TCP transparent proxy listening", zap.String("addr", config.Listen))
	return p.ListenAndServe(laddr)
}

func clientUDPTProxy(config udpTProxyConfig, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	laddr, err := net.ResolveUDPAddr("udp", config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	p := &tproxy.UDPTProxy{
		HyClient:    c,
		Timeout:     config.Timeout,
		EventLogger: &udpTProxyLogger{},
	}
	logger.Info("UDP transparent proxy listening", zap.String("addr", config.Listen))
	return p.ListenAndServe(laddr)
}

func clientTCPRedirect(config tcpRedirectConfig, c client.Client) error {
	if config.Listen == "" {
		return configError{Field: "listen", Err: errors.New("listen address is empty")}
	}
	laddr, err := net.ResolveTCPAddr("tcp", config.Listen)
	if err != nil {
		return configError{Field: "listen", Err: err}
	}
	p := &redirect.TCPRedirect{
		HyClient:    c,
		EventLogger: &tcpRedirectLogger{},
	}
	logger.Info("TCP redirect listening", zap.String("addr", config.Listen))
	return p.ListenAndServe(laddr)
}

// parseServerAddrString parses server address string.
// Server address can be in either "host:port" or "host" format (in which case we assume port 443).
func parseServerAddrString(addrStr string) (host, port, hostPort string) {
	h, p, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr, "443", net.JoinHostPort(addrStr, "443")
	}
	return h, p, addrStr
}

// isPortHoppingPort returns whether the port string is a port hopping port.
// We consider a port string to be a port hopping port if it contains "-" or ",".
func isPortHoppingPort(port string) bool {
	return strings.Contains(port, "-") || strings.Contains(port, ",")
}

// normalizeCertHash normalizes a certificate hash string.
// It converts all characters to lowercase and removes possible separators such as ":" and "-".
func normalizeCertHash(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}

type adaptiveConnFactory struct {
	NewFunc    func(addr net.Addr) (net.PacketConn, error)
	Obfuscator obfs.Obfuscator // nil if no obfuscation
}

func (f *adaptiveConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	if f.Obfuscator == nil {
		return f.NewFunc(addr)
	} else {
		conn, err := f.NewFunc(addr)
		if err != nil {
			return nil, err
		}
		return obfs.WrapPacketConn(conn, f.Obfuscator), nil
	}
}

func connectLog(count int) {
	logger.Info("connected to server", zap.Int("count", count))
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

type tcpLogger struct{}

func (l *tcpLogger) Connect(addr net.Addr) {
	logger.Debug("TCP forwarding connect", zap.String("addr", addr.String()))
}

func (l *tcpLogger) Error(addr net.Addr, err error) {
	if err == nil {
		logger.Debug("TCP forwarding closed", zap.String("addr", addr.String()))
	} else {
		logger.Error("TCP forwarding error", zap.String("addr", addr.String()), zap.Error(err))
	}
}

type udpLogger struct{}

func (l *udpLogger) Connect(addr net.Addr) {
	logger.Debug("UDP forwarding connect", zap.String("addr", addr.String()))
}

func (l *udpLogger) Error(addr net.Addr, err error) {
	if err == nil {
		logger.Debug("UDP forwarding closed", zap.String("addr", addr.String()))
	} else {
		logger.Error("UDP forwarding error", zap.String("addr", addr.String()), zap.Error(err))
	}
}

type tcpTProxyLogger struct{}

func (l *tcpTProxyLogger) Connect(addr, reqAddr net.Addr) {
	logger.Debug("TCP transparent proxy connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *tcpTProxyLogger) Error(addr, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("TCP transparent proxy closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Error("TCP transparent proxy error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}

type udpTProxyLogger struct{}

func (l *udpTProxyLogger) Connect(addr, reqAddr net.Addr) {
	logger.Debug("UDP transparent proxy connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *udpTProxyLogger) Error(addr, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("UDP transparent proxy closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Error("UDP transparent proxy error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}

type tcpRedirectLogger struct{}

func (l *tcpRedirectLogger) Connect(addr, reqAddr net.Addr) {
	logger.Debug("TCP redirect connect", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
}

func (l *tcpRedirectLogger) Error(addr, reqAddr net.Addr, err error) {
	if err == nil {
		logger.Debug("TCP redirect closed", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()))
	} else {
		logger.Error("TCP redirect error", zap.String("addr", addr.String()), zap.String("reqAddr", reqAddr.String()), zap.Error(err))
	}
}
