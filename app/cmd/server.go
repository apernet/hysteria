package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/apernet/hysteria/app/auth"

	"github.com/apernet/hysteria/core/pktconns"

	"github.com/apernet/hysteria/core/acl"
	"github.com/apernet/hysteria/core/cs"
	"github.com/apernet/hysteria/core/pmtud"
	"github.com/apernet/hysteria/core/sockopt"
	"github.com/apernet/hysteria/core/transport"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
	"github.com/yosuke-furukawa/json5/encoding/json5"
)

var serverPacketConnFuncFactoryMap = map[string]pktconns.ServerPacketConnFuncFactory{
	"":             pktconns.NewServerUDPConnFunc,
	"udp":          pktconns.NewServerUDPConnFunc,
	"wechat":       pktconns.NewServerWeChatConnFunc,
	"wechat-video": pktconns.NewServerWeChatConnFunc,
	"faketcp":      pktconns.NewServerFakeTCPConnFunc,
}

func server(config *serverConfig) {
	logrus.WithField("config", config.String()).Info("Server configuration loaded")
	config.Fill() // Fill default values
	// Resolver
	if len(config.Resolver) > 0 {
		err := setResolver(config.Resolver)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to set resolver")
		}
	}
	// Load TLS config
	var tlsConfig *tls.Config
	if len(config.ACME.Domains) > 0 {
		// ACME mode
		tc, err := acmeTLSConfig(config.ACME.Domains, config.ACME.Email,
			config.ACME.DisableHTTPChallenge, config.ACME.DisableTLSALPNChallenge,
			config.ACME.AltHTTPPort, config.ACME.AltTLSALPNPort)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to get a certificate with ACME")
		}
		tc.NextProtos = []string{config.ALPN}
		tc.MinVersion = tls.VersionTLS13
		tlsConfig = tc
	} else {
		// Local cert mode
		kpl, err := newKeypairLoader(config.CertFile, config.KeyFile)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"cert":  config.CertFile,
				"key":   config.KeyFile,
			}).Fatal("Failed to load the certificate")
		}
		tlsConfig = &tls.Config{
			GetCertificate: kpl.GetCertificateFunc(),
			NextProtos:     []string{config.ALPN},
			MinVersion:     tls.VersionTLS13,
		}
	}
	// QUIC config
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     config.ReceiveWindowConn,
		MaxStreamReceiveWindow:         config.ReceiveWindowConn,
		InitialConnectionReceiveWindow: config.ReceiveWindowClient,
		MaxConnectionReceiveWindow:     config.ReceiveWindowClient,
		MaxIncomingStreams:             int64(config.MaxConnClient),
		MaxIdleTimeout:                 ServerMaxIdleTimeoutSec * time.Second,
		KeepAlivePeriod:                0, // Keep alive should solely be client's responsibility
		DisablePathMTUDiscovery:        config.DisableMTUDiscovery,
		EnableDatagrams:                true,
	}
	if !quicConfig.DisablePathMTUDiscovery && pmtud.DisablePathMTUDiscovery {
		logrus.Info("Path MTU Discovery is not yet supported on this platform")
	}
	// Auth
	var authFunc cs.ConnectFunc
	var err error
	switch authMode := config.Auth.Mode; authMode {
	case "", "none":
		if len(config.Obfs) == 0 {
			logrus.Warn("Neither authentication nor obfuscation is turned on. " +
				"Your server could be used by anyone! Are you sure this is what you want?")
		}
		authFunc = func(addr net.Addr, auth []byte, sSend, sRecv uint64) (bool, string) {
			return true, "Welcome"
		}
	case "password", "passwords":
		authFunc, err = auth.PasswordAuthFunc(config.Auth.Config)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to enable password authentication")
		} else {
			logrus.Info("Password authentication enabled")
		}
	case "external":
		authFunc, err = auth.ExternalAuthFunc(config.Auth.Config)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to enable external authentication")
		} else {
			logrus.Info("External authentication enabled")
		}
	default:
		logrus.WithField("mode", config.Auth.Mode).Fatal("Unsupported authentication mode")
	}
	connectFunc := func(addr net.Addr, auth []byte, sSend, sRecv uint64) (bool, string) {
		ok, msg := authFunc(addr, auth, sSend, sRecv)
		if !ok {
			logrus.WithFields(logrus.Fields{
				"src": defaultIPMasker.Mask(addr.String()),
				"msg": msg,
			}).Info("Authentication failed, client rejected")
		} else {
			logrus.WithFields(logrus.Fields{
				"src": defaultIPMasker.Mask(addr.String()),
			}).Info("Client connected")
		}
		return ok, msg
	}
	// Resolve preference
	if len(config.ResolvePreference) > 0 {
		pref, err := transport.ResolvePreferenceFromString(config.ResolvePreference)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to parse the resolve preference")
		}
		transport.DefaultServerTransport.ResolvePreference = pref
	}
	// SOCKS5 outbound
	if config.SOCKS5Outbound.Server != "" {
		transport.DefaultServerTransport.SOCKS5Client = transport.NewSOCKS5Client(config.SOCKS5Outbound.Server,
			config.SOCKS5Outbound.User, config.SOCKS5Outbound.Password)
	}
	// Bind outbound
	if config.BindOutbound.Device != "" {
		iface, err := net.InterfaceByName(config.BindOutbound.Device)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to find the interface")
		}
		transport.DefaultServerTransport.LocalUDPIntf = iface
		sockopt.BindDialer(transport.DefaultServerTransport.Dialer, iface)
	}
	if config.BindOutbound.Address != "" {
		ip := net.ParseIP(config.BindOutbound.Address)
		if ip == nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to parse the address")
		}
		transport.DefaultServerTransport.Dialer.LocalAddr = &net.TCPAddr{IP: ip}
		transport.DefaultServerTransport.LocalUDPAddr = &net.UDPAddr{IP: ip}
	}
	// ACL
	var aclEngine *acl.Engine
	if len(config.ACL) > 0 {
		aclEngine, err = acl.LoadFromFile(config.ACL, func(addr string) (*net.IPAddr, error) {
			ipAddr, _, err := transport.DefaultServerTransport.ResolveIPAddr(addr)
			return ipAddr, err
		},
			func() (*geoip2.Reader, error) {
				return loadMMDBReader(config.MMDB)
			})
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.ACL,
			}).Fatal("Failed to parse ACL")
		}
		aclEngine.DefaultAction = acl.ActionDirect
	}
	// Prometheus
	var trafficCounter cs.TrafficCounter
	if len(config.PrometheusListen) > 0 {
		promReg := prometheus.NewRegistry()
		trafficCounter = NewPrometheusTrafficCounter(promReg)
		go func() {
			http.Handle("/metrics", promhttp.HandlerFor(promReg, promhttp.HandlerOpts{}))
			err := http.ListenAndServe(config.PrometheusListen, nil)
			logrus.WithField("error", err).Fatal("Prometheus HTTP server error")
		}()
	}
	// Packet conn
	pktConnFuncFactory := serverPacketConnFuncFactoryMap[config.Protocol]
	if pktConnFuncFactory == nil {
		logrus.WithField("protocol", config.Protocol).Fatal("Unsupported protocol")
	}
	pktConnFunc := pktConnFuncFactory(config.Obfs)
	pktConn, err := pktConnFunc(config.Listen)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
			"addr":  config.Listen,
		}).Fatal("Failed to listen on the UDP address")
	}
	// Server
	up, down, _ := config.Speed()
	server, err := cs.NewServer(tlsConfig, quicConfig, pktConn,
		transport.DefaultServerTransport, up, down, config.DisableUDP, aclEngine,
		connectFunc, disconnectFunc, tcpRequestFunc, tcpErrorFunc, udpRequestFunc, udpErrorFunc, trafficCounter)
	if err != nil {
		logrus.WithField("error", err).Fatal("Failed to initialize server")
	}
	defer server.Close()
	logrus.WithField("addr", config.Listen).Info("Server up and running")

	err = server.Serve()
	logrus.WithField("error", err).Fatal("Server shutdown")
}

func disconnectFunc(addr net.Addr, auth []byte, err error) {
	logrus.WithFields(logrus.Fields{
		"src":   defaultIPMasker.Mask(addr.String()),
		"error": err,
	}).Info("Client disconnected")
}

func tcpRequestFunc(addr net.Addr, auth []byte, reqAddr string, action acl.Action, arg string) {
	logrus.WithFields(logrus.Fields{
		"src":    defaultIPMasker.Mask(addr.String()),
		"dst":    defaultIPMasker.Mask(reqAddr),
		"action": actionToString(action, arg),
	}).Debug("TCP request")
}

func tcpErrorFunc(addr net.Addr, auth []byte, reqAddr string, err error) {
	if err != io.EOF {
		logrus.WithFields(logrus.Fields{
			"src":   defaultIPMasker.Mask(addr.String()),
			"dst":   defaultIPMasker.Mask(reqAddr),
			"error": err,
		}).Info("TCP error")
	} else {
		logrus.WithFields(logrus.Fields{
			"src": defaultIPMasker.Mask(addr.String()),
			"dst": defaultIPMasker.Mask(reqAddr),
		}).Debug("TCP EOF")
	}
}

func udpRequestFunc(addr net.Addr, auth []byte, sessionID uint32) {
	logrus.WithFields(logrus.Fields{
		"src":     defaultIPMasker.Mask(addr.String()),
		"session": sessionID,
	}).Debug("UDP request")
}

func udpErrorFunc(addr net.Addr, auth []byte, sessionID uint32, err error) {
	if err != io.EOF {
		logrus.WithFields(logrus.Fields{
			"src":     defaultIPMasker.Mask(addr.String()),
			"session": sessionID,
			"error":   err,
		}).Info("UDP error")
	} else {
		logrus.WithFields(logrus.Fields{
			"src":     defaultIPMasker.Mask(addr.String()),
			"session": sessionID,
		}).Debug("UDP EOF")
	}
}

func actionToString(action acl.Action, arg string) string {
	switch action {
	case acl.ActionDirect:
		return "Direct"
	case acl.ActionProxy:
		return "Proxy"
	case acl.ActionBlock:
		return "Block"
	case acl.ActionHijack:
		return "Hijack to " + arg
	default:
		return "Unknown"
	}
}

func parseServerConfig(cb []byte) (*serverConfig, error) {
	var c serverConfig
	err := json5.Unmarshal(cb, &c)
	if err != nil {
		return nil, err
	}
	return &c, c.Check()
}
