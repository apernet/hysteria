package main

import (
	"crypto/tls"
	"errors"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/oschwald/geoip2-golang"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/tobyxdd/hysteria/cmd/auth"
	"github.com/tobyxdd/hysteria/pkg/acl"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/pmtud_fix"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"github.com/yosuke-furukawa/json5/encoding/json5"
	"io"
	"net"
	"net/http"
	"time"
)

func server(config *serverConfig) {
	logrus.WithField("config", config.String()).Info("Server configuration loaded")
	// Resolver
	if len(config.Resolver) > 0 {
		setResolver(config.Resolver)
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
			MinVersion:     tls.VersionTLS13,
		}
	}
	if config.ALPN != "" {
		tlsConfig.NextProtos = []string{config.ALPN}
	} else {
		tlsConfig.NextProtos = []string{DefaultALPN}
	}
	// QUIC config
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     config.ReceiveWindowConn,
		MaxStreamReceiveWindow:         config.ReceiveWindowConn,
		InitialConnectionReceiveWindow: config.ReceiveWindowClient,
		MaxConnectionReceiveWindow:     config.ReceiveWindowClient,
		MaxIncomingStreams:             int64(config.MaxConnClient),
		KeepAlive:                      true,
		DisablePathMTUDiscovery:        config.DisableMTUDiscovery,
		EnableDatagrams:                true,
	}
	if config.ReceiveWindowConn == 0 {
		quicConfig.InitialStreamReceiveWindow = DefaultStreamReceiveWindow
		quicConfig.MaxStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if config.ReceiveWindowClient == 0 {
		quicConfig.InitialConnectionReceiveWindow = DefaultConnectionReceiveWindow
		quicConfig.MaxConnectionReceiveWindow = DefaultConnectionReceiveWindow
	}
	if quicConfig.MaxIncomingStreams == 0 {
		quicConfig.MaxIncomingStreams = DefaultMaxIncomingStreams
	}
	if !quicConfig.DisablePathMTUDiscovery && pmtud_fix.DisablePathMTUDiscovery {
		logrus.Info("Path MTU Discovery is not yet supported on this platform")
	}
	// Auth
	var authFunc core.ConnectFunc
	var err error
	switch authMode := config.Auth.Mode; authMode {
	case "", "none":
		if len(config.Obfs) == 0 {
			logrus.Warn("No authentication or obfuscation enabled. " +
				"Your server could be accessed by anyone! Are you sure this is what you intended?")
		}
		authFunc = func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string) {
			return true, "Welcome"
		}
	case "password", "passwords":
		authFunc, err = passwordAuthFunc(config.Auth.Config)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to enable password authentication")
		} else {
			logrus.Info("Password authentication enabled")
		}
	case "external":
		authFunc, err = externalAuthFunc(config.Auth.Config)
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
	connectFunc := func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string) {
		ok, msg := authFunc(addr, auth, sSend, sRecv)
		if !ok {
			logrus.WithFields(logrus.Fields{
				"src": addr,
				"msg": msg,
			}).Info("Authentication failed, client rejected")
		} else {
			logrus.WithFields(logrus.Fields{
				"src": addr,
			}).Info("Client connected")
		}
		return ok, msg
	}
	// Obfuscator
	var obfuscator obfs.Obfuscator
	if len(config.Obfs) > 0 {
		obfuscator = obfs.NewXPlusObfuscator([]byte(config.Obfs))
	}
	// Resolve preference
	if len(config.ResolvePreference) > 0 {
		pref, excl, err := transport.ResolvePreferenceFromString(config.ResolvePreference)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to parse the resolve preference")
		}
		transport.DefaultServerTransport.PrefEnabled = true
		transport.DefaultServerTransport.PrefIPv6 = pref
		transport.DefaultServerTransport.PrefExclusive = excl
	}
	// SOCKS5 outbound
	if config.SOCKS5Outbound.Server != "" {
		ob, err := transport.NewSOCKS5Client(config.SOCKS5Outbound.Server,
			config.SOCKS5Outbound.User, config.SOCKS5Outbound.Password, 10*time.Second)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to initialize SOCKS5 outbound")
		}
		transport.DefaultServerTransport.SOCKS5Client = ob
	}
	// ACL
	var aclEngine *acl.Engine
	if len(config.ACL) > 0 {
		aclEngine, err = acl.LoadFromFile(config.ACL, func(addr string) (*net.IPAddr, error) {
			ipAddr, _, err := transport.DefaultServerTransport.ResolveIPAddr(addr)
			return ipAddr, err
		},
			func() (*geoip2.Reader, error) {
				if len(config.MMDB) > 0 {
					return loadMMDBReader(config.MMDB)
				} else {
					return loadMMDBReader(DefaultMMDBFilename)
				}
			})
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.ACL,
			}).Fatal("Failed to parse ACL")
		}
		aclEngine.DefaultAction = acl.ActionDirect
	}
	// Server
	var promReg *prometheus.Registry
	if len(config.PrometheusListen) > 0 {
		promReg = prometheus.NewRegistry()
		go func() {
			http.Handle("/metrics", promhttp.HandlerFor(promReg, promhttp.HandlerOpts{}))
			err := http.ListenAndServe(config.PrometheusListen, nil)
			logrus.WithField("error", err).Fatal("Prometheus HTTP server error")
		}()
	}
	up, down, _ := config.Speed()
	server, err := core.NewServer(config.Listen, config.Protocol, tlsConfig, quicConfig, transport.DefaultServerTransport,
		up, down,
		func(refBPS uint64) congestion.CongestionControl {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		}, config.DisableUDP, aclEngine, obfuscator, connectFunc, disconnectFunc,
		tcpRequestFunc, tcpErrorFunc, udpRequestFunc, udpErrorFunc, promReg)
	if err != nil {
		logrus.WithField("error", err).Fatal("Failed to initialize server")
	}
	defer server.Close()
	logrus.WithField("addr", config.Listen).Info("Server up and running")

	err = server.Serve()
	logrus.WithField("error", err).Fatal("Server shutdown")
}

func passwordAuthFunc(rawMsg json5.RawMessage) (core.ConnectFunc, error) {
	var pwds []string
	err := json5.Unmarshal(rawMsg, &pwds)
	if err != nil {
		// not a string list, legacy format?
		var pwdConfig map[string]string
		err = json5.Unmarshal(rawMsg, &pwdConfig)
		if err != nil || len(pwdConfig["password"]) == 0 {
			// still no, invalid config
			return nil, errors.New("invalid config")
		}
		// yes it is
		pwds = []string{pwdConfig["password"]}
	}
	return func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string) {
		for _, pwd := range pwds {
			if string(auth) == pwd {
				return true, "Welcome"
			}
		}
		return false, "Wrong password"
	}, nil
}

func externalAuthFunc(rawMsg json5.RawMessage) (core.ConnectFunc, error) {
	var extConfig map[string]string
	err := json5.Unmarshal(rawMsg, &extConfig)
	if err != nil {
		return nil, errors.New("invalid config")
	}
	if len(extConfig["http"]) != 0 {
		hp := &auth.HTTPAuthProvider{
			Client: &http.Client{
				Timeout: 10 * time.Second,
			},
			URL: extConfig["http"],
		}
		return hp.Auth, nil
	} else if len(extConfig["cmd"]) != 0 {
		cp := &auth.CmdAuthProvider{
			Cmd: extConfig["cmd"],
		}
		return cp.Auth, nil
	} else {
		return nil, errors.New("invalid config")
	}
}

func disconnectFunc(addr net.Addr, auth []byte, err error) {
	logrus.WithFields(logrus.Fields{
		"src":   addr,
		"error": err,
	}).Info("Client disconnected")
}

func tcpRequestFunc(addr net.Addr, auth []byte, reqAddr string, action acl.Action, arg string) {
	logrus.WithFields(logrus.Fields{
		"src":    addr.String(),
		"dst":    reqAddr,
		"action": actionToString(action, arg),
	}).Debug("TCP request")
}

func tcpErrorFunc(addr net.Addr, auth []byte, reqAddr string, err error) {
	if err != io.EOF {
		logrus.WithFields(logrus.Fields{
			"src":   addr.String(),
			"dst":   reqAddr,
			"error": err,
		}).Info("TCP error")
	} else {
		logrus.WithFields(logrus.Fields{
			"src": addr.String(),
			"dst": reqAddr,
		}).Debug("TCP EOF")
	}
}

func udpRequestFunc(addr net.Addr, auth []byte, sessionID uint32) {
	logrus.WithFields(logrus.Fields{
		"src":     addr.String(),
		"session": sessionID,
	}).Debug("UDP request")
}

func udpErrorFunc(addr net.Addr, auth []byte, sessionID uint32, err error) {
	if err != io.EOF {
		logrus.WithFields(logrus.Fields{
			"src":     addr.String(),
			"session": sessionID,
			"error":   err,
		}).Info("UDP error")
	} else {
		logrus.WithFields(logrus.Fields{
			"src":     addr.String(),
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
