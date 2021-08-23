package main

import (
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/auth"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"github.com/yosuke-furukawa/json5/encoding/json5"
	"io"
	"net"
	"net/http"
	"time"
)

func server(config *serverConfig) {
	logrus.WithField("config", config.String()).Info("Server configuration loaded")
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
		tc.NextProtos = []string{tlsProtocolName}
		tc.MinVersion = tls.VersionTLS13
		tlsConfig = tc
	} else {
		// Local cert mode
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"cert":  config.CertFile,
				"key":   config.KeyFile,
			}).Fatal("Failed to load the certificate")
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{tlsProtocolName},
			MinVersion:   tls.VersionTLS13,
		}
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
	// Auth
	var authFunc func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string)
	var err error
	switch authMode := config.Auth.Mode; authMode {
	case "", "none":
		logrus.Warn("No authentication configured")
		authFunc = func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string) {
			return true, "Welcome"
		}
	case "password":
		logrus.Info("Password authentication enabled")
		var pwdConfig map[string]string
		err = json5.Unmarshal(config.Auth.Config, &pwdConfig)
		if err != nil || len(pwdConfig["password"]) == 0 {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Invalid password authentication config")
		}
		pwd := pwdConfig["password"]
		authFunc = func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string) {
			if string(auth) == pwd {
				return true, "Welcome"
			} else {
				return false, "Wrong password"
			}
		}
	case "external":
		logrus.Info("External authentication enabled")
		var extConfig map[string]string
		err = json5.Unmarshal(config.Auth.Config, &extConfig)
		if err != nil || len(extConfig["http"]) == 0 {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Invalid external authentication config")
		}
		provider := &auth.HTTPAuthProvider{
			Client: &http.Client{
				Timeout: 10 * time.Second,
			},
			URL: extConfig["http"],
		}
		authFunc = provider.Auth
	default:
		logrus.WithField("mode", config.Auth.Mode).Fatal("Unsupported authentication mode")
	}
	// Obfuscator
	var obfuscator core.Obfuscator
	if len(config.Obfs) > 0 {
		obfuscator = obfs.NewXPlusObfuscator([]byte(config.Obfs))
	}
	// ACL
	var aclEngine *acl.Engine
	if len(config.ACL) > 0 {
		aclEngine, err = acl.LoadFromFile(config.ACL, transport.DefaultTransport)
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
	server, err := core.NewServer(config.Listen, tlsConfig, quicConfig, transport.DefaultTransport,
		uint64(config.UpMbps)*mbpsToBps, uint64(config.DownMbps)*mbpsToBps,
		func(refBPS uint64) congestion.CongestionControl {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		}, config.DisableUDP, aclEngine, obfuscator, authFunc,
		tcpRequestFunc, tcpErrorFunc, udpRequestFunc, udpErrorFunc, promReg)
	if err != nil {
		logrus.WithField("error", err).Fatal("Failed to initialize server")
	}
	defer server.Close()
	logrus.WithField("addr", config.Listen).Info("Server up and running")

	err = server.Serve()
	logrus.WithField("error", err).Fatal("Server shutdown")
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
