package main

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/sirupsen/logrus"
	"github.com/tobyxdd/hysteria/pkg/acl"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	hyHTTP "github.com/tobyxdd/hysteria/pkg/http"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/socks5"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

func client(config *clientConfig) {
	logrus.WithField("config", config.String()).Info("Client configuration loaded")
	// TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.Insecure,
		NextProtos:         []string{tlsProtocolName},
		MinVersion:         tls.VersionTLS13,
	}
	// Load CA
	if len(config.CustomCA) > 0 {
		bs, err := ioutil.ReadFile(config.CustomCA)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.CustomCA,
			}).Fatal("Failed to load CA")
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(bs) {
			logrus.WithFields(logrus.Fields{
				"file": config.CustomCA,
			}).Fatal("Failed to parse CA")
		}
		tlsConfig.RootCAs = cp
	}
	// QUIC config
	quicConfig := &quic.Config{
		MaxReceiveStreamFlowControlWindow:     config.ReceiveWindowConn,
		MaxReceiveConnectionFlowControlWindow: config.ReceiveWindow,
		KeepAlive:                             true,
	}
	if quicConfig.MaxReceiveStreamFlowControlWindow == 0 {
		quicConfig.MaxReceiveStreamFlowControlWindow = DefaultMaxReceiveStreamFlowControlWindow
	}
	if quicConfig.MaxReceiveConnectionFlowControlWindow == 0 {
		quicConfig.MaxReceiveConnectionFlowControlWindow = DefaultMaxReceiveConnectionFlowControlWindow
	}
	// Auth
	var auth []byte
	if len(config.Auth) > 0 {
		auth = config.Auth
	} else {
		auth = []byte(config.AuthString)
	}
	// Obfuscator
	var obfuscator core.Obfuscator
	if len(config.Obfs) > 0 {
		obfuscator = obfs.XORObfuscator(config.Obfs)
	}
	// ACL
	var aclEngine *acl.Engine
	if len(config.ACL) > 0 {
		var err error
		aclEngine, err = acl.LoadFromFile(config.ACL)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.ACL,
			}).Fatal("Failed to parse ACL")
		}
	}
	// Client
	client, err := core.NewClient(config.Server, auth, tlsConfig, quicConfig,
		uint64(config.UpMbps)*mbpsToBps, uint64(config.DownMbps)*mbpsToBps,
		func(refBPS uint64) congestion.CongestionControl {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		}, obfuscator)
	if err != nil {
		logrus.WithField("error", err).Fatal("Failed to initialize client")
	}
	defer client.Close()
	logrus.WithField("addr", config.Server).Info("Connected")

	// Local
	errChan := make(chan error)
	if len(config.SOCKS5.Listen) > 0 {
		go func() {
			var authFunc func(user, password string) bool
			if config.SOCKS5.User != "" && config.SOCKS5.Password != "" {
				authFunc = func(user, password string) bool {
					return config.SOCKS5.User == user && config.SOCKS5.Password == password
				}
			}
			socks5server, err := socks5.NewServer(client, config.SOCKS5.Listen, authFunc, config.SOCKS5.Timeout, aclEngine,
				config.SOCKS5.DisableUDP,
				func(addr net.Addr, reqAddr string, action acl.Action, arg string) {
					logrus.WithFields(logrus.Fields{
						"action": actionToString(action, arg),
						"src":    addr.String(),
						"dst":    reqAddr,
					}).Debug("New SOCKS5 TCP request")
				},
				func(addr net.Addr, reqAddr string, err error) {
					logrus.WithFields(logrus.Fields{
						"error": err,
						"src":   addr.String(),
						"dst":   reqAddr,
					}).Debug("SOCKS5 TCP request closed")
				},
				func(addr net.Addr) {
					logrus.WithFields(logrus.Fields{
						"src": addr.String(),
					}).Debug("New SOCKS5 UDP associate request")
				},
				func(addr net.Addr, err error) {
					logrus.WithFields(logrus.Fields{
						"error": err,
						"src":   addr.String(),
					}).Debug("SOCKS5 UDP associate request closed")
				},
				func(addr net.Addr, reqAddr string, action acl.Action, arg string) {
					logrus.WithFields(logrus.Fields{
						"action": actionToString(action, arg),
						"src":    addr.String(),
						"dst":    reqAddr,
					}).Debug("New SOCKS5 UDP tunnel")
				},
				func(addr net.Addr, reqAddr string, err error) {
					logrus.WithFields(logrus.Fields{
						"error": err,
						"src":   addr.String(),
						"dst":   reqAddr,
					}).Debug("SOCKS5 UDP tunnel closed")
				})
			if err != nil {
				logrus.WithField("error", err).Fatal("Failed to initialize SOCKS5 server")
			}
			logrus.WithField("addr", config.SOCKS5.Listen).Info("SOCKS5 server up and running")
			errChan <- socks5server.ListenAndServe()
		}()
	}

	if len(config.HTTP.Listen) > 0 {
		go func() {
			var authFunc func(user, password string) bool
			if config.HTTP.User != "" && config.HTTP.Password != "" {
				authFunc = func(user, password string) bool {
					return config.HTTP.User == user && config.HTTP.Password == password
				}
			}
			proxy, err := hyHTTP.NewProxyHTTPServer(client, time.Duration(config.HTTP.Timeout)*time.Second, aclEngine,
				func(reqAddr string, action acl.Action, arg string) {
					logrus.WithFields(logrus.Fields{
						"action": actionToString(action, arg),
						"dst":    reqAddr,
					}).Debug("New HTTP request")
				},
				authFunc)
			if err != nil {
				logrus.WithField("error", err).Fatal("Failed to initialize HTTP server")
			}
			if config.HTTP.Cert != "" && config.HTTP.Key != "" {
				logrus.WithField("addr", config.HTTP.Listen).Info("HTTPS server up and running")
				errChan <- http.ListenAndServeTLS(config.HTTP.Listen, config.HTTP.Cert, config.HTTP.Key, proxy)
			} else {
				logrus.WithField("addr", config.HTTP.Listen).Info("HTTP server up and running")
				errChan <- http.ListenAndServe(config.HTTP.Listen, proxy)
			}
		}()
	}

	err = <-errChan
	logrus.WithField("error", err).Fatal("Client shutdown")
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
