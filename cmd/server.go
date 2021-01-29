package main

import (
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/sirupsen/logrus"
	"github.com/tobyxdd/hysteria/pkg/acl"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"net"
	"strings"
)

func server(config *serverConfig) {
	logrus.WithField("config", config.String()).Info("Server configuration loaded")
	// Load cert
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
			"cert":  config.CertFile,
			"key":   config.KeyFile,
		}).Fatal("Failed to load the certificate")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{tlsProtocolName},
		MinVersion:   tls.VersionTLS13,
	}
	// QUIC config
	quicConfig := &quic.Config{
		MaxReceiveStreamFlowControlWindow:     config.ReceiveWindowConn,
		MaxReceiveConnectionFlowControlWindow: config.ReceiveWindowClient,
		MaxIncomingStreams:                    int64(config.MaxConnClient),
		KeepAlive:                             true,
	}
	if quicConfig.MaxReceiveStreamFlowControlWindow == 0 {
		quicConfig.MaxReceiveStreamFlowControlWindow = DefaultMaxReceiveStreamFlowControlWindow
	}
	if quicConfig.MaxReceiveConnectionFlowControlWindow == 0 {
		quicConfig.MaxReceiveConnectionFlowControlWindow = DefaultMaxReceiveConnectionFlowControlWindow
	}
	if quicConfig.MaxIncomingStreams == 0 {
		quicConfig.MaxIncomingStreams = DefaultMaxIncomingStreams
	}
	// Auth
	var authFunc func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string)
	if len(config.Auth.Mode) == 0 || strings.EqualFold(config.Auth.Mode, "none") {
		logrus.Warn("No authentication configured")
		authFunc = func(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string) {
			return true, "Welcome"
		}
	} else {
		// TODO
		logrus.WithField("mode", config.Auth.Mode).Fatal("Unsupported authentication mode")
	}
	// Obfuscator
	var obfuscator core.Obfuscator
	if len(config.Obfs) > 0 {
		obfuscator = obfs.XORObfuscator(config.Obfs)
	}
	// ACL
	var aclEngine *acl.Engine
	if len(config.ACL) > 0 {
		aclEngine, err = acl.LoadFromFile(config.ACL)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.ACL,
			}).Fatal("Failed to parse ACL")
		}
		aclEngine.DefaultAction = acl.ActionDirect
	}
	// Server
	server, err := core.NewServer(config.Listen, tlsConfig, quicConfig,
		uint64(config.UpMbps)*mbpsToBps, uint64(config.DownMbps)*mbpsToBps,
		func(refBPS uint64) congestion.CongestionControl {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		}, aclEngine, obfuscator, authFunc, func(addr net.Addr, auth []byte, udp bool, reqAddr string) {
			if !udp {
				logrus.WithFields(logrus.Fields{
					"src": addr.String(),
					"dst": reqAddr,
				}).Debug("New TCP request")
			} else {
				// TODO
			}
		})
	if err != nil {
		logrus.WithField("error", err).Fatal("Failed to initialize server")
	}
	defer server.Close()
	logrus.WithField("addr", config.Listen).Info("Server up and running")

	err = server.Serve()
	logrus.WithField("error", err).Fatal("Server shutdown")
}
