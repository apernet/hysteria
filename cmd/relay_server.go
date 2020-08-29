package main

import (
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/sirupsen/logrus"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"io"
	"net"
)

func relayServer(args []string) {
	var config relayServerConfig
	err := loadConfig(&config, args)
	if err != nil {
		logrus.WithField("error", err).Fatal("Unable to load configuration")
	}
	if err := config.Check(); err != nil {
		logrus.WithField("error", err).Fatal("Configuration error")
	}
	logrus.WithField("config", config.String()).Info("Configuration loaded")
	// Load cert
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
			"cert":  config.CertFile,
			"key":   config.KeyFile,
		}).Fatal("Unable to load the certificate")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{relayTLSProtocol},
		MinVersion:   tls.VersionTLS13,
	}

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

	var obfuscator core.Obfuscator
	if len(config.Obfs) > 0 {
		obfuscator = obfs.XORObfuscator(config.Obfs)
	}

	server, err := core.NewServer(config.ListenAddr, tlsConfig, quicConfig,
		uint64(config.UpMbps)*mbpsToBps, uint64(config.DownMbps)*mbpsToBps,
		func(refBPS uint64) congestion.ExternalSendAlgorithm {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		},
		obfuscator,
		func(addr net.Addr, username string, password string, sSend uint64, sRecv uint64) (core.AuthResult, string) {
			// No authentication logic in relay, just log username and speed
			logrus.WithFields(logrus.Fields{
				"addr":     addr.String(),
				"username": username,
				"up":       sSend / mbpsToBps,
				"down":     sRecv / mbpsToBps,
			}).Info("Client connected")
			return core.AuthSuccess, ""
		},
		func(addr net.Addr, username string, err error) {
			logrus.WithFields(logrus.Fields{
				"error":    err.Error(),
				"addr":     addr.String(),
				"username": username,
			}).Info("Client disconnected")
		},
		func(addr net.Addr, username string, id int, packet bool, reqAddr string) (core.ConnectResult, string, io.ReadWriteCloser) {
			logrus.WithFields(logrus.Fields{
				"username": username,
				"src":      addr.String(),
				"id":       id,
			}).Debug("New stream")
			if packet {
				return core.ConnBlocked, "unsupported", nil
			}
			conn, err := net.DialTimeout("tcp", config.RemoteAddr, dialTimeout)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"error": err,
					"dst":   config.RemoteAddr,
				}).Error("TCP error")
				return core.ConnFailed, err.Error(), nil
			}
			return core.ConnSuccess, "", conn
		},
		func(addr net.Addr, username string, id int, packet bool, reqAddr string, err error) {
			logrus.WithFields(logrus.Fields{
				"error":    err,
				"username": username,
				"src":      addr.String(),
				"id":       id,
			}).Debug("Stream closed")
		},
	)
	if err != nil {
		logrus.WithField("error", err).Fatal("Server initialization failed")
	}
	defer server.Close()
	logrus.WithField("addr", config.ListenAddr).Info("Server up and running")

	err = server.Serve()
	logrus.WithField("error", err).Fatal("Server shutdown")
}
