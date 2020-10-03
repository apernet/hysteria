package main

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/sirupsen/logrus"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"io/ioutil"
	"net"
	"os/user"
)

func relayClient(args []string) {
	var config relayClientConfig
	err := loadConfig(&config, args)
	if err != nil {
		logrus.WithField("error", err).Fatal("Unable to load configuration")
	}
	if err := config.Check(); err != nil {
		logrus.WithField("error", err).Fatal("Configuration error")
	}
	if len(config.Name) == 0 {
		usr, err := user.Current()
		if err == nil {
			config.Name = usr.Name
		}
	}
	logrus.WithField("config", config.String()).Info("Configuration loaded")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.Insecure,
		NextProtos:         []string{relayTLSProtocol},
		MinVersion:         tls.VersionTLS13,
	}
	// Load CA
	if len(config.CustomCAFile) > 0 {
		bs, err := ioutil.ReadFile(config.CustomCAFile)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.CustomCAFile,
			}).Fatal("Unable to load CA file")
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(bs) {
			logrus.WithFields(logrus.Fields{
				"file": config.CustomCAFile,
			}).Fatal("Unable to parse CA file")
		}
		tlsConfig.RootCAs = cp
	}

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

	var obfuscator core.Obfuscator
	if len(config.Obfs) > 0 {
		obfuscator = obfs.XORObfuscator(config.Obfs)
	}

	client, err := core.NewClient(config.ServerAddr, config.Name, "", tlsConfig, quicConfig,
		uint64(config.UpMbps)*mbpsToBps, uint64(config.DownMbps)*mbpsToBps,
		func(refBPS uint64) congestion.ExternalSendAlgorithm {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		}, obfuscator)
	if err != nil {
		logrus.WithField("error", err).Fatal("Client initialization failed")
	}
	defer client.Close()
	logrus.WithField("addr", config.ServerAddr).Info("Connected")

	listener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		logrus.WithField("error", err).Fatal("TCP listen failed")
	}
	defer listener.Close()
	logrus.WithField("addr", listener.Addr().String()).Info("TCP server listening")

	for {
		conn, err := listener.Accept()
		if err != nil {
			logrus.WithField("error", err).Fatal("TCP accept failed")
		}
		go relayClientHandleConn(conn, client)
	}
}

func relayClientHandleConn(conn net.Conn, client *core.Client) {
	logrus.WithField("src", conn.RemoteAddr().String()).Debug("New connection")
	var closeErr error
	defer func() {
		_ = conn.Close()
		logrus.WithFields(logrus.Fields{
			"error": closeErr,
			"src":   conn.RemoteAddr().String(),
		}).Debug("Connection closed")
	}()
	rwc, err := client.Dial(false, "")
	if err != nil {
		closeErr = err
		return
	}
	defer rwc.Close()
	closeErr = utils.PipePair(conn, rwc, nil, nil)
}
