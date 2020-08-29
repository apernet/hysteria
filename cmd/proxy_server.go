package main

import (
	"bufio"
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/sirupsen/logrus"
	"github.com/tobyxdd/hysteria/pkg/acl"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"io"
	"net"
	"os"
	"strings"
)

func proxyServer(args []string) {
	var config proxyServerConfig
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
		NextProtos:   []string{proxyTLSProtocol},
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

	if len(config.AuthFile) == 0 {
		logrus.Warn("No authentication configured, this server can be used by anyone")
	}

	var obfuscator core.Obfuscator
	if len(config.Obfs) > 0 {
		obfuscator = obfs.XORObfuscator(config.Obfs)
	}

	var aclEngine *acl.Engine
	if len(config.ACLFile) > 0 {
		aclEngine, err = acl.LoadFromFile(config.ACLFile)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.ACLFile,
			}).Fatal("Unable to parse ACL")
		}
		aclEngine.DefaultAction = acl.ActionDirect
	}

	server, err := core.NewServer(config.ListenAddr, tlsConfig, quicConfig,
		uint64(config.UpMbps)*mbpsToBps, uint64(config.DownMbps)*mbpsToBps,
		func(refBPS uint64) congestion.ExternalSendAlgorithm {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		},
		obfuscator,
		func(addr net.Addr, username string, password string, sSend uint64, sRecv uint64) (core.AuthResult, string) {
			if len(config.AuthFile) == 0 {
				logrus.WithFields(logrus.Fields{
					"addr":     addr.String(),
					"username": username,
					"up":       sSend / mbpsToBps,
					"down":     sRecv / mbpsToBps,
				}).Info("Client connected")
				return core.AuthSuccess, ""
			} else {
				// Need auth
				ok, err := checkAuth(config.AuthFile, username, password)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"error":    err.Error(),
						"addr":     addr.String(),
						"username": username,
					}).Error("Client authentication error")
					return core.AuthInternalError, "Server auth error"
				}
				if ok {
					logrus.WithFields(logrus.Fields{
						"addr":     addr.String(),
						"username": username,
						"up":       sSend / mbpsToBps,
						"down":     sRecv / mbpsToBps,
					}).Info("Client authenticated")
					return core.AuthSuccess, ""
				} else {
					logrus.WithFields(logrus.Fields{
						"addr":     addr.String(),
						"username": username,
						"up":       sSend / mbpsToBps,
						"down":     sRecv / mbpsToBps,
					}).Info("Client rejected due to invalid credential")
					return core.AuthInvalidCred, "Invalid credential"
				}
			}
		},
		func(addr net.Addr, username string, err error) {
			logrus.WithFields(logrus.Fields{
				"error":    err.Error(),
				"addr":     addr.String(),
				"username": username,
			}).Info("Client disconnected")
		},
		func(addr net.Addr, username string, id int, packet bool, reqAddr string) (core.ConnectResult, string, io.ReadWriteCloser) {
			if packet && config.DisableUDP {
				return core.ConnBlocked, "UDP disabled", nil
			}
			host, port, err := net.SplitHostPort(reqAddr)
			if err != nil {
				return core.ConnFailed, err.Error(), nil
			}
			ip := net.ParseIP(host)
			if ip != nil {
				// IP request, clear host for ACL engine
				host = ""
			}
			action, arg := acl.ActionDirect, ""
			if aclEngine != nil {
				action, arg = aclEngine.Lookup(host, ip)
			}
			switch action {
			case acl.ActionDirect, acl.ActionProxy: // Treat proxy as direct on server side
				if !packet {
					// TCP
					logrus.WithFields(logrus.Fields{
						"action":   "direct",
						"username": username,
						"src":      addr.String(),
						"dst":      reqAddr,
					}).Debug("New TCP request")
					conn, err := net.DialTimeout("tcp", reqAddr, dialTimeout)
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"dst":   reqAddr,
						}).Error("TCP error")
						return core.ConnFailed, err.Error(), nil
					}
					return core.ConnSuccess, "", conn
				} else {
					// UDP
					logrus.WithFields(logrus.Fields{
						"action":   "direct",
						"username": username,
						"src":      addr.String(),
						"dst":      reqAddr,
					}).Debug("New UDP request")
					conn, err := net.Dial("udp", reqAddr)
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"dst":   reqAddr,
						}).Error("UDP error")
						return core.ConnFailed, err.Error(), nil
					}
					return core.ConnSuccess, "", conn
				}
			case acl.ActionBlock:
				if !packet {
					// TCP
					logrus.WithFields(logrus.Fields{
						"action":   "block",
						"username": username,
						"src":      addr.String(),
						"dst":      reqAddr,
					}).Debug("New TCP request")
					return core.ConnBlocked, "blocked by ACL", nil
				} else {
					// UDP
					logrus.WithFields(logrus.Fields{
						"action":   "block",
						"username": username,
						"src":      addr.String(),
						"dst":      reqAddr,
					}).Debug("New UDP request")
					return core.ConnBlocked, "blocked by ACL", nil
				}
			case acl.ActionHijack:
				hijackAddr := net.JoinHostPort(arg, port)
				if !packet {
					// TCP
					logrus.WithFields(logrus.Fields{
						"action":   "hijack",
						"username": username,
						"src":      addr.String(),
						"dst":      reqAddr,
						"rdst":     arg,
					}).Debug("New TCP request")
					conn, err := net.DialTimeout("tcp", hijackAddr, dialTimeout)
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"dst":   hijackAddr,
						}).Error("TCP error")
						return core.ConnFailed, err.Error(), nil
					}
					return core.ConnSuccess, "", conn
				} else {
					// UDP
					logrus.WithFields(logrus.Fields{
						"action":   "hijack",
						"username": username,
						"src":      addr.String(),
						"dst":      reqAddr,
						"rdst":     arg,
					}).Debug("New UDP request")
					conn, err := net.Dial("udp", hijackAddr)
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"dst":   hijackAddr,
						}).Error("UDP error")
						return core.ConnFailed, err.Error(), nil
					}
					return core.ConnSuccess, "", conn
				}
			default:
				return core.ConnFailed, "server ACL error", nil
			}
		},
		func(addr net.Addr, username string, id int, packet bool, reqAddr string, err error) {
			if !packet {
				logrus.WithFields(logrus.Fields{
					"error":    err,
					"username": username,
					"src":      addr.String(),
					"dst":      reqAddr,
				}).Debug("TCP request closed")
			} else {
				logrus.WithFields(logrus.Fields{
					"error":    err,
					"username": username,
					"src":      addr.String(),
					"dst":      reqAddr,
				}).Debug("UDP request closed")
			}
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

func checkAuth(authFile, username, password string) (bool, error) {
	f, err := os.Open(authFile)
	if err != nil {
		return false, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		pair := strings.Fields(scanner.Text())
		if len(pair) != 2 {
			// Invalid format
			continue
		}
		if username == pair[0] && password == pair[1] {
			return true, nil
		}
	}
	return false, nil
}
