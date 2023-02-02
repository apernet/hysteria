package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	hyHTTP "github.com/apernet/hysteria/app/http"
	"github.com/apernet/hysteria/app/redirect"
	"github.com/apernet/hysteria/app/relay"
	"github.com/apernet/hysteria/app/socks5"
	"github.com/apernet/hysteria/app/tproxy"

	"github.com/apernet/hysteria/core/pktconns"

	"github.com/apernet/hysteria/core/pmtud"
	"github.com/oschwald/geoip2-golang"
	"github.com/yosuke-furukawa/json5/encoding/json5"

	"github.com/apernet/hysteria/core/acl"
	"github.com/apernet/hysteria/core/cs"
	"github.com/apernet/hysteria/core/transport"
	"github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
)

var clientPacketConnFuncFactoryMap = map[string]pktconns.ClientPacketConnFuncFactory{
	"":             pktconns.NewClientUDPConnFunc,
	"udp":          pktconns.NewClientUDPConnFunc,
	"wechat":       pktconns.NewClientWeChatConnFunc,
	"wechat-video": pktconns.NewClientWeChatConnFunc,
	"faketcp":      pktconns.NewClientFakeTCPConnFunc,
}

func client(config *clientConfig) {
	logrus.WithField("config", config.String()).Info("Client configuration loaded")
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
	// TLS
	tlsConfig := &tls.Config{
		NextProtos:         []string{config.ALPN},
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.Insecure,
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
		InitialStreamReceiveWindow:     config.ReceiveWindowConn,
		MaxStreamReceiveWindow:         config.ReceiveWindowConn,
		InitialConnectionReceiveWindow: config.ReceiveWindow,
		MaxConnectionReceiveWindow:     config.ReceiveWindow,
		HandshakeIdleTimeout:           time.Duration(config.HandshakeTimeout) * time.Second,
		MaxIdleTimeout:                 time.Duration(config.IdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(config.IdleTimeout) * time.Second * 2 / 5,
		DisablePathMTUDiscovery:        config.DisableMTUDiscovery,
		EnableDatagrams:                true,
	}
	if !quicConfig.DisablePathMTUDiscovery && pmtud.DisablePathMTUDiscovery {
		logrus.Info("Path MTU Discovery is not yet supported on this platform")
	}
	// Auth
	var auth []byte
	if len(config.Auth) > 0 {
		auth = config.Auth
	} else {
		auth = []byte(config.AuthString)
	}
	// Packet conn
	pktConnFuncFactory := clientPacketConnFuncFactoryMap[config.Protocol]
	if pktConnFuncFactory == nil {
		logrus.WithFields(logrus.Fields{
			"protocol": config.Protocol,
		}).Fatal("Unsupported protocol")
	}
	pktConnFunc := pktConnFuncFactory(config.Obfs, time.Duration(config.HopInterval)*time.Second)
	// Resolve preference
	if len(config.ResolvePreference) > 0 {
		pref, err := transport.ResolvePreferenceFromString(config.ResolvePreference)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to parse the resolve preference")
		}
		transport.DefaultClientTransport.ResolvePreference = pref
	}
	// ACL
	var aclEngine *acl.Engine
	if len(config.ACL) > 0 {
		var err error
		aclEngine, err = acl.LoadFromFile(config.ACL, transport.DefaultClientTransport.ResolveIPAddr,
			func() (*geoip2.Reader, error) {
				return loadMMDBReader(config.MMDB)
			})
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"file":  config.ACL,
			}).Fatal("Failed to parse ACL")
		}
	}
	// Client
	var client *cs.Client
	try := 0
	up, down, _ := config.Speed()
	for {
		try += 1
		c, err := cs.NewClient(config.Server, auth, tlsConfig, quicConfig, pktConnFunc, up, down, config.FastOpen,
			func(err error) {
				if config.QuitOnDisconnect {
					logrus.WithFields(logrus.Fields{
						"addr":  config.Server,
						"error": err,
					}).Fatal("Connection to server lost, exiting...")
				} else {
					logrus.WithFields(logrus.Fields{
						"addr":  config.Server,
						"error": err,
					}).Error("Connection to server lost, reconnecting...")
				}
			})
		if err != nil {
			logrus.WithField("error", err).Error("Failed to initialize client")
			if try <= config.Retry || config.Retry < 0 {
				retryInterval := 1
				if config.RetryInterval != nil {
					retryInterval = *config.RetryInterval
				}
				logrus.WithFields(logrus.Fields{
					"retry":    try,
					"interval": retryInterval,
				}).Info("Retrying...")
				time.Sleep(time.Duration(retryInterval) * time.Second)
			} else {
				logrus.Fatal("Out of retries, exiting...")
			}
		} else {
			client = c
			break
		}
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
			socks5server, err := socks5.NewServer(client, transport.DefaultClientTransport, config.SOCKS5.Listen,
				authFunc, time.Duration(config.SOCKS5.Timeout)*time.Second, aclEngine, config.SOCKS5.DisableUDP,
				func(addr net.Addr, reqAddr string, action acl.Action, arg string) {
					logrus.WithFields(logrus.Fields{
						"action": actionToString(action, arg),
						"src":    defaultIPMasker.Mask(addr.String()),
						"dst":    defaultIPMasker.Mask(reqAddr),
					}).Debug("SOCKS5 TCP request")
				},
				func(addr net.Addr, reqAddr string, err error) {
					if err != io.EOF {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   defaultIPMasker.Mask(addr.String()),
							"dst":   defaultIPMasker.Mask(reqAddr),
						}).Info("SOCKS5 TCP error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": defaultIPMasker.Mask(addr.String()),
							"dst": defaultIPMasker.Mask(reqAddr),
						}).Debug("SOCKS5 TCP EOF")
					}
				},
				func(addr net.Addr) {
					logrus.WithFields(logrus.Fields{
						"src": defaultIPMasker.Mask(addr.String()),
					}).Debug("SOCKS5 UDP associate")
				},
				func(addr net.Addr, err error) {
					if err != io.EOF {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   defaultIPMasker.Mask(addr.String()),
						}).Info("SOCKS5 UDP error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": defaultIPMasker.Mask(addr.String()),
						}).Debug("SOCKS5 UDP EOF")
					}
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
			proxy, err := hyHTTP.NewProxyHTTPServer(client, transport.DefaultClientTransport,
				time.Duration(config.HTTP.Timeout)*time.Second, aclEngine, authFunc,
				func(reqAddr string, action acl.Action, arg string) {
					logrus.WithFields(logrus.Fields{
						"action": actionToString(action, arg),
						"dst":    defaultIPMasker.Mask(reqAddr),
					}).Debug("HTTP request")
				},
				func(reqAddr string, err error) {
					logrus.WithFields(logrus.Fields{
						"error": err,
						"dst":   defaultIPMasker.Mask(reqAddr),
					}).Info("HTTP error")
				})
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

	if len(config.TUN.Name) != 0 {
		go startTUN(config, client, errChan)
	}

	if len(config.TCPRelay.Listen) > 0 {
		config.TCPRelays = append(config.TCPRelays, Relay{
			Listen:  config.TCPRelay.Listen,
			Remote:  config.TCPRelay.Remote,
			Timeout: config.TCPRelay.Timeout,
		})
	}

	if len(config.TCPRelays) > 0 {
		for _, tcpr := range config.TCPRelays {
			go func(tcpr Relay) {
				rl, err := relay.NewTCPRelay(client, tcpr.Listen, tcpr.Remote,
					time.Duration(tcpr.Timeout)*time.Second,
					func(addr net.Addr) {
						logrus.WithFields(logrus.Fields{
							"src": defaultIPMasker.Mask(addr.String()),
						}).Debug("TCP relay request")
					},
					func(addr net.Addr, err error) {
						if err != io.EOF {
							logrus.WithFields(logrus.Fields{
								"error": err,
								"src":   defaultIPMasker.Mask(addr.String()),
							}).Info("TCP relay error")
						} else {
							logrus.WithFields(logrus.Fields{
								"src": defaultIPMasker.Mask(addr.String()),
							}).Debug("TCP relay EOF")
						}
					})
				if err != nil {
					logrus.WithField("error", err).Fatal("Failed to initialize TCP relay")
				}
				logrus.WithField("addr", tcpr.Listen).Info("TCP relay up and running")
				errChan <- rl.ListenAndServe()
			}(tcpr)
		}
	}

	if len(config.UDPRelay.Listen) > 0 {
		config.UDPRelays = append(config.UDPRelays, Relay{
			Listen:  config.UDPRelay.Listen,
			Remote:  config.UDPRelay.Remote,
			Timeout: config.UDPRelay.Timeout,
		})
	}

	if len(config.UDPRelays) > 0 {
		for _, udpr := range config.UDPRelays {
			go func(udpr Relay) {
				rl, err := relay.NewUDPRelay(client, udpr.Listen, udpr.Remote,
					time.Duration(udpr.Timeout)*time.Second,
					func(addr net.Addr) {
						logrus.WithFields(logrus.Fields{
							"src": defaultIPMasker.Mask(addr.String()),
						}).Debug("UDP relay request")
					},
					func(addr net.Addr, err error) {
						if err != relay.ErrTimeout {
							logrus.WithFields(logrus.Fields{
								"error": err,
								"src":   defaultIPMasker.Mask(addr.String()),
							}).Info("UDP relay error")
						} else {
							logrus.WithFields(logrus.Fields{
								"src": defaultIPMasker.Mask(addr.String()),
							}).Debug("UDP relay session closed")
						}
					})
				if err != nil {
					logrus.WithField("error", err).Fatal("Failed to initialize UDP relay")
				}
				logrus.WithField("addr", udpr.Listen).Info("UDP relay up and running")
				errChan <- rl.ListenAndServe()
			}(udpr)
		}
	}

	if len(config.TCPTProxy.Listen) > 0 {
		go func() {
			rl, err := tproxy.NewTCPTProxy(client, config.TCPTProxy.Listen,
				time.Duration(config.TCPTProxy.Timeout)*time.Second,
				func(addr, reqAddr net.Addr) {
					logrus.WithFields(logrus.Fields{
						"src": defaultIPMasker.Mask(addr.String()),
						"dst": defaultIPMasker.Mask(reqAddr.String()),
					}).Debug("TCP TProxy request")
				},
				func(addr, reqAddr net.Addr, err error) {
					if err != io.EOF {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   defaultIPMasker.Mask(addr.String()),
							"dst":   defaultIPMasker.Mask(reqAddr.String()),
						}).Info("TCP TProxy error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": defaultIPMasker.Mask(addr.String()),
							"dst": defaultIPMasker.Mask(reqAddr.String()),
						}).Debug("TCP TProxy EOF")
					}
				})
			if err != nil {
				logrus.WithField("error", err).Fatal("Failed to initialize TCP TProxy")
			}
			logrus.WithField("addr", config.TCPTProxy.Listen).Info("TCP TProxy up and running")
			errChan <- rl.ListenAndServe()
		}()
	}

	if len(config.UDPTProxy.Listen) > 0 {
		go func() {
			rl, err := tproxy.NewUDPTProxy(client, config.UDPTProxy.Listen,
				time.Duration(config.UDPTProxy.Timeout)*time.Second,
				func(addr, reqAddr net.Addr) {
					logrus.WithFields(logrus.Fields{
						"src": defaultIPMasker.Mask(addr.String()),
						"dst": defaultIPMasker.Mask(reqAddr.String()),
					}).Debug("UDP TProxy request")
				},
				func(addr, reqAddr net.Addr, err error) {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   defaultIPMasker.Mask(addr.String()),
							"dst":   defaultIPMasker.Mask(reqAddr.String()),
						}).Info("UDP TProxy error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": defaultIPMasker.Mask(addr.String()),
							"dst": defaultIPMasker.Mask(reqAddr.String()),
						}).Debug("UDP TProxy session closed")
					}
				})
			if err != nil {
				logrus.WithField("error", err).Fatal("Failed to initialize UDP TProxy")
			}
			logrus.WithField("addr", config.UDPTProxy.Listen).Info("UDP TProxy up and running")
			errChan <- rl.ListenAndServe()
		}()
	}

	if len(config.TCPRedirect.Listen) > 0 {
		go func() {
			rl, err := redirect.NewTCPRedirect(client, config.TCPRedirect.Listen,
				time.Duration(config.TCPRedirect.Timeout)*time.Second,
				func(addr, reqAddr net.Addr) {
					logrus.WithFields(logrus.Fields{
						"src": defaultIPMasker.Mask(addr.String()),
						"dst": defaultIPMasker.Mask(reqAddr.String()),
					}).Debug("TCP Redirect request")
				},
				func(addr, reqAddr net.Addr, err error) {
					if err != io.EOF {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   defaultIPMasker.Mask(addr.String()),
							"dst":   defaultIPMasker.Mask(reqAddr.String()),
						}).Info("TCP Redirect error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": defaultIPMasker.Mask(addr.String()),
							"dst": defaultIPMasker.Mask(reqAddr.String()),
						}).Debug("TCP Redirect EOF")
					}
				})
			if err != nil {
				logrus.WithField("error", err).Fatal("Failed to initialize TCP Redirect")
			}
			logrus.WithField("addr", config.TCPRedirect.Listen).Info("TCP Redirect up and running")
			errChan <- rl.ListenAndServe()
		}()
	}

	err := <-errChan
	logrus.WithField("error", err).Fatal("Client shutdown")
}

func parseClientConfig(cb []byte) (*clientConfig, error) {
	var c clientConfig
	err := json5.Unmarshal(cb, &c)
	if err != nil {
		return nil, err
	}
	return &c, c.Check()
}
