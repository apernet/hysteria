package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/oschwald/geoip2-golang"
	"github.com/tobyxdd/hysteria/pkg/pmtud_fix"
	"github.com/yosuke-furukawa/json5/encoding/json5"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/sirupsen/logrus"
	"github.com/tobyxdd/hysteria/pkg/acl"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	hyHTTP "github.com/tobyxdd/hysteria/pkg/http"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/relay"
	"github.com/tobyxdd/hysteria/pkg/socks5"
	"github.com/tobyxdd/hysteria/pkg/tproxy"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"github.com/tobyxdd/hysteria/pkg/tun"
)

func client(config *clientConfig) {
	logrus.WithField("config", config.String()).Info("Client configuration loaded")
	// Resolver
	if len(config.Resolver) > 0 {
		setResolver(config.Resolver)
	}
	// TLS
	tlsConfig := &tls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.Insecure,
		MinVersion:         tls.VersionTLS13,
	}
	if config.ALPN != "" {
		tlsConfig.NextProtos = []string{config.ALPN}
	} else {
		tlsConfig.NextProtos = []string{DefaultALPN}
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
		KeepAlive:                      true,
		DisablePathMTUDiscovery:        config.DisableMTUDiscovery,
		EnableDatagrams:                true,
	}
	if config.ReceiveWindowConn == 0 {
		quicConfig.InitialStreamReceiveWindow = DefaultStreamReceiveWindow
		quicConfig.MaxStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if config.ReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = DefaultConnectionReceiveWindow
		quicConfig.MaxConnectionReceiveWindow = DefaultConnectionReceiveWindow
	}
	if !quicConfig.DisablePathMTUDiscovery && pmtud_fix.DisablePathMTUDiscovery {
		logrus.Info("Path MTU Discovery is not yet supported on this platform")
	}
	// Auth
	var auth []byte
	if len(config.Auth) > 0 {
		auth = config.Auth
	} else {
		auth = []byte(config.AuthString)
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
		transport.DefaultClientTransport.PrefEnabled = true
		transport.DefaultClientTransport.PrefIPv6 = pref
		transport.DefaultClientTransport.PrefExclusive = excl
	}
	// ACL
	var aclEngine *acl.Engine
	if len(config.ACL) > 0 {
		var err error
		aclEngine, err = acl.LoadFromFile(config.ACL, transport.DefaultClientTransport.ResolveIPAddr,
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
	}
	// Client
	var client *core.Client
	try := 0
	up, down, _ := config.Speed()
	for {
		try += 1
		c, err := core.NewClient(config.Server, config.Protocol, auth, tlsConfig, quicConfig,
			transport.DefaultClientTransport, up, down,
			func(refBPS uint64) congestion.CongestionControl {
				return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
			}, obfuscator)
		if err != nil {
			logrus.WithField("error", err).Error("Failed to initialize client")
			if try <= config.Retry || config.Retry < 0 {
				logrus.WithFields(logrus.Fields{
					"retry":    try,
					"interval": config.RetryInterval,
				}).Info("Retrying...")
				time.Sleep(time.Duration(config.RetryInterval) * time.Second)
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
						"src":    addr.String(),
						"dst":    reqAddr,
					}).Debug("SOCKS5 TCP request")
				},
				func(addr net.Addr, reqAddr string, err error) {
					if err != io.EOF {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   addr.String(),
							"dst":   reqAddr,
						}).Info("SOCKS5 TCP error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": addr.String(),
							"dst": reqAddr,
						}).Debug("SOCKS5 TCP EOF")
					}
				},
				func(addr net.Addr) {
					logrus.WithFields(logrus.Fields{
						"src": addr.String(),
					}).Debug("SOCKS5 UDP associate")
				},
				func(addr net.Addr, err error) {
					if err != io.EOF {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   addr.String(),
						}).Info("SOCKS5 UDP error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": addr.String(),
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
				time.Duration(config.HTTP.Timeout)*time.Second, aclEngine,
				func(reqAddr string, action acl.Action, arg string) {
					logrus.WithFields(logrus.Fields{
						"action": actionToString(action, arg),
						"dst":    reqAddr,
					}).Debug("HTTP request")
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

	if len(config.TUN.Name) != 0 {
		go func() {
			timeout := time.Duration(config.TUN.Timeout) * time.Second
			if timeout == 0 {
				timeout = 300 * time.Second
			}
			tunServer, err := tun.NewServer(client, time.Duration(config.TUN.Timeout)*time.Second,
				config.TUN.Name, config.TUN.Address, config.TUN.Gateway, config.TUN.Mask, config.TUN.DNS, config.TUN.Persist)
			if err != nil {
				logrus.WithField("error", err).Fatal("Failed to initialize TUN server")
			}
			tunServer.RequestFunc = func(addr net.Addr, reqAddr string) {
				logrus.WithFields(logrus.Fields{
					"src": addr.String(),
					"dst": reqAddr,
				}).Debugf("TUN %s request", strings.ToUpper(addr.Network()))
			}
			tunServer.ErrorFunc = func(addr net.Addr, reqAddr string, err error) {
				if err != nil {
					if err == io.EOF {
						logrus.WithFields(logrus.Fields{
							"src": addr.String(),
							"dst": reqAddr,
						}).Debugf("TUN %s EOF", strings.ToUpper(addr.Network()))
					} else if err == core.ErrClosed && strings.HasPrefix(addr.Network(), "udp") {
						logrus.WithFields(logrus.Fields{
							"src": addr.String(),
							"dst": reqAddr,
						}).Debugf("TUN %s closed for timeout", strings.ToUpper(addr.Network()))
					} else if nErr, ok := err.(net.Error); ok && nErr.Timeout() && strings.HasPrefix(addr.Network(), "tcp") {
						logrus.WithFields(logrus.Fields{
							"src": addr.String(),
							"dst": reqAddr,
						}).Debugf("TUN %s closed for timeout", strings.ToUpper(addr.Network()))
					} else {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   addr.String(),
							"dst":   reqAddr,
						}).Infof("TUN %s error", strings.ToUpper(addr.Network()))
					}
				}
			}
			errChan <- tunServer.ListenAndServe()
		}()
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
							"src": addr.String(),
						}).Debug("TCP relay request")
					},
					func(addr net.Addr, err error) {
						if err != io.EOF {
							logrus.WithFields(logrus.Fields{
								"error": err,
								"src":   addr.String(),
							}).Info("TCP relay error")
						} else {
							logrus.WithFields(logrus.Fields{
								"src": addr.String(),
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
							"src": addr.String(),
						}).Debug("UDP relay request")
					},
					func(addr net.Addr, err error) {
						if err != relay.ErrTimeout {
							logrus.WithFields(logrus.Fields{
								"error": err,
								"src":   addr.String(),
							}).Info("UDP relay error")
						} else {
							logrus.WithFields(logrus.Fields{
								"src": addr.String(),
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
						"src": addr.String(),
						"dst": reqAddr.String(),
					}).Debug("TCP TProxy request")
				},
				func(addr, reqAddr net.Addr, err error) {
					if err != io.EOF {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   addr.String(),
							"dst":   reqAddr.String(),
						}).Info("TCP TProxy error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": addr.String(),
							"dst": reqAddr.String(),
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
						"src": addr.String(),
						"dst": reqAddr.String(),
					}).Debug("UDP TProxy request")
				},
				func(addr, reqAddr net.Addr, err error) {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						logrus.WithFields(logrus.Fields{
							"error": err,
							"src":   addr.String(),
							"dst":   reqAddr.String(),
						}).Info("UDP TProxy error")
					} else {
						logrus.WithFields(logrus.Fields{
							"src": addr.String(),
							"dst": reqAddr.String(),
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
