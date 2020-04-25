package main

import (
	"bufio"
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func proxyServer(args []string) {
	var config proxyServerConfig
	err := loadConfig(&config, args)
	if err != nil {
		log.Fatalln("Unable to load configuration:", err)
	}
	if err := config.Check(); err != nil {
		log.Fatalln("Configuration error:", err.Error())
	}
	log.Printf("Configuration loaded: %+v\n", config)
	// Load cert
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		log.Fatalln("Unable to load the certificate:", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{proxyTLSProtocol},
		MinVersion:   tls.VersionTLS13,
	}

	quicConfig := &quic.Config{
		MaxReceiveStreamFlowControlWindow:     config.ReceiveWindowConn,
		MaxReceiveConnectionFlowControlWindow: config.ReceiveWindowClient,
		MaxIncomingStreams:                    config.MaxConnClient,
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
		log.Println("WARNING: No authentication configured. This server can be used by anyone!")
	}

	var obfuscator core.Obfuscator
	if len(config.Obfs) > 0 {
		obfuscator = obfs.XORObfuscator(config.Obfs)
	}

	server, err := core.NewServer(config.ListenAddr, tlsConfig, quicConfig,
		uint64(config.UpMbps)*mbpsToBps, uint64(config.DownMbps)*mbpsToBps,
		func(refBPS uint64) congestion.SendAlgorithmWithDebugInfos {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		},
		obfuscator,
		func(addr net.Addr, username string, password string, sSend uint64, sRecv uint64) (core.AuthResult, string) {
			if len(config.AuthFile) == 0 {
				log.Printf("%s (%s) connected, negotiated speed (Mbps): Up %d / Down %d\n",
					addr.String(), username, sSend/mbpsToBps, sRecv/mbpsToBps)
				return core.AuthSuccess, ""
			} else {
				// Need auth
				ok, err := checkAuth(config.AuthFile, username, password)
				if err != nil {
					log.Printf("%s (%s) auth error: %s\n", addr.String(), username, err.Error())
					return core.AuthInternalError, "Server auth error"
				}
				if ok {
					log.Printf("%s (%s) authenticated, negotiated speed (Mbps): Up %d / Down %d\n",
						addr.String(), username, sSend/mbpsToBps, sRecv/mbpsToBps)
					return core.AuthSuccess, ""
				} else {
					log.Printf("%s (%s) auth failed (invalid credential)\n", addr.String(), username)
					return core.AuthInvalidCred, "Invalid credential"
				}
			}
		},
		func(addr net.Addr, username string, err error) {
			log.Printf("%s (%s) disconnected: %s\n", addr.String(), username, err.Error())
		},
		func(addr net.Addr, username string, id int, packet bool, reqAddr string) (core.ConnectResult, string, io.ReadWriteCloser) {
			if !packet {
				// TCP
				log.Printf("%s (%s): [TCP] %s\n", addr.String(), username, reqAddr)
				conn, err := net.DialTimeout("tcp", reqAddr, dialTimeout)
				if err != nil {
					log.Printf("TCP error %s: %s\n", reqAddr, err.Error())
					return core.ConnFailed, err.Error(), nil
				}
				return core.ConnSuccess, "", conn
			} else {
				// UDP
				log.Printf("%s (%s): [UDP] %s\n", addr.String(), username, reqAddr)
				conn, err := net.Dial("udp", reqAddr)
				if err != nil {
					log.Printf("UDP error %s: %s\n", reqAddr, err.Error())
					return core.ConnFailed, err.Error(), nil
				}
				return core.ConnSuccess, "", conn
			}
		},
		func(addr net.Addr, username string, id int, packet bool, reqAddr string, err error) {
			if !packet {
				log.Printf("%s (%s): closed [TCP] %s: %s\n", addr.String(), username, reqAddr, err.Error())
			} else {
				log.Printf("%s (%s): closed [UDP] %s: %s\n", addr.String(), username, reqAddr, err.Error())
			}
		},
	)
	if err != nil {
		log.Fatalln("Server initialization failed:", err)
	}
	defer server.Close()
	log.Println("Up and running on", config.ListenAddr)

	log.Fatalln(server.Serve())
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
