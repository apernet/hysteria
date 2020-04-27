package main

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/tobyxdd/hysteria/pkg/acl"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/socks5"
	"io/ioutil"
	"log"
	"net"
)

func proxyClient(args []string) {
	var config proxyClientConfig
	err := loadConfig(&config, args)
	if err != nil {
		log.Fatalln("Unable to load configuration:", err)
	}
	if err := config.Check(); err != nil {
		log.Fatalln("Configuration error:", err)
	}
	log.Printf("Configuration loaded: %+v\n", config)

	tlsConfig := &tls.Config{
		NextProtos: []string{proxyTLSProtocol},
		MinVersion: tls.VersionTLS13,
	}
	// Load CA
	if len(config.CustomCAFile) > 0 {
		bs, err := ioutil.ReadFile(config.CustomCAFile)
		if err != nil {
			log.Fatalln("Unable to load CA file:", err)
		}
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(bs) {
			log.Fatalln("Unable to parse CA file", config.CustomCAFile)
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

	var aclEngine *acl.Engine
	if len(config.ACLFile) > 0 {
		aclEngine, err = acl.LoadFromFile(config.ACLFile)
		if err != nil {
			log.Fatalln("Unable to parse ACL:", err)
		}
	}

	client, err := core.NewClient(config.ServerAddr, config.Username, config.Password, tlsConfig, quicConfig,
		uint64(config.UpMbps)*mbpsToBps, uint64(config.DownMbps)*mbpsToBps,
		func(refBPS uint64) congestion.SendAlgorithmWithDebugInfos {
			return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
		}, obfuscator)
	if err != nil {
		log.Fatalln("Client initialization failed:", err)
	}
	defer client.Close()
	log.Println("Connected to", config.ServerAddr)

	socks5server, err := socks5.NewServer(client, config.SOCKS5Addr, nil, config.SOCKS5Timeout, aclEngine,
		func(addr net.Addr, reqAddr string, action acl.Action, arg string) {
			log.Printf("[TCP] [%s] %s <-> %s\n", actionToString(action, arg), addr.String(), reqAddr)
		},
		func(addr net.Addr, reqAddr string, err error) {
			log.Printf("Closed [TCP] %s <-> %s: %s\n", addr.String(), reqAddr, err.Error())
		},
		func(addr net.Addr) {
			log.Printf("[UDP] Associate %s\n", addr.String())
		},
		func(addr net.Addr, err error) {
			log.Printf("Closed [UDP] Associate %s: %s\n", addr.String(), err.Error())
		},
		func(addr net.Addr, reqAddr string, action acl.Action, arg string) {
			log.Printf("[UDP] [%s] %s <-> %s\n", actionToString(action, arg), addr.String(), reqAddr)
		},
		func(addr net.Addr, reqAddr string, err error) {
			log.Printf("Closed [UDP] %s <-> %s: %s\n", addr.String(), reqAddr, err.Error())
		})
	if err != nil {
		log.Fatalln("SOCKS5 server initialization failed:", err)
	}
	log.Println("SOCKS5 server up and running on", config.SOCKS5Addr)

	log.Fatalln(socks5server.ListenAndServe())
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
