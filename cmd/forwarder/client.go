package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/lucas-clemente/quic-go/congestion"
	hyCongestion "github.com/tobyxdd/hysteria/pkg/congestion"
	"github.com/tobyxdd/hysteria/pkg/forwarder"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
)

func loadCmdClientConfig(args []string) (CmdClientConfig, error) {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	// Config file
	configFile := fs.String("config", "", "Configuration file path")
	// Listen
	listen := fs.String("listen", "", "TCP listen address")
	// Server
	server := fs.String("server", "", "Server address")
	// Name
	name := fs.String("name", "", "Client name presented to the server")
	// Insecure
	var insecure optionalBoolFlag
	fs.Var(&insecure, "insecure", "Ignore TLS certificate errors")
	// Custom CA
	customCAFile := fs.String("ca", "", "Specify a trusted CA file")
	// Up Mbps
	upMbps := fs.Int("up-mbps", 0, "Upload speed in Mbps")
	// Down Mbps
	downMbps := fs.Int("down-mbps", 0, "Download speed in Mbps")
	// Receive window conn
	recvWindowConn := fs.Uint64("recv-window-conn", 0, "Max receive window size per connection")
	// Receive window
	recvWindow := fs.Uint64("recv-window", 0, "Max receive window size")
	// Parse
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	// Put together the config
	var config CmdClientConfig
	// Load from file first
	if len(*configFile) > 0 {
		cb, err := ioutil.ReadFile(*configFile)
		if err != nil {
			return CmdClientConfig{}, err
		}
		if err := json.Unmarshal(cb, &config); err != nil {
			return CmdClientConfig{}, err
		}
	}
	// Then CLI options can override config
	if len(*listen) > 0 {
		config.ListenAddr = *listen
	}
	if len(*server) > 0 {
		config.ServerAddr = *server
	}
	if len(*name) > 0 {
		config.Name = *name
	}
	if insecure.Exists {
		config.Insecure = insecure.Value
	}
	if len(*customCAFile) > 0 {
		config.CustomCAFile = *customCAFile
	}
	if *upMbps != 0 {
		config.UpMbps = *upMbps
	}
	if *downMbps != 0 {
		config.DownMbps = *downMbps
	}
	if *recvWindowConn != 0 {
		config.ReceiveWindowConn = *recvWindowConn
	}
	if *recvWindow != 0 {
		config.ReceiveWindow = *recvWindow
	}
	return config, nil
}

func client(args []string) {
	config, err := loadCmdClientConfig(args)
	if err != nil {
		log.Fatalln("Unable to load configuration:", err.Error())
	}
	if err := config.Check(); err != nil {
		log.Fatalln("Configuration error:", err.Error())
	}
	if len(config.Name) == 0 {
		usr, err := user.Current()
		if err == nil {
			config.Name = usr.Name
		}
	}
	fmt.Printf("Configuration loaded: %+v\n", config)

	tlsConfig := &tls.Config{
		NextProtos: []string{forwarder.TLSAppProtocol},
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

	logChan := make(chan string, 4)

	go func() {
		_, err = forwarder.NewClient(config.ListenAddr, config.ServerAddr, forwarder.ClientConfig{
			Name:      config.Name,
			TLSConfig: tlsConfig,
			Speed: &forwarder.Speed{
				SendBPS:    uint64(config.UpMbps) * mbpsToBps,
				ReceiveBPS: uint64(config.DownMbps) * mbpsToBps,
			},
			MaxReceiveWindowPerConnection: config.ReceiveWindowConn,
			MaxReceiveWindow:              config.ReceiveWindow,
			CongestionFactory: func(refBPS uint64) congestion.SendAlgorithmWithDebugInfos {
				return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
			},
		}, forwarder.ClientCallbacks{
			ServerConnectedCallback: func(addr net.Addr, banner string, cSend uint64, cRecv uint64) {
				logChan <- fmt.Sprintf("Connected to server %s, negotiated speed in Mbps: Up %d / Down %d",
					addr.String(), cSend/mbpsToBps, cRecv/mbpsToBps)
				logChan <- fmt.Sprintf("Server banner: [%s]", banner)
			},
			ServerErrorCallback: func(err error) {
				logChan <- fmt.Sprintf("Error connecting to the server: %s", err.Error())
			},
			NewTCPConnectionCallback: func(addr net.Addr) {
				logChan <- fmt.Sprintf("New connection: %s", addr.String())
			},
			TCPConnectionClosedCallback: func(addr net.Addr, err error) {
				logChan <- fmt.Sprintf("Connection %s closed: %s", addr.String(), err.Error())
			},
		})
		if err != nil {
			log.Fatalln("Client startup failure:", err)
		} else {
			log.Println("The client is now up and running :)")
		}
	}()

	for {
		logStr := <-logChan
		if len(logStr) == 0 {
			break
		}
		log.Println(logStr)
	}

}
