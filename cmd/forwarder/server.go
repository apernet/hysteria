package main

import (
	"crypto/tls"
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
	"strings"
)

const mbpsToBps = 125000

func loadCmdServerConfig(args []string) (CmdServerConfig, error) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	// Config file
	configFile := fs.String("config", "", "Configuration file path")
	// Entries
	var entries stringSliceFlag
	fs.Var(&entries, "entry", "Add a forwarding entry. Separate the listen address and the remote address with a comma. You can add this option multiple times. Example: localhost:444,google.com:443")
	// Banner
	banner := fs.String("banner", "", "A banner to present to clients")
	// Cert file
	certFile := fs.String("cert", "", "TLS certificate file")
	// Key file
	keyFile := fs.String("key", "", "TLS key file")
	// Up Mbps
	upMbps := fs.Int("up-mbps", 0, "Max upload speed per client in Mbps")
	// Down Mbps
	downMbps := fs.Int("down-mbps", 0, "Max download speed per client in Mbps")
	// Receive window conn
	recvWindowConn := fs.Uint64("recv-window-conn", 0, "Max receive window size per connection")
	// Receive window client
	recvWindowClient := fs.Uint64("recv-window-client", 0, "Max receive window size per client")
	// Max conn client
	maxConnClient := fs.Int("max-conn-client", 0, "Max simultaneous connections allowed per client")
	// Parse
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	// Put together the config
	var config CmdServerConfig
	// Load from file first
	if len(*configFile) > 0 {
		cb, err := ioutil.ReadFile(*configFile)
		if err != nil {
			return CmdServerConfig{}, err
		}
		if err := json.Unmarshal(cb, &config); err != nil {
			return CmdServerConfig{}, err
		}
	}
	// Then CLI options can override config
	if len(entries) > 0 {
		fe, err := flagToEntries(entries)
		if err != nil {
			return CmdServerConfig{}, err
		}
		config.Entries = append(config.Entries, fe...)
	}
	if len(*banner) > 0 {
		config.Banner = *banner
	}
	if len(*certFile) > 0 {
		config.CertFile = *certFile
	}
	if len(*keyFile) > 0 {
		config.KeyFile = *keyFile
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
	if *recvWindowClient != 0 {
		config.ReceiveWindowClient = *recvWindowClient
	}
	if *maxConnClient != 0 {
		config.MaxConnClient = *maxConnClient
	}
	return config, nil
}

func flagToEntries(f stringSliceFlag) ([]ForwardEntry, error) {
	out := make([]ForwardEntry, len(f))
	for i, entry := range f {
		es := strings.Split(entry, ",")
		if len(es) != 2 {
			return nil, fmt.Errorf("incorrect entry syntax: %s", entry)
		}
		out[i] = ForwardEntry{
			ListenAddr: es[0],
			RemoteAddr: es[1],
		}
	}
	return out, nil
}

func server(args []string) {
	config, err := loadCmdServerConfig(args)
	if err != nil {
		log.Fatalln("Unable to load configuration:", err.Error())
	}
	if err := config.Check(); err != nil {
		log.Fatalln("Configuration error:", err.Error())
	}
	fmt.Printf("Configuration loaded: %+v\n", config)
	// Load cert
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		log.Fatalln("Unable to load the certificate:", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{forwarder.TLSAppProtocol},
		MinVersion:   tls.VersionTLS13,
	}

	logChan := make(chan string, 4)

	go func() {
		server := forwarder.NewServer(forwarder.ServerConfig{
			BannerMessage: config.Banner,
			TLSConfig:     tlsConfig,
			MaxSpeedPerClient: &forwarder.Speed{
				SendBPS:    uint64(config.UpMbps) * mbpsToBps,
				ReceiveBPS: uint64(config.DownMbps) * mbpsToBps,
			},
			MaxReceiveWindowPerConnection: config.ReceiveWindowConn,
			MaxReceiveWindowPerClient:     config.ReceiveWindowClient,
			MaxConnectionPerClient:        config.MaxConnClient,
			CongestionFactory: func(refBPS uint64) congestion.SendAlgorithmWithDebugInfos {
				return hyCongestion.NewBrutalSender(congestion.ByteCount(refBPS))
			},
		}, forwarder.ServerCallbacks{
			ClientConnectedCallback: func(listenAddr string, clientAddr net.Addr, name string, sSend uint64, sRecv uint64) {
				if len(name) > 0 {
					logChan <- fmt.Sprintf("[%s] Client %s (%s) connected, negotiated speed in Mbps: Up %d / Down %d",
						listenAddr, clientAddr.String(), name, sSend/mbpsToBps, sRecv/mbpsToBps)
				} else {
					logChan <- fmt.Sprintf("[%s] Client %s connected, negotiated speed in Mbps: Up %d / Down %d",
						listenAddr, clientAddr.String(), sSend/mbpsToBps, sRecv/mbpsToBps)
				}
			},
			ClientDisconnectedCallback: func(listenAddr string, clientAddr net.Addr, name string, err error) {
				if len(name) > 0 {
					logChan <- fmt.Sprintf("[%s] Client %s (%s) disconnected: %s",
						listenAddr, clientAddr.String(), name, err.Error())
				} else {
					logChan <- fmt.Sprintf("[%s] Client %s disconnected: %s",
						listenAddr, clientAddr.String(), err.Error())
				}
			},
			ClientNewStreamCallback: func(listenAddr string, clientAddr net.Addr, name string, id int) {
				if len(name) > 0 {
					logChan <- fmt.Sprintf("[%s] Client %s (%s) opened stream ID %d",
						listenAddr, clientAddr.String(), name, id)
				} else {
					logChan <- fmt.Sprintf("[%s] Client %s opened stream ID %d",
						listenAddr, clientAddr.String(), id)
				}
			},
			ClientStreamClosedCallback: func(listenAddr string, clientAddr net.Addr, name string, id int, err error) {
				if len(name) > 0 {
					logChan <- fmt.Sprintf("[%s] Client %s (%s) closed stream ID %d: %s",
						listenAddr, clientAddr.String(), name, id, err.Error())
				} else {
					logChan <- fmt.Sprintf("[%s] Client %s closed stream ID %d: %s",
						listenAddr, clientAddr.String(), id, err.Error())
				}
			},
			TCPErrorCallback: func(listenAddr string, remoteAddr string, err error) {
				logChan <- fmt.Sprintf("[%s] TCP error when connecting to %s: %s",
					listenAddr, remoteAddr, err.Error())
			},
		})
		for _, entry := range config.Entries {
			log.Println("Starting", entry.String(), "...")
			if err := server.Add(entry.ListenAddr, entry.RemoteAddr); err != nil {
				log.Fatalln(err)
			}
		}
		log.Println("The server is now up and running :)")
	}()

	for {
		logStr := <-logChan
		if len(logStr) == 0 {
			break
		}
		log.Println(logStr)
	}

}
