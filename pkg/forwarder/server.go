package forwarder

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/tobyxdd/hysteria/internal/forwarder"
	"math/big"
	"net"
)

type server struct {
	config    ServerConfig
	callbacks ServerCallbacks
	entries   map[string]*forwarder.QUICServer
}

func NewServer(config ServerConfig, callbacks ServerCallbacks) Server {
	// Fix config first
	if config.TLSConfig == nil {
		config.TLSConfig = generateInsecureTLSConfig()
	}
	if config.MaxSpeedPerClient == nil {
		config.MaxSpeedPerClient = &Speed{0, 0}
	}
	if config.MaxReceiveWindowPerConnection == 0 {
		config.MaxReceiveWindowPerConnection = defaultReceiveWindowConn
	}
	if config.MaxReceiveWindowPerClient == 0 {
		config.MaxReceiveWindowPerClient = defaultReceiveWindow
	}
	if config.MaxConnectionPerClient <= 0 {
		config.MaxConnectionPerClient = defaultMaxClientConn
	}
	return &server{config: config, callbacks: callbacks, entries: make(map[string]*forwarder.QUICServer)}
}

func (s *server) Add(listenAddr, remoteAddr string) error {
	qs, err := forwarder.NewQUICServer(listenAddr, remoteAddr, s.config.BannerMessage, s.config.TLSConfig,
		s.config.MaxSpeedPerClient.SendBPS, s.config.MaxSpeedPerClient.ReceiveBPS,
		s.config.MaxReceiveWindowPerConnection, s.config.MaxReceiveWindowPerClient,
		s.config.MaxConnectionPerClient, forwarder.CongestionFactory(s.config.CongestionFactory),
		func(addr net.Addr, name string, sSend uint64, sRecv uint64) {
			if s.callbacks.ClientConnectedCallback != nil {
				s.callbacks.ClientConnectedCallback(listenAddr, addr, name, sSend, sRecv)
			}
		},
		func(addr net.Addr, name string, err error) {
			if s.callbacks.ClientDisconnectedCallback != nil {
				s.callbacks.ClientDisconnectedCallback(listenAddr, addr, name, err)
			}
		},
		func(addr net.Addr, name string, id int) {
			if s.callbacks.ClientNewStreamCallback != nil {
				s.callbacks.ClientNewStreamCallback(listenAddr, addr, name, id)
			}
		},
		func(addr net.Addr, name string, id int, err error) {
			if s.callbacks.ClientStreamClosedCallback != nil {
				s.callbacks.ClientStreamClosedCallback(listenAddr, addr, name, id, err)
			}
		},
		func(remoteAddr string, err error) {
			if s.callbacks.TCPErrorCallback != nil {
				s.callbacks.TCPErrorCallback(listenAddr, remoteAddr, err)
			}
		},
	)
	if err != nil {
		return err
	}
	s.entries[listenAddr] = qs
	return nil
}

func (s *server) Remove(listenAddr string) error {
	defer delete(s.entries, listenAddr)
	if qs, ok := s.entries[listenAddr]; ok && qs != nil {
		return qs.Close()
	}
	return nil
}

func (s *server) Stats() map[string]Stats {
	r := make(map[string]Stats, len(s.entries))
	for laddr, sv := range s.entries {
		addr, in, out := sv.Stats()
		r[laddr] = Stats{
			RemoteAddr:    addr,
			inboundBytes:  in,
			outboundBytes: out,
		}
	}
	return r
}

func generateInsecureTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{TLSAppProtocol},
	}
}
