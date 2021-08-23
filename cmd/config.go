package main

import (
	"errors"
	"fmt"
	"github.com/yosuke-furukawa/json5/encoding/json5"
)

const (
	mbpsToBps = 125000

	DefaultStreamReceiveWindow     = 15728640 // 15 MB/s
	DefaultConnectionReceiveWindow = 67108864 // 64 MB/s
	DefaultMaxIncomingStreams      = 1024

	tlsProtocolName = "hysteria"
)

type serverConfig struct {
	Listen string `json:"listen"`
	ACME   struct {
		Domains                 []string `json:"domains"`
		Email                   string   `json:"email"`
		DisableHTTPChallenge    bool     `json:"disable_http"`
		DisableTLSALPNChallenge bool     `json:"disable_tlsalpn"`
		AltHTTPPort             int      `json:"alt_http_port"`
		AltTLSALPNPort          int      `json:"alt_tlsalpn_port"`
	} `json:"acme"`
	CertFile string `json:"cert"`
	KeyFile  string `json:"key"`
	// Optional below
	UpMbps     int    `json:"up_mbps"`
	DownMbps   int    `json:"down_mbps"`
	DisableUDP bool   `json:"disable_udp"`
	ACL        string `json:"acl"`
	Obfs       string `json:"obfs"`
	Auth       struct {
		Mode   string           `json:"mode"`
		Config json5.RawMessage `json:"config"`
	} `json:"auth"`
	PrometheusListen    string `json:"prometheus_listen"`
	ReceiveWindowConn   uint64 `json:"recv_window_conn"`
	ReceiveWindowClient uint64 `json:"recv_window_client"`
	MaxConnClient       int    `json:"max_conn_client"`
	DisableMTUDiscovery bool   `json:"disable_mtu_discovery"`
}

func (c *serverConfig) Check() error {
	if len(c.Listen) == 0 {
		return errors.New("no listen address")
	}
	if len(c.ACME.Domains) == 0 && (len(c.CertFile) == 0 || len(c.KeyFile) == 0) {
		return errors.New("ACME domain or TLS cert not provided")
	}
	if c.UpMbps < 0 || c.DownMbps < 0 {
		return errors.New("invalid speed")
	}
	if (c.ReceiveWindowConn != 0 && c.ReceiveWindowConn < 65536) ||
		(c.ReceiveWindowClient != 0 && c.ReceiveWindowClient < 65536) {
		return errors.New("invalid receive window size")
	}
	if c.MaxConnClient < 0 {
		return errors.New("invalid max connections per client")
	}
	return nil
}

func (c *serverConfig) String() string {
	return fmt.Sprintf("%+v", *c)
}

type clientConfig struct {
	Server   string `json:"server"`
	UpMbps   int    `json:"up_mbps"`
	DownMbps int    `json:"down_mbps"`
	// Optional below
	SOCKS5 struct {
		Listen     string `json:"listen"`
		Timeout    int    `json:"timeout"`
		DisableUDP bool   `json:"disable_udp"`
		User       string `json:"user"`
		Password   string `json:"password"`
	} `json:"socks5"`
	HTTP struct {
		Listen   string `json:"listen"`
		Timeout  int    `json:"timeout"`
		User     string `json:"user"`
		Password string `json:"password"`
		Cert     string `json:"cert"`
		Key      string `json:"key"`
	} `json:"http"`
	TUN struct {
		Name    string   `json:"name"`
		Timeout int      `json:"timeout"`
		Address string   `json:"address"`
		Gateway string   `json:"gateway"`
		Mask    string   `json:"mask"`
		DNS     []string `json:"dns"`
		Persist bool     `json:"persist"`
	} `json:"tun"`
	TCPRelay struct {
		Listen  string `json:"listen"`
		Remote  string `json:"remote"`
		Timeout int    `json:"timeout"`
	} `json:"relay_tcp"`
	UDPRelay struct {
		Listen  string `json:"listen"`
		Remote  string `json:"remote"`
		Timeout int    `json:"timeout"`
	} `json:"relay_udp"`
	TCPTProxy struct {
		Listen  string `json:"listen"`
		Timeout int    `json:"timeout"`
	} `json:"tproxy_tcp"`
	UDPTProxy struct {
		Listen  string `json:"listen"`
		Timeout int    `json:"timeout"`
	} `json:"tproxy_udp"`
	ACL                 string `json:"acl"`
	Obfs                string `json:"obfs"`
	Auth                []byte `json:"auth"`
	AuthString          string `json:"auth_str"`
	ServerName          string `json:"server_name"`
	Insecure            bool   `json:"insecure"`
	CustomCA            string `json:"ca"`
	ReceiveWindowConn   uint64 `json:"recv_window_conn"`
	ReceiveWindow       uint64 `json:"recv_window"`
	DisableMTUDiscovery bool   `json:"disable_mtu_discovery"`
}

func (c *clientConfig) Check() error {
	if len(c.SOCKS5.Listen) == 0 && len(c.HTTP.Listen) == 0 && len(c.TUN.Name) == 0 &&
		len(c.TCPRelay.Listen) == 0 && len(c.UDPRelay.Listen) == 0 &&
		len(c.TCPTProxy.Listen) == 0 && len(c.UDPTProxy.Listen) == 0 {
		return errors.New("please enable at least one mode")
	}
	if len(c.TCPRelay.Listen) > 0 && len(c.TCPRelay.Remote) == 0 {
		return errors.New("no TCP relay remote address")
	}
	if len(c.UDPRelay.Listen) > 0 && len(c.UDPRelay.Remote) == 0 {
		return errors.New("no UDP relay remote address")
	}
	if c.SOCKS5.Timeout != 0 && c.SOCKS5.Timeout <= 4 {
		return errors.New("invalid SOCKS5 timeout")
	}
	if c.HTTP.Timeout != 0 && c.HTTP.Timeout <= 4 {
		return errors.New("invalid HTTP timeout")
	}
	if c.TUN.Timeout != 0 && c.TUN.Timeout < 4 {
		return errors.New("invalid TUN timeout")
	}
	if c.TCPRelay.Timeout != 0 && c.TCPRelay.Timeout <= 4 {
		return errors.New("invalid TCP relay timeout")
	}
	if c.UDPRelay.Timeout != 0 && c.UDPRelay.Timeout <= 4 {
		return errors.New("invalid UDP relay timeout")
	}
	if c.TCPTProxy.Timeout != 0 && c.TCPTProxy.Timeout <= 4 {
		return errors.New("invalid TCP TProxy timeout")
	}
	if c.UDPTProxy.Timeout != 0 && c.UDPTProxy.Timeout <= 4 {
		return errors.New("invalid UDP TProxy timeout")
	}
	if len(c.Server) == 0 {
		return errors.New("no server address")
	}
	if c.UpMbps <= 0 || c.DownMbps <= 0 {
		return errors.New("invalid speed")
	}
	if (c.ReceiveWindowConn != 0 && c.ReceiveWindowConn < 65536) ||
		(c.ReceiveWindow != 0 && c.ReceiveWindow < 65536) {
		return errors.New("invalid receive window size")
	}
	return nil
}

func (c *clientConfig) String() string {
	return fmt.Sprintf("%+v", *c)
}
