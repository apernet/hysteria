package main

import (
	"errors"
	"fmt"
	"github.com/yosuke-furukawa/json5/encoding/json5"
)

const (
	mbpsToBps = 125000

	DefaultMaxReceiveStreamFlowControlWindow     = 33554432
	DefaultMaxReceiveConnectionFlowControlWindow = 67108864
	DefaultMaxIncomingStreams                    = 4096

	tlsProtocolName = "hysteria"
)

type serverConfig struct {
	Listen   string `json:"listen"`
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
}

func (c *serverConfig) Check() error {
	if len(c.Listen) == 0 {
		return errors.New("no listen address")
	}
	if len(c.CertFile) == 0 || len(c.KeyFile) == 0 {
		return errors.New("TLS cert or key not provided")
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
	ACL               string `json:"acl"`
	Obfs              string `json:"obfs"`
	Auth              []byte `json:"auth"`
	AuthString        string `json:"auth_str"`
	Insecure          bool   `json:"insecure"`
	CustomCA          string `json:"ca"`
	ReceiveWindowConn uint64 `json:"recv_window_conn"`
	ReceiveWindow     uint64 `json:"recv_window"`
}

func (c *clientConfig) Check() error {
	if len(c.SOCKS5.Listen) == 0 && len(c.HTTP.Listen) == 0 &&
		len(c.TCPRelay.Listen) == 0 && len(c.UDPRelay.Listen) == 0 &&
		len(c.TCPTProxy.Listen) == 0 && len(c.UDPTProxy.Listen) == 0 {
		return errors.New("no SOCKS5, HTTP, relay or TProxy listen address")
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
