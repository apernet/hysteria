package main

import "errors"

const proxyTLSProtocol = "hysteria-proxy"

type proxyClientConfig struct {
	SOCKS5Addr        string `json:"socks5_addr" desc:"SOCKS5 listen address"`
	SOCKS5Timeout     int    `json:"socks5_timeout" desc:"SOCKS5 connection timeout in seconds"`
	ServerAddr        string `json:"server" desc:"Server address"`
	Username          string `json:"username" desc:"Authentication username"`
	Password          string `json:"password" desc:"Authentication password"`
	Insecure          bool   `json:"insecure" desc:"Ignore TLS certificate errors"`
	CustomCAFile      string `json:"ca" desc:"Specify a trusted CA file"`
	UpMbps            int    `json:"up_mbps" desc:"Upload speed in Mbps"`
	DownMbps          int    `json:"down_mbps" desc:"Download speed in Mbps"`
	ReceiveWindowConn uint64 `json:"recv_window_conn" desc:"Max receive window size per connection"`
	ReceiveWindow     uint64 `json:"recv_window" desc:"Max receive window size"`
}

func (c *proxyClientConfig) Check() error {
	if len(c.SOCKS5Addr) == 0 {
		return errors.New("no SOCKS5 listen address")
	}
	if c.SOCKS5Timeout != 0 && c.SOCKS5Timeout <= 4 {
		return errors.New("invalid SOCKS5 timeout")
	}
	if len(c.ServerAddr) == 0 {
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

type proxyServerConfig struct {
	ListenAddr          string `json:"listen" desc:"Server listen address"`
	CertFile            string `json:"cert" desc:"TLS certificate file"`
	KeyFile             string `json:"key" desc:"TLS key file"`
	AuthFile            string `json:"auth" desc:"Authentication file"`
	UpMbps              int    `json:"up_mbps" desc:"Max upload speed per client in Mbps"`
	DownMbps            int    `json:"down_mbps" desc:"Max download speed per client in Mbps"`
	ReceiveWindowConn   uint64 `json:"recv_window_conn" desc:"Max receive window size per connection"`
	ReceiveWindowClient uint64 `json:"recv_window_client" desc:"Max receive window size per client"`
	MaxConnClient       int    `json:"max_conn_client" desc:"Max simultaneous connections allowed per client"`
}

func (c *proxyServerConfig) Check() error {
	if len(c.ListenAddr) == 0 {
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
