package main

import "errors"

const relayTLSProtocol = "hysteria-relay"

type relayClientConfig struct {
	ListenAddr        string `json:"listen" desc:"TCP listen address"`
	ServerAddr        string `json:"server" desc:"Server address"`
	Name              string `json:"name" desc:"Client name presented to the server"`
	Insecure          bool   `json:"insecure" desc:"Ignore TLS certificate errors"`
	CustomCAFile      string `json:"ca" desc:"Specify a trusted CA file"`
	UpMbps            int    `json:"up_mbps" desc:"Upload speed in Mbps"`
	DownMbps          int    `json:"down_mbps" desc:"Download speed in Mbps"`
	ReceiveWindowConn uint64 `json:"recv_window_conn" desc:"Max receive window size per connection"`
	ReceiveWindow     uint64 `json:"recv_window" desc:"Max receive window size"`
	Obfs              string `json:"obfs" desc:"Obfuscation key"`
}

func (c *relayClientConfig) Check() error {
	if len(c.ListenAddr) == 0 {
		return errors.New("no listen address")
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

type relayServerConfig struct {
	ListenAddr          string `json:"listen" desc:"Server listen address"`
	RemoteAddr          string `json:"remote" desc:"Remote relay address"`
	CertFile            string `json:"cert" desc:"TLS certificate file"`
	KeyFile             string `json:"key" desc:"TLS key file"`
	UpMbps              int    `json:"up_mbps" desc:"Max upload speed per client in Mbps"`
	DownMbps            int    `json:"down_mbps" desc:"Max download speed per client in Mbps"`
	ReceiveWindowConn   uint64 `json:"recv_window_conn" desc:"Max receive window size per connection"`
	ReceiveWindowClient uint64 `json:"recv_window_client" desc:"Max receive window size per client"`
	MaxConnClient       int    `json:"max_conn_client" desc:"Max simultaneous connections allowed per client"`
	Obfs                string `json:"obfs" desc:"Obfuscation key"`
}

func (c *relayServerConfig) Check() error {
	if len(c.ListenAddr) == 0 {
		return errors.New("no listen address")
	}
	if len(c.RemoteAddr) == 0 {
		return errors.New("no remote address")
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
