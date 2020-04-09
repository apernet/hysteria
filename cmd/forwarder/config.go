package main

import (
	"errors"
	"fmt"
)

type CmdClientConfig struct {
	ListenAddr        string `json:"listen"`
	ServerAddr        string `json:"server"`
	Name              string `json:"name"`
	Insecure          bool   `json:"insecure"`
	CustomCAFile      string `json:"ca"`
	UpMbps            int    `json:"up_mbps"`
	DownMbps          int    `json:"down_mbps"`
	ReceiveWindowConn uint64 `json:"recv_window_conn"`
	ReceiveWindow     uint64 `json:"recv_window"`
}

func (c *CmdClientConfig) Check() error {
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

type ForwardEntry struct {
	ListenAddr string `json:"listen"`
	RemoteAddr string `json:"remote"`
}

func (e *ForwardEntry) String() string {
	return fmt.Sprintf("%s <-> %s", e.ListenAddr, e.RemoteAddr)
}

type CmdServerConfig struct {
	Entries             []ForwardEntry `json:"entries"`
	Banner              string         `json:"banner"`
	CertFile            string         `json:"cert"`
	KeyFile             string         `json:"key"`
	UpMbps              int            `json:"up_mbps"`
	DownMbps            int            `json:"down_mbps"`
	ReceiveWindowConn   uint64         `json:"recv_window_conn"`
	ReceiveWindowClient uint64         `json:"recv_window_client"`
	MaxConnClient       int            `json:"max_conn_client"`
}

func (c *CmdServerConfig) Check() error {
	if len(c.Entries) == 0 {
		return errors.New("no entries")
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
