package forwarder

import (
	"crypto/tls"
	"errors"
	"github.com/tobyxdd/hysteria/internal/forwarder"
	"net"
)

type client struct {
	qc *forwarder.QUICClient
}

func NewClient(localAddr string, remoteAddr string, config ClientConfig, callbacks ClientCallbacks) (Client, error) {
	// Fix config first
	if config.Speed == nil || config.Speed.SendBPS == 0 || config.Speed.ReceiveBPS == 0 {
		return nil, errors.New("invalid speed")
	}
	if config.TLSConfig == nil {
		config.TLSConfig = &tls.Config{NextProtos: []string{TLSAppProtocol}}
	}
	if config.MaxReceiveWindowPerConnection == 0 {
		config.MaxReceiveWindowPerConnection = defaultReceiveWindowConn
	}
	if config.MaxReceiveWindow == 0 {
		config.MaxReceiveWindow = defaultReceiveWindow
	}
	qc, err := forwarder.NewQUICClient(localAddr, remoteAddr, config.Name, config.TLSConfig,
		config.Speed.SendBPS, config.Speed.ReceiveBPS,
		config.MaxReceiveWindowPerConnection, config.MaxReceiveWindow,
		forwarder.CongestionFactory(config.CongestionFactory),
		func(addr net.Addr, banner string, cSend uint64, cRecv uint64) {
			if callbacks.ServerConnectedCallback != nil {
				callbacks.ServerConnectedCallback(addr, banner, cSend, cRecv)
			}
		},
		func(err error) {
			if callbacks.ServerErrorCallback != nil {
				callbacks.ServerErrorCallback(err)
			}
		},
		func(addr net.Addr) {
			if callbacks.NewTCPConnectionCallback != nil {
				callbacks.NewTCPConnectionCallback(addr)
			}
		},
		func(addr net.Addr, err error) {
			if callbacks.TCPConnectionClosedCallback != nil {
				callbacks.TCPConnectionClosedCallback(addr, err)
			}
		},
	)
	if err != nil {
		return nil, err
	}
	return &client{qc: qc}, nil
}

func (c *client) Stats() Stats {
	addr, in, out := c.qc.Stats()
	return Stats{
		RemoteAddr:    addr,
		inboundBytes:  in,
		outboundBytes: out,
	}
}

func (c *client) Close() error {
	return c.Close()
}
