package client

import (
	"crypto/x509"
	"net"
	"strconv"
	"time"

	"github.com/apernet/hysteria/core/errors"
	"github.com/apernet/hysteria/core/internal/pmtud"
	"github.com/apernet/hysteria/extras/outbounds"
	"github.com/apernet/hysteria/extras/outbounds/acl"
)

const (
	udpBufferSize = 4096
	defaultStreamReceiveWindow = 8388608                            // 8MB
	defaultConnReceiveWindow   = defaultStreamReceiveWindow * 5 / 2 // 20MB
	defaultMaxIdleTimeout      = 30 * time.Second
	defaultKeepAlivePeriod     = 10 * time.Second
)

// Outbound provides the implementation of how the server should connect to remote servers.
// Although UDP includes a reqAddr, the implementation does not necessarily have to use it
// to make a "connected" UDP connection that does not accept packets from other addresses.
// In fact, the default implementation simply uses net.ListenUDP for a "full-cone" behavior.
type Outbound interface {
	TCP(reqAddr string) (net.Conn, error)
	UDP(reqAddr string) (UDPConn, error)
}

// UDPConn is like net.PacketConn, but uses string for addresses.
type UDPConn interface {
	ReadFrom(b []byte) (int, string, error)
	WriteTo(b []byte, addr string) (int, error)
	Close() error
}

type PluggableClientOutboundAdapter struct {
	outbounds.PluggableOutbound
}

func (a *PluggableClientOutboundAdapter) TCP(reqAddr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(reqAddr)
	if err != nil {
		return nil, err
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	return a.PluggableOutbound.TCP(&outbounds.AddrEx{
		Host: host,
		Port: uint16(portInt),
	})
}

func (a *PluggableClientOutboundAdapter) UDP(reqAddr string) (UDPConn, error) {
	host, port, err := net.SplitHostPort(reqAddr)
	if err != nil {
		return nil, err
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	conn, err := a.PluggableOutbound.UDP(&outbounds.AddrEx{
		Host: host,
		Port: uint16(portInt),
	})
	if err != nil {
		return nil, err
	}
	return &outbounds.UdpConnAdapter{UDPConn: conn}, nil
}

type Config struct {
	ConnFactory     ConnFactory
	ServerAddr      net.Addr
	Auth            string
	TLSConfig       TLSConfig
	QUICConfig      QUICConfig
	BandwidthConfig BandwidthConfig
	FastOpen        bool
	Outbound        Outbound
	Outbounds       []outbounds.OutboundEntry
	GeoLoader		acl.GeoLoader
	ACLs			string

	filled bool // whether the fields have been verified and filled
}

// verifyAndFill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field or has set an invalid value.
func (c *Config) verifyAndFill() error {
	if c.filled {
		return nil
	}
	if c.ConnFactory == nil {
		c.ConnFactory = &udpConnFactory{}
	}
	if c.ServerAddr == nil {
		return errors.ConfigError{Field: "ServerAddr", Reason: "must be set"}
	}
	if c.QUICConfig.InitialStreamReceiveWindow == 0 {
		c.QUICConfig.InitialStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.InitialStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxStreamReceiveWindow == 0 {
		c.QUICConfig.MaxStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.MaxStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.InitialConnectionReceiveWindow == 0 {
		c.QUICConfig.InitialConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.InitialConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxConnectionReceiveWindow == 0 {
		c.QUICConfig.MaxConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.MaxConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxIdleTimeout == 0 {
		c.QUICConfig.MaxIdleTimeout = defaultMaxIdleTimeout
	} else if c.QUICConfig.MaxIdleTimeout < 4*time.Second || c.QUICConfig.MaxIdleTimeout > 120*time.Second {
		return errors.ConfigError{Field: "QUICConfig.MaxIdleTimeout", Reason: "must be between 4s and 120s"}
	}
	if c.QUICConfig.KeepAlivePeriod == 0 {
		c.QUICConfig.KeepAlivePeriod = defaultKeepAlivePeriod
	} else if c.QUICConfig.KeepAlivePeriod < 2*time.Second || c.QUICConfig.KeepAlivePeriod > 60*time.Second {
		return errors.ConfigError{Field: "QUICConfig.KeepAlivePeriod", Reason: "must be between 2s and 60s"}
	}
	c.QUICConfig.DisablePathMTUDiscovery = c.QUICConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery

	c.filled = true
	return nil
}

type ConnFactory interface {
	New(net.Addr) (net.PacketConn, error)
}

type udpConnFactory struct{}

func (f *udpConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	return net.ListenUDP("udp", nil)
}

// TLSConfig contains the TLS configuration fields that we want to expose to the user.
type TLSConfig struct {
	ServerName            string
	InsecureSkipVerify    bool
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	RootCAs               *x509.CertPool
}

// QUICConfig contains the QUIC configuration fields that we want to expose to the user.
type QUICConfig struct {
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
	DisablePathMTUDiscovery        bool // The server may still override this to true on unsupported platforms.
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx uint64
	MaxRx uint64
}
