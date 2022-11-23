// Package sdk provides an official API for integrating Hysteria client into other projects.
// It aims to be as stable & simple as possible, so that it can be easily maintained and
// widely adopted.
package sdk

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"

	"github.com/apernet/hysteria/pkg/core"
	"github.com/lucas-clemente/quic-go"
)

const (
	defaultALPN = "hysteria"

	defaultStreamReceiveWindow     = 16777216                           // 16 MB
	defaultConnectionReceiveWindow = defaultStreamReceiveWindow * 5 / 2 // 40 MB

	defaultClientIdleTimeoutSec = 20

	defaultClientHopIntervalSec = 10
)

type (
	Protocol      string
	ResolveFunc   func(network string, address string) (net.Addr, error)
	ListenUDPFunc func(network string, laddr *net.UDPAddr) (*net.UDPConn, error)
)

const (
	ProtocolUDP     Protocol = "udp"
	ProtocolWeChat  Protocol = "wechat"
	ProtocolFakeTCP Protocol = "faketcp"
)

// Client is a Hysteria client.
type Client interface {
	// DialTCP dials a TCP connection to the specified address.
	// The remote address must be in "host:port" format.
	DialTCP(addr string) (net.Conn, error)

	// DialUDP dials a UDP connection.
	// It is bound to a fixed port on the server side.
	// Can be used to send and receive UDP packets to/from any address.
	DialUDP() (HyUDPConn, error)

	// Close closes the client.
	Close() error
}

// HyUDPConn is a Hysteria-proxied UDP connection.
type HyUDPConn interface {
	// ReadFrom reads a packet from the connection.
	// It returns the data, the source address (in "host:port" format) and any error encountered.
	ReadFrom() ([]byte, string, error)

	// WriteTo writes a packet to the connection.
	// The remote address must be in "host:port" format.
	WriteTo([]byte, string) error

	// Close closes the connection.
	Close() error
}

// ClientConfig is the configuration for a Hysteria client.
type ClientConfig struct {
	// ServerAddress is the address of the Hysteria server.
	// It must be in "host:port" format.
	ServerAddress string

	// ResolveFunc is the function used to resolve the server address.
	// If not set, the default resolver will be used.
	ResolveFunc ResolveFunc

	// ListenUDPFunc is the function used to listen on a UDP port.
	// If not set, the default listener will be used.
	// Please note that ProtocolFakeTCP does NOT use this function,
	// as it is not a UDP-based protocol and has its own stack.
	ListenUDPFunc ListenUDPFunc

	// Protocol is the protocol to use.
	// It must be one of the following:
	//   - ProtocolUDP
	//   - ProtocolWeChat
	//   - ProtocolFakeTCP
	Protocol Protocol

	// Obfs is the obfuscation password.
	// Empty = no obfuscation.
	Obfs string

	// HopInterval is the port hopping interval.
	// 0 = default 10s.
	HopInterval time.Duration

	// Auth is the authentication payload to be sent to the server.
	// It can be empty or nil if no authentication is required.
	Auth []byte

	// SendBPS is the maximum sending speed in bytes per second.
	// Required and cannot be 0.
	SendBPS uint64

	// RecvBPS is the maximum receiving speed in bytes per second.
	// Required and cannot be 0.
	RecvBPS uint64

	// ALPN is the ALPN protocol to be used.
	// Empty = default "hysteria".
	ALPN string

	// ServerName is the SNI to be used.
	// Empty = get from ServerAddress.
	ServerName string

	// Insecure is whether to skip certificate verification.
	// It is not recommended to set this to true.
	Insecure bool

	// RootCAs is the root CA certificates to be used.
	// Empty = use system default.
	RootCAs *x509.CertPool

	// ReceiveWindowConn is the flow control receive window size for each connection.
	// 0 = default 16MB.
	ReceiveWindowConn uint64

	// ReceiveWindow is the flow control receive window size for the whole client.
	// 0 = default 40MB.
	ReceiveWindow uint64

	// HandshakeTimeout is the timeout for the initial handshake.
	// 0 = default 5s.
	HandshakeTimeout time.Duration

	// IdleTimeout is the timeout for idle connections.
	// The client will send a heartbeat packet every 2/5 of this value.
	// If the server does not respond within IdleTimeout, the connection will be closed.
	// 0 = default 20s.
	IdleTimeout time.Duration

	// DisableMTUDiscovery is whether to disable MTU discovery.
	// Only disable this if you are having MTU issues.
	DisableMTUDiscovery bool

	// TLSConfig, if not nil, will override all TLS-related fields above!!!
	// Only set this if you know what you are doing.
	TLSConfig *tls.Config

	// QUICConfig, if not nil, will override all QUIC-related fields above!!!
	// Only set this if you know what you are doing.
	QUICConfig *quic.Config
}

// fill in the default values (if not set) for the configuration.
func (c *ClientConfig) fill() {
	if c.ResolveFunc == nil {
		c.ResolveFunc = func(network string, address string) (net.Addr, error) {
			switch network {
			case "tcp", "tcp4", "tcp6":
				return net.ResolveTCPAddr(network, address)
			case "udp", "udp4", "udp6":
				return net.ResolveUDPAddr(network, address)
			case "ip", "ip4", "ip6":
				return net.ResolveIPAddr(network, address)
			default:
				return nil, errors.New("unsupported network type")
			}
		}
	}
	if c.ListenUDPFunc == nil {
		c.ListenUDPFunc = net.ListenUDP
	}
	if c.Protocol == "" {
		c.Protocol = ProtocolUDP
	}
	if c.HopInterval == 0 {
		c.HopInterval = defaultClientHopIntervalSec * time.Second
	}
	if c.ALPN == "" {
		c.ALPN = defaultALPN
	}
	if c.ReceiveWindowConn == 0 {
		c.ReceiveWindowConn = defaultStreamReceiveWindow
	}
	if c.ReceiveWindow == 0 {
		c.ReceiveWindow = defaultConnectionReceiveWindow
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = defaultClientIdleTimeoutSec * time.Second
	}
}

// NewClient creates a new Hysteria client.
func NewClient(config ClientConfig) (Client, error) {
	// Fill in default values
	config.fill()
	// TLS config
	var tlsConfig *tls.Config
	if config.TLSConfig != nil {
		tlsConfig = config.TLSConfig
	} else {
		tlsConfig = &tls.Config{
			NextProtos:         []string{config.ALPN},
			ServerName:         config.ServerName,
			InsecureSkipVerify: config.Insecure,
			RootCAs:            config.RootCAs,
			MinVersion:         tls.VersionTLS13,
		}
	}
	// QUIC config
	var quicConfig *quic.Config
	if config.QUICConfig != nil {
		quicConfig = config.QUICConfig
	} else {
		quicConfig = &quic.Config{
			InitialStreamReceiveWindow:     config.ReceiveWindowConn,
			MaxStreamReceiveWindow:         config.ReceiveWindowConn,
			InitialConnectionReceiveWindow: config.ReceiveWindow,
			MaxConnectionReceiveWindow:     config.ReceiveWindow,
			HandshakeIdleTimeout:           config.HandshakeTimeout,
			MaxIdleTimeout:                 config.IdleTimeout,
			KeepAlivePeriod:                config.IdleTimeout * 2 / 5,
			DisablePathMTUDiscovery:        config.DisableMTUDiscovery,
			EnableDatagrams:                true,
		}
	}
	// Packet conn func
	pff := clientPacketConnFuncFactoryMap[config.Protocol]
	if pff == nil {
		return nil, errors.New("unsupported protocol")
	}
	pf := pff(config.Obfs, config.HopInterval, config.ResolveFunc, config.ListenUDPFunc)
	c, err := core.NewClient(config.ServerAddress, config.Auth, tlsConfig, quicConfig, pf,
		config.SendBPS, config.RecvBPS, nil)
	if err != nil {
		return nil, err
	}
	return &clientImpl{c}, nil
}

type clientImpl struct {
	*core.Client
}

func (c *clientImpl) DialTCP(addr string) (net.Conn, error) {
	return c.Client.DialTCP(addr)
}

func (c *clientImpl) DialUDP() (HyUDPConn, error) {
	conn, err := c.Client.DialUDP()
	return HyUDPConn(conn), err
}

func (c *clientImpl) Close() error {
	return c.Client.Close()
}
