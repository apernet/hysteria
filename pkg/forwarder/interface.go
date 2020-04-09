package forwarder

import (
	"crypto/tls"
	"github.com/tobyxdd/hysteria/internal/forwarder"
	"net"
)

type CongestionFactory forwarder.CongestionFactory

// A server can support multiple forwarding entries (listenAddr/remoteAddr pairs)
type Server interface {
	Add(listenAddr, remoteAddr string) error
	Remove(listenAddr string) error
	Stats() map[string]Stats
}

// An empty ServerConfig is a valid one
type ServerConfig struct {
	// A banner message that will be sent to the client after the connection is established.
	// No message if not set.
	BannerMessage string
	// TLSConfig is used to configure the TLS server.
	// Use an insecure self-signed certificate if not set.
	TLSConfig *tls.Config
	// MaxSpeedPerClient is the maximum allowed sending and receiving speed for each client.
	// Sending speed will never exceed this limit, even if a client demands a larger value.
	// No restrictions if not set.
	MaxSpeedPerClient *Speed
	// Corresponds to MaxReceiveStreamFlowControlWindow in QUIC.
	MaxReceiveWindowPerConnection uint64
	// Corresponds to MaxReceiveConnectionFlowControlWindow in QUIC.
	MaxReceiveWindowPerClient uint64
	// Max number of simultaneous connections allowed for a client
	MaxConnectionPerClient int
	// Congestion factory
	CongestionFactory CongestionFactory
}

type ServerCallbacks struct {
	ClientConnectedCallback    func(listenAddr string, clientAddr net.Addr, name string, sSend uint64, sRecv uint64)
	ClientDisconnectedCallback func(listenAddr string, clientAddr net.Addr, name string, err error)
	ClientNewStreamCallback    func(listenAddr string, clientAddr net.Addr, name string, id int)
	ClientStreamClosedCallback func(listenAddr string, clientAddr net.Addr, name string, id int, err error)
	TCPErrorCallback           func(listenAddr string, remoteAddr string, err error)
}

// A client supports one forwarding entry
type Client interface {
	Stats() Stats
	Close() error
}

// An empty ClientConfig is NOT a valid one, as Speed must be set
type ClientConfig struct {
	// A client can report its name to the server after the connection is established.
	// No name if not set.
	Name string
	// TLSConfig is used to configure the TLS client.
	// Use default settings if not set.
	TLSConfig *tls.Config
	// Speed reported by the client when negotiating with the server.
	// The actual speed will also depend on the configuration of the server.
	Speed *Speed
	// Corresponds to MaxReceiveStreamFlowControlWindow in QUIC.
	MaxReceiveWindowPerConnection uint64
	// Corresponds to MaxReceiveConnectionFlowControlWindow in QUIC.
	MaxReceiveWindow uint64
	// Congestion factory
	CongestionFactory CongestionFactory
}

type ClientCallbacks struct {
	ServerConnectedCallback     func(addr net.Addr, banner string, cSend uint64, cRecv uint64)
	ServerErrorCallback         func(err error)
	NewTCPConnectionCallback    func(addr net.Addr)
	TCPConnectionClosedCallback func(addr net.Addr, err error)
}

type Speed struct {
	SendBPS    uint64
	ReceiveBPS uint64
}

type Stats struct {
	RemoteAddr    string
	inboundBytes  uint64
	outboundBytes uint64
}
