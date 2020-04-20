package core

import (
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"github.com/tobyxdd/hysteria/internal/core"
	"io"
	"net"
)

type AuthResult int32

const (
	AuthSuccess = AuthResult(iota)
	AuthInvalidCred
	AuthInternalError
)

type ConnectResult int32

const (
	ConnSuccess = ConnectResult(iota)
	ConnFailed
	ConnBlocked
)

type CongestionFactory core.CongestionFactory
type ClientAuthFunc func(addr net.Addr, username string, password string, sSend uint64, sRecv uint64) (AuthResult, string)
type ClientDisconnectedFunc core.ClientDisconnectedFunc
type HandleRequestFunc func(addr net.Addr, username string, id int, isUDP bool, reqAddr string) (ConnectResult, string, io.ReadWriteCloser)
type RequestClosedFunc func(addr net.Addr, username string, id int, isUDP bool, reqAddr string, err error)

type Server interface {
	Serve() error
	Stats() (inbound uint64, outbound uint64)
	Close() error
}

func NewServer(addr string, tlsConfig *tls.Config, quicConfig *quic.Config,
	sendBPS uint64, recvBPS uint64, congestionFactory CongestionFactory,
	clientAuthFunc ClientAuthFunc,
	clientDisconnectedFunc ClientDisconnectedFunc,
	handleRequestFunc HandleRequestFunc,
	requestClosedFunc RequestClosedFunc) (Server, error) {
	return core.NewServer(addr, tlsConfig, quicConfig, sendBPS, recvBPS, core.CongestionFactory(congestionFactory),
		func(addr net.Addr, username string, password string, sSend uint64, sRecv uint64) (core.AuthResult, string) {
			r, msg := clientAuthFunc(addr, username, password, sSend, sRecv)
			return core.AuthResult(r), msg
		},
		core.ClientDisconnectedFunc(clientDisconnectedFunc),
		func(addr net.Addr, username string, id int, reqType core.ConnectionType, reqAddr string) (core.ConnectResult, string, io.ReadWriteCloser) {
			r, msg, conn := handleRequestFunc(addr, username, id, reqType == core.ConnectionType_UDP, reqAddr)
			return core.ConnectResult(r), msg, conn
		},
		func(addr net.Addr, username string, id int, reqType core.ConnectionType, reqAddr string, err error) {
			requestClosedFunc(addr, username, id, reqType == core.ConnectionType_UDP, reqAddr, err)
		})
}

type Client interface {
	Dial(udp bool, addr string) (io.ReadWriteCloser, error)
	Stats() (inbound uint64, outbound uint64)
	Close() error
}

func NewClient(serverAddr string, username string, password string,
	tlsConfig *tls.Config, quicConfig *quic.Config, sendBPS uint64, recvBPS uint64,
	congestionFactory CongestionFactory) (Client, error) {
	return core.NewClient(serverAddr, username, password, tlsConfig, quicConfig, sendBPS, recvBPS,
		core.CongestionFactory(congestionFactory))
}
