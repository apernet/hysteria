package forwarder

import (
	"github.com/lucas-clemente/quic-go/congestion"
	"net"
)

type CongestionFactory func(refBPS uint64) congestion.SendAlgorithmWithDebugInfos

// For server
type ClientConnectedCallback func(addr net.Addr, name string, sSend uint64, sRecv uint64)
type ClientDisconnectedCallback func(addr net.Addr, name string, err error)
type ClientNewStreamCallback func(addr net.Addr, name string, id int)
type ClientStreamClosedCallback func(addr net.Addr, name string, id int, err error)
type TCPErrorCallback func(remoteAddr string, err error)

// For client
type ServerConnectedCallback func(addr net.Addr, banner string, cSend uint64, cRecv uint64)
type ServerErrorCallback func(err error)
type NewTCPConnectionCallback func(addr net.Addr)
type TCPConnectionClosedCallback func(addr net.Addr, err error)
