package cs

import (
	"bytes"
	"context"
	"encoding/base64"
	"math/rand"
	"net"
	"strconv"
	"sync"

	"github.com/apernet/hysteria/core/acl"
	"github.com/apernet/hysteria/core/transport"
	"github.com/apernet/hysteria/core/utils"
	"github.com/lunixbochs/struc"
	"github.com/quic-go/quic-go"
)

const udpBufferSize = 4096

type serverClient struct {
	CC              quic.Connection
	Transport       *transport.ServerTransport
	Auth            []byte
	AuthLabel       string // Base64 encoded auth
	DisableUDP      bool
	ACLEngine       *acl.Engine
	CTCPRequestFunc TCPRequestFunc
	CTCPErrorFunc   TCPErrorFunc
	CUDPRequestFunc UDPRequestFunc
	CUDPErrorFunc   UDPErrorFunc

	TrafficCounter TrafficCounter

	udpSessionMutex  sync.RWMutex
	udpSessionMap    map[uint32]transport.STPacketConn
	nextUDPSessionID uint32
	udpDefragger     defragger
}

func newServerClient(cc quic.Connection, tr *transport.ServerTransport, auth []byte, disableUDP bool, ACLEngine *acl.Engine,
	CTCPRequestFunc TCPRequestFunc, CTCPErrorFunc TCPErrorFunc,
	CUDPRequestFunc UDPRequestFunc, CUDPErrorFunc UDPErrorFunc,
	TrafficCounter TrafficCounter,
) *serverClient {
	sc := &serverClient{
		CC:              cc,
		Transport:       tr,
		Auth:            auth,
		AuthLabel:       base64.StdEncoding.EncodeToString(auth),
		DisableUDP:      disableUDP,
		ACLEngine:       ACLEngine,
		CTCPRequestFunc: CTCPRequestFunc,
		CTCPErrorFunc:   CTCPErrorFunc,
		CUDPRequestFunc: CUDPRequestFunc,
		CUDPErrorFunc:   CUDPErrorFunc,
		TrafficCounter:  TrafficCounter,
		udpSessionMap:   make(map[uint32]transport.STPacketConn),
	}
	return sc
}

func (c *serverClient) ClientAddr() net.Addr {
	// quic.Connection's remote address may change since we have connection migration now,
	// so logs need to dynamically get the remote address every time.
	return c.CC.RemoteAddr()
}

func (c *serverClient) Run() error {
	if !c.DisableUDP {
		go func() {
			for {
				msg, err := c.CC.ReceiveMessage()
				if err != nil {
					break
				}
				c.handleMessage(msg)
			}
		}()
	}
	for {
		stream, err := c.CC.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		if c.TrafficCounter != nil {
			c.TrafficCounter.IncConn(c.AuthLabel)
		}
		go func() {
			stream := &qStream{stream}
			c.handleStream(stream)
			_ = stream.Close()
			if c.TrafficCounter != nil {
				c.TrafficCounter.DecConn(c.AuthLabel)
			}
		}()
	}
}

func (c *serverClient) handleStream(stream quic.Stream) {
	// Read request
	var req clientRequest
	err := struc.Unpack(stream, &req)
	if err != nil {
		return
	}
	if !req.UDP {
		// TCP connection
		c.handleTCP(stream, req.Host, req.Port)
	} else if !c.DisableUDP {
		// UDP connection
		c.handleUDP(stream)
	} else {
		// UDP disabled
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "UDP disabled",
		})
	}
}

func (c *serverClient) handleMessage(msg []byte) {
	var udpMsg udpMessage
	err := struc.Unpack(bytes.NewBuffer(msg), &udpMsg)
	if err != nil {
		return
	}
	dfMsg := c.udpDefragger.Feed(udpMsg)
	if dfMsg == nil {
		return
	}
	c.udpSessionMutex.RLock()
	conn, ok := c.udpSessionMap[dfMsg.SessionID]
	c.udpSessionMutex.RUnlock()
	if ok {
		// Session found, send the message
		action, arg := acl.ActionDirect, ""
		var isDomain bool
		var ipAddr *net.IPAddr
		var err error
		if c.ACLEngine != nil {
			action, arg, isDomain, ipAddr, err = c.ACLEngine.ResolveAndMatch(dfMsg.Host, dfMsg.Port, true)
		} else if c.Transport.ProxyEnabled() { // Case for SOCKS5 outbound
			ipAddr, isDomain = c.Transport.ParseIPAddr(dfMsg.Host) // It is safe to leave ipAddr as nil since addrExToSOCKS5Addr will ignore it when there is a domain
			err = nil
		} else {
			ipAddr, isDomain, err = c.Transport.ResolveIPAddr(dfMsg.Host)
		}
		if err != nil {
			return
		}
		switch action {
		case acl.ActionDirect, acl.ActionProxy: // Treat proxy as direct on server side
			addrEx := &transport.AddrEx{
				IPAddr: ipAddr,
				Port:   int(dfMsg.Port),
			}
			if isDomain {
				addrEx.Domain = dfMsg.Host
			}
			_, _ = conn.WriteTo(dfMsg.Data, addrEx)
			if c.TrafficCounter != nil {
				c.TrafficCounter.Tx(c.AuthLabel, len(dfMsg.Data))
			}
		case acl.ActionBlock:
			// Do nothing
		case acl.ActionHijack:
			var isDomain bool
			var hijackIPAddr *net.IPAddr
			var err error
			if c.Transport.ProxyEnabled() { // Case for domain requests + SOCKS5 outbound
				hijackIPAddr, isDomain = c.Transport.ParseIPAddr(arg) // It is safe to leave ipAddr as nil since addrExToSOCKS5Addr will ignore it when there is a domain
				err = nil
			} else {
				hijackIPAddr, isDomain, err = c.Transport.ResolveIPAddr(arg)
			}
			if err == nil {
				addrEx := &transport.AddrEx{
					IPAddr: hijackIPAddr,
					Port:   int(dfMsg.Port),
				}
				if isDomain {
					addrEx.Domain = arg
				}
				_, _ = conn.WriteTo(dfMsg.Data, addrEx)
				if c.TrafficCounter != nil {
					c.TrafficCounter.Tx(c.AuthLabel, len(dfMsg.Data))
				}
			}
		default:
			// Do nothing
		}
	}
}

func (c *serverClient) handleTCP(stream quic.Stream, host string, port uint16) {
	addrStr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	action, arg := acl.ActionDirect, ""
	var isDomain bool
	var ipAddr *net.IPAddr
	var err error
	if c.ACLEngine != nil {
		action, arg, isDomain, ipAddr, err = c.ACLEngine.ResolveAndMatch(host, port, false)
	} else if c.Transport.ProxyEnabled() { // Case for domain requests + SOCKS5 outbound
		ipAddr, isDomain = c.Transport.ParseIPAddr(host) // It is safe to leave ipAddr as nil since addrExToSOCKS5Addr will ignore it when there is a domain
		err = nil
	} else {
		ipAddr, isDomain, err = c.Transport.ResolveIPAddr(host)
	}
	if err != nil {
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "host resolution failure",
		})
		c.CTCPErrorFunc(c.ClientAddr(), c.Auth, addrStr, err)
		return
	}
	c.CTCPRequestFunc(c.ClientAddr(), c.Auth, addrStr, action, arg)

	var conn net.Conn // Connection to be piped
	switch action {
	case acl.ActionDirect, acl.ActionProxy: // Treat proxy as direct on server side
		addrEx := &transport.AddrEx{
			IPAddr: ipAddr,
			Port:   int(port),
		}
		if isDomain {
			addrEx.Domain = host
		}
		conn, err = c.Transport.DialTCP(addrEx)
		if err != nil {
			_ = struc.Pack(stream, &serverResponse{
				OK:      false,
				Message: err.Error(),
			})
			c.CTCPErrorFunc(c.ClientAddr(), c.Auth, addrStr, err)
			return
		}
	case acl.ActionBlock:
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "blocked by ACL",
		})
		return
	case acl.ActionHijack:
		var isDomain bool
		var hijackIPAddr *net.IPAddr
		var err error
		if c.Transport.ProxyEnabled() { // Case for domain requests + SOCKS5 outbound
			hijackIPAddr, isDomain = c.Transport.ParseIPAddr(arg) // It is safe to leave ipAddr as nil since addrExToSOCKS5Addr will ignore it when there is a domain
			err = nil
		} else {
			hijackIPAddr, isDomain, err = c.Transport.ResolveIPAddr(arg)
		}
		if err != nil {
			_ = struc.Pack(stream, &serverResponse{
				OK:      false,
				Message: err.Error(),
			})
			c.CTCPErrorFunc(c.ClientAddr(), c.Auth, addrStr, err)
			return
		}
		addrEx := &transport.AddrEx{
			IPAddr: hijackIPAddr,
			Port:   int(port),
		}
		if isDomain {
			addrEx.Domain = arg
		}
		conn, err = c.Transport.DialTCP(addrEx)
		if err != nil {
			_ = struc.Pack(stream, &serverResponse{
				OK:      false,
				Message: err.Error(),
			})
			c.CTCPErrorFunc(c.ClientAddr(), c.Auth, addrStr, err)
			return
		}
	default:
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "ACL error",
		})
		return
	}
	// So far so good if we reach here
	defer conn.Close()
	err = struc.Pack(stream, &serverResponse{
		OK: true,
	})
	if err != nil {
		return
	}
	if c.TrafficCounter != nil {
		err = utils.Pipe2Way(stream, conn, func(i int) {
			if i > 0 {
				c.TrafficCounter.Tx(c.AuthLabel, i)
			} else {
				c.TrafficCounter.Rx(c.AuthLabel, -i)
			}
		})
	} else {
		err = utils.Pipe2Way(stream, conn, nil)
	}
	c.CTCPErrorFunc(c.ClientAddr(), c.Auth, addrStr, err)
}

func (c *serverClient) handleUDP(stream quic.Stream) {
	// Like in SOCKS5, the stream here is only used to maintain the UDP session. No need to read anything from it
	conn, err := c.Transport.ListenUDP()
	if err != nil {
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "UDP initialization failed",
		})
		c.CUDPErrorFunc(c.ClientAddr(), c.Auth, 0, err)
		return
	}
	defer conn.Close()

	var id uint32
	c.udpSessionMutex.Lock()
	id = c.nextUDPSessionID
	c.udpSessionMap[id] = conn
	c.nextUDPSessionID += 1
	c.udpSessionMutex.Unlock()

	err = struc.Pack(stream, &serverResponse{
		OK:           true,
		UDPSessionID: id,
	})
	if err != nil {
		return
	}
	c.CUDPRequestFunc(c.ClientAddr(), c.Auth, id)

	// Receive UDP packets, send them to the client
	go func() {
		buf := make([]byte, udpBufferSize)
		for {
			n, rAddr, err := conn.ReadFrom(buf)
			if n > 0 {
				var msgBuf bytes.Buffer
				msg := udpMessage{
					SessionID: id,
					Host:      rAddr.IP.String(),
					Port:      uint16(rAddr.Port),
					FragCount: 1,
					Data:      buf[:n],
				}
				// try no frag first
				_ = struc.Pack(&msgBuf, &msg)
				sendErr := c.CC.SendMessage(msgBuf.Bytes())
				if sendErr != nil {
					if errSize, ok := sendErr.(quic.ErrMessageTooLarge); ok {
						// need to frag
						msg.MsgID = uint16(rand.Intn(0xFFFF)) + 1 // msgID must be > 0 when fragCount > 1
						fragMsgs := fragUDPMessage(msg, int(errSize))
						for _, fragMsg := range fragMsgs {
							msgBuf.Reset()
							_ = struc.Pack(&msgBuf, &fragMsg)
							_ = c.CC.SendMessage(msgBuf.Bytes())
						}
					}
				}
				if c.TrafficCounter != nil {
					c.TrafficCounter.Rx(c.AuthLabel, n)
				}
			}
			if err != nil {
				break
			}
		}
		_ = stream.Close()
	}()

	// Hold the stream until it's closed by the client
	buf := make([]byte, 1024)
	for {
		_, err = stream.Read(buf)
		if err != nil {
			break
		}
	}
	c.CUDPErrorFunc(c.ClientAddr(), c.Auth, id, err)

	// Remove the session
	c.udpSessionMutex.Lock()
	delete(c.udpSessionMap, id)
	c.udpSessionMutex.Unlock()
}
