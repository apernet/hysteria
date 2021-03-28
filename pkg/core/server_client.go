package core

import (
	"bytes"
	"context"
	"github.com/lucas-clemente/quic-go"
	"github.com/lunixbochs/struc"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"sync"
)

const udpBufferSize = 65535

type serverClient struct {
	CS              quic.Session
	Auth            []byte
	ClientAddr      net.Addr
	DisableUDP      bool
	ACLEngine       *acl.Engine
	CTCPRequestFunc TCPRequestFunc
	CTCPErrorFunc   TCPErrorFunc
	CUDPRequestFunc UDPRequestFunc
	CUDPErrorFunc   UDPErrorFunc

	udpSessionMutex  sync.RWMutex
	udpSessionMap    map[uint32]*net.UDPConn
	nextUDPSessionID uint32
}

func newServerClient(cs quic.Session, auth []byte, disableUDP bool, ACLEngine *acl.Engine,
	CTCPRequestFunc TCPRequestFunc, CTCPErrorFunc TCPErrorFunc,
	CUDPRequestFunc UDPRequestFunc, CUDPErrorFunc UDPErrorFunc) *serverClient {
	return &serverClient{
		CS:              cs,
		Auth:            auth,
		ClientAddr:      cs.RemoteAddr(),
		DisableUDP:      disableUDP,
		ACLEngine:       ACLEngine,
		CTCPRequestFunc: CTCPRequestFunc,
		CTCPErrorFunc:   CTCPErrorFunc,
		CUDPRequestFunc: CUDPRequestFunc,
		CUDPErrorFunc:   CUDPErrorFunc,
		udpSessionMap:   make(map[uint32]*net.UDPConn),
	}
}

func (c *serverClient) Run() {
	if !c.DisableUDP {
		go func() {
			for {
				msg, err := c.CS.ReceiveMessage()
				if err != nil {
					break
				}
				c.handleMessage(msg)
			}
		}()
	}
	for {
		stream, err := c.CS.AcceptStream(context.Background())
		if err != nil {
			break
		}
		go c.handleStream(stream)
	}
}

func (c *serverClient) handleStream(stream quic.Stream) {
	defer stream.Close()
	// Read request
	var req clientRequest
	err := struc.Unpack(stream, &req)
	if err != nil {
		return
	}
	if !req.UDP {
		// TCP connection
		c.handleTCP(stream, req.Address)
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
	c.udpSessionMutex.RLock()
	conn, ok := c.udpSessionMap[udpMsg.SessionID]
	c.udpSessionMutex.RUnlock()
	if ok {
		// Session found, send the message
		host, port, err := net.SplitHostPort(udpMsg.Address)
		if err != nil {
			return
		}
		action, arg := acl.ActionDirect, ""
		if c.ACLEngine != nil {
			ip := net.ParseIP(host)
			if ip != nil {
				// IP request, clear host for ACL engine
				host = ""
			}
			action, arg = c.ACLEngine.Lookup(host, ip)
		}
		switch action {
		case acl.ActionDirect, acl.ActionProxy: // Treat proxy as direct on server side
			addr, err := net.ResolveUDPAddr("udp", udpMsg.Address)
			if err == nil {
				_, _ = conn.WriteToUDP(udpMsg.Data, addr)
			}
		case acl.ActionBlock:
			// Do nothing
		case acl.ActionHijack:
			hijackAddr := net.JoinHostPort(arg, port)
			addr, err := net.ResolveUDPAddr("udp", hijackAddr)
			if err == nil {
				_, _ = conn.WriteToUDP(udpMsg.Data, addr)
			}
		default:
			// Do nothing
		}
	}
}

func (c *serverClient) handleTCP(stream quic.Stream, reqAddr string) {
	host, port, err := net.SplitHostPort(reqAddr)
	if err != nil {
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "invalid address",
		})
		c.CTCPErrorFunc(c.ClientAddr, c.Auth, reqAddr, err)
		return
	}
	action, arg := acl.ActionDirect, ""
	if c.ACLEngine != nil {
		ip := net.ParseIP(host)
		if ip != nil {
			// IP request, clear host for ACL engine
			host = ""
		}
		action, arg = c.ACLEngine.Lookup(host, ip)
	}
	c.CTCPRequestFunc(c.ClientAddr, c.Auth, reqAddr, action, arg)

	var conn net.Conn // Connection to be piped
	switch action {
	case acl.ActionDirect, acl.ActionProxy: // Treat proxy as direct on server side
		conn, err = net.DialTimeout("tcp", reqAddr, dialTimeout)
		if err != nil {
			_ = struc.Pack(stream, &serverResponse{
				OK:      false,
				Message: err.Error(),
			})
			c.CTCPErrorFunc(c.ClientAddr, c.Auth, reqAddr, err)
			return
		}
	case acl.ActionBlock:
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "blocked by ACL",
		})
		return
	case acl.ActionHijack:
		hijackAddr := net.JoinHostPort(arg, port)
		conn, err = net.DialTimeout("tcp", hijackAddr, dialTimeout)
		if err != nil {
			_ = struc.Pack(stream, &serverResponse{
				OK:      false,
				Message: err.Error(),
			})
			c.CTCPErrorFunc(c.ClientAddr, c.Auth, reqAddr, err)
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
	err = utils.Pipe2Way(stream, conn)
	c.CTCPErrorFunc(c.ClientAddr, c.Auth, reqAddr, err)
}

func (c *serverClient) handleUDP(stream quic.Stream) {
	// Like in SOCKS5, the stream here is only used to maintain the UDP session. No need to read anything from it
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "UDP initialization failed",
		})
		c.CUDPErrorFunc(c.ClientAddr, c.Auth, 0, err)
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
	c.CUDPRequestFunc(c.ClientAddr, c.Auth, id)

	// Receive UDP packets, send them to the client
	go func() {
		buf := make([]byte, udpBufferSize)
		for {
			n, rAddr, err := conn.ReadFromUDP(buf)
			if n > 0 {
				var msgBuf bytes.Buffer
				_ = struc.Pack(&msgBuf, &udpMessage{
					SessionID: id,
					Address:   rAddr.String(),
					Data:      buf[:n],
				})
				_ = c.CS.SendMessage(msgBuf.Bytes())
			}
			if err != nil {
				break
			}
		}
	}()

	// Hold the stream until it's closed by the client
	buf := make([]byte, 1024)
	for {
		_, err = stream.Read(buf)
		if err != nil {
			break
		}
	}
	c.CUDPErrorFunc(c.ClientAddr, c.Auth, id, err)

	// Remove the session
	c.udpSessionMutex.Lock()
	delete(c.udpSessionMap, id)
	c.udpSessionMutex.Unlock()
}
