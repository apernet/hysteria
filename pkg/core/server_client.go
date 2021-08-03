package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/lucas-clemente/quic-go"
	"github.com/lunixbochs/struc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"strconv"
	"sync"
)

const udpBufferSize = 65535

type serverClient struct {
	CS              quic.Session
	Transport       transport.Transport
	Auth            []byte
	ClientAddr      net.Addr
	DisableUDP      bool
	ACLEngine       *acl.Engine
	CTCPRequestFunc TCPRequestFunc
	CTCPErrorFunc   TCPErrorFunc
	CUDPRequestFunc UDPRequestFunc
	CUDPErrorFunc   UDPErrorFunc

	UpCounter, DownCounter prometheus.Counter
	ConnGauge              prometheus.Gauge

	udpSessionMutex  sync.RWMutex
	udpSessionMap    map[uint32]*net.UDPConn
	nextUDPSessionID uint32
}

func newServerClient(cs quic.Session, transport transport.Transport, auth []byte, disableUDP bool, ACLEngine *acl.Engine,
	CTCPRequestFunc TCPRequestFunc, CTCPErrorFunc TCPErrorFunc,
	CUDPRequestFunc UDPRequestFunc, CUDPErrorFunc UDPErrorFunc,
	UpCounterVec, DownCounterVec *prometheus.CounterVec,
	ConnGaugeVec *prometheus.GaugeVec) *serverClient {
	sc := &serverClient{
		CS:              cs,
		Transport:       transport,
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
	if UpCounterVec != nil && DownCounterVec != nil && ConnGaugeVec != nil {
		authB64 := base64.StdEncoding.EncodeToString(auth)
		sc.UpCounter = UpCounterVec.WithLabelValues(authB64)
		sc.DownCounter = DownCounterVec.WithLabelValues(authB64)
		sc.ConnGauge = ConnGaugeVec.WithLabelValues(authB64)
	}
	return sc
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
		if c.ConnGauge != nil {
			c.ConnGauge.Inc()
		}
		go func() {
			stream := &wrappedQUICStream{stream}
			c.handleStream(stream)
			_ = stream.Close()
			if c.ConnGauge != nil {
				c.ConnGauge.Dec()
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
	c.udpSessionMutex.RLock()
	conn, ok := c.udpSessionMap[udpMsg.SessionID]
	c.udpSessionMutex.RUnlock()
	if ok {
		// Session found, send the message
		action, arg := acl.ActionDirect, ""
		var ipAddr *net.IPAddr
		if c.ACLEngine != nil {
			action, arg, ipAddr, err = c.ACLEngine.ResolveAndMatch(udpMsg.Host)
		} else {
			ipAddr, err = c.Transport.LocalResolveIPAddr(udpMsg.Host)
		}
		if err != nil {
			return
		}
		switch action {
		case acl.ActionDirect, acl.ActionProxy: // Treat proxy as direct on server side
			_, _ = conn.WriteToUDP(udpMsg.Data, &net.UDPAddr{
				IP:   ipAddr.IP,
				Port: int(udpMsg.Port),
				Zone: ipAddr.Zone,
			})
			if c.UpCounter != nil {
				c.UpCounter.Add(float64(len(udpMsg.Data)))
			}
		case acl.ActionBlock:
			// Do nothing
		case acl.ActionHijack:
			hijackAddr := net.JoinHostPort(arg, strconv.Itoa(int(udpMsg.Port)))
			addr, err := c.Transport.LocalResolveUDPAddr(hijackAddr)
			if err == nil {
				_, _ = conn.WriteToUDP(udpMsg.Data, addr)
				if c.UpCounter != nil {
					c.UpCounter.Add(float64(len(udpMsg.Data)))
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
	var ipAddr *net.IPAddr
	var err error
	if c.ACLEngine != nil {
		action, arg, ipAddr, err = c.ACLEngine.ResolveAndMatch(host)
	} else {
		ipAddr, err = c.Transport.LocalResolveIPAddr(host)
	}
	if err != nil {
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "host resolution failure",
		})
		c.CTCPErrorFunc(c.ClientAddr, c.Auth, addrStr, err)
		return
	}
	c.CTCPRequestFunc(c.ClientAddr, c.Auth, addrStr, action, arg)

	var conn net.Conn // Connection to be piped
	switch action {
	case acl.ActionDirect, acl.ActionProxy: // Treat proxy as direct on server side
		conn, err = c.Transport.LocalDialTCP(nil, &net.TCPAddr{
			IP:   ipAddr.IP,
			Port: int(port),
			Zone: ipAddr.Zone,
		})
		if err != nil {
			_ = struc.Pack(stream, &serverResponse{
				OK:      false,
				Message: err.Error(),
			})
			c.CTCPErrorFunc(c.ClientAddr, c.Auth, addrStr, err)
			return
		}
	case acl.ActionBlock:
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "blocked by ACL",
		})
		return
	case acl.ActionHijack:
		hijackAddr := net.JoinHostPort(arg, strconv.Itoa(int(port)))
		conn, err = c.Transport.LocalDial("tcp", hijackAddr)
		if err != nil {
			_ = struc.Pack(stream, &serverResponse{
				OK:      false,
				Message: err.Error(),
			})
			c.CTCPErrorFunc(c.ClientAddr, c.Auth, addrStr, err)
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
	if c.UpCounter != nil && c.DownCounter != nil {
		err = utils.Pipe2Way(stream, conn, func(i int) {
			if i > 0 {
				c.UpCounter.Add(float64(i))
			} else {
				c.DownCounter.Add(float64(-i))
			}
		})
	} else {
		err = utils.Pipe2Way(stream, conn, nil)
	}
	c.CTCPErrorFunc(c.ClientAddr, c.Auth, addrStr, err)
}

func (c *serverClient) handleUDP(stream quic.Stream) {
	// Like in SOCKS5, the stream here is only used to maintain the UDP session. No need to read anything from it
	conn, err := c.Transport.LocalListenUDP(nil)
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
					Host:      rAddr.IP.String(),
					Port:      uint16(rAddr.Port),
					Data:      buf[:n],
				})
				_ = c.CS.SendMessage(msgBuf.Bytes())
				if c.DownCounter != nil {
					c.DownCounter.Add(float64(n))
				}
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
