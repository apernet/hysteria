package socks5

import "errors"

// Modified based on https://github.com/txthinking/socks5/blob/master/server.go

import (
	"github.com/txthinking/socks5"
	"log"
	"net"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/txthinking/runnergroup"
)

var (
	ErrUnsupportedCmd = errors.New("unsupported command")
	ErrUserPassAuth   = errors.New("invalid username or password")
)

// Server is socks5 server wrapper
type Server struct {
	AuthFunc          func(username, password string) bool
	Method            byte
	SupportedCommands []byte
	TCPAddr           *net.TCPAddr
	UDPAddr           *net.UDPAddr
	ServerAddr        *net.UDPAddr
	TCPListen         *net.TCPListener
	UDPConn           *net.UDPConn
	UDPExchanges      *cache.Cache
	TCPDeadline       int
	UDPDeadline       int
	UDPSessionTime    int // If client does't send address, use this fixed time
	Handle            Handler
	TCPUDPAssociate   *cache.Cache
	RunnerGroup       *runnergroup.RunnerGroup
}

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn *net.UDPConn
}

func NewServer(addr, ip string, authFunc func(username, password string) bool, tcpDeadline, udpDeadline, udpSessionTime int) (*Server, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	taddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	saddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, p))
	if err != nil {
		return nil, err
	}
	m := socks5.MethodNone
	if authFunc != nil {
		m = socks5.MethodUsernamePassword
	}
	cs := cache.New(cache.NoExpiration, cache.NoExpiration)
	cs1 := cache.New(cache.NoExpiration, cache.NoExpiration)
	s := &Server{
		Method:            m,
		AuthFunc:          authFunc,
		SupportedCommands: []byte{socks5.CmdConnect, socks5.CmdUDP},
		TCPAddr:           taddr,
		UDPAddr:           uaddr,
		ServerAddr:        saddr,
		UDPExchanges:      cs,
		TCPDeadline:       tcpDeadline,
		UDPDeadline:       udpDeadline,
		UDPSessionTime:    udpSessionTime,
		TCPUDPAssociate:   cs1,
		RunnerGroup:       runnergroup.New(),
	}
	return s, nil
}

// Negotiate handle negotiate packet.
// This method do not handle gssapi(0x01) method now.
// Error or OK both replied.
func (s *Server) Negotiate(c *net.TCPConn) error {
	rq, err := socks5.NewNegotiationRequestFrom(c)
	if err != nil {
		return err
	}
	var got bool
	var m byte
	for _, m = range rq.Methods {
		if m == s.Method {
			got = true
		}
	}
	if !got {
		rp := socks5.NewNegotiationReply(socks5.MethodUnsupportAll)
		if _, err := rp.WriteTo(c); err != nil {
			return err
		}
	}
	rp := socks5.NewNegotiationReply(s.Method)
	if _, err := rp.WriteTo(c); err != nil {
		return err
	}

	if s.Method == socks5.MethodUsernamePassword {
		urq, err := socks5.NewUserPassNegotiationRequestFrom(c)
		if err != nil {
			return err
		}
		if !s.AuthFunc(string(urq.Uname), string(urq.Passwd)) {
			urp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure)
			if _, err := urp.WriteTo(c); err != nil {
				return err
			}
			return ErrUserPassAuth
		}
		urp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess)
		if _, err := urp.WriteTo(c); err != nil {
			return err
		}
	}
	return nil
}

// GetRequest get request packet from client, and check command according to SupportedCommands
// Error replied.
func (s *Server) GetRequest(c *net.TCPConn) (*socks5.Request, error) {
	r, err := socks5.NewRequestFrom(c)
	if err != nil {
		return nil, err
	}
	var supported bool
	for _, c := range s.SupportedCommands {
		if r.Cmd == c {
			supported = true
			break
		}
	}
	if !supported {
		var p *socks5.Reply
		if r.Atyp == socks5.ATYPIPv4 || r.Atyp == socks5.ATYPDomain {
			p = socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, net.IPv4zero, []byte{0x00, 0x00})
		} else {
			p = socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv6, net.IPv6zero, []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(c); err != nil {
			return nil, err
		}
		return nil, ErrUnsupportedCmd
	}
	return r, nil
}

// Run server
func (s *Server) ListenAndServe(h Handler) error {
	if h == nil {
		s.Handle = &DefaultHandle{}
	} else {
		s.Handle = h
	}
	s.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			return s.RunTCPServer()
		},
		Stop: func() error {
			if s.TCPListen != nil {
				return s.TCPListen.Close()
			}
			return nil
		},
	})
	s.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			return s.RunUDPServer()
		},
		Stop: func() error {
			if s.UDPConn != nil {
				return s.UDPConn.Close()
			}
			return nil
		},
	})
	return s.RunnerGroup.Wait()
}

// RunTCPServer starts tcp server
func (s *Server) RunTCPServer() error {
	var err error
	s.TCPListen, err = net.ListenTCP("tcp", s.TCPAddr)
	if err != nil {
		return err
	}
	defer s.TCPListen.Close()
	for {
		c, err := s.TCPListen.AcceptTCP()
		if err != nil {
			return err
		}
		go func(c *net.TCPConn) {
			defer c.Close()
			if s.TCPDeadline != 0 {
				if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
					return
				}
			}
			if err := s.Negotiate(c); err != nil {
				return
			}
			r, err := s.GetRequest(c)
			if err != nil {
				return
			}
			_ = s.Handle.TCPHandle(s, c, r)
		}(c)
	}
}

// RunUDPServer starts udp server
func (s *Server) RunUDPServer() error {
	var err error
	s.UDPConn, err = net.ListenUDP("udp", s.UDPAddr)
	if err != nil {
		return err
	}
	defer s.UDPConn.Close()
	for {
		b := make([]byte, 65536)
		n, addr, err := s.UDPConn.ReadFromUDP(b)
		if err != nil {
			return err
		}
		go func(addr *net.UDPAddr, b []byte) {
			d, err := socks5.NewDatagramFromBytes(b)
			if err != nil {
				return
			}
			if d.Frag != 0x00 {
				return
			}
			_ = s.Handle.UDPHandle(s, addr, d)
		}(addr, b[0:n])
	}
}

// Stop server
func (s *Server) Shutdown() error {
	return s.RunnerGroup.Done()
}

// TCP connection waits for associated UDP to close
func (s *Server) TCPWaitsForUDP(addr *net.UDPAddr) error {
	_, p, err := net.SplitHostPort(addr.String())
	if err != nil {
		return err
	}
	if p == "0" {
		time.Sleep(time.Duration(s.UDPSessionTime) * time.Second)
		return nil
	}
	ch := make(chan byte)
	s.TCPUDPAssociate.Set(addr.String(), ch, cache.DefaultExpiration)
	<-ch
	return nil
}

// UDP releases associated TCP
func (s *Server) UDPReleasesTCP(addr *net.UDPAddr) {
	v, ok := s.TCPUDPAssociate.Get(addr.String())
	if ok {
		ch := v.(chan byte)
		ch <- 0x00
		s.TCPUDPAssociate.Delete(addr.String())
	}
}

// Handler handle tcp, udp request
type Handler interface {
	// Request has not been replied yet
	TCPHandle(*Server, *net.TCPConn, *socks5.Request) error
	UDPHandle(*Server, *net.UDPAddr, *socks5.Datagram) error
}

// DefaultHandle implements Handler interface
type DefaultHandle struct {
}

// TCPHandle auto handle request. You may prefer to do yourself.
func (h *DefaultHandle) TCPHandle(s *Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdConnect {
		rc, err := r.Connect(c)
		if err != nil {
			return err
		}
		defer rc.Close()
		go func() {
			var bf [1024 * 2]byte
			for {
				if s.TCPDeadline != 0 {
					if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
						return
					}
				}
				i, err := rc.Read(bf[:])
				if err != nil {
					return
				}
				if _, err := c.Write(bf[0:i]); err != nil {
					return
				}
			}
		}()
		var bf [1024 * 2]byte
		for {
			if s.TCPDeadline != 0 {
				if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second)); err != nil {
					return nil
				}
			}
			i, err := c.Read(bf[:])
			if err != nil {
				return nil
			}
			if _, err := rc.Write(bf[0:i]); err != nil {
				return nil
			}
		}
	}
	if r.Cmd == socks5.CmdUDP {
		caddr, err := r.UDP(c, s.ServerAddr)
		if err != nil {
			return err
		}
		if err := s.TCPWaitsForUDP(caddr); err != nil {
			return err
		}
		return nil
	}
	return ErrUnsupportedCmd
}

// UDPHandle auto handle packet. You may prefer to do yourself.
func (h *DefaultHandle) UDPHandle(s *Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	send := func(ue *UDPExchange, data []byte) error {
		_, err := ue.RemoteConn.Write(data)
		if err != nil {
			return err
		}
		if socks5.Debug {
			log.Printf("Sent UDP data to remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), data)
		}
		return nil
	}

	var ue *UDPExchange
	iue, ok := s.UDPExchanges.Get(addr.String())
	if ok {
		ue = iue.(*UDPExchange)
		return send(ue, d.Data)
	}

	if socks5.Debug {
		log.Printf("Call udp: %#v\n", d.Address())
	}
	c, err := socks5.Dial.Dial("udp", d.Address())
	if err != nil {
		s.UDPReleasesTCP(addr)
		return err
	}
	// A UDP association terminates when the TCP connection that the UDP
	// ASSOCIATE request arrived on terminates.
	rc := c.(*net.UDPConn)
	ue = &UDPExchange{
		ClientAddr: addr,
		RemoteConn: rc,
	}
	if socks5.Debug {
		log.Printf("Created remote UDP conn for client. client: %#v server: %#v remote: %#v\n", addr.String(), ue.RemoteConn.LocalAddr().String(), d.Address())
	}
	if err := send(ue, d.Data); err != nil {
		s.UDPReleasesTCP(ue.ClientAddr)
		ue.RemoteConn.Close()
		return err
	}
	s.UDPExchanges.Set(ue.ClientAddr.String(), ue, cache.DefaultExpiration)
	go func(ue *UDPExchange) {
		defer func() {
			s.UDPReleasesTCP(ue.ClientAddr)
			s.UDPExchanges.Delete(ue.ClientAddr.String())
			ue.RemoteConn.Close()
		}()
		var b [65536]byte
		for {
			if s.UDPDeadline != 0 {
				if err := ue.RemoteConn.SetDeadline(time.Now().Add(time.Duration(s.UDPDeadline) * time.Second)); err != nil {
					log.Println(err)
					break
				}
			}
			n, err := ue.RemoteConn.Read(b[:])
			if err != nil {
				break
			}
			if socks5.Debug {
				log.Printf("Got UDP data from remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), b[0:n])
			}
			a, addr, port, err := socks5.ParseAddress(ue.ClientAddr.String())
			if err != nil {
				log.Println(err)
				break
			}
			d1 := socks5.NewDatagram(a, addr, port, b[0:n])
			if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
				break
			}
			if socks5.Debug {
				log.Printf("Sent Datagram. client: %#v server: %#v remote: %#v data: %#v %#v %#v %#v %#v %#v datagram address: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), d1.Rsv, d1.Frag, d1.Atyp, d1.DstAddr, d1.DstPort, d1.Data, d1.Address())
			}
		}
	}(ue)
	return nil
}
