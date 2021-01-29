package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"io"
	"strconv"
)

import (
	"github.com/txthinking/socks5"
	"net"
	"time"
)

var (
	ErrUnsupportedCmd = errors.New("unsupported command")
	ErrUserPassAuth   = errors.New("invalid username or password")
)

type Server struct {
	HyClient    *core.Client
	AuthFunc    func(username, password string) bool
	Method      byte
	TCPAddr     *net.TCPAddr
	TCPDeadline int
	ACLEngine   *acl.Engine
	DisableUDP  bool

	NewRequestFunc         func(addr net.Addr, reqAddr string, action acl.Action, arg string)
	RequestClosedFunc      func(addr net.Addr, reqAddr string, err error)
	NewUDPAssociateFunc    func(addr net.Addr)
	UDPAssociateClosedFunc func(addr net.Addr, err error)
	NewUDPTunnelFunc       func(addr net.Addr, reqAddr string, action acl.Action, arg string)
	UDPTunnelClosedFunc    func(addr net.Addr, reqAddr string, err error)

	tcpListener *net.TCPListener
}

func NewServer(hyClient *core.Client, addr string, authFunc func(username, password string) bool, tcpDeadline int,
	aclEngine *acl.Engine, disableUDP bool,
	newReqFunc func(addr net.Addr, reqAddr string, action acl.Action, arg string),
	reqClosedFunc func(addr net.Addr, reqAddr string, err error),
	newUDPAssociateFunc func(addr net.Addr),
	udpAssociateClosedFunc func(addr net.Addr, err error),
	newUDPTunnelFunc func(addr net.Addr, reqAddr string, action acl.Action, arg string),
	udpTunnelClosedFunc func(addr net.Addr, reqAddr string, err error)) (*Server, error) {

	taddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	m := socks5.MethodNone
	if authFunc != nil {
		m = socks5.MethodUsernamePassword
	}
	s := &Server{
		HyClient:               hyClient,
		AuthFunc:               authFunc,
		Method:                 m,
		TCPAddr:                taddr,
		TCPDeadline:            tcpDeadline,
		ACLEngine:              aclEngine,
		DisableUDP:             disableUDP,
		NewRequestFunc:         newReqFunc,
		RequestClosedFunc:      reqClosedFunc,
		NewUDPAssociateFunc:    newUDPAssociateFunc,
		UDPAssociateClosedFunc: udpAssociateClosedFunc,
		NewUDPTunnelFunc:       newUDPTunnelFunc,
		UDPTunnelClosedFunc:    udpTunnelClosedFunc,
	}
	return s, nil
}

func (s *Server) negotiate(c *net.TCPConn) error {
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

func (s *Server) ListenAndServe() error {
	var err error
	s.tcpListener, err = net.ListenTCP("tcp", s.TCPAddr)
	if err != nil {
		return err
	}
	defer s.tcpListener.Close()
	for {
		c, err := s.tcpListener.AcceptTCP()
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
			if err := s.negotiate(c); err != nil {
				return
			}
			r, err := socks5.NewRequestFrom(c)
			if err != nil {
				return
			}
			_ = s.handle(c, r)
		}(c)
	}
}

func (s *Server) handle(c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdConnect {
		// TCP
		return s.handleTCP(c, r)
	} else if r.Cmd == socks5.CmdUDP {
		// UDP
		_ = sendReply(c, socks5.RepCommandNotSupported)
		return ErrUnsupportedCmd
	} else {
		_ = sendReply(c, socks5.RepCommandNotSupported)
		return ErrUnsupportedCmd
	}
}

func (s *Server) handleTCP(c *net.TCPConn, r *socks5.Request) error {
	domain, ip, port, addr := parseRequestAddress(r)
	action, arg := acl.ActionProxy, ""
	if s.ACLEngine != nil {
		action, arg = s.ACLEngine.Lookup(domain, ip)
	}
	s.NewRequestFunc(c.RemoteAddr(), addr, action, arg)
	var closeErr error
	defer func() {
		s.RequestClosedFunc(c.RemoteAddr(), addr, closeErr)
	}()
	// Handle according to the action
	switch action {
	case acl.ActionDirect:
		rc, err := net.Dial("tcp", addr)
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		defer rc.Close()
		_ = sendReply(c, socks5.RepSuccess)
		closeErr = pipePair(c, rc, s.TCPDeadline)
		return nil
	case acl.ActionProxy:
		rc, err := s.HyClient.DialTCP(addr)
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		defer rc.Close()
		_ = sendReply(c, socks5.RepSuccess)
		closeErr = pipePair(c, rc, s.TCPDeadline)
		return nil
	case acl.ActionBlock:
		_ = sendReply(c, socks5.RepHostUnreachable)
		closeErr = errors.New("blocked in ACL")
		return nil
	case acl.ActionHijack:
		rc, err := net.Dial("tcp", net.JoinHostPort(arg, port))
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		defer rc.Close()
		_ = sendReply(c, socks5.RepSuccess)
		closeErr = pipePair(c, rc, s.TCPDeadline)
		return nil
	default:
		_ = sendReply(c, socks5.RepServerFailure)
		closeErr = fmt.Errorf("unknown action %d", action)
		return nil
	}
}

func sendReply(conn *net.TCPConn, rep byte) error {
	p := socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	_, err := p.WriteTo(conn)
	return err
}

func parseRequestAddress(r *socks5.Request) (domain string, ip net.IP, port string, addr string) {
	p := strconv.Itoa(int(binary.BigEndian.Uint16(r.DstPort)))
	if r.Atyp == socks5.ATYPDomain {
		d := string(r.DstAddr[1:])
		return d, nil, p, net.JoinHostPort(d, p)
	} else {
		return "", r.DstAddr, p, net.JoinHostPort(net.IP(r.DstAddr).String(), p)
	}
}

func pipePair(conn *net.TCPConn, stream io.ReadWriteCloser, deadline int) error {
	deadlineDuration := time.Duration(deadline) * time.Second
	errChan := make(chan error, 2)
	// TCP to stream
	go func() {
		buf := make([]byte, utils.PipeBufferSize)
		for {
			if deadline != 0 {
				_ = conn.SetDeadline(time.Now().Add(deadlineDuration))
			}
			rn, err := conn.Read(buf)
			if rn > 0 {
				_, err := stream.Write(buf[:rn])
				if err != nil {
					errChan <- err
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	// Stream to TCP
	go func() {
		errChan <- utils.Pipe(stream, conn)
	}()
	return <-errChan
}
