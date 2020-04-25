package socks5

import (
	"errors"
	"github.com/tobyxdd/hysteria/internal/utils"
	"github.com/tobyxdd/hysteria/pkg/core"
	"io"
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
	HyClient    core.Client
	AuthFunc    func(username, password string) bool
	Method      byte
	TCPAddr     *net.TCPAddr
	TCPDeadline int

	NewRequestFunc         func(addr net.Addr, reqAddr string)
	RequestClosedFunc      func(addr net.Addr, reqAddr string, err error)
	NewUDPAssociateFunc    func(addr net.Addr)
	UDPAssociateClosedFunc func(addr net.Addr, err error)
	NewUDPTunnelFunc       func(addr net.Addr, reqAddr string)
	UDPTunnelClosedFunc    func(addr net.Addr, reqAddr string, err error)

	tcpListener *net.TCPListener
}

func NewServer(hyClient core.Client, addr string, authFunc func(username, password string) bool, tcpDeadline int,
	newReqFunc func(addr net.Addr, reqAddr string), reqClosedFunc func(addr net.Addr, reqAddr string, err error),
	newUDPAssociateFunc func(addr net.Addr), udpAssociateClosedFunc func(addr net.Addr, err error),
	newUDPTunnelFunc func(addr net.Addr, reqAddr string), udpTunnelClosedFunc func(addr net.Addr, reqAddr string, err error)) (*Server, error) {

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
		s.NewRequestFunc(c.RemoteAddr(), r.Address())
		var closeErr error
		defer func() {
			s.RequestClosedFunc(c.RemoteAddr(), r.Address(), closeErr)
		}()
		rc, err := s.HyClient.Dial(false, r.Address())
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		defer rc.Close()
		// All good
		_ = sendReply(c, socks5.RepSuccess)
		closeErr = pipePair(c, rc, s.TCPDeadline)
		return nil
	} else if r.Cmd == socks5.CmdUDP {
		// UDP
		s.NewUDPAssociateFunc(c.RemoteAddr())
		var closeErr error
		defer func() {
			s.UDPAssociateClosedFunc(c.RemoteAddr(), closeErr)
		}()
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   s.TCPAddr.IP,
			Zone: s.TCPAddr.Zone,
		})
		if err != nil {
			_ = sendReply(c, socks5.RepServerFailure)
			closeErr = err
			return err
		}
		defer udpConn.Close()
		// Send UDP server addr to the client
		atyp, addr, port, err := socks5.ParseAddress(udpConn.LocalAddr().String())
		if err != nil {
			_ = sendReply(c, socks5.RepServerFailure)
			closeErr = err
			return err
		}
		_, _ = socks5.NewReply(socks5.RepSuccess, atyp, addr, port).WriteTo(c)
		// Let UDP server do its job, we hold the TCP connection here
		go s.handleUDP(udpConn)
		buf := make([]byte, 1024)
		for {
			if s.TCPDeadline != 0 {
				_ = c.SetDeadline(time.Now().Add(time.Duration(s.TCPDeadline) * time.Second))
			}
			_, err := c.Read(buf)
			if err != nil {
				closeErr = err
				break
			}
		}
		// As the TCP connection closes, so does the UDP listener
		return nil
	} else {
		_ = sendReply(c, socks5.RepCommandNotSupported)
		return ErrUnsupportedCmd
	}
}

func (s *Server) handleUDP(c *net.UDPConn) {
	var clientAddr *net.UDPAddr
	remoteMap := make(map[string]io.ReadWriteCloser) //  Remote addr <-> Remote conn
	buf := make([]byte, utils.PipeBufferSize)
	var closeErr error

	for {
		n, caddr, err := c.ReadFromUDP(buf)
		if err != nil {
			closeErr = err
			break
		}
		d, err := socks5.NewDatagramFromBytes(buf[:n])
		if err != nil || d.Frag != 0 {
			// Ignore bad packets
			continue
		}
		if clientAddr == nil {
			// Whoever sends the first valid packet is our client :P
			clientAddr = caddr
		} else if caddr.String() != clientAddr.String() {
			// We already have a client and you're not it!
			continue
		}
		rc := remoteMap[d.Address()]
		if rc == nil {
			// Need a new entry
			rc, err = s.HyClient.Dial(true, d.Address())
			if err != nil {
				// Failed to establish a connection, silently ignore
				continue
			}
			// The other direction
			go udpReversePipe(clientAddr, c, rc)
			remoteMap[d.Address()] = rc
			s.NewUDPTunnelFunc(clientAddr, d.Address())
		}
		_, err = rc.Write(d.Data)
		if err != nil {
			// The connection is no longer valid, close & remove from map
			_ = rc.Close()
			delete(remoteMap, d.Address())
			s.UDPTunnelClosedFunc(clientAddr, d.Address(), err)
		}
	}
	// Close all remote connections
	for raddr, rc := range remoteMap {
		_ = rc.Close()
		s.UDPTunnelClosedFunc(clientAddr, raddr, closeErr)
	}
}

func sendReply(conn *net.TCPConn, rep byte) error {
	p := socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	_, err := p.WriteTo(conn)
	return err
}

func pipePair(conn *net.TCPConn, stream io.ReadWriteCloser, deadline int) error {
	errChan := make(chan error, 2)
	// TCP to stream
	go func() {
		buf := make([]byte, utils.PipeBufferSize)
		for {
			if deadline != 0 {
				_ = conn.SetDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
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
		errChan <- utils.Pipe(stream, conn, nil)
	}()
	return <-errChan
}

func udpReversePipe(clientAddr *net.UDPAddr, c *net.UDPConn, rc io.ReadWriteCloser) {
	buf := make([]byte, utils.PipeBufferSize)
	for {
		n, err := rc.Read(buf)
		if err != nil {
			break
		}
		d := socks5.NewDatagram(socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, buf[:n])
		_, err = c.WriteTo(d.Bytes(), clientAddr)
		if err != nil {
			break
		}
	}
}
