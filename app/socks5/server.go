package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/apernet/hysteria/core/acl"
	"github.com/apernet/hysteria/core/cs"
	"github.com/apernet/hysteria/core/transport"
	"github.com/apernet/hysteria/core/utils"
)

import (
	"net"
	"time"

	"github.com/txthinking/socks5"
)

const udpBufferSize = 4096

var (
	ErrUnsupportedCmd = errors.New("unsupported command")
	ErrUserPassAuth   = errors.New("invalid username or password")
)

type Server struct {
	HyClient   *cs.Client
	Transport  *transport.ClientTransport
	AuthFunc   func(username, password string) bool
	Method     byte
	TCPAddr    *net.TCPAddr
	TCPTimeout time.Duration
	ACLEngine  *acl.Engine
	DisableUDP bool

	TCPRequestFunc   func(addr net.Addr, reqAddr string, action acl.Action, arg string)
	TCPErrorFunc     func(addr net.Addr, reqAddr string, err error)
	UDPAssociateFunc func(addr net.Addr)
	UDPErrorFunc     func(addr net.Addr, err error)

	tcpListener *net.TCPListener
}

func NewServer(hyClient *cs.Client, transport *transport.ClientTransport, addr string,
	authFunc func(username, password string) bool, tcpTimeout time.Duration,
	aclEngine *acl.Engine, disableUDP bool,
	tcpReqFunc func(addr net.Addr, reqAddr string, action acl.Action, arg string),
	tcpErrorFunc func(addr net.Addr, reqAddr string, err error),
	udpAssocFunc func(addr net.Addr), udpErrorFunc func(addr net.Addr, err error),
) (*Server, error) {
	tAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	m := socks5.MethodNone
	if authFunc != nil {
		m = socks5.MethodUsernamePassword
	}
	s := &Server{
		HyClient:         hyClient,
		Transport:        transport,
		AuthFunc:         authFunc,
		Method:           m,
		TCPAddr:          tAddr,
		TCPTimeout:       tcpTimeout,
		ACLEngine:        aclEngine,
		DisableUDP:       disableUDP,
		TCPRequestFunc:   tcpReqFunc,
		TCPErrorFunc:     tcpErrorFunc,
		UDPAssociateFunc: udpAssocFunc,
		UDPErrorFunc:     udpErrorFunc,
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
		go func() {
			defer c.Close()
			if s.TCPTimeout != 0 {
				if err := c.SetDeadline(time.Now().Add(s.TCPTimeout)); err != nil {
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
		}()
	}
}

func (s *Server) handle(c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdConnect {
		// TCP
		return s.handleTCP(c, r)
	} else if r.Cmd == socks5.CmdUDP {
		// UDP
		if !s.DisableUDP {
			return s.handleUDP(c, r)
		} else {
			_ = sendReply(c, socks5.RepCommandNotSupported)
			return ErrUnsupportedCmd
		}
	} else {
		_ = sendReply(c, socks5.RepCommandNotSupported)
		return ErrUnsupportedCmd
	}
}

func (s *Server) handleTCP(c *net.TCPConn, r *socks5.Request) error {
	host, port, addr := parseRequestAddress(r)
	action, arg := acl.ActionProxy, ""
	var ipAddr *net.IPAddr
	var resErr error
	if s.ACLEngine != nil {
		action, arg, _, ipAddr, resErr = s.ACLEngine.ResolveAndMatch(host, port, false)
		// Doesn't always matter if the resolution fails, as we may send it through HyClient
	}
	s.TCPRequestFunc(c.RemoteAddr(), addr, action, arg)
	var closeErr error
	defer func() {
		s.TCPErrorFunc(c.RemoteAddr(), addr, closeErr)
	}()
	// Handle according to the action
	switch action {
	case acl.ActionDirect:
		if resErr != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = resErr
			return resErr
		}
		rc, err := s.Transport.DialTCP(&net.TCPAddr{
			IP:   ipAddr.IP,
			Port: int(port),
			Zone: ipAddr.Zone,
		})
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		defer rc.Close()
		_ = sendReply(c, socks5.RepSuccess)
		closeErr = utils.PipePairWithTimeout(c, rc, s.TCPTimeout)
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
		closeErr = utils.PipePairWithTimeout(c, rc, s.TCPTimeout)
		return nil
	case acl.ActionBlock:
		_ = sendReply(c, socks5.RepHostUnreachable)
		closeErr = errors.New("blocked in ACL")
		return nil
	case acl.ActionHijack:
		hijackIPAddr, err := s.Transport.ResolveIPAddr(arg)
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		rc, err := s.Transport.DialTCP(&net.TCPAddr{
			IP:   hijackIPAddr.IP,
			Port: int(port),
			Zone: hijackIPAddr.Zone,
		})
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		defer rc.Close()
		_ = sendReply(c, socks5.RepSuccess)
		closeErr = utils.PipePairWithTimeout(c, rc, s.TCPTimeout)
		return nil
	default:
		_ = sendReply(c, socks5.RepServerFailure)
		closeErr = fmt.Errorf("unknown action %d", action)
		return nil
	}
}

func (s *Server) handleUDP(c *net.TCPConn, r *socks5.Request) error {
	s.UDPAssociateFunc(c.RemoteAddr())
	var closeErr error
	defer func() {
		s.UDPErrorFunc(c.RemoteAddr(), closeErr)
	}()
	// Start local UDP server
	// Bind to the same address that the incoming TCP connection is sending to
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   c.LocalAddr().(*net.TCPAddr).IP,
		Zone: c.LocalAddr().(*net.TCPAddr).Zone,
		Port: 0, // Random port
	})
	if err != nil {
		_ = sendReply(c, socks5.RepServerFailure)
		closeErr = err
		return err
	}
	defer udpConn.Close()
	// Local UDP relay conn for ACL Direct
	var localRelayConn *net.UDPConn
	if s.ACLEngine != nil {
		localRelayConn, err = s.Transport.ListenUDP()
		if err != nil {
			_ = sendReply(c, socks5.RepServerFailure)
			closeErr = err
			return err
		}
		defer localRelayConn.Close()
	}
	// HyClient UDP session
	hyUDP, err := s.HyClient.DialUDP()
	if err != nil {
		_ = sendReply(c, socks5.RepServerFailure)
		closeErr = err
		return err
	}
	defer hyUDP.Close()
	// Send UDP server addr to the client
	// Same IP as TCP but a different port
	tcpLocalAddr := c.LocalAddr().(*net.TCPAddr)
	var atyp byte
	var addr, port []byte
	if ip4 := tcpLocalAddr.IP.To4(); ip4 != nil {
		atyp = socks5.ATYPIPv4
		addr = ip4
	} else if ip6 := tcpLocalAddr.IP.To16(); ip6 != nil {
		atyp = socks5.ATYPIPv6
		addr = ip6
	} else {
		_ = sendReply(c, socks5.RepServerFailure)
		closeErr = errors.New("invalid local addr")
		return closeErr
	}
	port = make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(udpConn.LocalAddr().(*net.UDPAddr).Port))
	_, _ = socks5.NewReply(socks5.RepSuccess, atyp, addr, port).WriteTo(c)
	// Let UDP server do its job, we hold the TCP connection here
	go s.udpServer(udpConn, localRelayConn, hyUDP)
	if s.TCPTimeout != 0 {
		// Disable TCP timeout for UDP holder
		_ = c.SetDeadline(time.Time{})
	}
	buf := make([]byte, 1024)
	for {
		_, err := c.Read(buf)
		if err != nil {
			closeErr = err
			break
		}
	}
	// As the TCP connection closes, so does the UDP server & HyClient session
	return nil
}

func (s *Server) udpServer(clientConn, localRelayConn *net.UDPConn, hyUDP cs.HyUDPConn) {
	var clientAddr *net.UDPAddr
	buf := make([]byte, udpBufferSize)
	// Local to remote
	for {
		n, cAddr, err := clientConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		d, err := socks5.NewDatagramFromBytes(buf[:n])
		if err != nil || d.Frag != 0 {
			// Ignore bad packets
			continue
		}
		if clientAddr == nil {
			// Whoever sends the first valid packet is our client
			clientAddr = cAddr
			// Start remote to local
			go func() {
				for {
					bs, from, err := hyUDP.ReadFrom()
					if err != nil {
						break
					}
					atyp, addr, port, err := socks5.ParseAddress(from)
					if err != nil {
						continue
					}
					if atyp == socks5.ATYPDomain {
						addr = addr[1:] // Remove the leading length byte
					}
					d := socks5.NewDatagram(atyp, addr, port, bs)
					_, _ = clientConn.WriteToUDP(d.Bytes(), clientAddr)
				}
			}()
			if localRelayConn != nil {
				go func() {
					buf := make([]byte, udpBufferSize)
					for {
						n, from, err := localRelayConn.ReadFrom(buf)
						if n > 0 {
							atyp, addr, port, err := socks5.ParseAddress(from.String())
							if err != nil {
								continue
							}
							if atyp == socks5.ATYPDomain {
								addr = addr[1:] // Remove the leading length byte
							}
							d := socks5.NewDatagram(atyp, addr, port, buf[:n])
							_, _ = clientConn.WriteToUDP(d.Bytes(), clientAddr)
						}
						if err != nil {
							break
						}
					}
				}()
			}
		} else if cAddr.String() != clientAddr.String() {
			// Not our client, bye
			continue
		}
		host, port, addr := parseDatagramRequestAddress(d)
		action, arg := acl.ActionProxy, ""
		var ipAddr *net.IPAddr
		var resErr error
		if s.ACLEngine != nil && localRelayConn != nil {
			action, arg, _, ipAddr, resErr = s.ACLEngine.ResolveAndMatch(host, port, true)
			// Doesn't always matter if the resolution fails, as we may send it through HyClient
		}
		// Handle according to the action
		switch action {
		case acl.ActionDirect:
			if resErr != nil {
				return
			}
			_, _ = localRelayConn.WriteToUDP(d.Data, &net.UDPAddr{
				IP:   ipAddr.IP,
				Port: int(port),
				Zone: ipAddr.Zone,
			})
		case acl.ActionProxy:
			_ = hyUDP.WriteTo(d.Data, addr)
		case acl.ActionBlock:
			// Do nothing
		case acl.ActionHijack:
			hijackIPAddr, err := s.Transport.ResolveIPAddr(arg)
			if err == nil {
				_, _ = localRelayConn.WriteToUDP(d.Data, &net.UDPAddr{
					IP:   hijackIPAddr.IP,
					Port: int(port),
					Zone: hijackIPAddr.Zone,
				})
			}
		default:
			// Do nothing
		}
	}
}

func sendReply(conn *net.TCPConn, rep byte) error {
	p := socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	_, err := p.WriteTo(conn)
	return err
}

func parseRequestAddress(r *socks5.Request) (host string, port uint16, addr string) {
	p := binary.BigEndian.Uint16(r.DstPort)
	if r.Atyp == socks5.ATYPDomain {
		d := string(r.DstAddr[1:])
		return d, p, net.JoinHostPort(d, strconv.Itoa(int(p)))
	} else {
		ipStr := net.IP(r.DstAddr).String()
		return ipStr, p, net.JoinHostPort(ipStr, strconv.Itoa(int(p)))
	}
}

func parseDatagramRequestAddress(r *socks5.Datagram) (host string, port uint16, addr string) {
	p := binary.BigEndian.Uint16(r.DstPort)
	if r.Atyp == socks5.ATYPDomain {
		d := string(r.DstAddr[1:])
		return d, p, net.JoinHostPort(d, strconv.Itoa(int(p)))
	} else {
		ipStr := net.IP(r.DstAddr).String()
		return ipStr, p, net.JoinHostPort(ipStr, strconv.Itoa(int(p)))
	}
}
