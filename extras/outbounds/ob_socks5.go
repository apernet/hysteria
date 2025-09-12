package outbounds

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/txthinking/socks5"
)

const (
	socks5NegotiationTimeout = 10 * time.Second
	socks5RequestTimeout     = 10 * time.Second
)

var errSOCKS5AuthFailed = errors.New("SOCKS5 authentication failed")

type errSOCKS5UnsupportedAuthMethod struct {
	Method byte
}

func (e errSOCKS5UnsupportedAuthMethod) Error() string {
	return fmt.Sprintf("unsupported SOCKS5 authentication method: %d", e.Method)
}

type errSOCKS5RequestFailed struct {
	Rep byte
}

func (e errSOCKS5RequestFailed) Error() string {
	var msg string
	// RFC 1928
	switch e.Rep {
	case 0x00:
		msg = "succeeded"
	case 0x01:
		msg = "general SOCKS server failure"
	case 0x02:
		msg = "connection not allowed by ruleset"
	case 0x03:
		msg = "Network unreachable"
	case 0x04:
		msg = "Host unreachable"
	case 0x05:
		msg = "Connection refused"
	case 0x06:
		msg = "TTL expired"
	case 0x07:
		msg = "Command not supported"
	case 0x08:
		msg = "Address type not supported"
	default:
		msg = "undefined"
	}
	return fmt.Sprintf("SOCKS5 request failed: %s (%d)", msg, e.Rep)
}

// socks5Outbound is a PluggableOutbound that connects to the target using
// a SOCKS5 proxy server.
// Since SOCKS5 supports using either IP or domain name as the target address,
// it will ignore ResolveInfo in AddrEx and always only use Host.
type socks5Outbound struct {
	Dialer   *net.Dialer
	Addr     string
	Username string
	Password string
}

func NewSOCKS5Outbound(addr, username, password string) PluggableOutbound {
	return &socks5Outbound{
		Dialer: &net.Dialer{
			Timeout: defaultDialerTimeout,
		},
		Addr:     addr,
		Username: username,
		Password: password,
	}
}

// dialAndNegotiate creates a new TCP connection to the SOCKS5 proxy server
// and performs the negotiation. Returns an established connection ready to
// handle requests, or an error if the process fails.
func (o *socks5Outbound) dialAndNegotiate() (net.Conn, error) {
	conn, err := o.Dialer.Dial("tcp", o.Addr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(socks5NegotiationTimeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	authMethods := []byte{socks5.MethodNone}
	if o.Username != "" && o.Password != "" {
		authMethods = append(authMethods, socks5.MethodUsernamePassword)
	}
	req := socks5.NewNegotiationRequest(authMethods)
	if _, err := req.WriteTo(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp, err := socks5.NewNegotiationReplyFrom(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.Method == socks5.MethodUsernamePassword {
		upReq := socks5.NewUserPassNegotiationRequest([]byte(o.Username), []byte(o.Password))
		if _, err := upReq.WriteTo(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		upResp, err := socks5.NewUserPassNegotiationReplyFrom(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if upResp.Status != socks5.UserPassStatusSuccess {
			_ = conn.Close()
			return nil, errSOCKS5AuthFailed
		}
	} else if resp.Method != socks5.MethodNone {
		// We only support none & username/password authentication methods.
		_ = conn.Close()
		return nil, errSOCKS5UnsupportedAuthMethod{resp.Method}
	}
	// Negotiation succeeded, reset the deadline.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// request sends a SOCKS5 request to the proxy server and returns the reply.
// Note that it will return an error if the reply from the server indicates
// a failure.
func (o *socks5Outbound) request(conn net.Conn, req *socks5.Request) (*socks5.Reply, error) {
	if err := conn.SetDeadline(time.Now().Add(socks5RequestTimeout)); err != nil {
		return nil, err
	}
	if _, err := req.WriteTo(conn); err != nil {
		return nil, err
	}
	resp, err := socks5.NewReplyFrom(conn)
	if err != nil {
		return nil, err
	}
	if resp.Rep != socks5.RepSuccess {
		return nil, errSOCKS5RequestFailed{resp.Rep}
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *socks5Outbound) TCP(reqAddr *AddrEx) (net.Conn, error) {
	conn, err := s.dialAndNegotiate()
	if err != nil {
		return nil, err
	}
	atyp, dstAddr, dstPort := addrExToSOCKS5Addr(reqAddr)
	req := socks5.NewRequest(socks5.CmdConnect, atyp, dstAddr, dstPort)
	if _, err := s.request(conn, req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *socks5Outbound) UDP(reqAddr *AddrEx) (UDPConn, error) {
	conn, err := s.dialAndNegotiate()
	if err != nil {
		return nil, err
	}
	atyp, dstAddr, dstPort := addrExToSOCKS5Addr(reqAddr)
	req := socks5.NewRequest(socks5.CmdUDP, atyp, dstAddr, dstPort)
	resp, err := s.request(conn, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return newSOCKS5UDPConn(conn, resp.Address())
}

type socks5UDPConn struct {
	tcpConn net.Conn
	udpConn net.Conn
}

func newSOCKS5UDPConn(tcpConn net.Conn, udpAddr string) (*socks5UDPConn, error) {
	udpConn, err := net.Dial("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	sc := &socks5UDPConn{
		tcpConn: tcpConn,
		udpConn: udpConn,
	}
	go sc.hold()
	return sc, nil
}

func (c *socks5UDPConn) hold() {
	_, _ = io.Copy(io.Discard, c.tcpConn)
	_ = c.tcpConn.Close()
	_ = c.udpConn.Close()
}

func (c *socks5UDPConn) ReadFrom(b []byte) (int, *AddrEx, error) {
	n, err := c.udpConn.Read(b)
	if err != nil {
		return 0, nil, err
	}
	d, err := socks5.NewDatagramFromBytes(b[:n])
	if err != nil {
		return 0, nil, err
	}
	addr := socks5AddrToAddrEx(d.Atyp, d.DstAddr, d.DstPort)
	n = copy(b, d.Data)
	return n, addr, nil
}

func (c *socks5UDPConn) WriteTo(b []byte, addr *AddrEx) (int, error) {
	atyp, dstAddr, dstPort := addrExToSOCKS5Addr(addr)
	d := socks5.NewDatagram(atyp, dstAddr, dstPort, b)
	_, err := c.udpConn.Write(d.Bytes())
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socks5UDPConn) Close() error {
	_ = c.tcpConn.Close()
	_ = c.udpConn.Close()
	return nil
}

func addrExToSOCKS5Addr(addr *AddrEx) (atyp byte, dstAddr, dstPort []byte) {
	// Host
	ip := net.ParseIP(addr.Host)
	if ip != nil {
		if ip.To4() != nil {
			atyp = socks5.ATYPIPv4
			dstAddr = ip.To4()
		} else {
			atyp = socks5.ATYPIPv6
			dstAddr = ip.To16()
		}
	} else {
		atyp = socks5.ATYPDomain
		dstAddr = []byte(addr.Host)
	}
	// Port
	dstPort = make([]byte, 2)
	binary.BigEndian.PutUint16(dstPort, addr.Port)
	return atyp, dstAddr, dstPort
}

func socks5AddrToAddrEx(atyp byte, dstAddr, dstPort []byte) *AddrEx {
	// Host
	var host string
	if atyp == socks5.ATYPIPv4 {
		host = net.IP(dstAddr).To4().String()
	} else if atyp == socks5.ATYPIPv6 {
		host = net.IP(dstAddr).To16().String()
	} else if atyp == socks5.ATYPDomain {
		// Need to strip the first byte which is the domain length.
		host = string(dstAddr[1:])
	}
	// Port
	port := binary.BigEndian.Uint16(dstPort)
	return &AddrEx{
		Host: host,
		Port: port,
	}
}
