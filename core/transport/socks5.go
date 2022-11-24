package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/txthinking/socks5"
)

type SOCKS5Client struct {
	ServerTCPAddr *net.TCPAddr
	Username      string
	Password      string
	NegTimeout    time.Duration
}

func NewSOCKS5Client(serverAddr string, username string, password string, negTimeout time.Duration) (*SOCKS5Client, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	return &SOCKS5Client{
		ServerTCPAddr: tcpAddr,
		Username:      username,
		Password:      password,
		NegTimeout:    negTimeout,
	}, nil
}

func (c *SOCKS5Client) negotiate(conn *net.TCPConn) error {
	m := []byte{socks5.MethodNone}
	if c.Username != "" && c.Password != "" {
		m = append(m, socks5.MethodUsernamePassword)
	}
	rq := socks5.NewNegotiationRequest(m)
	_, err := rq.WriteTo(conn)
	if err != nil {
		return err
	}
	rs, err := socks5.NewNegotiationReplyFrom(conn)
	if err != nil {
		return err
	}
	if rs.Method == socks5.MethodUsernamePassword {
		urq := socks5.NewUserPassNegotiationRequest([]byte(c.Username), []byte(c.Password))
		_, err = urq.WriteTo(conn)
		if err != nil {
			return err
		}
		urs, err := socks5.NewUserPassNegotiationReplyFrom(conn)
		if err != nil {
			return err
		}
		if urs.Status != socks5.UserPassStatusSuccess {
			return errors.New("username or password error")
		}
	} else if rs.Method != socks5.MethodNone {
		return errors.New("unsupported auth method")
	}
	return nil
}

func (c *SOCKS5Client) request(conn *net.TCPConn, r *socks5.Request) (*socks5.Reply, error) {
	if _, err := r.WriteTo(conn); err != nil {
		return nil, err
	}
	reply, err := socks5.NewReplyFrom(conn)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *SOCKS5Client) DialTCP(raddr *AddrEx) (*net.TCPConn, error) {
	conn, err := net.DialTCP("tcp", nil, c.ServerTCPAddr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(c.NegTimeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	err = c.negotiate(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	atyp, addr, port, err := addrExToSOCKS5Addr(raddr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	r := socks5.NewRequest(socks5.CmdConnect, atyp, addr, port)
	reply, err := c.request(conn, r)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if reply.Rep != socks5.RepSuccess {
		_ = conn.Close()
		return nil, fmt.Errorf("request failed: %d", reply.Rep)
	}
	// Negotiation succeed, disable timeout
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *SOCKS5Client) ListenUDP() (STPacketConn, error) {
	conn, err := net.DialTCP("tcp", nil, c.ServerTCPAddr)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(c.NegTimeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	err = c.negotiate(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	r := socks5.NewRequest(socks5.CmdUDP, socks5.ATYPIPv4, nil, nil)
	reply, err := c.request(conn, r)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if reply.Rep != socks5.RepSuccess {
		_ = conn.Close()
		return nil, fmt.Errorf("request failed: %d", reply.Rep)
	}
	// Negotiation succeed, disable timeout
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	udpRelayAddr, err := socks5AddrToUDPAddr(reply.Atyp, reply.BndAddr, reply.BndPort)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	udpConn, err := net.DialUDP("udp", nil, udpRelayAddr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	sc := &socks5UDPConn{
		tcpConn: conn,
		udpConn: udpConn,
	}
	go sc.hold()
	return sc, nil
}

type socks5UDPConn struct {
	tcpConn *net.TCPConn
	udpConn *net.UDPConn
}

func (c *socks5UDPConn) hold() {
	buf := make([]byte, 1024)
	for {
		_, err := c.tcpConn.Read(buf)
		if err != nil {
			break
		}
	}
	_ = c.tcpConn.Close()
	_ = c.udpConn.Close()
}

func (c *socks5UDPConn) ReadFrom(b []byte) (int, *net.UDPAddr, error) {
	n, err := c.udpConn.Read(b)
	if err != nil {
		return 0, nil, err
	}
	d, err := socks5.NewDatagramFromBytes(b[:n])
	if err != nil {
		return 0, nil, err
	}
	addr, err := socks5AddrToUDPAddr(d.Atyp, d.DstAddr, d.DstPort)
	if err != nil {
		return 0, nil, err
	}
	n = copy(b, d.Data)
	return n, addr, nil
}

func (c *socks5UDPConn) WriteTo(b []byte, addr *AddrEx) (int, error) {
	atyp, dstAddr, dstPort, err := addrExToSOCKS5Addr(addr)
	if err != nil {
		return 0, err
	}
	d := socks5.NewDatagram(atyp, dstAddr, dstPort, b)
	_, err = c.udpConn.Write(d.Bytes())
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

func socks5AddrToUDPAddr(atyp byte, addr []byte, port []byte) (*net.UDPAddr, error) {
	iPort := int(binary.BigEndian.Uint16(port))
	switch atyp {
	case socks5.ATYPIPv4:
		if len(addr) != 4 {
			return nil, errors.New("invalid ipv4 address")
		}
		return &net.UDPAddr{
			IP:   addr,
			Port: iPort,
		}, nil
	case socks5.ATYPIPv6:
		if len(addr) != 16 {
			return nil, errors.New("invalid ipv6 address")
		}
		return &net.UDPAddr{
			IP:   addr,
			Port: iPort,
		}, nil
	case socks5.ATYPDomain:
		if len(addr) <= 1 {
			return nil, errors.New("invalid domain address")
		}
		ipAddr, err := net.ResolveIPAddr("ip", string(addr[1:]))
		if err != nil {
			return nil, err
		}
		return &net.UDPAddr{
			IP:   ipAddr.IP,
			Port: iPort,
			Zone: ipAddr.Zone,
		}, nil
	default:
		return nil, errors.New("unsupported address type")
	}
}

func addrExToSOCKS5Addr(addr *AddrEx) (byte, []byte, []byte, error) {
	sport := make([]byte, 2)
	binary.BigEndian.PutUint16(sport, uint16(addr.Port))
	if len(addr.Domain) > 0 {
		return socks5.ATYPDomain, []byte(addr.Domain), sport, nil
	} else {
		var atyp byte
		var saddr []byte
		if ip4 := addr.IPAddr.IP.To4(); ip4 != nil {
			atyp = socks5.ATYPIPv4
			saddr = ip4
		} else if ip6 := addr.IPAddr.IP.To16(); ip6 != nil {
			atyp = socks5.ATYPIPv6
			saddr = ip6
		} else {
			return 0, nil, nil, errors.New("unsupported address type")
		}
		return atyp, saddr, sport, nil
	}
}
