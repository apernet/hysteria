package transport

import (
	"net"
	"strconv"
	"time"

	"github.com/apernet/hysteria/core/sockopt"
	"github.com/apernet/hysteria/core/utils"
)

type ServerTransport struct {
	Dialer            *net.Dialer
	SOCKS5Client      *SOCKS5Client
	ResolvePreference ResolvePreference
	LocalUDPAddr      *net.UDPAddr
	LocalUDPIntf      *net.Interface
}

// AddrEx is like net.TCPAddr or net.UDPAddr, but with additional domain information for SOCKS5.
// At least one of Domain and IPAddr must be non-empty.
type AddrEx struct {
	Domain string
	IPAddr *net.IPAddr
	Port   int
}

func (a *AddrEx) String() string {
	if a == nil {
		return "<nil>"
	}
	var ip string
	if a.IPAddr != nil {
		ip = a.IPAddr.String()
	}
	return net.JoinHostPort(ip, strconv.Itoa(a.Port))
}

type STPacketConn interface {
	ReadFrom([]byte) (int, *net.UDPAddr, error)
	WriteTo([]byte, *AddrEx) (int, error)
	Close() error
}

type udpSTPacketConn struct {
	Conn *net.UDPConn
}

func (c *udpSTPacketConn) ReadFrom(bytes []byte) (int, *net.UDPAddr, error) {
	return c.Conn.ReadFromUDP(bytes)
}

func (c *udpSTPacketConn) WriteTo(bytes []byte, ex *AddrEx) (int, error) {
	return c.Conn.WriteToUDP(bytes, &net.UDPAddr{
		IP:   ex.IPAddr.IP,
		Port: ex.Port,
		Zone: ex.IPAddr.Zone,
	})
}

func (c *udpSTPacketConn) Close() error {
	return c.Conn.Close()
}

var DefaultServerTransport = &ServerTransport{
	Dialer: &net.Dialer{
		Timeout: 8 * time.Second,
	},
	ResolvePreference: ResolvePreferenceDefault,
}

func (st *ServerTransport) ParseIPAddr(address string) (*net.IPAddr, bool) {
	ip, zone := utils.ParseIPZone(address)
	if ip != nil {
		return &net.IPAddr{IP: ip, Zone: zone}, false
	}
	return nil, true
}

func (st *ServerTransport) ResolveIPAddr(address string) (*net.IPAddr, bool, error) {
	ip, isDomain := st.ParseIPAddr(address)
	if !isDomain {
		return ip, false, nil
	}
	ipAddr, err := resolveIPAddrWithPreference(address, st.ResolvePreference)
	return ipAddr, true, err
}

func (st *ServerTransport) DialTCP(raddr *AddrEx) (*net.TCPConn, error) {
	if st.SOCKS5Client != nil {
		conn, err := st.SOCKS5Client.DialTCP(raddr)
		if err != nil {
			return nil, err
		}
		return conn.(*net.TCPConn), nil
	} else {
		conn, err := st.Dialer.Dial("tcp", raddr.String())
		if err != nil {
			return nil, err
		}
		return conn.(*net.TCPConn), nil
	}
}

func (st *ServerTransport) ListenUDP() (STPacketConn, error) {
	if st.SOCKS5Client != nil {
		return st.SOCKS5Client.ListenUDP()
	} else {
		conn, err := net.ListenUDP("udp", st.LocalUDPAddr)
		if err != nil {
			return nil, err
		}
		if st.LocalUDPIntf != nil {
			err = sockopt.BindUDPConn("udp", conn, st.LocalUDPIntf)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
		}
		return &udpSTPacketConn{
			Conn: conn,
		}, nil
	}
}

func (st *ServerTransport) ProxyEnabled() bool {
	return st.SOCKS5Client != nil
}
