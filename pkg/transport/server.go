package transport

import (
	"crypto/tls"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/tobyxdd/hysteria/pkg/conns/faketcp"
	"github.com/tobyxdd/hysteria/pkg/conns/udp"
	"github.com/tobyxdd/hysteria/pkg/conns/wechat"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"strconv"
	"time"
)

type ServerTransport struct {
	Dialer        *net.Dialer
	SOCKS5Client  *SOCKS5Client
	PrefEnabled   bool
	PrefIPv6      bool
	PrefExclusive bool
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

type PUDPConn interface {
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	WriteToUDP([]byte, *AddrEx) (int, error)
	Close() error
}

type udpConnPUDPConn struct {
	Conn *net.UDPConn
}

func (c *udpConnPUDPConn) ReadFromUDP(bytes []byte) (int, *net.UDPAddr, error) {
	return c.Conn.ReadFromUDP(bytes)
}

func (c *udpConnPUDPConn) WriteToUDP(bytes []byte, ex *AddrEx) (int, error) {
	return c.Conn.WriteToUDP(bytes, &net.UDPAddr{
		IP:   ex.IPAddr.IP,
		Port: ex.Port,
		Zone: ex.IPAddr.Zone,
	})
}

func (c *udpConnPUDPConn) Close() error {
	return c.Conn.Close()
}

var DefaultServerTransport = &ServerTransport{
	Dialer: &net.Dialer{
		Timeout: 8 * time.Second,
	},
	PrefEnabled: false,
}

func (st *ServerTransport) quicPacketConn(proto string, laddr string, obfs obfs.Obfuscator) (net.PacketConn, error) {
	if len(proto) == 0 || proto == "udp" {
		laddrU, err := net.ResolveUDPAddr("udp", laddr)
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP("udp", laddrU)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			oc := udp.NewObfsUDPConn(conn, obfs)
			return oc, nil
		} else {
			return conn, nil
		}
	} else if proto == "wechat-video" {
		laddrU, err := net.ResolveUDPAddr("udp", laddr)
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP("udp", laddrU)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			oc := wechat.NewObfsWeChatUDPConn(conn, obfs)
			return oc, nil
		} else {
			return conn, nil
		}
	} else if proto == "faketcp" {
		conn, err := faketcp.Listen("tcp", laddr)
		if err != nil {
			return nil, err
		}
		if obfs != nil {
			oc := faketcp.NewObfsFakeTCPConn(conn, obfs)
			return oc, nil
		} else {
			return conn, nil
		}
	} else {
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

func (st *ServerTransport) QUICListen(proto string, listen string, tlsConfig *tls.Config, quicConfig *quic.Config, obfs obfs.Obfuscator) (quic.Listener, error) {
	pktConn, err := st.quicPacketConn(proto, listen, obfs)
	if err != nil {
		return nil, err
	}
	l, err := quic.Listen(pktConn, tlsConfig, quicConfig)
	if err != nil {
		_ = pktConn.Close()
		return nil, err
	}
	return l, nil
}

func (st *ServerTransport) ResolveIPAddr(address string) (*net.IPAddr, bool, error) {
	ip, zone := utils.ParseIPZone(address)
	if ip != nil {
		return &net.IPAddr{IP: ip, Zone: zone}, false, nil
	}
	if st.PrefEnabled {
		ipAddr, err := resolveIPAddrWithPreference(address, st.PrefIPv6, st.PrefExclusive)
		return ipAddr, true, err
	} else {
		ipAddr, err := net.ResolveIPAddr("ip", address)
		return ipAddr, true, err
	}
}

func (st *ServerTransport) DialTCP(raddr *AddrEx) (*net.TCPConn, error) {
	if st.SOCKS5Client != nil {
		return st.SOCKS5Client.DialTCP(raddr)
	} else {
		conn, err := st.Dialer.Dial("tcp", raddr.String())
		if err != nil {
			return nil, err
		}
		return conn.(*net.TCPConn), nil
	}
}

func (st *ServerTransport) ListenUDP() (PUDPConn, error) {
	if st.SOCKS5Client != nil {
		return st.SOCKS5Client.ListenUDP()
	} else {
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		return &udpConnPUDPConn{
			Conn: conn,
		}, nil
	}
}

func (st *ServerTransport) SOCKS5Enabled() bool {
	return st.SOCKS5Client != nil
}
