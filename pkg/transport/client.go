package transport

import (
	"crypto/tls"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/tobyxdd/hysteria/pkg/conns/faketcp"
	"github.com/tobyxdd/hysteria/pkg/conns/udp"
	"github.com/tobyxdd/hysteria/pkg/conns/wechat"
	"github.com/tobyxdd/hysteria/pkg/obfs"
	"net"
	"time"
)

type ClientTransport struct {
	Dialer        *net.Dialer
	PrefEnabled   bool
	PrefIPv6      bool
	PrefExclusive bool
}

var DefaultClientTransport = &ClientTransport{
	Dialer: &net.Dialer{
		Timeout: 8 * time.Second,
	},
	PrefEnabled: false,
}

func (ct *ClientTransport) quicPacketConn(proto string, server string, obfs obfs.Obfuscator) (net.PacketConn, error) {
	if len(proto) == 0 || proto == "udp" {
		conn, err := net.ListenUDP("udp", nil)
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
		conn, err := net.ListenUDP("udp", nil)
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
		var conn *faketcp.TCPConn
		conn, err := faketcp.Dial("tcp", server)
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

func (ct *ClientTransport) QUICDial(proto string, server string, tlsConfig *tls.Config, quicConfig *quic.Config, obfs obfs.Obfuscator) (quic.Connection, error) {
	serverUDPAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	pktConn, err := ct.quicPacketConn(proto, server, obfs)
	if err != nil {
		return nil, err
	}
	qs, err := quic.Dial(pktConn, serverUDPAddr, server, tlsConfig, quicConfig)
	if err != nil {
		_ = pktConn.Close()
		return nil, err
	}
	return qs, nil
}

func (ct *ClientTransport) ResolveIPAddr(address string) (*net.IPAddr, error) {
	if ct.PrefEnabled {
		return resolveIPAddrWithPreference(address, ct.PrefIPv6, ct.PrefExclusive)
	} else {
		return net.ResolveIPAddr("ip", address)
	}
}

func (ct *ClientTransport) DialTCP(raddr *net.TCPAddr) (*net.TCPConn, error) {
	conn, err := ct.Dialer.Dial("tcp", raddr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

func (ct *ClientTransport) ListenUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp", nil)
}
