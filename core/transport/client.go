package transport

import (
	"net"
	"time"
)

type ClientTransport struct {
	Dialer            *net.Dialer
	ResolvePreference ResolvePreference
}

var DefaultClientTransport = &ClientTransport{
	Dialer: &net.Dialer{
		Timeout: 8 * time.Second,
	},
	ResolvePreference: ResolvePreferenceDefault,
}

func (ct *ClientTransport) ResolveIPAddr(address string) (*net.IPAddr, error) {
	return resolveIPAddrWithPreference(address, ct.ResolvePreference)
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
