package core

import "net"

type Transport interface {
	QUICResolveUDPAddr(address string) (*net.UDPAddr, error)
	QUICListenUDP(laddr *net.UDPAddr) (*net.UDPConn, error)

	OutResolveIPAddr(address string) (*net.IPAddr, error)
	OutResolveUDPAddr(address string) (*net.UDPAddr, error)
	OutDial(network, address string) (net.Conn, error)
	OutDialTCP(laddr, raddr *net.TCPAddr) (*net.TCPConn, error)
	OutListenUDP(laddr *net.UDPAddr) (*net.UDPConn, error)
}
