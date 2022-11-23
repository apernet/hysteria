package sdk

import (
	"net"
	"strings"
	"time"

	"github.com/apernet/hysteria/pkg/pktconns"
	"github.com/apernet/hysteria/pkg/pktconns/faketcp"
	"github.com/apernet/hysteria/pkg/pktconns/obfs"
	"github.com/apernet/hysteria/pkg/pktconns/udp"
	"github.com/apernet/hysteria/pkg/pktconns/wechat"
)

type (
	clientPacketConnFuncFactory func(obfsPassword string, hopInterval time.Duration,
		resolveFunc ResolveFunc, listenUDPFunc ListenUDPFunc) pktconns.ClientPacketConnFunc
)

var clientPacketConnFuncFactoryMap = map[Protocol]clientPacketConnFuncFactory{
	ProtocolUDP:     newClientUDPConnFunc,
	ProtocolWeChat:  newClientWeChatConnFunc,
	ProtocolFakeTCP: newClientFakeTCPConnFunc,
}

func resolveFuncToIPResolveFunc(resolveFunc ResolveFunc) func(network string, address string) (*net.IPAddr, error) {
	return func(network string, address string) (*net.IPAddr, error) {
		addr, err := resolveFunc(network, address)
		if err != nil {
			return nil, err
		}
		if ipAddr, ok := addr.(*net.IPAddr); ok {
			return ipAddr, nil
		}
		return nil, net.InvalidAddrError("not an IP address")
	}
}

func newClientUDPConnFunc(obfsPassword string, hopInterval time.Duration,
	resolveFunc ResolveFunc, listenUDPFunc ListenUDPFunc,
) pktconns.ClientPacketConnFunc {
	if obfsPassword == "" {
		return func(server string) (net.PacketConn, net.Addr, error) {
			if isMultiPortAddr(server) {
				return udp.NewObfsUDPHopClientPacketConn(server, hopInterval, nil,
					resolveFuncToIPResolveFunc(resolveFunc), listenUDPFunc)
			}
			sAddr, err := resolveFunc("udp", server)
			if err != nil {
				return nil, nil, err
			}
			udpConn, err := listenUDPFunc("udp", nil)
			return udpConn, sAddr, err
		}
	} else {
		return func(server string) (net.PacketConn, net.Addr, error) {
			if isMultiPortAddr(server) {
				ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
				return udp.NewObfsUDPHopClientPacketConn(server, hopInterval, ob,
					resolveFuncToIPResolveFunc(resolveFunc), listenUDPFunc)
			}
			sAddr, err := resolveFunc("udp", server)
			if err != nil {
				return nil, nil, err
			}
			udpConn, err := listenUDPFunc("udp", nil)
			if err != nil {
				return nil, nil, err
			}
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			return udp.NewObfsUDPConn(udpConn, ob), sAddr, nil
		}
	}
}

func newClientWeChatConnFunc(obfsPassword string, hopInterval time.Duration,
	resolveFunc ResolveFunc, listenUDPFunc ListenUDPFunc,
) pktconns.ClientPacketConnFunc {
	if obfsPassword == "" {
		return func(server string) (net.PacketConn, net.Addr, error) {
			sAddr, err := resolveFunc("udp", server)
			if err != nil {
				return nil, nil, err
			}
			udpConn, err := listenUDPFunc("udp", nil)
			if err != nil {
				return nil, nil, err
			}
			return wechat.NewObfsWeChatUDPConn(udpConn, nil), sAddr, nil
		}
	} else {
		return func(server string) (net.PacketConn, net.Addr, error) {
			sAddr, err := resolveFunc("udp", server)
			if err != nil {
				return nil, nil, err
			}
			udpConn, err := listenUDPFunc("udp", nil)
			if err != nil {
				return nil, nil, err
			}
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			return wechat.NewObfsWeChatUDPConn(udpConn, ob), sAddr, nil
		}
	}
}

func newClientFakeTCPConnFunc(obfsPassword string, hopInterval time.Duration,
	resolveFunc ResolveFunc, listenUDPFunc ListenUDPFunc,
) pktconns.ClientPacketConnFunc {
	if obfsPassword == "" {
		return func(server string) (net.PacketConn, net.Addr, error) {
			sAddr, err := resolveFunc("tcp", server)
			if err != nil {
				return nil, nil, err
			}
			fTCPConn, err := faketcp.Dial("tcp", server)
			return fTCPConn, sAddr, err
		}
	} else {
		return func(server string) (net.PacketConn, net.Addr, error) {
			sAddr, err := resolveFunc("tcp", server)
			if err != nil {
				return nil, nil, err
			}
			fTCPConn, err := faketcp.Dial("tcp", server)
			if err != nil {
				return nil, nil, err
			}
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			return faketcp.NewObfsFakeTCPConn(fTCPConn, ob), sAddr, nil
		}
	}
}

func isMultiPortAddr(addr string) bool {
	_, portStr, err := net.SplitHostPort(addr)
	if err == nil && (strings.Contains(portStr, ",") || strings.Contains(portStr, "-")) {
		return true
	}
	return false
}
