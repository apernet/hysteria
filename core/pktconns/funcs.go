package pktconns

import (
	"net"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/pktconns/faketcp"
	"github.com/apernet/hysteria/core/pktconns/obfs"
	"github.com/apernet/hysteria/core/pktconns/udp"
	"github.com/apernet/hysteria/core/pktconns/wechat"
)

type (
	ClientPacketConnFunc func(server string) (net.PacketConn, net.Addr, error)
	ServerPacketConnFunc func(listen string) (net.PacketConn, error)
)

type (
	ClientPacketConnFuncFactory func(obfsPassword string, hopInterval time.Duration) ClientPacketConnFunc
	ServerPacketConnFuncFactory func(obfsPassword string) ServerPacketConnFunc
)

func NewClientUDPConnFunc(obfsPassword string, hopInterval time.Duration) ClientPacketConnFunc {
	if obfsPassword == "" {
		return func(server string) (net.PacketConn, net.Addr, error) {
			if isMultiPortAddr(server) {
				return udp.NewObfsUDPHopClientPacketConn(server, hopInterval, nil)
			}
			sAddr, err := net.ResolveUDPAddr("udp", server)
			if err != nil {
				return nil, nil, err
			}
			udpConn, err := net.ListenUDP("udp", nil)
			return udpConn, sAddr, err
		}
	} else {
		return func(server string) (net.PacketConn, net.Addr, error) {
			if isMultiPortAddr(server) {
				ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
				return udp.NewObfsUDPHopClientPacketConn(server, hopInterval, ob)
			}
			sAddr, err := net.ResolveUDPAddr("udp", server)
			if err != nil {
				return nil, nil, err
			}
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, nil, err
			}
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			return udp.NewObfsUDPConn(udpConn, ob), sAddr, nil
		}
	}
}

func NewClientWeChatConnFunc(obfsPassword string, hopInterval time.Duration) ClientPacketConnFunc {
	if obfsPassword == "" {
		return func(server string) (net.PacketConn, net.Addr, error) {
			sAddr, err := net.ResolveUDPAddr("udp", server)
			if err != nil {
				return nil, nil, err
			}
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, nil, err
			}
			return wechat.NewObfsWeChatUDPConn(udpConn, nil), sAddr, nil
		}
	} else {
		return func(server string) (net.PacketConn, net.Addr, error) {
			sAddr, err := net.ResolveUDPAddr("udp", server)
			if err != nil {
				return nil, nil, err
			}
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, nil, err
			}
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			return wechat.NewObfsWeChatUDPConn(udpConn, ob), sAddr, nil
		}
	}
}

func NewClientFakeTCPConnFunc(obfsPassword string, hopInterval time.Duration) ClientPacketConnFunc {
	if obfsPassword == "" {
		return func(server string) (net.PacketConn, net.Addr, error) {
			sAddr, err := net.ResolveTCPAddr("tcp", server)
			if err != nil {
				return nil, nil, err
			}
			fTCPConn, err := faketcp.Dial("tcp", server)
			return fTCPConn, sAddr, err
		}
	} else {
		return func(server string) (net.PacketConn, net.Addr, error) {
			sAddr, err := net.ResolveTCPAddr("tcp", server)
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

func NewServerUDPConnFunc(obfsPassword string) ServerPacketConnFunc {
	if obfsPassword == "" {
		return func(listen string) (net.PacketConn, error) {
			laddrU, err := net.ResolveUDPAddr("udp", listen)
			if err != nil {
				return nil, err
			}
			return net.ListenUDP("udp", laddrU)
		}
	} else {
		return func(listen string) (net.PacketConn, error) {
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			laddrU, err := net.ResolveUDPAddr("udp", listen)
			if err != nil {
				return nil, err
			}
			udpConn, err := net.ListenUDP("udp", laddrU)
			if err != nil {
				return nil, err
			}
			return udp.NewObfsUDPConn(udpConn, ob), nil
		}
	}
}

func NewServerWeChatConnFunc(obfsPassword string) ServerPacketConnFunc {
	if obfsPassword == "" {
		return func(listen string) (net.PacketConn, error) {
			laddrU, err := net.ResolveUDPAddr("udp", listen)
			if err != nil {
				return nil, err
			}
			udpConn, err := net.ListenUDP("udp", laddrU)
			if err != nil {
				return nil, err
			}
			return wechat.NewObfsWeChatUDPConn(udpConn, nil), nil
		}
	} else {
		return func(listen string) (net.PacketConn, error) {
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			laddrU, err := net.ResolveUDPAddr("udp", listen)
			if err != nil {
				return nil, err
			}
			udpConn, err := net.ListenUDP("udp", laddrU)
			if err != nil {
				return nil, err
			}
			return wechat.NewObfsWeChatUDPConn(udpConn, ob), nil
		}
	}
}

func NewServerFakeTCPConnFunc(obfsPassword string) ServerPacketConnFunc {
	if obfsPassword == "" {
		return func(listen string) (net.PacketConn, error) {
			return faketcp.Listen("tcp", listen)
		}
	} else {
		return func(listen string) (net.PacketConn, error) {
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			fakeTCPListener, err := faketcp.Listen("tcp", listen)
			if err != nil {
				return nil, err
			}
			return faketcp.NewObfsFakeTCPConn(fakeTCPListener, ob), nil
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
