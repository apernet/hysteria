package pktconns

import (
	"net"

	"github.com/HyNetwork/hysteria/pkg/transport/pktconns/faketcp"
	"github.com/HyNetwork/hysteria/pkg/transport/pktconns/obfs"
	"github.com/HyNetwork/hysteria/pkg/transport/pktconns/udp"
	"github.com/HyNetwork/hysteria/pkg/transport/pktconns/wechat"
)

type (
	ClientPacketConnFunc func(server string) (net.PacketConn, error)
	ServerPacketConnFunc func(listen string) (net.PacketConn, error)
)

type (
	ClientPacketConnFuncFactory func(obfsPassword string) ClientPacketConnFunc
	ServerPacketConnFuncFactory func(obfsPassword string) ServerPacketConnFunc
)

func NewClientUDPConnFunc(obfsPassword string) ClientPacketConnFunc {
	if obfsPassword == "" {
		return func(server string) (net.PacketConn, error) {
			return net.ListenUDP("udp", nil)
		}
	} else {
		return func(server string) (net.PacketConn, error) {
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			return udp.NewObfsUDPConn(udpConn, ob), nil
		}
	}
}

func NewClientWeChatConnFunc(obfsPassword string) ClientPacketConnFunc {
	if obfsPassword == "" {
		return func(server string) (net.PacketConn, error) {
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			return wechat.NewObfsWeChatUDPConn(udpConn, nil), nil
		}
	} else {
		return func(server string) (net.PacketConn, error) {
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			return wechat.NewObfsWeChatUDPConn(udpConn, ob), nil
		}
	}
}

func NewClientFakeTCPConnFunc(obfsPassword string) ClientPacketConnFunc {
	if obfsPassword == "" {
		return func(server string) (net.PacketConn, error) {
			return faketcp.Dial("tcp", server)
		}
	} else {
		return func(server string) (net.PacketConn, error) {
			ob := obfs.NewXPlusObfuscator([]byte(obfsPassword))
			fakeTCPConn, err := faketcp.Dial("tcp", server)
			if err != nil {
				return nil, err
			}
			return faketcp.NewObfsFakeTCPConn(fakeTCPConn, ob), nil
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
