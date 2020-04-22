package socks5

import (
	"github.com/tobyxdd/hysteria/internal/utils"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/txthinking/socks5"
	"net"
)

type HyHandler struct {
	Client               core.Client
	NewTCPRequestFunc    func(addr, reqAddr string)
	TCPRequestClosedFunc func(addr, reqAddr string, err error)
}

func (h *HyHandler) TCPHandle(server *Server, conn *net.TCPConn, request *socks5.Request) error {
	if request.Cmd == socks5.CmdConnect {
		h.NewTCPRequestFunc(conn.RemoteAddr().String(), request.Address())
		var closeErr error
		defer func() {
			h.TCPRequestClosedFunc(conn.RemoteAddr().String(), request.Address(), closeErr)
		}()
		rc, err := h.Client.Dial(false, request.Address())
		if err != nil {
			_ = sendFailed(request, conn, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		// All good
		p := socks5.NewReply(socks5.RepSuccess, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		_, _ = p.WriteTo(conn)
		defer rc.Close()
		closeErr = utils.PipePair(conn, rc, nil, nil)
		return nil
	} else {
		p := socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		_, _ = p.WriteTo(conn)
		return ErrUnsupportedCmd
	}
}

func (h *HyHandler) UDPHandle(server *Server, addr *net.UDPAddr, datagram *socks5.Datagram) error {
	// Not supported for now
	return nil
}

func sendFailed(request *socks5.Request, conn *net.TCPConn, rep byte) error {
	var p *socks5.Reply
	if request.Atyp == socks5.ATYPIPv4 || request.Atyp == socks5.ATYPDomain {
		p = socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	} else {
		p = socks5.NewReply(rep, socks5.ATYPIPv6, net.IPv6zero, []byte{0x00, 0x00})
	}
	_, err := p.WriteTo(conn)
	return err
}
