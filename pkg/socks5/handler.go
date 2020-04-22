package socks5

import (
	"github.com/tobyxdd/hysteria/internal/utils"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/txthinking/socks5"
	"io"
	"net"
	"time"
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
			_ = sendReply(request, conn, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		// All good
		_ = sendReply(request, conn, socks5.RepSuccess)
		defer rc.Close()
		closeErr = pipePair(conn, rc, server.TCPDeadline)
		return nil
	} else {
		_ = sendReply(request, conn, socks5.RepCommandNotSupported)
		return ErrUnsupportedCmd
	}
}

func (h *HyHandler) UDPHandle(server *Server, addr *net.UDPAddr, datagram *socks5.Datagram) error {
	// Not supported for now
	return nil
}

func sendReply(request *socks5.Request, conn *net.TCPConn, rep byte) error {
	var p *socks5.Reply
	if request.Atyp == socks5.ATYPIPv4 || request.Atyp == socks5.ATYPDomain {
		p = socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	} else {
		p = socks5.NewReply(rep, socks5.ATYPIPv6, net.IPv6zero, []byte{0x00, 0x00})
	}
	_, err := p.WriteTo(conn)
	return err
}

func pipePair(conn *net.TCPConn, stream io.ReadWriteCloser, deadline int) error {
	errChan := make(chan error, 2)
	// TCP to stream
	go func() {
		buf := make([]byte, utils.PipeBufferSize)
		for {
			if deadline != 0 {
				_ = conn.SetDeadline(time.Now().Add(time.Duration(deadline) * time.Second))
			}
			rn, err := conn.Read(buf)
			if rn > 0 {
				_, err := stream.Write(buf[:rn])
				if err != nil {
					errChan <- err
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	// Stream to TCP
	go func() {
		errChan <- utils.Pipe(stream, conn, nil)
	}()
	return <-errChan
}
