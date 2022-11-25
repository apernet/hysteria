//go:build gpl
// +build gpl

package tun

import (
	"net"

	"github.com/apernet/hysteria/core/utils"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
)

func (s *Server) HandleTCP(localConn adapter.TCPConn) {
	go s.handleTCPConn(localConn)
}

func (s *Server) handleTCPConn(localConn adapter.TCPConn) {
	defer localConn.Close()

	id := localConn.ID()
	remoteAddr := net.TCPAddr{
		IP:   net.IP(id.LocalAddress),
		Port: int(id.LocalPort),
	}
	localAddr := net.TCPAddr{
		IP:   net.IP(id.RemoteAddress),
		Port: int(id.RemotePort),
	}

	if s.RequestFunc != nil {
		s.RequestFunc(&localAddr, remoteAddr.String())
	}

	var err error
	defer func() {
		if s.ErrorFunc != nil && err != nil {
			s.ErrorFunc(&localAddr, remoteAddr.String(), err)
		}
	}()

	rc, err := s.HyClient.DialTCP(remoteAddr.String())
	if err != nil {
		return
	}
	defer rc.Close()

	err = utils.PipePairWithTimeout(localConn, rc, s.Timeout)
}
