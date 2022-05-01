//go:build cgo
// +build cgo

package tun

import (
	tun2socks "github.com/eycorsican/go-tun2socks/core"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
)

func (s *Server) Handle(conn net.Conn, target *net.TCPAddr) error {
	if s.RequestFunc != nil {
		s.RequestFunc(conn.LocalAddr(), target.String())
	}
	var closeErr error
	defer func() {
		if s.ErrorFunc != nil && closeErr != nil {
			s.ErrorFunc(conn.LocalAddr(), target.String(), closeErr)
		}
	}()
	rc, err := s.HyClient.DialTCP(target.String())
	if err != nil {
		closeErr = err
		return err
	}
	go s.relayTCP(conn, rc)
	return nil
}

func (s *Server) relayTCP(clientConn, relayConn net.Conn) {
	closeErr := utils.PipePairWithTimeout(relayConn, clientConn, s.Timeout)
	if s.ErrorFunc != nil {
		s.ErrorFunc(clientConn.LocalAddr(), relayConn.RemoteAddr().String(), closeErr)
	}
	relayConn.Close()
	clientConn.Close()
	if closeErr != nil {
		if err, ok := closeErr.(net.Error); ok && err.Timeout() {
			if clientConn, ok := clientConn.(tun2socks.TCPConn); ok {
				clientConn.Abort()
			}
		}
	}
}
