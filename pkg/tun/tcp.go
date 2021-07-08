// +build cgo

package tun

import (
	"errors"
	"fmt"
	tun2socks "github.com/eycorsican/go-tun2socks/core"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"strconv"
)

func (s *Server) Handle(conn net.Conn, target *net.TCPAddr) error {
	action, arg := acl.ActionProxy, ""
	var resErr error
	if s.ACLEngine != nil {
		action, arg, _, resErr = s.ACLEngine.ResolveAndMatch(target.IP.String())
	}
	if s.RequestFunc != nil {
		s.RequestFunc(conn.LocalAddr(), target.String(), action, arg)
	}
	var closeErr error
	defer func() {
		if s.ErrorFunc != nil && closeErr != nil {
			s.ErrorFunc(conn.LocalAddr(), target.String(), closeErr)
		}
	}()
	switch action {
	case acl.ActionDirect:
		if resErr != nil {
			closeErr = resErr
			return resErr
		}
		rc, err := s.Transport.LocalDialTCP(nil, target)
		if err != nil {
			closeErr = err
			return err
		}
		go s.relayTCP(conn, rc)
		return nil
	case acl.ActionProxy:
		rc, err := s.HyClient.DialTCP(target.String())
		if err != nil {
			closeErr = err
			return err
		}
		go s.relayTCP(conn, rc)
		return nil
	case acl.ActionBlock:
		closeErr = errors.New("blocked in ACL")
		// caller will abort the connection when err != nil
		return closeErr
	case acl.ActionHijack:
		rc, err := s.Transport.LocalDial("tcp", net.JoinHostPort(arg, strconv.Itoa(target.Port)))
		if err != nil {
			closeErr = err
			return err
		}
		go s.relayTCP(conn, rc)
		return nil
	default:
		closeErr = fmt.Errorf("unknown action %d", action)
		// caller will abort the connection when err != nil
		return closeErr
	}
}

func (s *Server) relayTCP(clientConn, relayConn net.Conn) {
	closeErr := utils.PipePairWithTimeout(relayConn, clientConn, s.Timeout)
	if s.ErrorFunc != nil {
		s.ErrorFunc(clientConn.LocalAddr(), relayConn.RemoteAddr().String(), closeErr)
	}
	relayConn.Close()
	clientConn.Close()
	if closeErr != nil && closeErr.Error() == "deadline exceeded" {
		if clientConn, ok := clientConn.(tun2socks.TCPConn); ok {
			clientConn.Abort()
		}
	}
}
