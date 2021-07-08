// +build cgo

package tun

import (
	"bytes"
	"errors"
	"fmt"
	tun2socks "github.com/eycorsican/go-tun2socks/core"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/core"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

const udpBufferSize = 65535

type udpConnInfo struct {
	hyConn core.UDPConn
	target string
	expire atomic.Value
}

func (s *Server) fetchUDPInput(conn tun2socks.UDPConn, ci *udpConnInfo) {
	defer func() {
		s.closeUDPConn(conn)
	}()

	if s.Timeout > 0 {
		go func() {
			for {
				life := ci.expire.Load().(time.Time).Sub(time.Now())
				if life < 0 {
					s.closeUDPConn(conn)
					break
				} else {
					time.Sleep(life)
				}
			}
		}()
	}

	var err error

	for {
		var bs []byte
		var from string
		bs, from, err = ci.hyConn.ReadFrom()
		if err != nil {
			break
		}
		ci.expire.Store(time.Now().Add(s.Timeout))
		udpAddr, _ := net.ResolveUDPAddr("udp", from)
		_, err = conn.WriteFrom(bs, udpAddr)
		if err != nil {
			break
		}
	}

	if s.ErrorFunc != nil {
		s.ErrorFunc(conn.LocalAddr(), ci.target, err)
	}
}

func (s *Server) Connect(conn tun2socks.UDPConn, target *net.UDPAddr) error {
	action, arg := acl.ActionProxy, ""
	var resErr error
	if s.ACLEngine != nil {
		action, arg, _, resErr = s.ACLEngine.ResolveAndMatch(target.IP.String())
	}
	if s.RequestFunc != nil {
		s.RequestFunc(conn.LocalAddr(), target.String(), action, arg)
	}
	var hyConn core.UDPConn
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
		var relayConn net.Conn
		relayConn, closeErr = s.Transport.LocalDial("udp", target.String())
		if closeErr != nil {
			return closeErr
		}
		hyConn = &delegatedUDPConn{
			underlayConn:        relayConn,
			delegatedRemoteAddr: target.String(),
		}
	case acl.ActionProxy:
		hyConn, closeErr = s.HyClient.DialUDP()
		if closeErr != nil {
			return closeErr
		}
	case acl.ActionBlock:
		closeErr = errors.New("blocked in ACL")
		return closeErr
	case acl.ActionHijack:
		hijackAddr := net.JoinHostPort(arg, strconv.Itoa(target.Port))
		var relayConn net.Conn
		relayConn, closeErr = s.Transport.LocalDial("udp", hijackAddr)
		if closeErr != nil {
			return closeErr
		}
		hyConn = &delegatedUDPConn{
			underlayConn:        relayConn,
			delegatedRemoteAddr: target.String(),
		}
	default:
		closeErr = fmt.Errorf("unknown action %d", action)
		return nil
	}
	ci := udpConnInfo{
		hyConn: hyConn,
		target: net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port)),
	}
	ci.expire.Store(time.Now().Add(s.Timeout))
	s.udpConnMapLock.Lock()
	s.udpConnMap[conn] = &ci
	s.udpConnMapLock.Unlock()
	go s.fetchUDPInput(conn, &ci)
	return nil
}

func (s *Server) ReceiveTo(conn tun2socks.UDPConn, data []byte, addr *net.UDPAddr) error {
	s.udpConnMapLock.RLock()
	ci, ok := s.udpConnMap[conn]
	s.udpConnMapLock.RUnlock()
	if !ok {
		err := errors.New("previous connection closed for timeout")
		s.ErrorFunc(conn.LocalAddr(), addr.String(), err)
		return err
	}
	ci.expire.Store(time.Now().Add(s.Timeout))
	_ = ci.hyConn.WriteTo(data, addr.String())
	return nil
}

func (s *Server) closeUDPConn(conn tun2socks.UDPConn) {
	conn.Close()
	s.udpConnMapLock.Lock()
	defer s.udpConnMapLock.Unlock()
	if c, ok := s.udpConnMap[conn]; ok {
		c.hyConn.Close()
		delete(s.udpConnMap, conn)
	}
}

type delegatedUDPConn struct {
	underlayConn        net.Conn
	delegatedRemoteAddr string
}

func (c *delegatedUDPConn) ReadFrom() (bs []byte, addr string, err error) {
	buf := make([]byte, udpBufferSize)
	n, err := c.underlayConn.Read(buf)
	if n > 0 {
		bs = append(bs, buf[0:n]...)
	}
	if err != nil || err == io.EOF {
		addr = c.delegatedRemoteAddr
	}
	return
}

func (c *delegatedUDPConn) WriteTo(bs []byte, addr string) error {
	_, err := io.Copy(c.underlayConn, bytes.NewReader(bs))
	return err
}

func (c *delegatedUDPConn) Close() error {
	return c.underlayConn.Close()
}
