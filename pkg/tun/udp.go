//go:build cgo
// +build cgo

package tun

import (
	"errors"
	tun2socks "github.com/eycorsican/go-tun2socks/core"
	"github.com/tobyxdd/hysteria/pkg/core"
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
	if s.RequestFunc != nil {
		s.RequestFunc(conn.LocalAddr(), target.String())
	}
	var hyConn core.UDPConn
	var closeErr error
	defer func() {
		if s.ErrorFunc != nil && closeErr != nil {
			s.ErrorFunc(conn.LocalAddr(), target.String(), closeErr)
		}
	}()
	hyConn, closeErr = s.HyClient.DialUDP()
	if closeErr != nil {
		return closeErr
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
