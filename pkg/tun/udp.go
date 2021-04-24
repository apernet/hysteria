package tun

import (
	"fmt"
	tun2socks "github.com/eycorsican/go-tun2socks/core"
	"github.com/tobyxdd/hysteria/pkg/core"
	"log"
	"net"
	"sync/atomic"
	"time"
)

type UDPConnInfo struct {
	hyConn core.UDPConn
	expire atomic.Value
}

func (s *Server) fetchUDPInput(conn tun2socks.UDPConn, ci *UDPConnInfo) {
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

	for {
		bs, from, err := ci.hyConn.ReadFrom()
		if err != nil {
			break
		}
		ci.expire.Store(time.Now().Add(s.Timeout))
		udpAddr, _ := net.ResolveUDPAddr("udp", from)
		_, _ = conn.WriteFrom(bs, udpAddr)
	}
}

func (s *Server) Connect(conn tun2socks.UDPConn, target *net.UDPAddr) error {
	c, err := s.HyClient.DialUDP()
	if err != nil {
		return err
	}
	ci := UDPConnInfo{
		hyConn: c,
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
		log.Printf("not connected: %s <-> %s\n", conn.LocalAddr().String(), addr.String())
		return fmt.Errorf("not connected: %s <-> %s", conn.LocalAddr().String(), addr.String())
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
