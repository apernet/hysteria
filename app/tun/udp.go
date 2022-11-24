//go:build gpl
// +build gpl

package tun

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/apernet/hysteria/core/cs"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
)

const udpBufferSize = 4096

func (s *Server) HandleUDP(conn adapter.UDPConn) {
	go s.handleUDPConn(conn)
}

func (s *Server) handleUDPConn(conn adapter.UDPConn) {
	defer conn.Close()

	id := conn.ID()
	remoteAddr := net.UDPAddr{
		IP:   net.IP(id.LocalAddress),
		Port: int(id.LocalPort),
	}
	localAddr := net.UDPAddr{
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

	rc, err := s.HyClient.DialUDP()
	if err != nil {
		return
	}
	defer rc.Close()

	err = s.relayUDP(conn, rc, &remoteAddr, s.Timeout)
}

func (s *Server) relayUDP(lc adapter.UDPConn, rc cs.HyUDPConn, to *net.UDPAddr, timeout time.Duration) (err error) {
	errChan := make(chan error, 2)
	// local => remote
	go func() {
		buf := make([]byte, udpBufferSize)
		for {
			if timeout != 0 {
				_ = lc.SetDeadline(time.Now().Add(timeout))
				n, err := lc.Read(buf)
				if n > 0 {
					err = rc.WriteTo(buf[:n], to.String())
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
		}
	}()
	// remote => local
	go func() {
		for {
			pkt, addr, err := rc.ReadFrom()
			if err != nil {
				errChan <- err
				return
			}
			if pkt != nil {
				host, portStr, err := net.SplitHostPort(addr)
				if err != nil {
					errChan <- err
					return
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					errChan <- fmt.Errorf("cannot parse as port: %s", portStr)
					return
				}

				// adapter.UDPConn doesn't support WriteFrom() yet,
				// so we check the src address and behavior like a symmetric NAT
				if !to.IP.Equal(net.ParseIP(host)) || to.Port != port {
					// drop the packet silently
					continue
				}

				_, err = lc.Write(pkt)
				if err != nil {
					errChan <- err
					return
				}
			}
		}
	}()
	return <-errChan
}
