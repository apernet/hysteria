package tun

import (
	"io"
	"net"
)

func (s *Server) Handle(conn net.Conn, target *net.TCPAddr) error {
	hyConn, err := s.HyClient.DialTCP(target.String())
	if err != nil {
		return err
	}
	go s.relay(conn, hyConn)
	return nil
}

type direction byte

const (
	directionUplink direction = iota
	directionDownlink
)

type duplexConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

func (s *Server) relay(clientConn, relayConn net.Conn) {
	uplinkDone := make(chan struct{})

	halfCloseConn := func(dir direction, interrupt bool) {
		clientDuplexConn, ok1 := clientConn.(duplexConn)
		relayDuplexConn, ok2 := relayConn.(duplexConn)
		if !interrupt && ok1 && ok2 {
			switch dir {
			case directionUplink:
				clientDuplexConn.CloseRead()
				relayDuplexConn.CloseWrite()
			case directionDownlink:
				clientDuplexConn.CloseWrite()
				relayDuplexConn.CloseRead()
			}
		} else {
			clientConn.Close()
			relayConn.Close()
		}
	}

	// Uplink
	go func() {
		var err error
		_, err = io.Copy(relayConn, clientConn)
		if err != nil {
			halfCloseConn(directionUplink, true)
		} else {
			halfCloseConn(directionUplink, false)
		}
		uplinkDone <- struct{}{}
	}()

	// Downlink
	var err error
	_, err = io.Copy(clientConn, relayConn)
	if err != nil {
		halfCloseConn(directionDownlink, true)
	} else {
		halfCloseConn(directionDownlink, false)
	}

	<-uplinkDone
}
