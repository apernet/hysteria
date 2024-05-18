package tproxy

import (
	"errors"
	"net"
	"time"

	"github.com/apernet/go-tproxy"
	"github.com/apernet/hysteria/core/v2/client"
)

const (
	udpBufferSize  = 4096
	defaultTimeout = 60 * time.Second
)

type UDPTProxy struct {
	HyClient    client.Client
	Timeout     time.Duration
	EventLogger UDPEventLogger
}

type UDPEventLogger interface {
	Connect(addr, reqAddr net.Addr)
	Error(addr, reqAddr net.Addr, err error)
}

func (r *UDPTProxy) ListenAndServe(laddr *net.UDPAddr) error {
	conn, err := tproxy.ListenUDP("udp", laddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	buf := make([]byte, udpBufferSize)
	for {
		// We will only get the first packet of each src/dst pair here,
		// because newPair will create a TProxy connection and take over
		// the src/dst pair. Later packets will be sent there instead of here.
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(conn, buf)
		if err != nil {
			return err
		}
		r.newPair(srcAddr, dstAddr, buf[:n])
	}
}

func (r *UDPTProxy) newPair(srcAddr, dstAddr *net.UDPAddr, initPkt []byte) {
	if r.EventLogger != nil {
		r.EventLogger.Connect(srcAddr, dstAddr)
	}
	var closeErr error
	defer func() {
		// If closeErr is nil, it means we at least successfully sent the first packet
		// and started forwarding, in which case we don't call the error logger.
		if r.EventLogger != nil && closeErr != nil {
			r.EventLogger.Error(srcAddr, dstAddr, closeErr)
		}
	}()
	conn, err := tproxy.DialUDP("udp", dstAddr, srcAddr)
	if err != nil {
		closeErr = err
		return
	}
	hyConn, err := r.HyClient.UDP()
	if err != nil {
		_ = conn.Close()
		closeErr = err
		return
	}
	// Send the first packet
	err = hyConn.Send(initPkt, dstAddr.String())
	if err != nil {
		_ = conn.Close()
		_ = hyConn.Close()
		closeErr = err
		return
	}
	// Start forwarding
	go func() {
		err := r.forwarding(conn, hyConn, dstAddr.String())
		_ = conn.Close()
		_ = hyConn.Close()
		if r.EventLogger != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// We don't consider deadline exceeded (timeout) an error
				err = nil
			}
			r.EventLogger.Error(srcAddr, dstAddr, err)
		}
	}()
}

func (r *UDPTProxy) forwarding(conn *net.UDPConn, hyConn client.HyUDPConn, dst string) error {
	errChan := make(chan error, 2)
	// Local <- Remote
	go func() {
		for {
			bs, _, err := hyConn.Receive()
			if err != nil {
				errChan <- err
				return
			}
			_, err = conn.Write(bs)
			if err != nil {
				errChan <- err
				return
			}
			_ = r.updateConnDeadline(conn)
		}
	}()
	// Local -> Remote
	go func() {
		buf := make([]byte, udpBufferSize)
		for {
			_ = r.updateConnDeadline(conn)
			n, err := conn.Read(buf)
			if n > 0 {
				err := hyConn.Send(buf[:n], dst)
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
	return <-errChan
}

func (r *UDPTProxy) updateConnDeadline(conn *net.UDPConn) error {
	if r.Timeout == 0 {
		return conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	} else {
		return conn.SetReadDeadline(time.Now().Add(r.Timeout))
	}
}
