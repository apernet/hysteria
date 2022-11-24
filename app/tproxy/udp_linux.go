package tproxy

import (
	"net"
	"time"

	"github.com/LiamHaworth/go-tproxy"
	"github.com/apernet/hysteria/core/cs"
)

const udpBufferSize = 4096

type UDPTProxy struct {
	HyClient   *cs.Client
	ListenAddr *net.UDPAddr
	Timeout    time.Duration

	ConnFunc  func(addr, reqAddr net.Addr)
	ErrorFunc func(addr, reqAddr net.Addr, err error)
}

func NewUDPTProxy(hyClient *cs.Client, listen string, timeout time.Duration,
	connFunc func(addr, reqAddr net.Addr),
	errorFunc func(addr, reqAddr net.Addr, err error),
) (*UDPTProxy, error) {
	uAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	r := &UDPTProxy{
		HyClient:   hyClient,
		ListenAddr: uAddr,
		Timeout:    timeout,
		ConnFunc:   connFunc,
		ErrorFunc:  errorFunc,
	}
	if timeout == 0 {
		r.Timeout = 1 * time.Minute
	}
	return r, nil
}

func (r *UDPTProxy) ListenAndServe() error {
	conn, err := tproxy.ListenUDP("udp", r.ListenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Read loop
	buf := make([]byte, udpBufferSize)
	for {
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(conn, buf) // Huge Caveat!! This essentially works as TCP's Accept here - won't repeat for the same srcAddr/dstAddr pair - because and only because we have tproxy.DialUDP("udp", dstAddr, srcAddr) to take over the connection below
		if n > 0 {
			r.ConnFunc(srcAddr, dstAddr)
			localConn, err := tproxy.DialUDP("udp", dstAddr, srcAddr)
			if err != nil {
				r.ErrorFunc(srcAddr, dstAddr, err)
				continue
			}
			hyConn, err := r.HyClient.DialUDP()
			if err != nil {
				r.ErrorFunc(srcAddr, dstAddr, err)
				_ = localConn.Close()
				continue
			}
			_ = hyConn.WriteTo(buf[:n], dstAddr.String())

			errChan := make(chan error, 2)
			// Start remote to local
			go func() {
				for {
					bs, _, err := hyConn.ReadFrom()
					if err != nil {
						errChan <- err
						return
					}
					_, err = localConn.Write(bs)
					if err != nil {
						errChan <- err
						return
					}
					_ = localConn.SetDeadline(time.Now().Add(r.Timeout))
				}
			}()
			// Start local to remote
			go func() {
				for {
					_ = localConn.SetDeadline(time.Now().Add(r.Timeout))
					n, err := localConn.Read(buf)
					if n > 0 {
						err := hyConn.WriteTo(buf[:n], dstAddr.String())
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
			// Error cleanup routine
			go func() {
				err := <-errChan
				_ = localConn.Close()
				_ = hyConn.Close()
				r.ErrorFunc(srcAddr, dstAddr, err)
			}()
		}
		if err != nil {
			return err
		}
	}
}
