package tproxy

import (
	"errors"
	"github.com/LiamHaworth/go-tproxy"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const udpBufferSize = 65535

var ErrTimeout = errors.New("inactivity timeout")

type UDPTProxy struct {
	HyClient   *core.Client
	Transport  transport.Transport
	ListenAddr *net.UDPAddr
	Timeout    time.Duration

	ConnFunc  func(addr net.Addr)
	ErrorFunc func(addr net.Addr, err error)
}

func NewUDPTProxy(hyClient *core.Client, transport transport.Transport, listen string, timeout time.Duration,
	connFunc func(addr net.Addr), errorFunc func(addr net.Addr, err error)) (*UDPTProxy, error) {
	uAddr, err := transport.LocalResolveUDPAddr(listen)
	if err != nil {
		return nil, err
	}
	r := &UDPTProxy{
		HyClient:   hyClient,
		Transport:  transport,
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

type connEntry struct {
	LocalConn *net.UDPConn
	HyConn    core.UDPConn
	Deadline  atomic.Value
}

func (r *UDPTProxy) ListenAndServe() error {
	conn, err := tproxy.ListenUDP("udp", r.ListenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// src <-> HyClient UDPConn
	connMap := make(map[string]*connEntry)
	var connMapMutex sync.RWMutex
	// Read loop
	buf := make([]byte, udpBufferSize)
	for {
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(conn, buf)
		if n > 0 {
			connMapMutex.RLock()
			entry := connMap[srcAddr.String()]
			connMapMutex.RUnlock()
			if entry != nil {
				// Existing conn
				entry.Deadline.Store(time.Now().Add(r.Timeout))
				_ = entry.HyConn.WriteTo(buf[:n], dstAddr.String())
			} else {
				// New
				r.ConnFunc(srcAddr)
				// TODO: Change fixed dstAddr
				localConn, err := tproxy.DialUDP("udp", dstAddr, srcAddr)
				if err != nil {
					r.ErrorFunc(srcAddr, err)
					continue
				}
				hyConn, err := r.HyClient.DialUDP()
				if err != nil {
					r.ErrorFunc(srcAddr, err)
					_ = localConn.Close()
					continue
				}
				// Send
				entry := &connEntry{
					LocalConn: localConn,
					HyConn:    hyConn,
				}
				entry.Deadline.Store(time.Now().Add(r.Timeout))
				// Add it to the map
				connMapMutex.Lock()
				connMap[srcAddr.String()] = entry
				connMapMutex.Unlock()
				// Start remote to local
				go func() {
					for {
						bs, _, err := hyConn.ReadFrom()
						if err != nil {
							break
						}
						entry.Deadline.Store(time.Now().Add(r.Timeout))
						_, _ = localConn.Write(bs)
					}
				}()
				// Timeout cleanup routine
				go func() {
					for {
						ttl := entry.Deadline.Load().(time.Time).Sub(time.Now())
						if ttl <= 0 {
							// Time to die
							connMapMutex.Lock()
							_ = localConn.Close()
							_ = hyConn.Close()
							delete(connMap, srcAddr.String())
							connMapMutex.Unlock()
							r.ErrorFunc(srcAddr, ErrTimeout)
							return
						} else {
							time.Sleep(ttl)
						}
					}
				}()
				_ = hyConn.WriteTo(buf[:n], dstAddr.String())
			}
		}
		if err != nil {
			return err
		}
	}
}
