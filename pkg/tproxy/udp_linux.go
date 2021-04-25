package tproxy

import (
	"errors"
	"github.com/LiamHaworth/go-tproxy"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/core"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const udpBufferSize = 65535

var ErrTimeout = errors.New("inactivity timeout")

type UDPTProxy struct {
	HyClient   *core.Client
	ListenAddr *net.UDPAddr
	Timeout    time.Duration
	ACLEngine  *acl.Engine

	ConnFunc  func(addr net.Addr)
	ErrorFunc func(addr net.Addr, err error)
}

func NewUDPTProxy(hyClient *core.Client, listen string, timeout time.Duration, aclEngine *acl.Engine,
	connFunc func(addr net.Addr), errorFunc func(addr net.Addr, err error)) (*UDPTProxy, error) {
	uAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	r := &UDPTProxy{
		HyClient:   hyClient,
		ListenAddr: uAddr,
		Timeout:    timeout,
		ACLEngine:  aclEngine,
		ConnFunc:   connFunc,
		ErrorFunc:  errorFunc,
	}
	if timeout == 0 {
		r.Timeout = 1 * time.Minute
	}
	return r, nil
}

type connEntry struct {
	HyConn   core.UDPConn
	Deadline atomic.Value
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
			cme := connMap[srcAddr.String()]
			connMapMutex.RUnlock()
			if cme != nil {
				// Existing conn
				cme.Deadline.Store(time.Now().Add(r.Timeout))
				_ = cme.HyConn.WriteTo(buf[:n], dstAddr.String())
			} else {
				// New
				r.ConnFunc(srcAddr)
				hyConn, err := r.HyClient.DialUDP()
				if err != nil {
					r.ErrorFunc(srcAddr, err)
				} else {
					// Add it to the map
					ent := &connEntry{HyConn: hyConn}
					ent.Deadline.Store(time.Now().Add(r.Timeout))
					connMapMutex.Lock()
					connMap[srcAddr.String()] = ent
					connMapMutex.Unlock()
					// Start remote to local
					go func() {
						for {
							bs, _, err := hyConn.ReadFrom()
							if err != nil {
								break
							}
							ent.Deadline.Store(time.Now().Add(r.Timeout))
							_, _ = conn.WriteToUDP(bs, srcAddr)
						}
					}()
					// Timeout cleanup routine
					go func() {
						for {
							ttl := ent.Deadline.Load().(time.Time).Sub(time.Now())
							if ttl <= 0 {
								// Time to die
								connMapMutex.Lock()
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
					// Send the packet
					_ = hyConn.WriteTo(buf[:n], dstAddr.String())
				}
			}
		}
		if err != nil {
			return err
		}
	}
}
