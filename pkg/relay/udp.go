package relay

import (
	"errors"
	"github.com/tobyxdd/hysteria/pkg/core"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const udpBufferSize = 65535

var ErrTimeout = errors.New("inactivity timeout")

type UDPRelay struct {
	HyClient   *core.Client
	ListenAddr *net.UDPAddr
	Remote     string
	Timeout    time.Duration

	ConnFunc  func(addr net.Addr)
	ErrorFunc func(addr net.Addr, err error)
}

func NewUDPRelay(hyClient *core.Client, listen, remote string, timeout time.Duration,
	connFunc func(addr net.Addr), errorFunc func(addr net.Addr, err error)) (*UDPRelay, error) {
	uAddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	r := &UDPRelay{
		HyClient:   hyClient,
		ListenAddr: uAddr,
		Remote:     remote,
		Timeout:    timeout,
		ConnFunc:   connFunc,
		ErrorFunc:  errorFunc,
	}
	if timeout == 0 {
		r.Timeout = 1 * time.Minute
	}
	return r, nil
}

type cmEntry struct {
	HyConn   core.UDPConn
	Deadline atomic.Value
}

func (r *UDPRelay) ListenAndServe() error {
	conn, err := net.ListenUDP("udp", r.ListenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// src <-> HyClient UDPConn
	connMap := make(map[string]*cmEntry)
	var connMapMutex sync.RWMutex
	// Read loop
	buf := make([]byte, udpBufferSize)
	for {
		n, rAddr, err := conn.ReadFromUDP(buf)
		if n > 0 {
			connMapMutex.RLock()
			cme := connMap[rAddr.String()]
			connMapMutex.RUnlock()
			if cme != nil {
				// Existing conn
				cme.Deadline.Store(time.Now().Add(r.Timeout))
				_ = cme.HyConn.WriteTo(buf[:n], r.Remote)
			} else {
				// New
				r.ConnFunc(rAddr)
				hyConn, err := r.HyClient.DialUDP()
				if err != nil {
					r.ErrorFunc(rAddr, err)
				} else {
					// Add it to the map
					ent := &cmEntry{HyConn: hyConn}
					ent.Deadline.Store(time.Now().Add(r.Timeout))
					connMapMutex.Lock()
					connMap[rAddr.String()] = ent
					connMapMutex.Unlock()
					// Start remote to local
					go func() {
						for {
							bs, _, err := hyConn.ReadFrom()
							if err != nil {
								break
							}
							ent.Deadline.Store(time.Now().Add(r.Timeout))
							_, _ = conn.WriteToUDP(bs, rAddr)
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
								delete(connMap, rAddr.String())
								connMapMutex.Unlock()
								r.ErrorFunc(rAddr, ErrTimeout)
								return
							} else {
								time.Sleep(ttl)
							}
						}
					}()
					// Send the packet
					_ = hyConn.WriteTo(buf[:n], r.Remote)
				}
			}
		}
		if err != nil {
			return err
		}
	}
}
