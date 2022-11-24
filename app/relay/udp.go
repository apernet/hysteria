package relay

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/cs"
)

const udpBufferSize = 4096

var ErrTimeout = errors.New("inactivity timeout")

type UDPRelay struct {
	HyClient   *cs.Client
	ListenAddr *net.UDPAddr
	Remote     string
	Timeout    time.Duration

	ConnFunc  func(addr net.Addr)
	ErrorFunc func(addr net.Addr, err error)
}

func NewUDPRelay(hyClient *cs.Client, listen, remote string, timeout time.Duration,
	connFunc func(addr net.Addr), errorFunc func(addr net.Addr, err error),
) (*UDPRelay, error) {
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

type connEntry struct {
	HyConn   cs.HyUDPConn
	Deadline atomic.Value
}

func (r *UDPRelay) ListenAndServe() error {
	conn, err := net.ListenUDP("udp", r.ListenAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	// src <-> HyClient HyUDPConn
	connMap := make(map[string]*connEntry)
	var connMapMutex sync.RWMutex
	// Read loop
	buf := make([]byte, udpBufferSize)
	for {
		n, rAddr, err := conn.ReadFromUDP(buf)
		if n > 0 {
			connMapMutex.RLock()
			entry := connMap[rAddr.String()]
			connMapMutex.RUnlock()
			if entry != nil {
				// Existing conn
				entry.Deadline.Store(time.Now().Add(r.Timeout))
				_ = entry.HyConn.WriteTo(buf[:n], r.Remote)
			} else {
				// New
				r.ConnFunc(rAddr)
				hyConn, err := r.HyClient.DialUDP()
				if err != nil {
					r.ErrorFunc(rAddr, err)
				} else {
					// Add it to the map
					entry := &connEntry{HyConn: hyConn}
					entry.Deadline.Store(time.Now().Add(r.Timeout))
					connMapMutex.Lock()
					connMap[rAddr.String()] = entry
					connMapMutex.Unlock()
					// Start remote to local
					go func() {
						for {
							bs, _, err := hyConn.ReadFrom()
							if err != nil {
								break
							}
							entry.Deadline.Store(time.Now().Add(r.Timeout))
							_, _ = conn.WriteToUDP(bs, rAddr)
						}
					}()
					// Timeout cleanup routine
					go func() {
						for {
							ttl := entry.Deadline.Load().(time.Time).Sub(time.Now())
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
