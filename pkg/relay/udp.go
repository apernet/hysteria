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

const udpMinTimeout = 4 * time.Second

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
	} else if timeout < udpMinTimeout {
		r.Timeout = udpMinTimeout
	}
	return r, nil
}

type cmEntry struct {
	HyConn         core.UDPConn
	Addr           *net.UDPAddr
	LastActiveTime atomic.Value
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
	// Timeout cleanup routine
	stopChan := make(chan bool)
	defer close(stopChan)
	go func() {
		ticker := time.NewTicker(udpMinTimeout)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case t := <-ticker.C:
				allowedLAT := t.Add(-r.Timeout)
				connMapMutex.Lock()
				for k, v := range connMap {
					if v.LastActiveTime.Load().(time.Time).Before(allowedLAT) {
						// Timeout
						r.ErrorFunc(v.Addr, ErrTimeout)
						_ = v.HyConn.Close()
						delete(connMap, k)
					}
				}
				connMapMutex.Unlock()
			}
		}
	}()
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
				cme.LastActiveTime.Store(time.Now())
				_ = cme.HyConn.WriteTo(buf[:n], r.Remote)
			} else {
				// New
				r.ConnFunc(rAddr)
				hyConn, err := r.HyClient.DialUDP()
				if err != nil {
					r.ErrorFunc(rAddr, err)
				} else {
					// Add it to the map
					ent := &cmEntry{HyConn: hyConn, Addr: rAddr}
					ent.LastActiveTime.Store(time.Now())
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
							ent.LastActiveTime.Store(time.Now())
							_, _ = conn.WriteToUDP(bs, rAddr)
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
