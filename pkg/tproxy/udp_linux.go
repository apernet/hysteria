package tproxy

import (
	"errors"
	"github.com/LiamHaworth/go-tproxy"
	"github.com/tobyxdd/hysteria/pkg/acl"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"github.com/tobyxdd/hysteria/pkg/utils"
	"net"
	"strconv"
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
	ACLEngine  *acl.Engine

	ConnFunc  func(addr net.Addr)
	ErrorFunc func(addr net.Addr, err error)
}

func NewUDPTProxy(hyClient *core.Client, transport transport.Transport, listen string, timeout time.Duration,
	aclEngine *acl.Engine,
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
	LocalConn  *net.UDPConn
	HyConn     core.UDPConn
	DirectConn *net.UDPConn
	Deadline   atomic.Value
}

func (r *UDPTProxy) sendPacket(entry *connEntry, dstAddr *net.UDPAddr, data []byte) error {
	entry.Deadline.Store(time.Now().Add(r.Timeout))
	host, port, err := utils.SplitHostPort(dstAddr.String())
	if err != nil {
		return err
	}
	action, arg := acl.ActionProxy, ""
	var ipAddr *net.IPAddr
	var resErr error
	if r.ACLEngine != nil && entry.DirectConn != nil {
		action, arg, ipAddr, resErr = r.ACLEngine.ResolveAndMatch(host)
		// Doesn't always matter if the resolution fails, as we may send it through HyClient
	}
	switch action {
	case acl.ActionDirect:
		if resErr != nil {
			return resErr
		}
		_, err = entry.DirectConn.WriteToUDP(data, &net.UDPAddr{
			IP:   ipAddr.IP,
			Port: int(port),
			Zone: ipAddr.Zone,
		})
		return err
	case acl.ActionProxy:
		return entry.HyConn.WriteTo(data, dstAddr.String())
	case acl.ActionBlock:
		// Do nothing
		return nil
	case acl.ActionHijack:
		hijackAddr := net.JoinHostPort(arg, strconv.Itoa(int(port)))
		rAddr, err := r.Transport.LocalResolveUDPAddr(hijackAddr)
		if err != nil {
			return err
		}
		_, err = entry.DirectConn.WriteToUDP(data, rAddr)
		return err
	default:
		// Do nothing
		return nil
	}
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
				_ = r.sendPacket(entry, dstAddr, buf[:n])
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
				var directConn *net.UDPConn
				if r.ACLEngine != nil {
					directConn, err = r.Transport.LocalListenUDP(nil)
					if err != nil {
						r.ErrorFunc(srcAddr, err)
						_ = localConn.Close()
						_ = hyConn.Close()
						continue
					}
				}
				// Send
				entry := &connEntry{
					LocalConn:  localConn,
					HyConn:     hyConn,
					DirectConn: directConn,
				}
				_ = r.sendPacket(entry, dstAddr, buf[:n])
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
				if directConn != nil {
					go func() {
						buf := make([]byte, udpBufferSize)
						for {
							n, _, err := directConn.ReadFrom(buf)
							if n > 0 {
								entry.Deadline.Store(time.Now().Add(r.Timeout))
								_, _ = localConn.Write(buf[:n])
							}
							if err != nil {
								break
							}
						}
					}()
				}
				// Timeout cleanup routine
				go func() {
					for {
						ttl := entry.Deadline.Load().(time.Time).Sub(time.Now())
						if ttl <= 0 {
							// Time to die
							connMapMutex.Lock()
							_ = localConn.Close()
							_ = hyConn.Close()
							if directConn != nil {
								_ = directConn.Close()
							}
							delete(connMap, srcAddr.String())
							connMapMutex.Unlock()
							r.ErrorFunc(srcAddr, ErrTimeout)
							return
						} else {
							time.Sleep(ttl)
						}
					}
				}()
			}
		}
		if err != nil {
			return err
		}
	}
}
