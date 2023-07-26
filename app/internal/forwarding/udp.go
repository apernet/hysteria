package forwarding

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/client"
)

const (
	udpBufferSize = 4096

	defaultTimeout = 5 * time.Minute
)

type UDPTunnel struct {
	HyClient    client.Client
	Remote      string
	Timeout     time.Duration
	EventLogger UDPEventLogger
}

type UDPEventLogger interface {
	Connect(addr net.Addr)
	Error(addr net.Addr, err error)
}

type sessionEntry struct {
	HyConn   client.HyUDPConn
	Deadline atomic.Value
}

type sessionManager struct {
	SessionMap  map[string]*sessionEntry
	Timeout     time.Duration
	TimeoutFunc func(addr net.Addr)
	Mutex       sync.RWMutex
}

func (sm *sessionManager) New(addr net.Addr, hyConn client.HyUDPConn) {
	entry := &sessionEntry{
		HyConn: hyConn,
	}
	entry.Deadline.Store(time.Now().Add(sm.Timeout))

	// Timeout cleanup routine
	go func() {
		for {
			ttl := entry.Deadline.Load().(time.Time).Sub(time.Now())
			if ttl <= 0 {
				// Inactive for too long, close the session
				sm.Mutex.Lock()
				delete(sm.SessionMap, addr.String())
				sm.Mutex.Unlock()
				_ = hyConn.Close()
				if sm.TimeoutFunc != nil {
					sm.TimeoutFunc(addr)
				}
				return
			} else {
				time.Sleep(ttl)
			}
		}
	}()

	sm.Mutex.Lock()
	defer sm.Mutex.Unlock()
	sm.SessionMap[addr.String()] = entry
}

func (sm *sessionManager) Get(addr net.Addr) client.HyUDPConn {
	sm.Mutex.RLock()
	defer sm.Mutex.RUnlock()
	if entry, ok := sm.SessionMap[addr.String()]; ok {
		return entry.HyConn
	} else {
		return nil
	}
}

func (sm *sessionManager) Renew(addr net.Addr) {
	sm.Mutex.RLock() // RLock is enough as we are not modifying the map itself, only a value in the entry
	defer sm.Mutex.RUnlock()
	if entry, ok := sm.SessionMap[addr.String()]; ok {
		entry.Deadline.Store(time.Now().Add(sm.Timeout))
	}
}

func (t *UDPTunnel) Serve(listener net.PacketConn) error {
	sm := &sessionManager{
		SessionMap:  make(map[string]*sessionEntry),
		Timeout:     t.Timeout,
		TimeoutFunc: func(addr net.Addr) { t.EventLogger.Error(addr, nil) },
	}
	if sm.Timeout <= 0 {
		sm.Timeout = defaultTimeout
	}
	buf := make([]byte, udpBufferSize)
	for {
		n, addr, err := listener.ReadFrom(buf)
		if err != nil {
			return err
		}
		t.handle(listener, sm, addr, buf[:n])
	}
}

func (t *UDPTunnel) handle(l net.PacketConn, sm *sessionManager, addr net.Addr, data []byte) {
	hyConn := sm.Get(addr)
	if hyConn != nil {
		// Existing session
		_ = hyConn.Send(data, t.Remote)
		sm.Renew(addr)
	} else {
		// New session
		if t.EventLogger != nil {
			t.EventLogger.Connect(addr)
		}
		hyConn, err := t.HyClient.UDP()
		if err != nil {
			if t.EventLogger != nil {
				t.EventLogger.Error(addr, err)
			}
			return
		}
		sm.New(addr, hyConn)
		_ = hyConn.Send(data, t.Remote)

		// Local <- Remote routine
		go func() {
			for {
				data, _, err := hyConn.Receive()
				if err != nil {
					return
				}
				_, err = l.WriteTo(data, addr)
				if err != nil {
					return
				}
				sm.Renew(addr)
			}
		}()
	}
}
