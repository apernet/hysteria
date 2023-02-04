package auth

import "sync"

type ConnLimiter struct {
	MaxConn int // <= 0 means no limit

	connMap map[string]int
	mutex   sync.RWMutex
}

func (l *ConnLimiter) Connect(auth []byte) bool {
	if l.MaxConn <= 0 {
		return true
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.connMap == nil {
		l.connMap = make(map[string]int)
	}
	authStr := string(auth)
	if l.connMap[authStr] >= l.MaxConn {
		return false
	}
	l.connMap[authStr]++
	return true
}

func (l *ConnLimiter) Disconnect(auth []byte) {
	if l.MaxConn <= 0 {
		return
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	authStr := string(auth)
	if l.connMap[authStr] > 1 {
		l.connMap[authStr]--
	} else {
		delete(l.connMap, authStr)
	}
}
