package trafficlogger

import (
	"encoding/json"
	"github.com/apernet/hysteria/core/server"
	"net"
	"net/http"
	"strconv"
	"sync"
)

const (
	indexHTML = `<!DOCTYPE html><html lang="en"><head> <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>Hysteria Traffic Stats API Server</title> <style>body{font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; padding: 0; background-color: #f4f4f4;}.container{padding: 20px; background-color: #fff; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); border-radius: 5px;}</style></head><body> <div class="container"> <p>This is a Hysteria Traffic Stats API server.</p><p>Check the documentation for usage.</p></div></body></html>`
)

// TrafficStatsServer implements both server.TrafficLogger and http.Handler
// to provide a simple HTTP API to get the traffic stats per user.
type TrafficStatsServer interface {
	server.TrafficLogger
	http.Handler
}

func NewTrafficStatsServer(secret string) TrafficStatsServer {
	return &trafficStatsServerImpl{
		StatsMap:  make(map[string]*trafficStatsEntry),
		KickMap:   make(map[string]struct{}),
		OnlineMap: make(map[string]map[string]bool),
		Secret:    secret,
	}
}

type trafficStatsServerImpl struct {
	Mutex     sync.RWMutex
	StatsMap  map[string]*trafficStatsEntry
	OnlineMap map[string]map[string]bool
	KickMap   map[string]struct{}
	Secret    string
}

type trafficStatsEntry struct {
	Tx uint64 `json:"tx"`
	Rx uint64 `json:"rx"`
}

func (s *trafficStatsServerImpl) Log(id string, tx, rx uint64) (ok bool) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	_, ok = s.KickMap[id]
	if ok {
		delete(s.KickMap, id)
		return false
	}

	entry, ok := s.StatsMap[id]
	if !ok {
		entry = &trafficStatsEntry{}
		s.StatsMap[id] = entry
	}
	entry.Tx += tx
	entry.Rx += rx

	return true
}

// LogOnline adds the user to the online map.
func (s *trafficStatsServerImpl) LogOnline(id string, addr net.Addr) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if _, ok := s.OnlineMap[id]; !ok {
		s.OnlineMap[id] = make(map[string]bool)
	}
	userIp, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	s.OnlineMap[id][userIp] = true
}

// LogOffline removes the user from the online map.
func (s *trafficStatsServerImpl) LogOffline(id string, addr net.Addr) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	userIp, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	if onlineUsers, ok := s.OnlineMap[id]; ok {
		if !onlineUsers[userIp] {
			//if the user's ip is not in the online map, delete the whole entry
			delete(s.OnlineMap, id)
			return
		}
		delete(onlineUsers, userIp)
		if len(onlineUsers) == 0 {
			delete(s.OnlineMap, id)
		}
	}

}

func (s *trafficStatsServerImpl) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.Secret != "" && r.Header.Get("Authorization") != s.Secret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/" {
		_, _ = w.Write([]byte(indexHTML))
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/traffic" {
		s.getTraffic(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/kick" {
		s.kick(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/online" {
		s.getOnline(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *trafficStatsServerImpl) getTraffic(w http.ResponseWriter, r *http.Request) {
	bClear, _ := strconv.ParseBool(r.URL.Query().Get("clear"))
	var jb []byte
	var err error
	if bClear {
		s.Mutex.Lock()
		jb, err = json.Marshal(s.StatsMap)
		s.StatsMap = make(map[string]*trafficStatsEntry)
		s.Mutex.Unlock()
	} else {
		s.Mutex.RLock()
		jb, err = json.Marshal(s.StatsMap)
		s.Mutex.RUnlock()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(jb)
}

func (s *trafficStatsServerImpl) getOnline(w http.ResponseWriter, r *http.Request) {
	var jb []byte
	var err error

	bClear, _ := strconv.ParseBool(r.URL.Query().Get("clear"))
	OnlineSet := make(map[string][]string)

	if bClear {
		s.Mutex.Lock()
		for id, addrs := range s.OnlineMap {
			for addr := range addrs {
				OnlineSet[id] = append(OnlineSet[id], addr)
			}
		}
		s.OnlineMap = make(map[string]map[string]bool)
		s.Mutex.Unlock()

	} else {
		s.Mutex.RLock()
		for id, addrs := range s.OnlineMap {
			for addr := range addrs {
				OnlineSet[id] = append(OnlineSet[id], addr)
			}
		}
		s.Mutex.RUnlock()
	}

	jb, err = json.Marshal(OnlineSet)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(jb)
}

func (s *trafficStatsServerImpl) kick(w http.ResponseWriter, r *http.Request) {
	var ids []string
	err := json.NewDecoder(r.Body).Decode(&ids)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.Mutex.Lock()
	for _, id := range ids {
		s.KickMap[id] = struct{}{}
	}
	s.Mutex.Unlock()

	w.WriteHeader(http.StatusOK)
}
