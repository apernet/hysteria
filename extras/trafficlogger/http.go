package trafficlogger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/server"
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
		StatsMap: make(map[string]*trafficStatsEntry),
		KickMap:  make(map[string]struct{}),
		Secret:   secret,
	}
}

type TrafficPushRequest struct {
	Data map[string][2]int64
}

// 定时提交用户流量情况
func (s *trafficStatsServerImpl) PushTrafficToV2boardInterval(url string, interval time.Duration) {
	fmt.Println("用户流量情况监控已启动")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.PushTrafficToV2board(url); err != nil {
				fmt.Println("用户流量信息提交失败:", err)
			}
		}
	}
}

// 向v2board 提交用户流量使用情况
func (s *trafficStatsServerImpl) PushTrafficToV2board(url string) error {
	s.Mutex.Lock()         // 写锁，阻止其他操作 StatsMap 的并发访问
	defer s.Mutex.Unlock() // 确保在函数退出时释放写锁

	// 创建一个请求对象并填充数据
	request := TrafficPushRequest{
		Data: make(map[string][2]int64),
	}
	for id, stats := range s.StatsMap {
		request.Data[id] = [2]int64{int64(stats.Tx), int64(stats.Rx)}
	}
	// 如果不存在数据则跳过
	if len(request.Data) == 0 {
		return nil
	}

	// 将请求对象转换为JSON
	jsonData, err := json.Marshal(request.Data)
	if err != nil {
		return err
	}

	// 发起HTTP请求并提交数据
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println(resp)
		return err
	}
	defer resp.Body.Close()

	// 检查HTTP响应状态，处理错误等
	if resp.StatusCode != http.StatusOK {
		return errors.New("HTTP request failed with status code: " + resp.Status)
	}

	// 清空流量记录
	s.StatsMap = make(map[string]*trafficStatsEntry)

	return nil
}

type trafficStatsServerImpl struct {
	Mutex    sync.RWMutex
	StatsMap map[string]*trafficStatsEntry
	KickMap  map[string]struct{}
	Secret   string
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
