package cmd

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sync/atomic"
	"testing"
)

type discardBenchmarkResponseWriter struct {
	header http.Header
	status int
}

func (w *discardBenchmarkResponseWriter) Header() http.Header {
	return w.header
}

func (w *discardBenchmarkResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *discardBenchmarkResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return len(body), nil
}

func BenchmarkMasqueradeProxy(b *testing.B) {
	payload := make([]byte, 4*1024)
	upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	})
	socketPath, _ := startUnixHTTPServer(b, upstreamHandler)
	tcpServer := httptest.NewServer(upstreamHandler)
	b.Cleanup(tcpServer.Close)

	for _, test := range []struct {
		name       string
		target     string
		bufferPool bool
		cloneTCP   bool
	}{
		{name: "unix_pooled_buffer", target: socketPath, bufferPool: true},
		{name: "tcp_32_idle_pooled_buffer", target: tcpServer.URL, bufferPool: true, cloneTCP: true},
		{name: "unix_unpooled_buffer", target: socketPath, bufferPool: false},
	} {
		b.Run(test.name, func(b *testing.B) {
			handler, err := newMasqueradeProxyHandler(serverConfigMasqueradeProxy{URL: test.target})
			if err != nil {
				b.Fatal(err)
			}
			proxy := handler.(*httputil.ReverseProxy)
			transport := proxy.Transport.(*http.Transport)
			if test.cloneTCP {
				transport = transport.Clone()
				transport.MaxIdleConns = masqueradeProxyMaxIdleConnections
				transport.MaxIdleConnsPerHost = masqueradeProxyMaxIdleConnsPerHost
				proxy.Transport = transport
			}
			b.Cleanup(transport.CloseIdleConnections)
			if !test.bufferPool {
				proxy.BufferPool = nil
			}

			var failures atomic.Int64
			var firstFailure atomic.Pointer[string]
			proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
				message := err.Error()
				firstFailure.CompareAndSwap(nil, &message)
				w.WriteHeader(http.StatusBadGateway)
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					request := httptest.NewRequest(http.MethodGet, "https://front.example/resource", nil)
					response := &discardBenchmarkResponseWriter{header: make(http.Header)}
					proxy.ServeHTTP(response, request)
					if response.status != http.StatusOK {
						failures.Add(1)
					}
				}
			})
			b.StopTimer()
			if count := failures.Load(); count != 0 {
				message := firstFailure.Load()
				if message == nil {
					b.Fatalf("%d proxy requests failed", count)
				}
				b.Fatalf("%d proxy requests failed: %s", count, *message)
			}
		})
	}
}
