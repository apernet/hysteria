package masq

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// MasqTCPServer covers the TCP parts of a standard web server (TCP based HTTP/HTTPS).
// We provide this as an option for masquerading, as some may consider a server
// "suspicious" if it only serves the QUIC protocol and not standard HTTP/HTTPS.
type MasqTCPServer struct {
	QUICPort   int
	HTTPSPort  int
	Handler    http.Handler
	TLSConfig  *tls.Config
	ForceHTTPS bool // Always 301 redirect from HTTP to HTTPS
}

func (s *MasqTCPServer) ListenAndServeHTTP(addr string) error {
	return http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ForceHTTPS {
			if s.HTTPSPort == 0 || s.HTTPSPort == 443 {
				// Omit port if it's the default
				http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
			} else {
				http.Redirect(w, r, fmt.Sprintf("https://%s:%d%s", r.Host, s.HTTPSPort, r.RequestURI), http.StatusMovedPermanently)
			}
			return
		}
		s.Handler.ServeHTTP(&altSvcHijackResponseWriter{
			Port:           s.QUICPort,
			ResponseWriter: w,
		}, r)
	}))
}

func (s *MasqTCPServer) ListenAndServeHTTPS(addr string) error {
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.Handler.ServeHTTP(&altSvcHijackResponseWriter{
				Port:           s.QUICPort,
				ResponseWriter: w,
			}, r)
		}),
		TLSConfig: s.TLSConfig,
	}
	return server.ListenAndServeTLS("", "")
}

// altSvcHijackResponseWriter makes sure that the Alt-Svc's port
// is always set with our own value, no matter what the handler sets.
type altSvcHijackResponseWriter struct {
	Port int
	http.ResponseWriter
}

func (w *altSvcHijackResponseWriter) WriteHeader(statusCode int) {
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=2592000`, w.Port))
	w.ResponseWriter.WriteHeader(statusCode)
}
