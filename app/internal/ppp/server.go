package ppp

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/apernet/hysteria/extras/v2/pppbridge"
	"go.uber.org/zap"
)

type Server struct {
	HyClient    client.Client
	Logger      *zap.Logger
	PPPDPath    string
	PPPDArgs    []string
	DataStreams  int  // 0 = datagram (default), >0 = N parallel streams
	ServerRoute bool // when true, inject server-route <ip> arg for the child
}

func (s *Server) Serve() error {
	const (
		minBackoff     = 1 * time.Second
		maxBackoff     = 30 * time.Second
		resetThreshold = 5 * time.Second
	)
	var backoff time.Duration

	for {
		dialFn := func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
			conn, err := s.HyClient.PPP(s.DataStreams)
			if err != nil {
				return nil, nil, nil, err
			}
			return conn.ControlStream, conn.Data, func() { conn.Close() }, nil
		}

		args := s.PPPDArgs
		if s.ServerRoute {
			if ip := addrIP(s.HyClient.RemoteAddr()); ip != "" {
				args = append(append([]string{}, s.PPPDArgs...), "server-route", ip)
			}
		}

		bridge := &pppbridge.Bridge{
			PPPDPath: s.PPPDPath,
			PPPDArgs: args,
			Logger:   s.Logger,
		}

		start := time.Now()
		runErr := bridge.Run(context.Background(), dialFn)
		elapsed := time.Since(start)

		if runErr != nil {
			s.Logger.Warn("PPP child exited with error, restarting", zap.Error(runErr))
		} else {
			s.Logger.Info("PPP child exited, restarting")
		}

		if elapsed < resetThreshold {
			if backoff == 0 {
				backoff = minBackoff
			} else {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
			s.Logger.Warn("PPP child exited too quickly, backing off",
				zap.Duration("elapsed", elapsed),
				zap.Duration("backoff", backoff))
			time.Sleep(backoff)
		} else {
			backoff = 0
		}
	}
}

func addrToIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	if u, ok := addr.(*net.UDPAddr); ok {
		return u.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func addrIP(addr net.Addr) string {
	if ip := addrToIP(addr); ip != nil {
		return ip.String()
	}
	return ""
}
