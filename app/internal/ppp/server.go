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
	DataStreams int  // 0 = datagram (default), >0 = N parallel streams
	ServerRoute bool // when true, inject server-route <ip> arg for the child
	NoSpawn     bool // when true, bridge stdin/stdout instead of spawning pppd

	// LinkMRU is the MRU pppd was configured with, when this process did not
	// choose it. Only nospawn sets it, and there it is not optional: pppd fixed
	// its MRU before this process existed, so measuring the path would cost a
	// dial's worth of latency to learn a number that cannot be applied. Zero
	// means "measure it", which is what spawn mode wants.
	LinkMRU int

	// OnSessionUp is called once the server has accepted a PPP session, which is
	// the moment this link starts being worth something. The OpenWrt handler uses
	// it to publish "this server is connected" for its status page; left nil
	// nothing happens.
	//
	// Deliberately not "once the Hysteria2 connection is up". A reachable server
	// that refuses the session leaves a perfectly healthy connection carrying
	// nothing, and reporting that as connected is how a bundle comes to show
	// three live links and one link's throughput.
	OnSessionUp func()
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
			// The transport ceiling is the frame, not the packet: pppd hands the
			// bridge address, control and protocol octets ahead of the payload.
			maxFrameSize := 0
			if s.LinkMRU > 0 {
				maxFrameSize = s.LinkMRU + pppbridge.PPPHeaderLen
			}
			conn, err := s.HyClient.PPP(s.DataStreams, maxFrameSize)
			if err != nil {
				return nil, nil, nil, err
			}
			// The server sizes the link to whichever direction's transport carries
			// less, measured after Path MTU discovery settled on both sides. Log it:
			// in nospawn mode this is the only place the number is visible, since
			// pppd learns it from the server's LCP MRU rather than from us.
			if conn.MTU > 0 {
				s.Logger.Info("PPP link MTU negotiated", zap.Int("mtu", conn.MTU))
			} else {
				s.Logger.Warn("server did not report a PPP MTU; " +
					"pppd will use whatever its own configuration says")
			}
			if s.OnSessionUp != nil {
				s.OnSessionUp()
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
			// In nospawn the MTU arrived with pppd and a rebuild would ask for the
			// same one, so a narrowed path is reported rather than acted on.
			MTUFixed: s.NoSpawn,
			// Without this the reason the server sends as it tears a session down
			// is never read, so Run can only ever report a plain link loss --
			// making AUTH_FAILED and NO_ROUTE unreachable, and leaving netifd to
			// redial a configuration that can never work.
			ReadReason: true,
			PPPDPath:   s.PPPDPath,
			PPPDArgs:   args,
			NoSpawn:    s.NoSpawn,
			Logger:     s.Logger,
		}

		start := time.Now()
		runErr := bridge.Run(context.Background(), dialFn)
		elapsed := time.Since(start)

		if s.NoSpawn {
			return runErr
		}

		// The link and the PPP session live and die together, so a restart here
		// rebuilds both: a fresh pppd and a fresh Hysteria2 connection. Nothing
		// is carried across, which is why there is no state to reconcile.
		if runErr != nil {
			s.Logger.Warn("PPP link down, rebuilding", zap.Error(runErr))
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
