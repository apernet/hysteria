package cmd

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/apernet/hysteria/app/v2/internal/ppp"
	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/pppbridge"
)

// pppdInvocation is everything clientPPP decides before anything is spawned:
// which program to run, with what arguments, and whether to route the server's
// address around the tunnel.
//
// Separated from clientPPP because the decision is where all the branching is --
// nospawn, SSTP, an explicit MTU or a measured one -- while what follows it is a
// Serve loop that blocks until the process ends. Kept together they could only
// be checked by running a real pppd.
type pppdInvocation struct {
	path        string
	args        []string
	serverRoute bool
	noSpawn     bool
}

func clientPPP(config pppConfig, c client.Client, salamander bool) error {
	inv, err := clientPPPDInvocation(config, c.RemoteAddr(), salamander)
	if err != nil {
		return err
	}

	if inv.noSpawn {
		logger.Info("PPP mode starting",
			zap.String("mode", "nospawn"),
			zap.Int("dataStreams", config.DataStreams))
		s := &ppp.Server{
			HyClient:    c,
			Logger:      logger,
			DataStreams: config.DataStreams,
			NoSpawn:     true,
			// Whatever started pppd chose its MRU; ppp.mtu is how it tells us. Left
			// unset the transport is measured instead, which still works -- pppd
			// simply never learns the answer -- but costs a dial's latency for
			// nothing. The netifd handler always sets it.
			LinkMRU: int(config.MTU),
			// Only in nospawn mode, which is the only mode where something outside
			// this process is trying to work out whether this server is connected.
			OnSessionUp: writePPPStateUp,
		}
		err := s.Serve()
		writePPPStatus(err)
		writePPPStateDown(err)
		return err
	}

	logger.Info("PPP mode starting",
		zap.String("pppdPath", inv.path),
		zap.Strings("pppdArgs", inv.args),
		zap.Int("dataStreams", config.DataStreams),
		zap.Bool("serverRoute", inv.serverRoute))

	s := &ppp.Server{
		HyClient:    c,
		Logger:      logger,
		PPPDPath:    inv.path,
		PPPDArgs:    inv.args,
		DataStreams: config.DataStreams,
		ServerRoute: inv.serverRoute,
	}

	return s.Serve()
}

func clientPPPDInvocation(config pppConfig, remoteAddr net.Addr, salamander bool) (pppdInvocation, error) {
	noSpawn := false
	switch strings.ToLower(config.Mode) {
	case "", "local":
	case "nospawn":
		noSpawn = true
	default:
		return pppdInvocation{}, configError{Field: "ppp.mode", Err: fmt.Errorf("unsupported mode %q (must be \"local\" or \"nospawn\")", config.Mode)}
	}

	if noSpawn {
		if config.SSTP != nil {
			return pppdInvocation{}, configError{Field: "ppp.mode", Err: errors.New("nospawn mode cannot be combined with ppp.sstp")}
		}
		return pppdInvocation{noSpawn: true}, nil
	}

	pppdPath := config.PPPDPath
	pppdArgs := config.PPPDArgs

	if len(pppdArgs) == 0 {
		// LCP echo is the only thing that notices a link which is nominally up but
		// silently dropping frames -- an MTU black hole, a stale NAT binding, a
		// middlebox eating large UDP. It travels the same transport as user data,
		// so it genuinely probes the path the data takes. Adaptive keeps it quiet
		// while traffic is flowing; 3 misses at 5s gives ~15s to detection, well
		// inside the 30s QUIC idle timeout.
		pppdArgs = []string{
			"nodetach", "local", "+ipv6", "multilink",
			"lcp-echo-interval", "5", "lcp-echo-failure", "3", "lcp-echo-adaptive",
		}
		if config.MTU > 0 {
			s := strconv.Itoa(int(config.MTU))
			pppdArgs = append(pppdArgs, "mtu", s, "mru", s)
		} else {
			linkMRU := pppbridge.AutoPPPMTU(pppbridge.MTUParams{
				RemoteAddr:  remoteAddr,
				Salamander:  salamander,
				DataStreams: config.DataStreams,
			})
			vpnMTU := linkMRU - pppbridge.MLPPPOverhead
			if config.SSTP != nil {
				s := strconv.Itoa(linkMRU)
				pppdArgs = append(pppdArgs, "mtu", s, "mru", s)
			} else {
				pppdArgs = append(pppdArgs, "mtu", strconv.Itoa(vpnMTU), "mru", strconv.Itoa(linkMRU))
			}
		}
	}

	serverRoute := false
	if config.SSTP != nil {
		if config.SSTP.LogLevel == "" {
			config.SSTP.LogLevel = logLevel
		}

		if pppdPath == "" {
			if config.SSTP.BinaryPath != "" {
				pppdPath = config.SSTP.BinaryPath
			} else {
				pppdPath = "ppp-sstp"
			}
		}

		sstpArgs := buildSSTPArgs(config.SSTP)
		pppdArgs = append(sstpArgs, pppdArgs...)

		serverRoute = true
		if config.SSTP.ServerRoute != nil {
			serverRoute = *config.SSTP.ServerRoute
		}
	} else if pppdPath == "" {
		pppdPath = "pppd"
	}

	return pppdInvocation{path: pppdPath, args: pppdArgs, serverRoute: serverRoute}, nil
}

// buildSSTPArgs generates command-line arguments for the ppp-sstp binary.
func buildSSTPArgs(cfg *pppSSTPConfig) []string {
	var args []string
	if cfg.LogLevel != "" {
		args = append(args, "-l", cfg.LogLevel)
	}

	listen := cfg.Listen
	if listen == "" {
		listen = "127.0.0.1:8443"
	}
	args = append(args, "listen", listen)

	if cfg.CertDir != "" {
		args = append(args, "cert-dir", cfg.CertDir)
	}
	if cfg.Endpoint != "" {
		args = append(args, "endpoint", cfg.Endpoint)
	}
	if cfg.User != "" {
		args = append(args, "user", cfg.User)
	}
	if cfg.Password != "" {
		args = append(args, "password", cfg.Password)
	}
	if cfg.MSSClamp != nil {
		args = append(args, "mss-clamp", strconv.Itoa(*cfg.MSSClamp))
	}
	return args
}
