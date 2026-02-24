package cmd

import (
	"strconv"

	"go.uber.org/zap"

	"github.com/apernet/hysteria/app/v2/internal/ppp"
	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/pppbridge"
)

func clientPPP(config pppConfig, c client.Client, salamander bool) error {
	pppdPath := config.PPPDPath
	pppdArgs := config.PPPDArgs

	if len(pppdArgs) == 0 {
		pppdArgs = []string{"nodetach", "local", "+ipv6", "multilink", "lcp-echo-interval", "0"}
		if config.MTU > 0 {
			s := strconv.Itoa(int(config.MTU))
			pppdArgs = append(pppdArgs, "mtu", s, "mru", s)
		} else {
			linkMRU := pppbridge.AutoPPPMTU(pppbridge.MTUParams{
				RemoteAddr:  c.RemoteAddr(),
				Salamander:  salamander,
				DataStreams: config.DataStreams,
				Multilink:   false,
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

	logger.Info("PPP mode starting",
		zap.String("pppdPath", pppdPath),
		zap.Strings("pppdArgs", pppdArgs),
		zap.Int("dataStreams", config.DataStreams),
		zap.Bool("serverRoute", serverRoute))

	s := &ppp.Server{
		HyClient:    c,
		Logger:      logger,
		PPPDPath:    pppdPath,
		PPPDArgs:    pppdArgs,
		DataStreams:  config.DataStreams,
		ServerRoute: serverRoute,
	}

	return s.Serve()
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
