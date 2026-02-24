package cmd

import (
	"os"
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
		calcMTU := pppbridge.AutoPPPMTU(pppbridge.MTUParams{
			RemoteAddr:  c.RemoteAddr(),
			Salamander:  salamander,
			DataStreams: config.DataStreams,
			Multilink:   true,
		})
		if config.MTU > 0 {
			calcMTU = int(config.MTU)
		}
		pppdArgs = []string{"nodetach", "local", "+ipv6", "multilink", "lcp-echo-interval", "0"}
		mtuStr := strconv.Itoa(calcMTU)
		pppdArgs = append(pppdArgs, "mtu", mtuStr, "mru", mtuStr)
	}

	serverRoute := false
	if config.SSTP != nil {
		if config.SSTP.LogLevel == "" {
			config.SSTP.LogLevel = logLevel
		}

		if pppdPath == "" {
			exe, err := os.Executable()
			if err != nil {
				logger.Fatal("failed to detect executable path", zap.Error(err))
			}
			pppdPath = exe
		}

		sstpArgs := buildSSTPArgs(config.SSTP)
		pppdArgs = append(sstpArgs, pppdArgs...)

		serverRoute = true
		if config.SSTP.ServerRoute != nil {
			serverRoute = *config.SSTP.ServerRoute
		}
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
		DataStreams: config.DataStreams,
		ServerRoute: serverRoute,
	}

	return s.Serve()
}

func buildSSTPArgs(cfg *pppSSTPConfig) []string {
	args := []string{"sstp"}
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
	return args
}
