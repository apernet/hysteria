package cmd

import (
	"github.com/apernet/hysteria/extras/v2/pppbridge"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var sstpCmd = &cobra.Command{
	Use:   "sstp [keyword value ...]",
	Short: "SSTP bridge (pppd interface)",
	Args:  cobra.ArbitraryArgs,
	Run:   runSSTP,
}

func init() {
	rootCmd.AddCommand(sstpCmd)
}

type sstpParsedArgs struct {
	Listen        string
	CertDir       string
	Endpoint      string
	MTU           int
	User          string
	Password      string
	ServerRouteIP string
	Ignored       []string
}

// parseSSTPArgs parses pppd-style keyword-value pairs from positional args.
// Unknown keywords are collected in Ignored for logging.
func parseSSTPArgs(args []string) sstpParsedArgs {
	cfg := sstpParsedArgs{
		Listen: "127.0.0.1:8443",
	}
	for i := 0; i < len(args); i++ {
		key := args[i]
		if i+1 < len(args) {
			val := args[i+1]
			switch key {
			case "listen":
				cfg.Listen = val
				i++
				continue
			case "cert-dir":
				cfg.CertDir = val
				i++
				continue
			case "endpoint":
				cfg.Endpoint = val
				i++
				continue
			case "mtu":
				n := 0
				for _, c := range val {
					if c >= '0' && c <= '9' {
						n = n*10 + int(c-'0')
					}
				}
				cfg.MTU = n
				i++
				continue
			case "user":
				cfg.User = val
				i++
				continue
			case "password":
				cfg.Password = val
				i++
				continue
			case "server-route":
				cfg.ServerRouteIP = val
				i++
				continue
			}
		}
		cfg.Ignored = append(cfg.Ignored, key)
	}
	return cfg
}

func runSSTP(cmd *cobra.Command, args []string) {
	l := logger.Named("sstp")

	cfg := parseSSTPArgs(args)

	if len(cfg.Ignored) > 0 {
		l.Warn("ignored unknown args", zap.Strings("args", cfg.Ignored))
	}

	if cfg.CertDir == "" {
		l.Fatal("cert-dir is required")
	}

	discLog := "none"
	if cfg.Endpoint != "" {
		discLog = cfg.Endpoint
	}
	l.Info("starting",
		zap.String("listen", cfg.Listen),
		zap.String("certDir", cfg.CertDir),
		zap.String("discriminator", discLog))

	if cfg.Endpoint == "" {
		bridge := &pppbridge.SSTPBridge{
			ListenAddr:    cfg.Listen,
			CertDir:       cfg.CertDir,
			Logger:        l,
			MTU:           cfg.MTU,
			PAPUser:       cfg.User,
			PAPPass:       cfg.Password,
			ServerRouteIP: cfg.ServerRouteIP,
		}
		if err := bridge.Run(); err != nil {
			l.Info("session ended", zap.Error(err))
		}
		return
	}

	// MLPPP mode: attempt master election via IPC
	master, ipcServer, err := pppbridge.TryBecomeMaster(cfg.Endpoint)
	if err != nil {
		l.Fatal("MLPPP IPC election failed", zap.Error(err))
	}

	if master {
		bridge := &pppbridge.SSTPBridge{
			ListenAddr:    cfg.Listen,
			CertDir:       cfg.CertDir,
			Logger:        l,
			Discriminator: cfg.Endpoint,
			PAPUser:       cfg.User,
			PAPPass:       cfg.Password,
			MTU:           cfg.MTU,
			IPCServer:     ipcServer,
			ServerRouteIP: cfg.ServerRouteIP,
		}
		if err := bridge.Run(); err != nil {
			l.Info("session ended", zap.Error(err))
		}
	} else {
		worker := &pppbridge.MLPPPWorker{
			ListenAddr:    cfg.Listen,
			CertDir:       cfg.CertDir,
			Discriminator: cfg.Endpoint,
			PAPUser:       cfg.User,
			PAPPass:       cfg.Password,
			MTU:           cfg.MTU,
			Logger:        l,
			ServerRouteIP: cfg.ServerRouteIP,
		}
		if err := worker.Run(); err != nil {
			l.Info("MLPPP worker exited", zap.Error(err))
		}
	}
}
