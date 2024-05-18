package cmd

import (
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/core/v2/client"
)

// pingCmd represents the ping command
var pingCmd = &cobra.Command{
	Use:   "ping address",
	Short: "Ping mode",
	Long:  "Perform a TCP ping to a specified remote address through the proxy server. Can be used as a simple connectivity test.",
	Run:   runPing,
}

func init() {
	rootCmd.AddCommand(pingCmd)
}

func runPing(cmd *cobra.Command, args []string) {
	logger.Info("ping mode")

	if len(args) != 1 {
		logger.Fatal("must specify one and only one address")
	}
	addr := args[0]

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read client config", zap.Error(err))
	}
	var config clientConfig
	if err := viper.Unmarshal(&config); err != nil {
		logger.Fatal("failed to parse client config", zap.Error(err))
	}
	hyConfig, err := config.Config()
	if err != nil {
		logger.Fatal("failed to load client config", zap.Error(err))
	}

	c, info, err := client.NewClient(hyConfig)
	if err != nil {
		logger.Fatal("failed to initialize client", zap.Error(err))
	}
	defer c.Close()
	logger.Info("connected to server",
		zap.Bool("udpEnabled", info.UDPEnabled),
		zap.Uint64("tx", info.Tx))

	logger.Info("connecting", zap.String("addr", addr))
	start := time.Now()
	conn, err := c.TCP(addr)
	if err != nil {
		logger.Fatal("failed to connect", zap.Error(err), zap.String("time", time.Since(start).String()))
	}
	defer conn.Close()

	logger.Info("connected", zap.String("time", time.Since(start).String()))
}
