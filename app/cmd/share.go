package cmd

import (
	"fmt"

	"github.com/apernet/hysteria/app/v2/internal/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	noText bool
	withQR bool
)

// shareCmd represents the share command
var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Generate share URI",
	Long:  "Generate a hysteria2:// URI from a client config for sharing",
	Run:   runShare,
}

func init() {
	initShareFlags()
	rootCmd.AddCommand(shareCmd)
}

func initShareFlags() {
	shareCmd.Flags().BoolVar(&noText, "notext", false, "do not show URI as text")
	shareCmd.Flags().BoolVar(&withQR, "qr", false, "show URI as QR code")
}

func runShare(cmd *cobra.Command, args []string) {
	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read client config", zap.Error(err))
	}
	var config clientConfig
	if err := viper.Unmarshal(&config); err != nil {
		logger.Fatal("failed to parse client config", zap.Error(err))
	}
	if _, err := config.Config(); err != nil {
		logger.Fatal("failed to load client config", zap.Error(err))
	}

	u := config.URI()

	if !noText {
		fmt.Println(u)
	}
	if withQR {
		utils.PrintQR(u)
	}
}
