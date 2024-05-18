package cmd

import (
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/app/v2/internal/utils"
	"github.com/apernet/hysteria/core/v2/client"
)

const (
	updateCheckInterval = 24 * time.Hour
)

// checkUpdateCmd represents the checkUpdate command
var checkUpdateCmd = &cobra.Command{
	Use:   "check-update",
	Short: "Check for updates",
	Long:  "Check for updates.",
	Run:   runCheckUpdate,
}

func init() {
	rootCmd.AddCommand(checkUpdateCmd)
}

func runCheckUpdate(cmd *cobra.Command, args []string) {
	logger.Info("checking for updates",
		zap.String("version", appVersion),
		zap.String("platform", appPlatform),
		zap.String("arch", appArch),
		zap.String("channel", appType),
	)

	checker := utils.NewServerUpdateChecker(appVersion, appPlatform, appArch, appType)
	resp, err := checker.Check()
	if err != nil {
		logger.Fatal("failed to check for updates", zap.Error(err))
	}
	if resp.HasUpdate {
		logger.Info("update available",
			zap.String("version", resp.LatestVersion),
			zap.String("url", resp.URL),
			zap.Bool("urgent", resp.Urgent),
		)
	} else {
		logger.Info("no update available")
	}
}

// runCheckUpdateServer is the background update checking routine for server mode
func runCheckUpdateServer() {
	checker := utils.NewServerUpdateChecker(appVersion, appPlatform, appArch, appType)
	checkUpdateRoutine(checker)
}

// runCheckUpdateClient is the background update checking routine for client mode
func runCheckUpdateClient(hyClient client.Client) {
	checker := utils.NewClientUpdateChecker(appVersion, appPlatform, appArch, appType, hyClient)
	checkUpdateRoutine(checker)
}

func checkUpdateRoutine(checker *utils.UpdateChecker) {
	ticker := time.NewTicker(updateCheckInterval)
	for {
		logger.Debug("checking for updates",
			zap.String("version", appVersion),
			zap.String("platform", appPlatform),
			zap.String("arch", appArch),
			zap.String("channel", appType),
		)
		resp, err := checker.Check()
		if err != nil {
			logger.Debug("failed to check for updates", zap.Error(err))
		} else if resp.HasUpdate {
			logger.Info("update available",
				zap.String("version", resp.LatestVersion),
				zap.String("url", resp.URL),
				zap.Bool("urgent", resp.Urgent),
			)
		} else {
			logger.Debug("no update available")
		}
		<-ticker.C
	}
}
