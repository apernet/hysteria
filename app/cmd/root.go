package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	appLogo = `
░█░█░█░█░█▀▀░▀█▀░█▀▀░█▀▄░▀█▀░█▀█░░░▀▀▄
░█▀█░░█░░▀▀█░░█░░█▀▀░█▀▄░░█░░█▀█░░░▄▀░
░▀░▀░░▀░░▀▀▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀░▀░░░▀▀▀
`
	appDesc    = "a powerful, censorship-resistant proxy tool optimized for lossy networks"
	appAuthors = "Aperture Internet Laboratory <https://github.com/apernet>"
)

var (
	// These values will be injected by the build system
	appVersion = "Unknown"
	appDate    = "Unknown"
	appCommit  = "Unknown"

	appVersionLong = fmt.Sprintf("Version:\t%s\nBuildDate:\t%s\nCommitHash:\t%s", appVersion, appDate, appCommit)
)

var logger *zap.Logger

// Flags
var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "hysteria",
	Short: appDesc,
	Long:  fmt.Sprintf("%s\n%s\n%s\n\n%s", appLogo, appDesc, appAuthors, appVersionLong),
	Run:   runClient, // Default to client mode
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	initLogger()
	initFlags()
	cobra.OnInitialize(initConfig)
}

func initLogger() {
	// TODO: Configurable logging
	l, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	logger = l
}

func initFlags() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/hysteria/")
		viper.AddConfigPath("$HOME/.hysteria")
		viper.AddConfigPath(".")
	}
}
