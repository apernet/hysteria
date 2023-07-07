package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	appLogo = `
░█░█░█░█░█▀▀░▀█▀░█▀▀░█▀▄░▀█▀░█▀█░░░▀▀▄
░█▀█░░█░░▀▀█░░█░░█▀▀░█▀▄░░█░░█▀█░░░▄▀░
░▀░▀░░▀░░▀▀▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀░▀░░░▀▀▀
`
	appDesc    = "a powerful, censorship-resistant proxy tool optimized for lossy networks"
	appAuthors = "Aperture Internet Laboratory <https://github.com/apernet>"

	appLogLevelEnv  = "HYSTERIA_LOG_LEVEL"
	appLogFormatEnv = "HYSTERIA_LOG_FORMAT"
)

var (
	// These values will be injected by the build system
	appVersion = "Unknown"
	appDate    = "Unknown"
	appType    = "Unknown"
	appCommit  = "Unknown"

	appVersionLong = fmt.Sprintf("Version:\t%s\nBuildDate:\t%s\nBuildType:\t%s\nCommitHash:\t%s",
		appVersion, appDate, appType, appCommit)
)

var logger *zap.Logger

// Flags
var (
	cfgFile   string
	logLevel  string
	logFormat string
)

var rootCmd = &cobra.Command{
	Use:   "hysteria",
	Short: appDesc,
	Long:  fmt.Sprintf("%s\n%s\n%s\n\n%s", appLogo, appDesc, appAuthors, appVersionLong),
	Run:   runClient, // Default to client mode
}

var logLevelMap = map[string]zapcore.Level{
	"debug": zapcore.DebugLevel,
	"info":  zapcore.InfoLevel,
	"warn":  zapcore.WarnLevel,
	"error": zapcore.ErrorLevel,
}

var logFormatMap = map[string]zapcore.EncoderConfig{
	"console": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
	"json": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.EpochMillisTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	initFlags()
	cobra.OnInitialize(initConfig)
	cobra.OnInitialize(initLogger) // initLogger must come after initConfig as it depends on config
}

func initFlags() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", envOrDefault(appLogLevelEnv, "info"), "log level")
	rootCmd.PersistentFlags().StringVarP(&logFormat, "log-format", "f", envOrDefault(appLogFormatEnv, "console"), "log format")
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

func initLogger() {
	level, ok := logLevelMap[strings.ToLower(logLevel)]
	if !ok {
		fmt.Printf("unsupported log level: %s\n", logLevel)
		os.Exit(1)
	}
	enc, ok := logFormatMap[strings.ToLower(logFormat)]
	if !ok {
		fmt.Printf("unsupported log format: %s\n", logFormat)
		os.Exit(1)
	}
	c := zap.Config{
		Level:             zap.NewAtomicLevelAt(level),
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          strings.ToLower(logFormat),
		EncoderConfig:     enc,
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
	var err error
	logger, err = c.Build()
	if err != nil {
		fmt.Printf("failed to initialize logger: %s\n", err)
		os.Exit(1)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
