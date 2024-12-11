package cmd

import (
	"fmt"
	"os"
	"strconv"
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
	appDesc    = "a powerful, lightning fast and censorship resistant proxy"
	appAuthors = "Aperture Internet Laboratory <https://github.com/apernet>"

	appLogLevelEnv           = "HYSTERIA_LOG_LEVEL"
	appLogFormatEnv          = "HYSTERIA_LOG_FORMAT"
	appDisableUpdateCheckEnv = "HYSTERIA_DISABLE_UPDATE_CHECK"
	appACMEDirEnv            = "HYSTERIA_ACME_DIR"
)

var (
	// These values will be injected by the build system
	appVersion   = "Unknown"
	appDate      = "Unknown"
	appType      = "Unknown" // aka channel
	appToolchain = "Unknown"
	appCommit    = "Unknown"
	appPlatform  = "Unknown"
	appArch      = "Unknown"
	libVersion   = "Unknown"

	appVersionLong = fmt.Sprintf("Version:\t%s\n"+
		"BuildDate:\t%s\n"+
		"BuildType:\t%s\n"+
		"Toolchain:\t%s\n"+
		"CommitHash:\t%s\n"+
		"Platform:\t%s\n"+
		"Architecture:\t%s\n"+
		"Libraries:\tquic-go=%s",
		appVersion, appDate, appType, appToolchain, appCommit, appPlatform, appArch, libVersion)

	appAboutLong = fmt.Sprintf("%s\n%s\n%s\n\n%s", appLogo, appDesc, appAuthors, appVersionLong)
)

var logger *zap.Logger

// Flags
var (
	cfgFile            string
	logLevel           string
	logFormat          string
	disableUpdateCheck bool
)

var rootCmd = &cobra.Command{
	Use:   "hysteria",
	Short: appDesc,
	Long:  appAboutLong,
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
	cobra.MousetrapHelpText = "" // Disable the mousetrap so Windows users can run the exe directly by double-clicking
	cobra.OnInitialize(initConfig)
	cobra.OnInitialize(initLogger) // initLogger must come after initConfig as it depends on config
}

func initFlags() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", envOrDefaultString(appLogLevelEnv, "info"), "log level")
	rootCmd.PersistentFlags().StringVarP(&logFormat, "log-format", "f", envOrDefaultString(appLogFormatEnv, "console"), "log format")
	rootCmd.PersistentFlags().BoolVar(&disableUpdateCheck, "disable-update-check", envOrDefaultBool(appDisableUpdateCheckEnv, false), "disable update check")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.SupportedExts = append([]string{"yaml", "yml"}, viper.SupportedExts...)
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.hysteria")
		viper.AddConfigPath("/etc/hysteria/")
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

func envOrDefaultString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrDefaultBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		b, _ := strconv.ParseBool(v)
		return b
	}
	return def
}
