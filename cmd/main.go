package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	logo = `
░█░█░█░█░█▀▀░▀█▀░█▀▀░█▀▄░▀█▀░█▀█
░█▀█░░█░░▀▀█░░█░░█▀▀░█▀▄░░█░░█▀█
░▀░▀░░▀░░▀▀▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀░▀

`
	desc    = "A TCP/UDP relay & SOCKS5/HTTP proxy tool optimized for poor network environments"
	authors = "HyNetwork <https://github.com/HyNetwork>"
)

var (
	appVersion = "Unknown"
	appCommit  = "Unknown"
	appDate    = "Unknown"
)

var rootCmd = &cobra.Command{
	Use:     "hysteria",
	Long:    fmt.Sprintf("%s%s\n\nVersion:\t%s\nBuildDate:\t%s\nCommitHash:\t%s\nAuthors:\t%s", logo, desc, appVersion, appDate, appCommit, authors),
	Example: "./hysteria server --config /etc/hysteria.json",
	Version: fmt.Sprintf("%s %s %s", appVersion, appDate, appCommit),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		rand.Seed(time.Now().UnixNano())

		// log config
		logrus.SetOutput(os.Stdout)
		if lvl, err := logrus.ParseLevel(viper.GetString("log-level")); err == nil {
			logrus.SetLevel(lvl)
		} else {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if strings.ToLower(viper.GetString("log-format")) == "json" {
			logrus.SetFormatter(&logrus.JSONFormatter{
				TimestampFormat: viper.GetString("log-timestamp"),
			})
		} else {
			logrus.SetFormatter(&nested.Formatter{
				FieldsOrder: []string{
					"version", "url",
					"config", "file", "mode",
					"addr", "src", "dst", "session", "action",
					"retry", "interval",
					"code", "msg", "error",
				},
				TimestampFormat: viper.GetString("log-timestamp"),
			})
		}

		// check update
		if !viper.GetBool("no-check") {
			go checkUpdate()
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		clientCmd.Run(cmd, args)
	},
}

var clientCmd = &cobra.Command{
	Use:     "client",
	Short:   "Run as client mode",
	Example: "./hysteria client --config /etc/hysteria/client.json",
	Run: func(cmd *cobra.Command, args []string) {
		cbs, err := ioutil.ReadFile(viper.GetString("config"))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"file":  viper.GetString("config"),
				"error": err,
			}).Fatal("Failed to read configuration")
		}
		// client mode
		cc, err := parseClientConfig(cbs)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"file":  viper.GetString("config"),
				"error": err,
			}).Fatal("Failed to parse client configuration")
		}
		client(cc)
	},
}

var serverCmd = &cobra.Command{
	Use:     "server",
	Short:   "Run as server mode",
	Example: "./hysteria server --config /etc/hysteria/server.json",
	Run: func(cmd *cobra.Command, args []string) {
		cbs, err := ioutil.ReadFile(viper.GetString("config"))
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"file":  viper.GetString("config"),
				"error": err,
			}).Fatal("Failed to read configuration")
		}
		// server mode
		sc, err := parseServerConfig(cbs)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"file":  viper.GetString("config"),
				"error": err,
			}).Fatal("Failed to parse server configuration")
		}
		server(sc)
	},
}

// fakeFlags replace the old flag format with the new format(eg: `-config` ->> `--config`)
func fakeFlags() {
	var args []string
	fr, _ := regexp.Compile(`^-[a-zA-Z]{2,}`)
	for _, arg := range os.Args {
		if fr.MatchString(arg) {
			args = append(args, "-"+arg)
		} else {
			args = append(args, arg)
		}
	}
	os.Args = args
}

func init() {
	// compatible with old flag format
	fakeFlags()

	// compatible windows double click
	cobra.MousetrapHelpText = ""

	// disable cmd sorting
	cobra.EnableCommandSorting = false

	// add global flags
	rootCmd.PersistentFlags().StringP("config", "c", "./config.json", "config file")
	rootCmd.PersistentFlags().String("mmdb-url", "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb", "mmdb download url")
	rootCmd.PersistentFlags().String("log-level", "debug", "log level")
	rootCmd.PersistentFlags().String("log-timestamp", time.RFC3339, "log timestamp format")
	rootCmd.PersistentFlags().String("log-format", "txt", "log output format(txt/json)")
	rootCmd.PersistentFlags().Bool("no-check", false, "disable update check")

	// add to root cmd
	rootCmd.AddCommand(clientCmd, serverCmd, completionCmd)

	// bind flag
	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	_ = viper.BindPFlag("mmdb-url", rootCmd.PersistentFlags().Lookup("mmdb-url"))
	_ = viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("log-timestamp", rootCmd.PersistentFlags().Lookup("log-timestamp"))
	_ = viper.BindPFlag("log-format", rootCmd.PersistentFlags().Lookup("log-format"))
	_ = viper.BindPFlag("no-check", rootCmd.PersistentFlags().Lookup("no-check"))

	// bind env
	_ = viper.BindEnv("config", "HYSTERIA_CONFIG")
	_ = viper.BindEnv("mmdb-url", "HYSTERIA_MMDB_URL")
	_ = viper.BindEnv("log-level", "HYSTERIA_LOG_LEVEL", "LOGGING_LEVEL")
	_ = viper.BindEnv("log-timestamp", "HYSTERIA_LOG_TIMESTAMP", "LOGGING_TIMESTAMP_FORMAT")
	_ = viper.BindEnv("log-format", "HYSTERIA_LOG_FORMAT", "LOGGING_FORMATTER")
	_ = viper.BindEnv("no-check", "HYSTERIA_NO_CHECK", "HYSTERIA_NO_CHECK_UPDATE")
	viper.AutomaticEnv()
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}
