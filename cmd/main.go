package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	appVersion = "Unknown"
	appCommit  = "Unknown"
	appDate    = "Unknown"

	logo = `
██╗  ██╗██╗   ██╗███████╗████████╗███████╗██████╗ ██╗ █████╗ 
██║  ██║╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║██╔══██╗
███████║ ╚████╔╝ ███████╗   ██║   █████╗  ██████╔╝██║███████║
██╔══██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗██║██╔══██║
██║  ██║   ██║   ███████║   ██║   ███████╗██║  ██║██║██║  ██║
╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
                                                             
`
)

var rootCmd = &cobra.Command{
	Use:     "hysteria",
	Short:   logo + "A TCP/UDP relay & SOCKS5/HTTP proxy tool optimized for poor network environments",
	Example: "./hysteria server --config /etc/hysteria.json",
	Version: fmt.Sprintf("%s%s %s %s", logo, appVersion, appDate, appCommit),
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		rand.Seed(time.Now().UnixNano())

		// log config
		logrus.SetOutput(os.Stdout)
		if lvl, err := logrus.ParseLevel(viper.GetString("log-level")); err == nil {
			logrus.SetLevel(lvl)
		} else {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if strings.ToLower(viper.GetString("log-timestamp")) == "json" {
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
}

var clientCmd = &cobra.Command{
	Use:     "client",
	Short:   "Run as client mode",
	Example: "./hysteria client --config /etc/client.json",
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
	Example: "./hysteria server --config /etc/server.json",
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

func init() {
	// add global flags
	rootCmd.PersistentFlags().StringP("config", "c", "./config.json", "config file")
	rootCmd.PersistentFlags().String("log-level", "debug", "log level")
	rootCmd.PersistentFlags().String("log-timestamp", time.RFC3339, "log timestamp format")
	rootCmd.PersistentFlags().String("log-format", "txt", "log output format")
	rootCmd.PersistentFlags().Bool("no-check", false, "disable update check")

	// add to root cmd
	rootCmd.AddCommand(clientCmd, serverCmd)

	// bind env
	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	_ = viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("log-timestamp", rootCmd.PersistentFlags().Lookup("log-timestamp"))
	_ = viper.BindPFlag("log-format", rootCmd.PersistentFlags().Lookup("log-format"))
	_ = viper.BindPFlag("no-check", rootCmd.PersistentFlags().Lookup("log-format"))

	viper.SetEnvPrefix("HYSTERIA")
	viper.AutomaticEnv()
	_ = viper.ReadInConfig()
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}
