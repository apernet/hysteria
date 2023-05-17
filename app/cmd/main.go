package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
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
	authors = "Aperture Internet Laboratory <https://github.com/apernet>"
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
					"config", "file", "mode", "protocol",
					"cert", "key",
					"addr", "src", "dst", "session", "action", "interface",
					"tcp-sndbuf", "tcp-rcvbuf",
					"retry", "interval",
					"code", "msg", "error",
				},
				TimestampFormat: viper.GetString("log-timestamp"),
			})
		}

		// license
		if viper.GetBool("license") {
			fmt.Printf("%s\n", license)
			os.Exit(0)
		}

		// ip mask config
		v4m := viper.GetUint("log-ipv4-mask")
		if v4m > 0 && v4m < 32 {
			defaultIPMasker.IPv4Mask = net.CIDRMask(int(v4m), 32)
		}
		v6m := viper.GetUint("log-ipv6-mask")
		if v6m > 0 && v6m < 128 {
			defaultIPMasker.IPv6Mask = net.CIDRMask(int(v6m), 128)
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
	openWinVT()

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
	rootCmd.PersistentFlags().String("log-format", "txt", "log output format (txt/json)")
	rootCmd.PersistentFlags().Uint("log-ipv4-mask", 0, "mask IPv4 addresses in log using a CIDR mask")
	rootCmd.PersistentFlags().Uint("log-ipv6-mask", 0, "mask IPv6 addresses in log using a CIDR mask")
	rootCmd.PersistentFlags().Bool("no-check", false, "disable update check")
	rootCmd.PersistentFlags().Bool("license", false, "show license and exit")

	// add to root cmd
	rootCmd.AddCommand(clientCmd, serverCmd, completionCmd)

	// bind flag
	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	_ = viper.BindPFlag("mmdb-url", rootCmd.PersistentFlags().Lookup("mmdb-url"))
	_ = viper.BindPFlag("log-level", rootCmd.PersistentFlags().Lookup("log-level"))
	_ = viper.BindPFlag("log-timestamp", rootCmd.PersistentFlags().Lookup("log-timestamp"))
	_ = viper.BindPFlag("log-format", rootCmd.PersistentFlags().Lookup("log-format"))
	_ = viper.BindPFlag("log-ipv4-mask", rootCmd.PersistentFlags().Lookup("log-ipv4-mask"))
	_ = viper.BindPFlag("log-ipv6-mask", rootCmd.PersistentFlags().Lookup("log-ipv6-mask"))
	_ = viper.BindPFlag("no-check", rootCmd.PersistentFlags().Lookup("no-check"))
	_ = viper.BindPFlag("license", rootCmd.PersistentFlags().Lookup("license"))

	// bind env
	_ = viper.BindEnv("config", "HYSTERIA_CONFIG")
	_ = viper.BindEnv("mmdb-url", "HYSTERIA_MMDB_URL")
	_ = viper.BindEnv("log-level", "HYSTERIA_LOG_LEVEL", "LOGGING_LEVEL")
	_ = viper.BindEnv("log-timestamp", "HYSTERIA_LOG_TIMESTAMP", "LOGGING_TIMESTAMP_FORMAT")
	_ = viper.BindEnv("log-format", "HYSTERIA_LOG_FORMAT", "LOGGING_FORMATTER")
	_ = viper.BindEnv("log-ipv4-mask", "HYSTERIA_LOG_IPV4_MASK", "LOGGING_IPV4_MASK")
	_ = viper.BindEnv("log-ipv6-mask", "HYSTERIA_LOG_IPV6_MASK", "LOGGING_IPV6_MASK")
	_ = viper.BindEnv("no-check", "HYSTERIA_NO_CHECK", "HYSTERIA_NO_CHECK_UPDATE")
	viper.AutomaticEnv()
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}
