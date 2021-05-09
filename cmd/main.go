package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"
	"github.com/yosuke-furukawa/json5/encoding/json5"

	"github.com/urfave/cli/v2"
)

var (
	appVersion = "Unknown"
	appCommit  = "Unknown"
	appDate    = "Unknown"
)

func main() {
	app := &cli.App{
		Name:                 "Hysteria",
		Usage:                "a TCP/UDP relay & SOCKS5/HTTP proxy tool optimized for poor network environments",
		Version:              fmt.Sprintf("%s %s %s", appVersion, appDate, appCommit),
		Authors:              []*cli.Author{{Name: "HyNetwork <https://github.com/HyNetwork>"}},
		EnableBashCompletion: true,
		Action:               clientAction,
		Flags:                commonFlags(),
		Before:               initApp,
		Commands: []*cli.Command{
			{
				Name:   "server",
				Usage:  "Run as server mode",
				Action: serverAction,
			},
			{
				Name:   "client",
				Usage:  "Run as client mode",
				Action: clientAction,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logrus.Fatal(err)
	}

}

func clientAction(c *cli.Context) error {
	cbs, err := ioutil.ReadFile(c.String("config"))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"file":  c.String("config"),
			"error": err,
		}).Fatal("Failed to read configuration")
	}
	// client mode
	cc, err := parseClientConfig(cbs)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"file":  c.String("config"),
			"error": err,
		}).Fatal("Failed to parse client configuration")
	}
	client(cc)
	return nil
}

func serverAction(c *cli.Context) error {
	cbs, err := ioutil.ReadFile(c.String("config"))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"file":  c.String("config"),
			"error": err,
		}).Fatal("Failed to read configuration")
	}
	// server mode
	sc, err := parseServerConfig(cbs)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"file":  c.String("config"),
			"error": err,
		}).Fatal("Failed to parse server configuration")
	}
	server(sc)
	return nil
}

func parseServerConfig(cb []byte) (*serverConfig, error) {
	var c serverConfig
	err := json5.Unmarshal(cb, &c)
	if err != nil {
		return nil, err
	}
	return &c, c.Check()
}

func parseClientConfig(cb []byte) (*clientConfig, error) {
	var c clientConfig
	err := json5.Unmarshal(cb, &c)
	if err != nil {
		return nil, err
	}
	return &c, c.Check()
}

func initApp(c *cli.Context) error {
	logrus.SetOutput(os.Stdout)

	lvl, err := logrus.ParseLevel(c.String("log-level"))
	if err == nil {
		logrus.SetLevel(lvl)
	} else {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if strings.ToLower(c.String("log-format")) == "json" {
		logrus.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: c.String("log-timestamp"),
		})
	} else {
		logrus.SetFormatter(&nested.Formatter{
			FieldsOrder: []string{
				"version", "url",
				"config", "file", "mode",
				"addr", "src", "dst", "session", "action",
				"error",
			},
			TimestampFormat: c.String("log-timestamp"),
		})
	}

	if !c.Bool("no-check") {
		go checkUpdate()
	}

	return nil
}

func commonFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "config file",
			EnvVars: []string{"HYSTERIA_CONFIG"},
			Value:   "./config.json",
		},
		&cli.StringFlag{
			Name:    "log-level",
			Usage:   "log level",
			EnvVars: []string{"HYSTERIA_LOG_LEVEL", "LOGGING_LEVEL"},
			Value:   "debug",
		},
		&cli.StringFlag{
			Name:    "log-timestamp",
			Usage:   "log timestamp format",
			EnvVars: []string{"HYSTERIA_LOG_TIMESTAMP", "LOGGING_TIMESTAMP_FORMAT"},
			Value:   time.RFC3339,
		},
		&cli.StringFlag{
			Name:    "log-format",
			Usage:   "log output format",
			EnvVars: []string{"HYSTERIA_LOG_FORMAT", "LOGGING_FORMATTER"},
			Value:   "txt",
		},
		&cli.BoolFlag{
			Name:    "no-check",
			Usage:   "disable update check",
			EnvVars: []string{"HYSTERIA_CHECK_UPDATE"},
		},
	}
}
