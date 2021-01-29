package main

import (
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/yosuke-furukawa/json5/encoding/json5"
	"io/ioutil"
	"os"
	"strings"
)

// Injected when compiling
var (
	appVersion = "Unknown"
	appCommit  = "Unknown"
	appDate    = "Unknown"
)

var (
	configPath  = flag.String("config", "config.json", "Config file")
	showVersion = flag.Bool("version", false, "Show version")
)

func init() {
	logrus.SetOutput(os.Stdout)

	lvl, err := logrus.ParseLevel(os.Getenv("LOGGING_LEVEL"))
	if err == nil {
		logrus.SetLevel(lvl)
	} else {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// tsFormat is used to format the log timestamp, by default(empty)
	// the RFC3339("2006-01-02T15:04:05Z07:00") format is used.
	// The user can use environment variable to override the default
	// timestamp format(e.g. "2006-01-02 15:04:05").
	tsFormat := os.Getenv("LOGGING_TIMESTAMP_FORMAT")

	fmtter := os.Getenv("LOGGING_FORMATTER")
	if strings.ToLower(fmtter) == "json" {
		logrus.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: tsFormat,
		})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			ForceColors:     true,
			FullTimestamp:   true,
			TimestampFormat: tsFormat,
		})
	}

	flag.Parse()
}

func main() {
	if *showVersion {
		// Print version and quit
		fmt.Printf("%-10s%s\n", "Version:", appVersion)
		fmt.Printf("%-10s%s\n", "Commit:", appCommit)
		fmt.Printf("%-10s%s\n", "Date:", appDate)
		return
	}
	cb, err := ioutil.ReadFile(*configPath)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"file":  *configPath,
			"error": err,
		}).Fatal("Failed to read configuration")
	}
	mode := flag.Arg(0)
	if strings.EqualFold(mode, "server") {
		// server mode
		c, err := parseServerConfig(cb)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"file":  *configPath,
				"error": err,
			}).Fatal("Failed to parse server configuration")
		}
		server(c)
	} else if len(mode) == 0 || strings.EqualFold(mode, "client") {
		// client mode
		c, err := parseClientConfig(cb)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"file":  *configPath,
				"error": err,
			}).Fatal("Failed to parse client configuration")
		}
		client(c)
	} else {
		// invalid
		fmt.Println()
		fmt.Printf("Usage: %s MODE [OPTIONS]\n\n"+
			"Available modes: server, client\n\n", os.Args[0])
	}
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
