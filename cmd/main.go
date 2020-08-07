package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// Injected when compiling
var (
	appVersion = "Unknown"
	appCommit  = "Unknown"
	appDate    = "Unknown"
)

var modeMap = map[string]func(args []string){
	"relay server": relayServer,
	"relay client": relayClient,
	"proxy server": proxyServer,
	"proxy client": proxyClient,
}

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
}

func main() {
	if len(os.Args) == 2 && strings.ToLower(strings.TrimSpace(os.Args[1])) == "version" {
		// Print version and quit
		fmt.Printf("%-10s%s\n", "Version:", appVersion)
		fmt.Printf("%-10s%s\n", "Commit:", appCommit)
		fmt.Printf("%-10s%s\n", "Date:", appDate)
		return
	}
	if len(os.Args) < 3 {
		fmt.Println()
		fmt.Printf("Usage: %s MODE SUBMODE [OPTIONS]\n\n"+
			"Available mode/submode combinations: "+getModes()+"\n"+
			"Use -h to see the available options for a mode.\n\n", os.Args[0])
		return
	}
	modeStr := fmt.Sprintf("%s %s", strings.ToLower(strings.TrimSpace(os.Args[1])),
		strings.ToLower(strings.TrimSpace(os.Args[2])))
	f := modeMap[modeStr]
	if f != nil {
		f(os.Args[3:])
	} else {
		fmt.Println("Invalid mode:", modeStr)
	}
}

func getModes() string {
	modes := make([]string, 0, len(modeMap))
	for mode := range modeMap {
		modes = append(modes, mode)
	}
	return strings.Join(modes, ", ")
}
