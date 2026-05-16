package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/apernet/hysteria/core/v2/client"
	hyErrors "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/outbounds"
	"github.com/apernet/hysteria/extras/v2/outbounds/speedtest"
)

var (
	skipDownload bool
	skipUpload   bool
	dataSize     uint32
	testDuration time.Duration
	useBytes     bool

	speedtestAddr = fmt.Sprintf("%s:%d", outbounds.SpeedtestDest, 0)
)

// speedtestCmd represents the speedtest command
var speedtestCmd = &cobra.Command{
	Use:   "speedtest",
	Short: "Speed test mode",
	Long:  "Perform a speed test through the proxy server. The server must have speed test support enabled.",
	Run:   runSpeedtestCmd,
}

func init() {
	initSpeedtestFlags()
	rootCmd.AddCommand(speedtestCmd)
}

func initSpeedtestFlags() {
	speedtestCmd.Flags().BoolVar(&skipDownload, "skip-download", false, "Skip download test")
	speedtestCmd.Flags().BoolVar(&skipUpload, "skip-upload", false, "Skip upload test")
	speedtestCmd.Flags().DurationVar(&testDuration, "duration", 10*time.Second, "Duration for each direction in time-based mode")
	speedtestCmd.Flags().Uint32Var(&dataSize, "data-size", 0, "Data size in bytes (switches to size-based mode when set)")
	speedtestCmd.Flags().BoolVar(&useBytes, "use-bytes", false, "Use bytes per second instead of bits per second")
}

func runSpeedtestCmd(cmd *cobra.Command, args []string) {
	logger.Info("speed test mode")
	sizeBased := cmd.Flags().Changed("data-size")
	runSpeedtest(defaultViper, sizeBased)
}

func runSpeedtest(v *viper.Viper, sizeBased bool) {
	if err := v.ReadInConfig(); err != nil {
		logger.Fatal("failed to read client config", zap.Error(err))
	}
	var config clientConfig
	if err := v.Unmarshal(&config); err != nil {
		logger.Fatal("failed to parse client config", zap.Error(err))
	}
	hyConfig, err := config.Config()
	if err != nil {
		logger.Fatal("failed to load client config", zap.Error(err))
	}

	c, info, err := client.NewClient(hyConfig)
	if err != nil {
		logger.Fatal("failed to initialize client", zap.Error(err))
	}
	defer c.Close()
	logger.Info("connected to server",
		zap.String("addr", info.ServerAddr.String()),
		zap.Bool("udpEnabled", info.UDPEnabled),
		zap.Uint64("tx", info.Tx))

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalChan)

	runChan := make(chan struct{}, 1)
	go func() {
		if !skipDownload {
			runSingleTest(c, sizeBased, true)
		}
		if !skipUpload {
			runSingleTest(c, sizeBased, false)
		}
		runChan <- struct{}{}
	}()

	select {
	case <-signalChan:
		logger.Info("received signal, shutting down gracefully")
	case <-runChan:
		logger.Info("speed test complete")
	}
}

func runSingleTest(c client.Client, sizeBased, download bool) {
	name := "upload"
	if download {
		name = "download"
	}
	logger.Info("performing " + name + " test")
	conn, err := c.TCP(speedtestAddr)
	if err != nil {
		if errors.As(err, &hyErrors.DialError{}) {
			logger.Fatal("failed to connect (server may not support speed test)", zap.Error(err))
		} else {
			logger.Fatal("failed to connect", zap.Error(err))
		}
	}
	defer conn.Close()

	sc := &speedtest.Client{Conn: conn}
	var currentTotal uint64
	var elapsed time.Duration
	dur := testDuration
	if sizeBased {
		dur = 0
	}
	cb := func(d time.Duration, b uint64, done bool) {
		if !done {
			currentTotal += b
			elapsed += d
			var progress float64
			if sizeBased {
				progress = float64(currentTotal) / float64(dataSize) * 100
			} else {
				progress = float64(elapsed) / float64(testDuration) * 100
			}
			logger.Info(name+"ing",
				zap.Uint64("bytes", b),
				zap.String("progress", fmt.Sprintf("%.2f%%", progress)),
				zap.String("speed", formatSpeed(b, d, useBytes)))
		} else {
			logger.Info(name+" complete",
				zap.Uint64("bytes", b),
				zap.String("speed", formatSpeed(b, d, useBytes)))
		}
	}
	if download {
		err = sc.Download(dataSize, dur, cb)
	} else {
		err = sc.Upload(dataSize, dur, cb)
	}
	if err != nil {
		logger.Fatal(name+" test failed", zap.Error(err))
	}
	logger.Info(name + " test complete")
}

func formatSpeed(bytes uint64, duration time.Duration, useBytes bool) string {
	speed := float64(bytes) / duration.Seconds()
	var units []string
	if useBytes {
		units = []string{"B/s", "KB/s", "MB/s", "GB/s"}
	} else {
		units = []string{"bps", "Kbps", "Mbps", "Gbps"}
		speed *= 8
	}
	unitIndex := 0
	for speed > 1000 && unitIndex < len(units)-1 {
		speed /= 1000
		unitIndex++
	}
	return fmt.Sprintf("%.2f %s", speed, units[unitIndex])
}
