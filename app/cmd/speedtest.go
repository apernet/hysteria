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
	useBytes     bool

	speedtestAddr = fmt.Sprintf("%s:%d", outbounds.SpeedtestDest, 0)
)

// speedtestCmd represents the speedtest command
var speedtestCmd = &cobra.Command{
	Use:   "speedtest",
	Short: "Speed test mode",
	Long:  "Perform a speed test through the proxy server. The server must have speed test support enabled.",
	Run:   runSpeedtest,
}

func init() {
	initSpeedtestFlags()
	rootCmd.AddCommand(speedtestCmd)
}

func initSpeedtestFlags() {
	speedtestCmd.Flags().BoolVar(&skipDownload, "skip-download", false, "Skip download test")
	speedtestCmd.Flags().BoolVar(&skipUpload, "skip-upload", false, "Skip upload test")
	speedtestCmd.Flags().Uint32Var(&dataSize, "data-size", 1024*1024*100, "Data size for download and upload tests")
	speedtestCmd.Flags().BoolVar(&useBytes, "use-bytes", false, "Use bytes per second instead of bits per second")
}

func runSpeedtest(cmd *cobra.Command, args []string) {
	logger.Info("speed test mode")

	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read client config", zap.Error(err))
	}
	var config clientConfig
	if err := viper.Unmarshal(&config); err != nil {
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
		zap.Bool("udpEnabled", info.UDPEnabled),
		zap.Uint64("tx", info.Tx))

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalChan)

	runChan := make(chan struct{}, 1)
	go func() {
		if !skipDownload {
			runDownloadTest(c)
		}
		if !skipUpload {
			runUploadTest(c)
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

func runDownloadTest(c client.Client) {
	logger.Info("performing download test")
	downConn, err := c.TCP(speedtestAddr)
	if err != nil {
		if errors.As(err, &hyErrors.DialError{}) {
			logger.Fatal("failed to connect (server may not support speed test)", zap.Error(err))
		} else {
			logger.Fatal("failed to connect", zap.Error(err))
		}
	}
	defer downConn.Close()

	downClient := &speedtest.Client{Conn: downConn}
	currentTotal := uint32(0)
	err = downClient.Download(dataSize, func(d time.Duration, b uint32, done bool) {
		if !done {
			currentTotal += b
			logger.Info("downloading",
				zap.Uint32("bytes", b),
				zap.String("progress", fmt.Sprintf("%.2f%%", float64(currentTotal)/float64(dataSize)*100)),
				zap.String("speed", formatSpeed(b, d, useBytes)))
		} else {
			logger.Info("download complete",
				zap.Uint32("bytes", b),
				zap.String("speed", formatSpeed(b, d, useBytes)))
		}
	})
	if err != nil {
		logger.Fatal("download test failed", zap.Error(err))
	}
	logger.Info("download test complete")
}

func runUploadTest(c client.Client) {
	logger.Info("performing upload test")
	upConn, err := c.TCP(speedtestAddr)
	if err != nil {
		if errors.As(err, &hyErrors.DialError{}) {
			logger.Fatal("failed to connect (server may not support speed test)", zap.Error(err))
		} else {
			logger.Fatal("failed to connect", zap.Error(err))
		}
	}
	defer upConn.Close()

	upClient := &speedtest.Client{Conn: upConn}
	currentTotal := uint32(0)
	err = upClient.Upload(dataSize, func(d time.Duration, b uint32, done bool) {
		if !done {
			currentTotal += b
			logger.Info("uploading",
				zap.Uint32("bytes", b),
				zap.String("progress", fmt.Sprintf("%.2f%%", float64(currentTotal)/float64(dataSize)*100)),
				zap.String("speed", formatSpeed(b, d, useBytes)))
		} else {
			logger.Info("upload complete",
				zap.Uint32("bytes", b),
				zap.String("speed", formatSpeed(b, d, useBytes)))
		}
	})
	if err != nil {
		logger.Fatal("upload test failed", zap.Error(err))
	}
	logger.Info("upload test complete")
}

func formatSpeed(bytes uint32, duration time.Duration, useBytes bool) string {
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
