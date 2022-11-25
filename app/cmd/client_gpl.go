//go:build gpl
// +build gpl

package main

import (
	"io"
	"net"
	"strings"
	"time"

	"github.com/apernet/hysteria/app/tun"

	"github.com/docker/go-units"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/apernet/hysteria/core/cs"
	"github.com/sirupsen/logrus"
)

const license = `Hysteria is a feature-packed proxy & relay utility optimized for lossy, unstable connections.
Copyright (C) 2022  Toby

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
`

func startTUN(config *clientConfig, client *cs.Client, errChan chan error) {
	timeout := time.Duration(config.TUN.Timeout) * time.Second
	if timeout == 0 {
		timeout = 300 * time.Second
	}

	var err error
	var tcpSendBufferSize, tcpReceiveBufferSize int64

	if config.TUN.TCPSendBufferSize != "" {
		tcpSendBufferSize, err = units.RAMInBytes(config.TUN.TCPSendBufferSize)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error":      err,
				"tcp-sndbuf": config.TUN.TCPSendBufferSize,
			}).Fatal("Failed to parse tcp-sndbuf in the TUN config")
		}
		if (tcpSendBufferSize != 0 && tcpSendBufferSize < tcp.MinBufferSize) || tcpSendBufferSize > tcp.MaxBufferSize {
			logrus.WithFields(logrus.Fields{
				"tcp-sndbuf": config.TUN.TCPSendBufferSize,
			}).Fatal("Invalid tcp-sndbuf in the TUN config")
		}
	}
	if config.TUN.TCPReceiveBufferSize != "" {
		tcpReceiveBufferSize, err = units.RAMInBytes(config.TUN.TCPReceiveBufferSize)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error":      err,
				"tcp-rcvbuf": config.TUN.TCPReceiveBufferSize,
			}).Fatal("Failed to parse tcp-rcvbuf in the TUN config")
		}
		if (tcpReceiveBufferSize != 0 && tcpReceiveBufferSize < tcp.MinBufferSize) || tcpReceiveBufferSize > tcp.MaxBufferSize {
			logrus.WithFields(logrus.Fields{
				"error":      err,
				"tcp-rcvbuf": config.TUN.TCPReceiveBufferSize,
			}).Fatal("Invalid tcp-rcvbuf in the TUN config")
		}
	}

	tunServer, err := tun.NewServer(client, timeout,
		config.TUN.Name, config.TUN.MTU,
		int(tcpSendBufferSize), int(tcpReceiveBufferSize), config.TUN.TCPModerateReceiveBuffer)
	if err != nil {
		logrus.WithField("error", err).Fatal("Failed to initialize TUN server")
	}
	tunServer.RequestFunc = func(addr net.Addr, reqAddr string) {
		logrus.WithFields(logrus.Fields{
			"src": defaultIPMasker.Mask(addr.String()),
			"dst": defaultIPMasker.Mask(reqAddr),
		}).Debugf("TUN %s request", strings.ToUpper(addr.Network()))
	}
	tunServer.ErrorFunc = func(addr net.Addr, reqAddr string, err error) {
		if err != nil {
			if err == io.EOF {
				logrus.WithFields(logrus.Fields{
					"src": defaultIPMasker.Mask(addr.String()),
					"dst": defaultIPMasker.Mask(reqAddr),
				}).Debugf("TUN %s EOF", strings.ToUpper(addr.Network()))
			} else if err == cs.ErrClosed && strings.HasPrefix(addr.Network(), "udp") {
				logrus.WithFields(logrus.Fields{
					"src": defaultIPMasker.Mask(addr.String()),
					"dst": defaultIPMasker.Mask(reqAddr),
				}).Debugf("TUN %s closed for timeout", strings.ToUpper(addr.Network()))
			} else if nErr, ok := err.(net.Error); ok && nErr.Timeout() && strings.HasPrefix(addr.Network(), "tcp") {
				logrus.WithFields(logrus.Fields{
					"src": defaultIPMasker.Mask(addr.String()),
					"dst": defaultIPMasker.Mask(reqAddr),
				}).Debugf("TUN %s closed for timeout", strings.ToUpper(addr.Network()))
			} else {
				logrus.WithFields(logrus.Fields{
					"error": err,
					"src":   defaultIPMasker.Mask(addr.String()),
					"dst":   defaultIPMasker.Mask(reqAddr),
				}).Infof("TUN %s error", strings.ToUpper(addr.Network()))
			}
		}
	}
	logrus.WithField("interface", config.TUN.Name).Info("TUN up and running")
	errChan <- tunServer.ListenAndServe()
}
