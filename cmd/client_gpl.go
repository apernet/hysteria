//go:build gpl
// +build gpl

package main

import (
	"io"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/tobyxdd/hysteria/pkg/core"
	"github.com/tobyxdd/hysteria/pkg/tun"
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

func startTUN(config *clientConfig, client *core.Client, errChan chan error) {
	timeout := time.Duration(config.TUN.Timeout) * time.Second
	if timeout == 0 {
		timeout = 300 * time.Second
	}
	tunServer, err := tun.NewServer(client, time.Duration(config.TUN.Timeout)*time.Second,
		config.TUN.Name, config.TUN.MTU)
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
			} else if err == core.ErrClosed && strings.HasPrefix(addr.Network(), "udp") {
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
