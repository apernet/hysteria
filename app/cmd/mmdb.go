package main

import (
	"io"
	"net/http"
	"os"

	"github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func downloadMMDB(filename string) error {
	resp, err := http.Get(viper.GetString("mmdb-url"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	return err
}

func loadMMDBReader(filename string) (*geoip2.Reader, error) {
	if _, err := os.Stat(filename); err != nil {
		if os.IsNotExist(err) {
			logrus.Info("GeoLite2 database not found, downloading...")
			if err := downloadMMDB(filename); err != nil {
				return nil, err
			}
			logrus.WithFields(logrus.Fields{
				"file": filename,
			}).Info("GeoLite2 database downloaded")
			return geoip2.Open(filename)
		} else {
			// some other error
			return nil, err
		}
	} else {
		// file exists, just open it
		return geoip2.Open(filename)
	}
}
