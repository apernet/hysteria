package utils

import (
	"io"
	"net/http"
	"os"

	"github.com/oschwald/geoip2-golang"
)

const (
	geoipDefaultFilename = "GeoLite2-Country.mmdb"
	geoipDownloadURL     = "https://git.io/GeoLite2-Country.mmdb"
)

// GeoIPLoader provides the on-demand GeoIP database loading function required by the ACL engine.
type GeoIPLoader struct {
	Filename        string
	DownloadFunc    func(filename, url string) // Called when downloading the GeoIP database.
	DownloadErrFunc func(err error)            // Called when downloading the GeoIP database succeeds/fails.

	db *geoip2.Reader
}

func (l *GeoIPLoader) download() error {
	resp, err := http.Get(geoipDownloadURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	f, err := os.Create(geoipDefaultFilename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func (l *GeoIPLoader) Load() *geoip2.Reader {
	if l.db == nil {
		if l.Filename == "" {
			// Filename not specified, try default.
			if _, err := os.Stat(geoipDefaultFilename); err == nil {
				// Default already exists, just use it.
				l.Filename = geoipDefaultFilename
			} else if os.IsNotExist(err) {
				// Default doesn't exist, download it.
				l.DownloadFunc(geoipDefaultFilename, geoipDownloadURL)
				err := l.download()
				l.DownloadErrFunc(err)
				if err != nil {
					return nil
				}
				l.Filename = geoipDefaultFilename
			} else {
				// Other error
				return nil
			}
		}
		db, err := geoip2.Open(l.Filename)
		if err != nil {
			return nil
		}
		l.db = db
	}
	return l.db
}
