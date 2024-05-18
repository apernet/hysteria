package utils

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/apernet/hysteria/extras/v2/outbounds/acl"
	"github.com/apernet/hysteria/extras/v2/outbounds/acl/v2geo"
)

const (
	geoipFilename   = "geoip.dat"
	geoipURL        = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
	geositeFilename = "geosite.dat"
	geositeURL      = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
	geoDlTmpPattern = ".hysteria-geoloader.dlpart.*"

	geoDefaultUpdateInterval = 7 * 24 * time.Hour // 7 days
)

var _ acl.GeoLoader = (*GeoLoader)(nil)

// GeoLoader provides the on-demand GeoIP/GeoSite database
// loading functionality required by the ACL engine.
// Empty filenames = automatic download from built-in URLs.
type GeoLoader struct {
	GeoIPFilename   string
	GeoSiteFilename string
	UpdateInterval  time.Duration

	DownloadFunc    func(filename, url string)
	DownloadErrFunc func(err error)

	geoipMap   map[string]*v2geo.GeoIP
	geositeMap map[string]*v2geo.GeoSite
}

func (l *GeoLoader) shouldDownload(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return true
	}
	if info.Size() == 0 {
		// empty files are loadable by v2geo, but we consider it broken
		return true
	}
	dt := time.Now().Sub(info.ModTime())
	if l.UpdateInterval == 0 {
		return dt > geoDefaultUpdateInterval
	} else {
		return dt > l.UpdateInterval
	}
}

func (l *GeoLoader) downloadAndCheck(filename, url string, checkFunc func(filename string) error) error {
	l.DownloadFunc(filename, url)

	resp, err := http.Get(url)
	if err != nil {
		l.DownloadErrFunc(err)
		return err
	}
	defer resp.Body.Close()

	f, err := os.CreateTemp(".", geoDlTmpPattern)
	if err != nil {
		l.DownloadErrFunc(err)
		return err
	}
	defer os.Remove(f.Name())

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		f.Close()
		l.DownloadErrFunc(err)
		return err
	}
	f.Close()

	err = checkFunc(f.Name())
	if err != nil {
		l.DownloadErrFunc(fmt.Errorf("integrity check failed: %w", err))
		return err
	}

	err = os.Rename(f.Name(), filename)
	if err != nil {
		l.DownloadErrFunc(fmt.Errorf("rename failed: %w", err))
		return err
	}

	return nil
}

func (l *GeoLoader) LoadGeoIP() (map[string]*v2geo.GeoIP, error) {
	if l.geoipMap != nil {
		return l.geoipMap, nil
	}
	autoDL := false
	filename := l.GeoIPFilename
	if filename == "" {
		autoDL = true
		filename = geoipFilename
	}
	if autoDL {
		if !l.shouldDownload(filename) {
			m, err := v2geo.LoadGeoIP(filename)
			if err == nil {
				l.geoipMap = m
				return m, nil
			}
			// file is broken, download it again
		}
		err := l.downloadAndCheck(filename, geoipURL, func(filename string) error {
			_, err := v2geo.LoadGeoIP(filename)
			return err
		})
		if err != nil {
			// as long as the previous download exists, fallback to it
			if _, serr := os.Stat(filename); os.IsNotExist(serr) {
				return nil, err
			}
		}
	}
	m, err := v2geo.LoadGeoIP(filename)
	if err != nil {
		return nil, err
	}
	l.geoipMap = m
	return m, nil
}

func (l *GeoLoader) LoadGeoSite() (map[string]*v2geo.GeoSite, error) {
	if l.geositeMap != nil {
		return l.geositeMap, nil
	}
	autoDL := false
	filename := l.GeoSiteFilename
	if filename == "" {
		autoDL = true
		filename = geositeFilename
	}
	if autoDL {
		if !l.shouldDownload(filename) {
			m, err := v2geo.LoadGeoSite(filename)
			if err == nil {
				l.geositeMap = m
				return m, nil
			}
			// file is broken, download it again
		}
		err := l.downloadAndCheck(filename, geositeURL, func(filename string) error {
			_, err := v2geo.LoadGeoSite(filename)
			return err
		})
		if err != nil {
			// as long as the previous download exists, fallback to it
			if _, serr := os.Stat(filename); os.IsNotExist(serr) {
				return nil, err
			}
		}
	}
	m, err := v2geo.LoadGeoSite(filename)
	if err != nil {
		return nil, err
	}
	l.geositeMap = m
	return m, nil
}
