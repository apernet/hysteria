package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/apernet/hysteria/extras/utils"
	"github.com/mdp/qrterminal/v3"
	"github.com/oschwald/geoip2-golang"
)

const (
	geoipDefaultFilename = "GeoLite2-Country.mmdb"
	geoipDownloadURL     = "https://git.io/GeoLite2-Country.mmdb"
)

// convBandwidth handles both string and int types for bandwidth.
// When using string, it will be parsed as a bandwidth string with units.
// When using int, it will be parsed as a raw bandwidth in bytes per second.
// It does NOT support float types.
func convBandwidth(bw interface{}) (uint64, error) {
	switch bwT := bw.(type) {
	case string:
		return utils.StringToBps(bwT)
	case int:
		return uint64(bwT), nil
	default:
		return 0, fmt.Errorf("invalid type %T for bandwidth", bwT)
	}
}

func printQR(str string) {
	qrterminal.GenerateWithConfig(str, qrterminal.Config{
		Level:     qrterminal.L,
		Writer:    os.Stdout,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
	})
}

type configError struct {
	Field string
	Err   error
}

func (e configError) Error() string {
	return fmt.Sprintf("invalid config: %s: %s", e.Field, e.Err)
}

func (e configError) Unwrap() error {
	return e.Err
}

// geoipLoader provides the on-demand GeoIP database loading function required by the ACL engine.
type geoipLoader struct {
	Filename        string
	DownloadFunc    func(filename, url string) // Called when downloading the GeoIP database.
	DownloadErrFunc func(err error)            // Called when downloading the GeoIP database succeeds/fails.

	db *geoip2.Reader
}

func (l *geoipLoader) download() error {
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

func (l *geoipLoader) Load() *geoip2.Reader {
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

// normalizeCertHash normalizes a certificate hash string.
// It converts all characters to lowercase and removes possible separators such as ":" and "-".
func normalizeCertHash(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}
