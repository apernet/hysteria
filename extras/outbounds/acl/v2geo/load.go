package v2geo

import (
	"os"
	"strings"

	"google.golang.org/protobuf/proto"
)

// LoadGeoIP loads a GeoIP data file and converts it to a map.
// The keys of the map (country codes) are all normalized to lowercase.
func LoadGeoIP(filename string) (map[string]*GeoIP, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var list GeoIPList
	if err := proto.Unmarshal(bs, &list); err != nil {
		return nil, err
	}
	m := make(map[string]*GeoIP)
	for _, entry := range list.Entry {
		m[strings.ToLower(entry.CountryCode)] = entry
	}
	return m, nil
}

// LoadGeoSite loads a GeoSite data file and converts it to a map.
// The keys of the map (site keys) are all normalized to lowercase.
func LoadGeoSite(filename string) (map[string]*GeoSite, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var list GeoSiteList
	if err := proto.Unmarshal(bs, &list); err != nil {
		return nil, err
	}
	m := make(map[string]*GeoSite)
	for _, entry := range list.Entry {
		m[strings.ToLower(entry.CountryCode)] = entry
	}
	return m, nil
}
