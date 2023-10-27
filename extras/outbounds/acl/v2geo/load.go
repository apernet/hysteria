package v2geo

import (
	"os"
	"strings"

	"google.golang.org/protobuf/proto"
)

type GeoIPMap map[string]*GeoIP

type GeoSiteMap map[string]*GeoSite

// LoadGeoIP loads a GeoIP data file and converts it to a map.
// The keys of the map (country codes) are all normalized to lowercase.
func LoadGeoIP(filename string) (GeoIPMap, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var list GeoIPList
	if err := proto.Unmarshal(bs, &list); err != nil {
		return nil, err
	}
	m := make(GeoIPMap)
	for _, entry := range list.Entry {
		m[strings.ToLower(entry.CountryCode)] = entry
	}
	return m, nil
}

// LoadGeoSite loads a GeoSite data file and converts it to a map.
// The keys of the map (site keys) are all normalized to lowercase.
func LoadGeoSite(filename string) (GeoSiteMap, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var list GeoSiteList
	if err := proto.Unmarshal(bs, &list); err != nil {
		return nil, err
	}
	m := make(GeoSiteMap)
	for _, entry := range list.Entry {
		m[strings.ToLower(entry.CountryCode)] = entry
	}
	return m, nil
}
