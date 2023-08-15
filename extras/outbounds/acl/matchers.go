package acl

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

type hostMatcher interface {
	Match(HostInfo) bool
}

type ipMatcher struct {
	IP net.IP
}

func (m *ipMatcher) Match(host HostInfo) bool {
	return m.IP.Equal(host.IPv4) || m.IP.Equal(host.IPv6)
}

type cidrMatcher struct {
	IPNet *net.IPNet
}

func (m *cidrMatcher) Match(host HostInfo) bool {
	return m.IPNet.Contains(host.IPv4) || m.IPNet.Contains(host.IPv6)
}

type domainMatcher struct {
	Pattern  string
	Wildcard bool
}

func (m *domainMatcher) Match(host HostInfo) bool {
	if m.Wildcard {
		return deepMatchRune([]rune(host.Name), []rune(m.Pattern))
	}
	return m.Pattern == host.Name
}

func deepMatchRune(str, pattern []rune) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		case '*':
			return deepMatchRune(str, pattern[1:]) ||
				(len(str) > 0 && deepMatchRune(str[1:], pattern))
		}
		str = str[1:]
		pattern = pattern[1:]
	}
	return len(str) == 0 && len(pattern) == 0
}

type geoipMatcher struct {
	DB      *geoip2.Reader
	Country string // must be uppercase ISO 3166-1 alpha-2 code
}

func (m *geoipMatcher) Match(host HostInfo) bool {
	if host.IPv4 != nil {
		record, err := m.DB.Country(host.IPv4)
		if err == nil && record.Country.IsoCode == m.Country {
			return true
		}
	}
	if host.IPv6 != nil {
		record, err := m.DB.Country(host.IPv6)
		if err == nil && record.Country.IsoCode == m.Country {
			return true
		}
	}
	return false
}

type allMatcher struct{}

func (m *allMatcher) Match(host HostInfo) bool {
	return true
}
