package acl

import (
	"net"

	"golang.org/x/net/idna"
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
	name, err := idna.ToUnicode(host.Name)
	if err != nil {
		name = host.Name
	}
	if m.Wildcard {
		return deepMatchRune([]rune(name), []rune(m.Pattern))
	}
	return name == m.Pattern
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

type allMatcher struct{}

func (m *allMatcher) Match(host HostInfo) bool {
	return true
}
