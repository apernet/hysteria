package acl

import (
	"errors"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"net"
	"strings"
)

type Action byte

const (
	ActionDirect = Action(iota)
	ActionProxy
	ActionBlock
	ActionHijack
)

type Entry struct {
	Net       *net.IPNet
	Domain    string
	Suffix    bool
	Country   string
	All       bool
	Action    Action
	ActionArg string
}

func (e Entry) MatchDomain(domain string) bool {
	if e.All {
		return true
	}
	if len(e.Domain) > 0 && len(domain) > 0 {
		ld := strings.ToLower(domain)
		if e.Suffix {
			return e.Domain == ld || strings.HasSuffix(ld, "."+e.Domain)
		} else {
			return e.Domain == ld
		}
	}
	return false
}

func (e Entry) MatchIP(ip net.IP, db *geoip2.Reader) bool {
	if e.All {
		return true
	}
	if ip == nil {
		return false
	}
	if e.Net != nil {
		return e.Net.Contains(ip)
	}
	if len(e.Country) > 0 && db != nil {
		country, err := db.Country(ip)
		if err != nil {
			return false
		}
		return country.Country.IsoCode == e.Country
	}
	return false
}

// Format: action cond_type cond arg
// Examples:
// proxy domain-suffix google.com
// block ip 8.8.8.8
// hijack cidr 192.168.1.1/24 127.0.0.1
func ParseEntry(s string) (Entry, error) {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return Entry{}, fmt.Errorf("expecting at least 2 fields, got %d", len(fields))
	}
	args := fields[1:]
	if len(args) == 1 {
		// Make sure there are at least 2 args
		args = append(args, "")
	}
	ipNet, domain, suffix, country, all, err := parseCond(args[0], args[1])
	if err != nil {
		return Entry{}, err
	}
	e := Entry{
		Net:     ipNet,
		Domain:  domain,
		Suffix:  suffix,
		Country: country,
		All:     all,
	}
	switch strings.ToLower(fields[0]) {
	case "direct":
		e.Action = ActionDirect
	case "proxy":
		e.Action = ActionProxy
	case "block":
		e.Action = ActionBlock
	case "hijack":
		if len(args) < 3 {
			return Entry{}, fmt.Errorf("no hijack destination for %s %s", args[0], args[1])
		}
		e.Action = ActionHijack
		e.ActionArg = args[2]
	default:
		return Entry{}, fmt.Errorf("invalid action %s", fields[0])
	}
	return e, nil
}

func parseCond(typ, cond string) (*net.IPNet, string, bool, string, bool, error) {
	switch strings.ToLower(typ) {
	case "domain":
		if len(cond) == 0 {
			return nil, "", false, "", false, errors.New("empty domain")
		}
		return nil, strings.ToLower(cond), false, "", false, nil
	case "domain-suffix":
		if len(cond) == 0 {
			return nil, "", false, "", false, errors.New("empty domain suffix")
		}
		return nil, strings.ToLower(cond), true, "", false, nil
	case "cidr":
		_, ipNet, err := net.ParseCIDR(cond)
		if err != nil {
			return nil, "", false, "", false, err
		}
		return ipNet, "", false, "", false, nil
	case "ip":
		ip := net.ParseIP(cond)
		if ip == nil {
			return nil, "", false, "", false, fmt.Errorf("invalid ip %s", cond)
		}
		if ip.To4() != nil {
			return &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(32, 32),
			}, "", false, "", false, nil
		} else {
			return &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(128, 128),
			}, "", false, "", false, nil
		}
	case "country":
		if len(cond) == 0 {
			return nil, "", false, "", false, errors.New("empty country")
		}
		return nil, "", false, strings.ToUpper(cond), false, nil
	case "all":
		return nil, "", false, "", true, nil
	default:
		return nil, "", false, "", false, fmt.Errorf("invalid condition type %s", typ)
	}
}
