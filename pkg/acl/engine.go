package acl

import (
	"bufio"
	lru "github.com/hashicorp/golang-lru"
	"github.com/tobyxdd/hysteria/pkg/transport"
	"net"
	"os"
	"strings"
)

const entryCacheSize = 1024

type Engine struct {
	DefaultAction Action
	Entries       []Entry
	Cache         *lru.ARCCache
	Transport     transport.Transport
}

type cacheEntry struct {
	Action Action
	Arg    string
}

func LoadFromFile(filename string, transport transport.Transport) (*Engine, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	entries := make([]Entry, 0, 1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			// Ignore empty lines & comments
			continue
		}
		entry, err := ParseEntry(line)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	cache, err := lru.NewARC(entryCacheSize)
	if err != nil {
		return nil, err
	}
	return &Engine{
		DefaultAction: ActionProxy,
		Entries:       entries,
		Cache:         cache,
		Transport:     transport,
	}, nil
}

func (e *Engine) ResolveAndMatch(host string) (Action, string, *net.IPAddr, error) {
	ip, zone := parseIPZone(host)
	if ip == nil {
		// Domain
		ipAddr, err := e.Transport.LocalResolveIPAddr(host)
		if v, ok := e.Cache.Get(host); ok {
			// Cache hit
			ce := v.(cacheEntry)
			return ce.Action, ce.Arg, ipAddr, err
		}
		for _, entry := range e.Entries {
			if entry.MatchDomain(host) || (ipAddr != nil && entry.MatchIP(ipAddr.IP)) {
				e.Cache.Add(host, cacheEntry{entry.Action, entry.ActionArg})
				return entry.Action, entry.ActionArg, ipAddr, err
			}
		}
		e.Cache.Add(host, cacheEntry{e.DefaultAction, ""})
		return e.DefaultAction, "", ipAddr, err
	} else {
		// IP
		if v, ok := e.Cache.Get(ip.String()); ok {
			// Cache hit
			ce := v.(cacheEntry)
			return ce.Action, ce.Arg, &net.IPAddr{
				IP:   ip,
				Zone: zone,
			}, nil
		}
		for _, entry := range e.Entries {
			if entry.MatchIP(ip) {
				e.Cache.Add(ip.String(), cacheEntry{entry.Action, entry.ActionArg})
				return entry.Action, entry.ActionArg, &net.IPAddr{
					IP:   ip,
					Zone: zone,
				}, nil
			}
		}
		e.Cache.Add(ip.String(), cacheEntry{e.DefaultAction, ""})
		return e.DefaultAction, "", &net.IPAddr{
			IP:   ip,
			Zone: zone,
		}, nil
	}
}
