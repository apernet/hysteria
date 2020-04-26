package acl

import (
	"bufio"
	lru "github.com/hashicorp/golang-lru"
	"net"
	"os"
	"strings"
)

const entryCacheSize = 1024

type Engine struct {
	DefaultAction Action
	Entries       []Entry
	Cache         *lru.ARCCache
}

type cacheEntry struct {
	Action Action
	Arg    string
}

func LoadFromFile(filename string) (*Engine, error) {
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
	}, nil
}

func (e *Engine) Lookup(domain string, ip net.IP) (Action, string) {
	if len(domain) > 0 {
		// Domain
		if v, ok := e.Cache.Get(domain); ok {
			// Cache hit
			ce := v.(cacheEntry)
			return ce.Action, ce.Arg
		}
		ips, _ := net.LookupIP(domain)
		for _, entry := range e.Entries {
			if entry.MatchDomain(domain) || (len(ips) > 0 && entry.MatchIPs(ips)) {
				e.Cache.Add(domain, cacheEntry{entry.Action, entry.ActionArg})
				return entry.Action, entry.ActionArg
			}
		}
		return e.DefaultAction, ""
	} else if ip != nil {
		// IP
		if v, ok := e.Cache.Get(ip.String()); ok {
			// Cache hit
			ce := v.(cacheEntry)
			return ce.Action, ce.Arg
		}
		for _, entry := range e.Entries {
			if entry.MatchIP(ip) {
				e.Cache.Add(ip.String(), cacheEntry{entry.Action, entry.ActionArg})
				return entry.Action, entry.ActionArg
			}
		}
		return e.DefaultAction, ""
	} else {
		return e.DefaultAction, ""
	}
}
