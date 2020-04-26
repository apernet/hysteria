package acl

import (
	"bufio"
	"net"
	"os"
	"strings"
)

type Engine struct {
	DefaultAction Action
	Entries       []Entry
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
	return &Engine{
		DefaultAction: ActionProxy,
		Entries:       entries,
	}, nil
}

func (e *Engine) Lookup(domain string, ip net.IP) (Action, string) {
	if len(domain) == 0 && ip == nil {
		return e.DefaultAction, ""
	}
	for _, entry := range e.Entries {
		if entry.Match(domain, ip) {
			return entry.Action, entry.ActionArg
		}
	}
	return e.DefaultAction, ""
}
