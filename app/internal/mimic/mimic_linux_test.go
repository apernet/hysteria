//go:build linux

package mimic

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFiltersFor(t *testing.T) {
	tests := []struct {
		name  string
		role  Role
		addrs []*net.UDPAddr
		want  []string
	}{
		{
			name:  "server explicit IPv4",
			role:  RoleServer,
			addrs: []*net.UDPAddr{{IP: net.ParseIP("192.0.2.1"), Port: 58000}},
			want:  []string{"local=192.0.2.1:58000,handshake=0:3"},
		},
		{
			name:  "server explicit IPv6",
			role:  RoleServer,
			addrs: []*net.UDPAddr{{IP: net.ParseIP("2001:db8::1"), Port: 58000}},
			want:  []string{"local=[2001:db8::1]:58000,handshake=0:3"},
		},
		{
			name:  "server nil IP wildcard",
			role:  RoleServer,
			addrs: []*net.UDPAddr{{Port: 58000}},
			want: []string{
				"local=0.0.0.0:58000,handshake=0:3",
				"local=[::]:58000,handshake=0:3",
			},
		},
		{
			name:  "server IPv4 wildcard",
			role:  RoleServer,
			addrs: []*net.UDPAddr{{IP: net.IPv4zero, Port: 58000}},
			want:  []string{"local=0.0.0.0:58000,handshake=0:3"},
		},
		{
			name:  "server IPv6 wildcard",
			role:  RoleServer,
			addrs: []*net.UDPAddr{{IP: net.IPv6zero, Port: 58000}},
			want: []string{
				"local=0.0.0.0:58000,handshake=0:3",
				"local=[::]:58000,handshake=0:3",
			},
		},
		{
			name:  "client IPv4",
			role:  RoleClient,
			addrs: []*net.UDPAddr{{IP: net.ParseIP("192.0.2.1"), Port: 58000}},
			want:  []string{"remote=192.0.2.1:58000"},
		},
		{
			name:  "client IPv6",
			role:  RoleClient,
			addrs: []*net.UDPAddr{{IP: net.ParseIP("2001:db8::1"), Port: 58000}},
			want:  []string{"remote=[2001:db8::1]:58000"},
		},
		{
			name: "client dual-stack name",
			role: RoleClient,
			addrs: []*net.UDPAddr{
				{IP: net.ParseIP("192.0.2.1"), Port: 58000},
				{IP: net.ParseIP("2001:db8::1"), Port: 58000},
			},
			want: []string{
				"remote=192.0.2.1:58000",
				"remote=[2001:db8::1]:58000",
			},
		},
		{
			name: "client drops duplicate addresses",
			role: RoleClient,
			addrs: []*net.UDPAddr{
				{IP: net.ParseIP("192.0.2.1"), Port: 58000},
				{IP: net.ParseIP("192.0.2.1"), Port: 58000},
			},
			want: []string{"remote=192.0.2.1:58000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filtersFor(tt.role, tt.addrs); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("filtersFor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunArgsIncludesEveryFilter(t *testing.T) {
	filters := filtersFor(RoleServer, []*net.UDPAddr{{Port: 58000}})
	cfg := Config{XDPMode: "skb", ExtraArgs: []string{"--keepalive", "10"}}

	want := []string{
		"run", "eth0",
		"-f", "local=0.0.0.0:58000,handshake=0:3",
		"-f", "local=[::]:58000,handshake=0:3",
		"--xdp-mode", "skb",
		"--keepalive", "10",
	}
	if got := runArgs("eth0", filters, cfg); !reflect.DeepEqual(got, want) {
		t.Fatalf("runArgs() = %v, want %v", got, want)
	}
}

func TestFiltersCoverRequiresEveryFilter(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "mimic")
	if err := os.WriteFile(bin, []byte(`#!/bin/sh
printf '%s\n' 'Filter: local=0.0.0.0:58000,handshake=0:3'
`), 0o755); err != nil {
		t.Fatal(err)
	}

	filters := filtersFor(RoleServer, []*net.UDPAddr{{Port: 58000}})
	covered, err := filtersCover(bin, "eth0", filters)
	if err != nil {
		t.Fatal(err)
	}
	if covered {
		t.Fatal("filtersCover() = true with only one wildcard-family filter")
	}

	if err := os.WriteFile(bin, []byte(`#!/bin/sh
printf '%s\n' 'Filter: local=0.0.0.0:58000,handshake=0:3'
printf '%s\n' 'Filter: local=[::]:58000,handshake=0:3'
`), 0o755); err != nil {
		t.Fatal(err)
	}
	covered, err = filtersCover(bin, "eth0", filters)
	if err != nil {
		t.Fatal(err)
	}
	if !covered {
		t.Fatal("filtersCover() = false with both wildcard-family filters")
	}
}

func TestFilterAddrStripsShowAnnotations(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"remote=192.0.2.1:58000", "remote=192.0.2.1:58000"},
		{"local=0.0.0.0:58000,handshake=0:3", "local=0.0.0.0:58000"},
		// "mimic show" appends this when the filter came from a name, and does
		// not print a comma when the settings match the global ones.
		{"remote=192.0.2.1:58000 (resolved from example.com)", "remote=192.0.2.1:58000"},
		{"local=[::]:58000,handshake=0:3 (resolved from example.com)", "local=[::]:58000"},
	}
	for _, tt := range tests {
		if got := filterAddr(tt.in); got != tt.want {
			t.Errorf("filterAddr(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
