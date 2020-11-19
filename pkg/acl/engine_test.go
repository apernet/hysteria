package acl

import (
	lru "github.com/hashicorp/golang-lru"
	"net"
	"testing"
)

func TestEngine_Lookup(t *testing.T) {
	cache, _ := lru.NewARC(4)
	e := &Engine{
		DefaultAction: ActionDirect,
		Entries: []Entry{
			{
				Net:       nil,
				Domain:    "google.com",
				Suffix:    false,
				All:       false,
				Action:    ActionProxy,
				ActionArg: "",
			},
			{
				Net:       nil,
				Domain:    "evil.corp",
				Suffix:    true,
				All:       false,
				Action:    ActionHijack,
				ActionArg: "good.org",
			},
			{
				Net: &net.IPNet{
					IP:   net.ParseIP("10.0.0.0"),
					Mask: net.CIDRMask(8, 32),
				},
				Domain:    "",
				Suffix:    false,
				All:       false,
				Action:    ActionProxy,
				ActionArg: "",
			},
			{
				Net:       nil,
				Domain:    "",
				Suffix:    false,
				All:       true,
				Action:    ActionBlock,
				ActionArg: "",
			},
		},
		Cache: cache,
	}
	type args struct {
		domain string
		ip     net.IP
	}
	tests := []struct {
		name  string
		args  args
		want  Action
		want1 string
	}{
		{
			name:  "domain direct",
			args:  args{"google.com", nil},
			want:  ActionProxy,
			want1: "",
		},
		{
			name:  "domain suffix 1",
			args:  args{"evil.corp", nil},
			want:  ActionHijack,
			want1: "good.org",
		},
		{
			name:  "domain suffix 2",
			args:  args{"notevil.corp", nil},
			want:  ActionBlock,
			want1: "",
		},
		{
			name:  "domain suffix 3",
			args:  args{"im.real.evil.corp", nil},
			want:  ActionHijack,
			want1: "good.org",
		},
		{
			name:  "ip match",
			args:  args{"", net.ParseIP("10.2.3.4")},
			want:  ActionProxy,
			want1: "",
		},
		{
			name:  "ip mismatch",
			args:  args{"", net.ParseIP("100.5.6.0")},
			want:  ActionBlock,
			want1: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := e.Lookup(tt.args.domain, tt.args.ip)
			if got != tt.want {
				t.Errorf("Lookup() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Lookup() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
