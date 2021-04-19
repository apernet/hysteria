package acl

import (
	lru "github.com/hashicorp/golang-lru"
	"net"
	"testing"
)

func TestEngine_ResolveAndMatch(t *testing.T) {
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
	tests := []struct {
		name    string
		addr    string
		want    Action
		want1   string
		wantErr bool
	}{
		{
			name:  "domain direct",
			addr:  "google.com",
			want:  ActionProxy,
			want1: "",
		},
		{
			name:    "domain suffix 1",
			addr:    "evil.corp",
			want:    ActionHijack,
			want1:   "good.org",
			wantErr: true,
		},
		{
			name:    "domain suffix 2",
			addr:    "notevil.corp",
			want:    ActionBlock,
			want1:   "",
			wantErr: true,
		},
		{
			name:    "domain suffix 3",
			addr:    "im.real.evil.corp",
			want:    ActionHijack,
			want1:   "good.org",
			wantErr: true,
		},
		{
			name:  "ip match",
			addr:  "10.2.3.4",
			want:  ActionProxy,
			want1: "",
		},
		{
			name:  "ip mismatch",
			addr:  "100.5.6.0",
			want:  ActionBlock,
			want1: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, _, err := e.ResolveAndMatch(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveAndMatch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ResolveAndMatch() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("ResolveAndMatch() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
