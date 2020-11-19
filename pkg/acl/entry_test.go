package acl

import (
	"net"
	"reflect"
	"testing"
)

func TestParseEntry(t *testing.T) {
	_, ok4ipnet, _ := net.ParseCIDR("8.8.8.0/24")

	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    Entry
		wantErr bool
	}{
		{name: "empty", args: args{""}, want: Entry{}, wantErr: true},
		{name: "ok 1", args: args{"direct domain-suffix google.com"},
			want:    Entry{nil, "google.com", true, false, ActionDirect, ""},
			wantErr: false},
		{name: "ok 2", args: args{"proxy ip 8.8.8.8"},
			want: Entry{&net.IPNet{net.ParseIP("8.8.8.8"), net.CIDRMask(32, 32)},
				"", false, false, ActionProxy, ""}, wantErr: false},
		{name: "ok 3", args: args{"hijack domain mad.bad 127.0.0.1"},
			want:    Entry{nil, "mad.bad", false, false, ActionHijack, "127.0.0.1"},
			wantErr: false},
		{name: "ok 4", args: args{"block cidr 8.8.8.0/24"},
			want:    Entry{ok4ipnet, "", false, false, ActionBlock, ""},
			wantErr: false},
		{name: "ok 5", args: args{"block all"},
			want:    Entry{nil, "", false, true, ActionBlock, ""},
			wantErr: false},
		{name: "invalid 1", args: args{"proxy domain"}, want: Entry{}, wantErr: true},
		{name: "invalid 2", args: args{"proxy dom google.com"}, want: Entry{}, wantErr: true},
		{name: "invalid 3", args: args{"hijack ip 1.1.1.1"}, want: Entry{}, wantErr: true},
		{name: "invalid 4", args: args{"direct cidr"}, want: Entry{}, wantErr: true},
		{name: "invalid 5", args: args{"oxy ip 8.8.8.8"}, want: Entry{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEntry(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEntry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseEntry() got = %v, want %v", got, tt.want)
			}
		})
	}
}
