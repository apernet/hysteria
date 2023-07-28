package outbounds

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitIPv4IPv6(t *testing.T) {
	type args struct {
		ips []net.IP
	}
	tests := []struct {
		name     string
		args     args
		wantIpv4 net.IP
		wantIpv6 net.IP
	}{
		{
			name: "IPv4 only",
			args: args{
				ips: []net.IP{
					net.ParseIP("4.5.6.7"),
					net.ParseIP("9.9.9.9"),
				},
			},
			wantIpv4: net.ParseIP("4.5.6.7"),
			wantIpv6: nil,
		},
		{
			name: "IPv6 only",
			args: args{
				ips: []net.IP{
					net.ParseIP("2001:db8::68"),
					net.ParseIP("2001:db8::69"),
				},
			},
			wantIpv4: nil,
			wantIpv6: net.ParseIP("2001:db8::68"),
		},
		{
			name: "Both 1",
			args: args{
				ips: []net.IP{
					net.ParseIP("2001:db8::68"),
					net.ParseIP("2001:db8::69"),
					net.ParseIP("4.5.6.7"),
					net.ParseIP("9.9.9.9"),
				},
			},
			wantIpv4: net.ParseIP("4.5.6.7"),
			wantIpv6: net.ParseIP("2001:db8::68"),
		},
		{
			name: "Both 2",
			args: args{
				ips: []net.IP{
					net.ParseIP("2001:db8::69"),
					net.ParseIP("9.9.9.9"),
					net.ParseIP("2001:db8::68"),
					net.ParseIP("4.5.6.7"),
				},
			},
			wantIpv4: net.ParseIP("9.9.9.9"),
			wantIpv6: net.ParseIP("2001:db8::69"),
		},
		{
			name: "Empty",
			args: args{
				ips: []net.IP{},
			},
			wantIpv4: nil,
			wantIpv6: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIpv4, gotIpv6 := splitIPv4IPv6(tt.args.ips)
			assert.Equalf(t, tt.wantIpv4, gotIpv4, "splitIPv4IPv6(%v)", tt.args.ips)
			assert.Equalf(t, tt.wantIpv6, gotIpv6, "splitIPv4IPv6(%v)", tt.args.ips)
		})
	}
}
