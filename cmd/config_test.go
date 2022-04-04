package main

import "testing"

func Test_stringToBps(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want uint64
	}{
		{name: "bps 1", s: "8 bps", want: 1},
		{name: "bps 2", s: "3   bps", want: 0},
		{name: "Bps", s: "9991Bps", want: 9991},
		{name: "KBps", s: "10 KBps", want: 10240},
		{name: "Kbps", s: "10 Kbps", want: 1280},
		{name: "MBps", s: "10 MBps", want: 10485760},
		{name: "Mbps", s: "10 Mbps", want: 1310720},
		{name: "GBps", s: "10 GBps", want: 10737418240},
		{name: "Gbps", s: "10 Gbps", want: 1342177280},
		{name: "TBps", s: "10 TBps", want: 10995116277760},
		{name: "Tbps", s: "10 Tbps", want: 1374389534720},
		{name: "invalid 1", s: "6699E Kbps", want: 0},
		{name: "invalid 2", s: "400 Bsp", want: 0},
		{name: "invalid 3", s: "9 GBbps", want: 0},
		{name: "invalid 4", s: "Mbps", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stringToBps(tt.s); got != tt.want {
				t.Errorf("stringToBps() = %v, want %v", got, tt.want)
			}
		})
	}
}
