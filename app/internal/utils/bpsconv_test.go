package utils

import "testing"

func TestStringToBps(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    uint64
		wantErr bool
	}{
		{"bps", args{"800 bps"}, 100, false},
		{"kbps", args{"800 kbps"}, 100_000, false},
		{"mbps", args{"800 mbps"}, 100_000_000, false},
		{"gbps", args{"800 gbps"}, 100_000_000_000, false},
		{"tbps", args{"800 tbps"}, 100_000_000_000_000, false},
		{"mbps simp", args{"100m"}, 12_500_000, false},
		{"gbps simp upper", args{"2G"}, 250_000_000, false},
		{"invalid 1", args{"damn"}, 0, true},
		{"invalid 2", args{"6444"}, 0, true},
		{"invalid 3", args{"5.4 mbps"}, 0, true},
		{"invalid 4", args{"kbps"}, 0, true},
		{"invalid 5", args{"1234 5678 gbps"}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := StringToBps(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("StringToBps() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("StringToBps() got = %v, want %v", got, tt.want)
			}
		})
	}
}
