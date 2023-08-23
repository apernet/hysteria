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
		{"kbps", args{"800 kbps"}, 102400, false},
		{"mbps", args{"800 mbps"}, 104857600, false},
		{"gbps", args{"800 gbps"}, 107374182400, false},
		{"tbps", args{"800 tbps"}, 109951162777600, false},
		{"mbps simp", args{"100m"}, 13107200, false},
		{"gbps simp upper", args{"2G"}, 268435456, false},
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
