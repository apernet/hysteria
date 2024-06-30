package utils

import (
	"reflect"
	"testing"
)

func TestParsePortUnion(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want PortUnion
	}{
		{
			name: "empty",
			s:    "",
			want: nil,
		},
		{
			name: "all 1",
			s:    "all",
			want: PortUnion{{0, 65535}},
		},
		{
			name: "all 2",
			s:    "*",
			want: PortUnion{{0, 65535}},
		},
		{
			name: "single port",
			s:    "1234",
			want: PortUnion{{1234, 1234}},
		},
		{
			name: "multiple ports (unsorted)",
			s:    "5678,1234,9012",
			want: PortUnion{{1234, 1234}, {5678, 5678}, {9012, 9012}},
		},
		{
			name: "one range",
			s:    "1234-1240",
			want: PortUnion{{1234, 1240}},
		},
		{
			name: "one range (reversed)",
			s:    "1240-1234",
			want: PortUnion{{1234, 1240}},
		},
		{
			name: "multiple ports and ranges (reversed, unsorted, overlapping)",
			s:    "5678,1200-1236,9100-9012,1234-1240",
			want: PortUnion{{1200, 1240}, {5678, 5678}, {9012, 9100}},
		},
		{
			name: "invalid 1",
			s:    "1234-",
			want: nil,
		},
		{
			name: "invalid 2",
			s:    "1234-ggez",
			want: nil,
		},
		{
			name: "invalid 3",
			s:    "233,",
			want: nil,
		},
		{
			name: "invalid 4",
			s:    "1234-1240-1250",
			want: nil,
		},
		{
			name: "invalid 5",
			s:    "-,,",
			want: nil,
		},
		{
			name: "invalid 6",
			s:    "http",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParsePortUnion(tt.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePortUnion() = %v, want %v", got, tt.want)
			}
		})
	}
}
