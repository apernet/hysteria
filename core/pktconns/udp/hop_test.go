package udp

import (
	"reflect"
	"testing"
)

func Test_parseAddr(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		wantHost  string
		wantPorts []uint16
		wantErr   bool
	}{
		{
			name:      "empty",
			addr:      "",
			wantHost:  "",
			wantPorts: nil,
			wantErr:   true,
		},
		{
			name:      "host only",
			addr:      "example.com",
			wantHost:  "",
			wantPorts: nil,
			wantErr:   true,
		},
		{
			name:      "single port",
			addr:      "example.com:1234",
			wantHost:  "example.com",
			wantPorts: []uint16{1234},
			wantErr:   false,
		},
		{
			name:      "multi ports",
			addr:      "example.com:1234,5678,9999",
			wantHost:  "example.com",
			wantPorts: []uint16{1234, 5678, 9999},
			wantErr:   false,
		},
		{
			name:      "multi ports with range",
			addr:      "example.com:1234,5678-5685,9999",
			wantHost:  "example.com",
			wantPorts: []uint16{1234, 5678, 5679, 5680, 5681, 5682, 5683, 5684, 5685, 9999},
			wantErr:   false,
		},
		{
			name:      "range single port",
			addr:      "example.com:1234-1234",
			wantHost:  "example.com",
			wantPorts: []uint16{1234},
			wantErr:   false,
		},
		{
			name:      "range reversed",
			addr:      "example.com:8003-8000",
			wantHost:  "example.com",
			wantPorts: []uint16{8000, 8001, 8002, 8003},
			wantErr:   false,
		},
		{
			name:      "invalid port",
			addr:      "example.com:1234,5678,9999,invalid",
			wantHost:  "",
			wantPorts: nil,
			wantErr:   true,
		},
		{
			name:      "invalid port range",
			addr:      "example.com:1234,5678,9999,8000-8002-8004",
			wantHost:  "",
			wantPorts: nil,
			wantErr:   true,
		},
		{
			name:      "invalid port range 2",
			addr:      "example.com:1234,5678,9999,8000-woot",
			wantHost:  "",
			wantPorts: nil,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotPorts, err := parseAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotHost != tt.wantHost {
				t.Errorf("parseAddr() gotHost = %v, want %v", gotHost, tt.wantHost)
			}
			if !reflect.DeepEqual(gotPorts, tt.wantPorts) {
				t.Errorf("parseAddr() gotPorts = %v, want %v", gotPorts, tt.wantPorts)
			}
		})
	}
}
