package udphop

import (
	"net"
	"reflect"
	"testing"
)

func TestResolveUDPHopAddr(t *testing.T) {
	type args struct {
		addr string
	}
	tests := []struct {
		name    string
		args    args
		want    *UDPHopAddr
		wantErr bool
	}{
		{
			name: "empty",
			args: args{
				addr: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "no port",
			args: args{
				addr: "8.8.8.8",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "single port",
			args: args{
				addr: "8.8.4.4:1234",
			},
			want: &UDPHopAddr{
				IP:      net.ParseIP("8.8.4.4"),
				Ports:   []uint16{1234},
				PortStr: "1234",
			},
			wantErr: false,
		},
		{
			name: "multiple ports",
			args: args{
				addr: "8.8.3.3:1234,5678,9012",
			},
			want: &UDPHopAddr{
				IP:      net.ParseIP("8.8.3.3"),
				Ports:   []uint16{1234, 5678, 9012},
				PortStr: "1234,5678,9012",
			},
			wantErr: false,
		},
		{
			name: "port range",
			args: args{
				addr: "1.2.3.4:1234-1240",
			},
			want: &UDPHopAddr{
				IP:      net.ParseIP("1.2.3.4"),
				Ports:   []uint16{1234, 1235, 1236, 1237, 1238, 1239, 1240},
				PortStr: "1234-1240",
			},
			wantErr: false,
		},
		{
			name: "port range reversed",
			args: args{
				addr: "123.123.123.123:9990-9980",
			},
			want: &UDPHopAddr{
				IP:      net.ParseIP("123.123.123.123"),
				Ports:   []uint16{9980, 9981, 9982, 9983, 9984, 9985, 9986, 9987, 9988, 9989, 9990},
				PortStr: "9990-9980",
			},
			wantErr: false,
		},
		{
			name: "port range & port list",
			args: args{
				addr: "9.9.9.9:1234-1236,5678,9012",
			},
			want: &UDPHopAddr{
				IP:      net.ParseIP("9.9.9.9"),
				Ports:   []uint16{1234, 1235, 1236, 5678, 9012},
				PortStr: "1234-1236,5678,9012",
			},
			wantErr: false,
		},
		{
			name: "invalid port",
			args: args{
				addr: "5.5.5.5:1234,bs",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid port range 1",
			args: args{
				addr: "6.6.6.6:7788-bbss",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid port range 2",
			args: args{
				addr: "1.0.0.1:8899-9002-9005",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveUDPHopAddr(tt.args.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseUDPHopAddr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseUDPHopAddr() got = %v, want %v", got, tt.want)
			}
		})
	}
}
