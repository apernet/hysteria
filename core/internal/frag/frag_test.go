package frag

import (
	"reflect"
	"testing"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func TestFragUDPMessage(t *testing.T) {
	type args struct {
		m       *protocol.UDPMessage
		maxSize int
	}
	tests := []struct {
		name string
		args args
		want []protocol.UDPMessage
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
				100,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
			},
		},
		{
			"2 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
				20,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("hel"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("lo"),
				},
			},
		},
		{
			"4 frags",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("abcdefgh"),
				},
				19,
			},
			[]protocol.UDPMessage{
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    0,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("ab"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    1,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("cd"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    2,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("ef"),
				},
				{
					SessionID: 123,
					PacketID:  123,
					FragID:    3,
					FragCount: 4,
					Addr:      "test:123",
					Data:      []byte("gh"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FragUDPMessage(tt.args.m, tt.args.maxSize); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FragUDPMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefragger(t *testing.T) {
	type args struct {
		m *protocol.UDPMessage
	}
	tests := []struct {
		name string
		args args
		want *protocol.UDPMessage
	}{
		{
			"no frag",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 1,
					Addr:      "test:123",
					Data:      []byte("hello"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      "test:123",
				Data:      []byte("hello"),
			},
		},
		{
			"frag 0 - 1/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("hello "),
				},
			},
			nil,
		},
		{
			"frag 0 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("moto"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      "test:123",
				Data:      []byte("hello moto"),
			},
		},
		{
			"frag 1 - 1/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    0,
					FragCount: 3,
					Addr:      "test:123",
					Data:      []byte("deco"),
				},
			},
			nil,
		},
		{
			"frag 1 - 2/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    1,
					FragCount: 3,
					Addr:      "test:123",
					Data:      []byte("*"),
				},
			},
			nil,
		},
		{
			"frag 1 - 3/3",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  987,
					FragID:    2,
					FragCount: 3,
					Addr:      "test:123",
					Data:      []byte("27"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  987,
				FragID:    0,
				FragCount: 1,
				Addr:      "test:123",
				Data:      []byte("deco*27"),
			},
		},
		{
			"frag 2 - 1/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("shinsekai"),
				},
			},
			nil,
		},
		{
			"frag 3 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  244,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("what???"),
				},
			},
			nil,
		},
		{
			"frag 2 - 2/2",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    1,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte(" annaijo"),
				},
			},
			nil,
		},
		{
			"invalid id",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    88,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("shinsekai"),
				},
			},
			nil,
		},
		{
			"frag 2 - 1/2 re",
			args{
				&protocol.UDPMessage{
					SessionID: 123,
					PacketID:  233,
					FragID:    0,
					FragCount: 2,
					Addr:      "test:123",
					Data:      []byte("shinsekai"),
				},
			},
			&protocol.UDPMessage{
				SessionID: 123,
				PacketID:  233,
				FragID:    0,
				FragCount: 1,
				Addr:      "test:123",
				Data:      []byte("shinsekai annaijo"),
			},
		},
	}

	d := &Defragger{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.Feed(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Feed() = %v, want %v", got, tt.want)
			}
		})
	}
}
