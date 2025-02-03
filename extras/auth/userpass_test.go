package auth

import (
	"net"
	"testing"
)

func TestUserPassAuthenticator(t *testing.T) {
	type fields struct {
		Users map[string]string
	}
	type args struct {
		addr net.Addr
		auth string
		tx   uint64
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		wantOk bool
		wantId string
	}{
		{
			name: "correct 1",
			fields: fields{
				Users: map[string]string{
					"saul": "goodman",
					"wang": "123",
				},
			},
			args: args{
				addr: nil,
				auth: "wang:123",
				tx:   0,
			},
			wantOk: true,
			wantId: "wang",
		},
		{
			name: "correct 2",
			fields: fields{
				Users: map[string]string{
					"gawr":   "gura",
					"fubuki": "shirakami",
				},
			},
			args: args{
				addr: nil,
				auth: "gawr:gura",
				tx:   0,
			},
			wantOk: true,
			wantId: "gawr",
		},
		{
			name: "incorrect 1",
			fields: fields{
				Users: map[string]string{
					"gawr":   "gura",
					"fubuki": "shirakami",
				},
			},
			args: args{
				addr: nil,
				auth: "random:stranger",
				tx:   0,
			},
			wantOk: false,
			wantId: "",
		},
		{
			name: "incorrect 2",
			fields: fields{
				Users: map[string]string{
					"gawr":   "gura",
					"fubuki": "shirakami",
				},
			},
			args: args{
				addr: nil,
				auth: "poop",
				tx:   0,
			},
			wantOk: false,
			wantId: "",
		},
		{
			name: "case insensitive username",
			fields: fields{
				Users: map[string]string{
					"gawR":   "gura",
					"fubuki": "shirakami",
				},
			},
			args: args{
				addr: nil,
				auth: "Gawr:gura",
				tx:   0,
			},
			wantOk: true,
			wantId: "gawr",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewUserPassAuthenticator(tt.fields.Users)
			gotOk, gotId := a.Authenticate(tt.args.addr, tt.args.auth, tt.args.tx)
			if gotOk != tt.wantOk {
				t.Errorf("Authenticate() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
			if gotId != tt.wantId {
				t.Errorf("Authenticate() gotId = %v, want %v", gotId, tt.wantId)
			}
		})
	}
}
