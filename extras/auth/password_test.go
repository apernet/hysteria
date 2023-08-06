package auth

import (
	"net"
	"testing"
)

func TestPasswordAuthenticator(t *testing.T) {
	type fields struct {
		Password string
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
			name: "correct",
			fields: fields{
				Password: "yes,yes",
			},
			args: args{
				addr: nil,
				auth: "yes,yes",
				tx:   0,
			},
			wantOk: true,
			wantId: "user",
		},
		{
			name: "incorrect",
			fields: fields{
				Password: "something_somehow",
			},
			args: args{
				addr: nil,
				auth: "random",
				tx:   0,
			},
			wantOk: false,
			wantId: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &PasswordAuthenticator{
				Password: tt.fields.Password,
			}
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
