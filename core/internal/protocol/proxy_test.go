package protocol

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func TestReadTCPRequest(t *testing.T) {
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "normal 1",
			args: args{
				r: bytes.NewReader([]byte("\x05hello")),
			},
			want:    "hello",
			wantErr: false,
		},
		{
			name: "normal 2",
			args: args{
				r: bytes.NewReader([]byte("\x41\x25We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People")),
			},
			want:    "We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People",
			wantErr: false,
		},
		{
			name: "empty",
			args: args{
				r: bytes.NewReader([]byte("\x00")),
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "incomplete",
			args: args{
				r: bytes.NewReader([]byte("\x06oh no")),
			},
			want:    "oh no\x00",
			wantErr: true,
		},
		{
			name: "too long",
			args: args{
				r: bytes.NewReader([]byte("\x66\x77\x88Whatever")),
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadTCPRequest(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadTCPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadTCPRequest() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteTCPRequest(t *testing.T) {
	type args struct {
		addr string
	}
	tests := []struct {
		name    string
		args    args
		wantW   string
		wantErr bool
	}{
		{
			name: "normal 1",
			args: args{
				addr: "hello",
			},
			wantW:   "\x44\x01\x05hello",
			wantErr: false,
		},
		{
			name: "normal 2",
			args: args{
				addr: "We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People",
			},
			wantW:   "\x44\x01\x41\x25We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People We the People",
			wantErr: false,
		},
		{
			name: "empty",
			args: args{
				addr: "",
			},
			wantW:   "\x44\x01\x00",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := WriteTCPRequest(w, tt.args.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTCPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("WriteTCPRequest() gotW = %v, want %v", []byte(gotW), tt.wantW)
			}
		})
	}
}

func TestUDPMessage(t *testing.T) {
	t.Run("buffer too small", func(t *testing.T) {
		// Make sure Serialize returns -1 when the buffer is too small.
		tBuf := make([]byte, 20)
		if (&UDPMessage{
			SessionID: 66,
			PacketID:  77,
			FragID:    2,
			FragCount: 5,
			Addr:      "random_addr",
			Data:      []byte("random_data"),
		}).Serialize(tBuf) != -1 {
			t.Error("Serialize() did not return -1 when the buffer was too small")
		}
	})

	type fields struct {
		SessionID uint32
		PacketID  uint16
		FragID    uint8
		FragCount uint8
		Addr      string
		Data      []byte
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		{
			name: "test 1",
			fields: fields{
				SessionID: 1,
				PacketID:  1,
				FragID:    0,
				FragCount: 1,
				Addr:      "example.com:80",
				Data:      []byte("GET /nothing HTTP/1.1\r\n"),
			},
			want: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x1, 0xe, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x38, 0x30, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0xd, 0xa},
		},
		{
			name: "test 2",
			fields: fields{
				SessionID: 1329655244,
				Addr:      "some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long_some_random_goofy_ahh_address_which_is_very_long:9000",
				PacketID:  62233,
				FragID:    8,
				FragCount: 19,
				Data:      []byte("God is great, beer is good, and people are crazy."),
			},
			want: []byte{0x4f, 0x40, 0xed, 0xcc, 0xf3, 0x19, 0x8, 0x13, 0x41, 0xee, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x5f, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x6f, 0x6f, 0x66, 0x79, 0x5f, 0x61, 0x68, 0x68, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x63, 0x68, 0x5f, 0x69, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6c, 0x6f, 0x6e, 0x67, 0x3a, 0x39, 0x30, 0x30, 0x30, 0x47, 0x6f, 0x64, 0x20, 0x69, 0x73, 0x20, 0x67, 0x72, 0x65, 0x61, 0x74, 0x2c, 0x20, 0x62, 0x65, 0x65, 0x72, 0x20, 0x69, 0x73, 0x20, 0x67, 0x6f, 0x6f, 0x64, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x70, 0x65, 0x6f, 0x70, 0x6c, 0x65, 0x20, 0x61, 0x72, 0x65, 0x20, 0x63, 0x72, 0x61, 0x7a, 0x79, 0x2e},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &UDPMessage{
				SessionID: tt.fields.SessionID,
				Addr:      tt.fields.Addr,
				PacketID:  tt.fields.PacketID,
				FragID:    tt.fields.FragID,
				FragCount: tt.fields.FragCount,
				Data:      tt.fields.Data,
			}
			// Serialize
			buf := make([]byte, MaxUDPSize)
			n := m.Serialize(buf)
			if got := buf[:n]; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Serialize() = %v, want %v", got, tt.want)
			}
			// Parse back
			if m2, err := ParseUDPMessage(tt.want); err != nil {
				t.Errorf("ParseUDPMessage() error = %v", err)
			} else {
				if !reflect.DeepEqual(m2, m) {
					t.Errorf("ParseUDPMessage() = %v, want %v", m2, m)
				}
			}
		})
	}
}

// TestUDPMessageMalformed is to make sure ParseUDPMessage() fails (but not panic) on malformed data.
func TestUDPMessageMalformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: []byte{},
		},
		{
			name: "zeroes 1",
			data: []byte{0, 0, 0, 0},
		},
		{
			name: "zeroes 2",
			data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "incomplete 1",
			data: []byte{0x66, 0xCC, 0xFF, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55},
		},
		{
			name: "incomplete 2",
			data: []byte{0x66, 0xCC, 0xFF, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x90, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseUDPMessage(tt.data); err == nil {
				t.Errorf("ParseUDPMessage() should fail")
			}
		})
	}
}

func TestReadTCPResponse(t *testing.T) {
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		want1   string
		wantErr bool
	}{
		{
			name: "success 1",
			args: args{
				r: bytes.NewReader([]byte("\x00\x00")),
			},
			want:    true,
			want1:   "",
			wantErr: false,
		},
		{
			name: "success 2",
			args: args{
				r: bytes.NewReader([]byte("\x00\x12are ya winning son")),
			},
			want:    true,
			want1:   "are ya winning son",
			wantErr: false,
		},
		{
			name: "failure 1",
			args: args{
				r: bytes.NewReader([]byte("\x01\x00")),
			},
			want:    false,
			want1:   "",
			wantErr: false,
		},
		{
			name: "failure 2",
			args: args{
				r: bytes.NewReader([]byte("\x01\x15you ain't winning son")),
			},
			want:    false,
			want1:   "you ain't winning son",
			wantErr: false,
		},
		{
			name: "incomplete",
			args: args{
				r: bytes.NewReader([]byte("\x01\x25princess peach is in another castle")),
			},
			want:    false,
			want1:   "princess peach is in another castle\x00\x00",
			wantErr: true,
		},
		{
			name: "too long",
			args: args{
				r: bytes.NewReader([]byte("\xAA\xBB\xCCrandom stuff")),
			},
			want:    false,
			want1:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := ReadTCPResponse(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadTCPResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadTCPResponse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("ReadTCPResponse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestWriteTCPResponse(t *testing.T) {
	type args struct {
		ok  bool
		msg string
	}
	tests := []struct {
		name    string
		args    args
		wantW   string
		wantErr bool
	}{
		{
			name: "success 1",
			args: args{
				ok:  true,
				msg: "",
			},
			wantW: "\x00\x00",
		},
		{
			name: "success 2",
			args: args{
				ok:  true,
				msg: "Welcome XDXDXD",
			},
			wantW: "\x00\x0EWelcome XDXDXD",
		},
		{
			name: "failure 1",
			args: args{
				ok:  false,
				msg: "",
			},
			wantW: "\x01\x00",
		},
		{
			name: "failure 2",
			args: args{
				ok:  false,
				msg: "me trying to find who u are: ...",
			},
			wantW: "\x01\x20me trying to find who u are: ...",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := WriteTCPResponse(w, tt.args.ok, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTCPResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("WriteTCPResponse() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestWriteUDPRequest(t *testing.T) {
	tests := []struct {
		name    string
		wantW   string
		wantErr bool
	}{
		{
			name:    "normal",
			wantW:   "\x44\x02",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := WriteUDPRequest(w)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteUDPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("WriteUDPRequest() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestReadUDPResponse(t *testing.T) {
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		want1   uint32
		want2   string
		wantErr bool
	}{
		{
			name: "success 1",
			args: args{
				r: bytes.NewReader([]byte("\x00\x00\x00\x00\x02\x00")),
			},
			want:    true,
			want1:   2,
			want2:   "",
			wantErr: false,
		},
		{
			name: "success 2",
			args: args{
				r: bytes.NewReader([]byte("\x00\x00\x00\x00\x03\x0EWelcome XDXDXD")),
			},
			want:    true,
			want1:   3,
			want2:   "Welcome XDXDXD",
			wantErr: false,
		},
		{
			name: "failure",
			args: args{
				r: bytes.NewReader([]byte("\x01\x00\x00\x00\x01\x20me trying to find who u are: ...")),
			},
			want:    false,
			want1:   1,
			want2:   "me trying to find who u are: ...",
			wantErr: false,
		},
		{
			name: "incomplete",
			args: args{
				r: bytes.NewReader([]byte("\x00\x00\x00\x00\x02")),
			},
			want:    false,
			want1:   0,
			want2:   "",
			wantErr: true,
		},
		{
			name: "too long",
			args: args{
				r: bytes.NewReader([]byte("\x00\x00\x00\x00\x02\xCC\xFF\x66no cap")),
			},
			want:    false,
			want1:   0,
			want2:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, err := ReadUDPResponse(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadUDPResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ReadUDPResponse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("ReadUDPResponse() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("ReadUDPResponse() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func TestWriteUDPResponse(t *testing.T) {
	type args struct {
		ok        bool
		sessionID uint32
		msg       string
	}
	tests := []struct {
		name    string
		args    args
		wantW   string
		wantErr bool
	}{
		{
			name: "success 1",
			args: args{
				ok:        true,
				sessionID: 88,
				msg:       "",
			},
			wantW: "\x00\x00\x00\x00\x58\x00",
		},
		{
			name: "success 2",
			args: args{
				ok:        true,
				sessionID: 233,
				msg:       "together forever",
			},
			wantW: "\x00\x00\x00\x00\xE9\x10together forever",
		},
		{
			name: "failure 1",
			args: args{
				ok:        false,
				sessionID: 1,
				msg:       "",
			},
			wantW: "\x01\x00\x00\x00\x01\x00",
		},
		{
			name: "failure 2",
			args: args{
				ok:        false,
				sessionID: 696969,
				msg:       "run away run away",
			},
			wantW: "\x01\x00\x0A\xA2\x89\x11run away run away",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := WriteUDPResponse(w, tt.args.ok, tt.args.sessionID, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteUDPResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("WriteUDPResponse() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}
