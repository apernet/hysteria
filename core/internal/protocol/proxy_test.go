package protocol

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

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

func TestReadTCPRequest(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name:    "normal no padding",
			data:    []byte("\x0egoogle.com:443\x00"),
			want:    "google.com:443",
			wantErr: false,
		},
		{
			name:    "normal with padding",
			data:    []byte("\x0bholy.cc:443\x02gg"),
			want:    "holy.cc:443",
			wantErr: false,
		},
		{
			name:    "incomplete 1",
			data:    []byte("\x0bhoho"),
			want:    "",
			wantErr: true,
		},
		{
			name:    "incomplete 2",
			data:    []byte("\x0bholy.cc:443\x05x"),
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, err := ReadTCPRequest(r)
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
	tests := []struct {
		name    string
		addr    string
		wantW   string // Just a prefix, we don't care about the padding
		wantErr bool
	}{
		{
			name:    "normal 1",
			addr:    "google.com:443",
			wantW:   "\x44\x01\x0egoogle.com:443",
			wantErr: false,
		},
		{
			name:    "normal 2",
			addr:    "client-api.arkoselabs.com:8080",
			wantW:   "\x44\x01\x1eclient-api.arkoselabs.com:8080",
			wantErr: false,
		},
		{
			name:    "empty",
			addr:    "",
			wantW:   "\x44\x01\x00",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := WriteTCPRequest(w, tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTCPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); !(strings.HasPrefix(gotW, tt.wantW) && len(gotW) > len(tt.wantW)) {
				t.Errorf("WriteTCPRequest() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestReadTCPResponse(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    bool
		want1   string
		wantErr bool
	}{
		{
			name:    "normal ok no padding",
			data:    []byte("\x00\x0bhello world\x00"),
			want:    true,
			want1:   "hello world",
			wantErr: false,
		},
		{
			name:    "normal error with padding",
			data:    []byte("\x01\x06stop!!\x05xxxxx"),
			want1:   "stop!!",
			wantErr: false,
		},
		{
			name:    "normal ok no message with padding",
			data:    []byte("\x01\x00\x05xxxxx"),
			want1:   "",
			wantErr: false,
		},
		{
			name:    "incomplete 1",
			data:    []byte("\x00\x0bhoho"),
			want1:   "",
			wantErr: true,
		},
		{
			name:    "incomplete 2",
			data:    []byte("\x01\x05jesus\x05x"),
			want1:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, got1, err := ReadTCPResponse(r)
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
		wantW   string // Just a prefix, we don't care about the padding
		wantErr bool
	}{
		{
			name:    "normal ok",
			args:    args{ok: true, msg: "hello world"},
			wantW:   "\x00\x0bhello world",
			wantErr: false,
		},
		{
			name:    "normal error",
			args:    args{ok: false, msg: "stop!!"},
			wantW:   "\x01\x06stop!!",
			wantErr: false,
		},
		{
			name:    "empty",
			args:    args{ok: true, msg: ""},
			wantW:   "\x00\x00",
			wantErr: false,
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
			if gotW := w.String(); !(strings.HasPrefix(gotW, tt.wantW) && len(gotW) > len(tt.wantW)) {
				t.Errorf("WriteTCPResponse() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

// PPP Protocol Tests

func TestReadPPPRequest(t *testing.T) {
	tests := []struct {
		name            string
		data            []byte
		wantDataStreams int
		wantErr         bool
	}{
		{
			name:            "datagram mode no padding",
			data:            []byte("\x00\x00"),
			wantDataStreams: 0,
			wantErr:         false,
		},
		{
			name:            "datagram mode with padding",
			data:            []byte("\x00\x02gg"),
			wantDataStreams: 0,
			wantErr:         false,
		},
		{
			name:            "multi-stream mode",
			data:            []byte("\x14\x00"),
			wantDataStreams: 20,
			wantErr:         false,
		},
		{
			name:    "incomplete",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "incomplete padding",
			data:    []byte("\x00\x05x"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			ds, err := ReadPPPRequest(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadPPPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && ds != tt.wantDataStreams {
				t.Errorf("ReadPPPRequest() dataStreams = %v, want %v", ds, tt.wantDataStreams)
			}
		})
	}
}

func TestWritePPPRequest(t *testing.T) {
	tests := []struct {
		name        string
		dataStreams int
		wantPrefix  string
	}{
		{
			name:        "datagram mode",
			dataStreams: 0,
			wantPrefix:  "\x44\x02\x00",
		},
		{
			name:        "multi-stream mode",
			dataStreams: 20,
			wantPrefix:  "\x44\x02\x14",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := WritePPPRequest(w, tt.dataStreams)
			if err != nil {
				t.Errorf("WritePPPRequest() error = %v", err)
				return
			}
			gotW := w.String()
			if !(strings.HasPrefix(gotW, tt.wantPrefix) && len(gotW) > len(tt.wantPrefix)) {
				t.Errorf("WritePPPRequest() gotW prefix mismatch, got len=%d", len(gotW))
			}
		})
	}
}

func TestReadPPPResponse(t *testing.T) {
	tests := []struct {
		name            string
		data            []byte
		wantOk          bool
		wantMsg         string
		wantDataStreams int
		wantErr         bool
	}{
		{
			name:            "ok with message datagram mode",
			data:            []byte("\x00\x02OK\x00\x00"),
			wantOk:          true,
			wantMsg:         "OK",
			wantDataStreams: 0,
			wantErr:         false,
		},
		{
			name:            "ok multi-stream mode with padding",
			data:            []byte("\x00\x02OK\x14\x03xxx"),
			wantOk:          true,
			wantMsg:         "OK",
			wantDataStreams: 20,
			wantErr:         false,
		},
		{
			name:            "error with padding",
			data:            []byte("\x01\x0dPPP disabled!\x00\x05xxxxx"),
			wantOk:          false,
			wantMsg:         "PPP disabled!",
			wantDataStreams: 0,
			wantErr:         false,
		},
		{
			name:            "ok no message with padding",
			data:            []byte("\x00\x00\x00\x03xxx"),
			wantOk:          true,
			wantMsg:         "",
			wantDataStreams: 0,
			wantErr:         false,
		},
		{
			name:    "incomplete status",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "incomplete message",
			data:    []byte("\x00\x0bhello"),
			wantErr: true,
		},
		{
			name:    "incomplete padding",
			data:    []byte("\x00\x00\x00\x05x"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			gotOk, gotMsg, gotDS, err := ReadPPPResponse(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadPPPResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotOk != tt.wantOk {
				t.Errorf("ReadPPPResponse() ok = %v, want %v", gotOk, tt.wantOk)
			}
			if gotMsg != tt.wantMsg {
				t.Errorf("ReadPPPResponse() msg = %v, want %v", gotMsg, tt.wantMsg)
			}
			if !tt.wantErr && gotDS != tt.wantDataStreams {
				t.Errorf("ReadPPPResponse() dataStreams = %v, want %v", gotDS, tt.wantDataStreams)
			}
		})
	}
}

func TestWritePPPResponse(t *testing.T) {
	type args struct {
		ok          bool
		msg         string
		dataStreams int
	}
	tests := []struct {
		name    string
		args    args
		wantW   string
		wantErr bool
	}{
		{
			name:    "ok with message datagram",
			args:    args{ok: true, msg: "OK", dataStreams: 0},
			wantW:   "\x00\x02OK\x00",
			wantErr: false,
		},
		{
			name:    "ok multi-stream",
			args:    args{ok: true, msg: "OK", dataStreams: 20},
			wantW:   "\x00\x02OK\x14",
			wantErr: false,
		},
		{
			name:    "error with message",
			args:    args{ok: false, msg: "PPP disabled!", dataStreams: 0},
			wantW:   "\x01\x0dPPP disabled!\x00",
			wantErr: false,
		},
		{
			name:    "ok empty message",
			args:    args{ok: true, msg: "", dataStreams: 0},
			wantW:   "\x00\x00\x00",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := WritePPPResponse(w, tt.args.ok, tt.args.msg, tt.args.dataStreams)
			if (err != nil) != tt.wantErr {
				t.Errorf("WritePPPResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); !(strings.HasPrefix(gotW, tt.wantW) && len(gotW) > len(tt.wantW)) {
				t.Errorf("WritePPPResponse() gotW = %v, want prefix %v", gotW, tt.wantW)
			}
		})
	}
}

func TestPPPRequestResponseRoundTrip(t *testing.T) {
	t.Run("request round trip datagram", func(t *testing.T) {
		w := &bytes.Buffer{}
		if err := WritePPPRequest(w, 0); err != nil {
			t.Fatalf("WritePPPRequest() error = %v", err)
		}
		// Skip the frame type varint (2 bytes for 0x402)
		data := w.Bytes()[2:]
		r := bytes.NewReader(data)
		ds, err := ReadPPPRequest(r)
		if err != nil {
			t.Errorf("ReadPPPRequest() error = %v", err)
		}
		if ds != 0 {
			t.Errorf("ReadPPPRequest() dataStreams = %v, want 0", ds)
		}
	})

	t.Run("request round trip multi-stream", func(t *testing.T) {
		w := &bytes.Buffer{}
		if err := WritePPPRequest(w, 20); err != nil {
			t.Fatalf("WritePPPRequest() error = %v", err)
		}
		data := w.Bytes()[2:]
		r := bytes.NewReader(data)
		ds, err := ReadPPPRequest(r)
		if err != nil {
			t.Errorf("ReadPPPRequest() error = %v", err)
		}
		if ds != 20 {
			t.Errorf("ReadPPPRequest() dataStreams = %v, want 20", ds)
		}
	})

	t.Run("response round trip ok datagram", func(t *testing.T) {
		w := &bytes.Buffer{}
		if err := WritePPPResponse(w, true, "hello", 0); err != nil {
			t.Fatalf("WritePPPResponse() error = %v", err)
		}
		r := bytes.NewReader(w.Bytes())
		ok, msg, ds, err := ReadPPPResponse(r)
		if err != nil {
			t.Errorf("ReadPPPResponse() error = %v", err)
		}
		if !ok {
			t.Errorf("ReadPPPResponse() ok = false, want true")
		}
		if msg != "hello" {
			t.Errorf("ReadPPPResponse() msg = %v, want hello", msg)
		}
		if ds != 0 {
			t.Errorf("ReadPPPResponse() dataStreams = %v, want 0", ds)
		}
	})

	t.Run("response round trip ok multi-stream", func(t *testing.T) {
		w := &bytes.Buffer{}
		if err := WritePPPResponse(w, true, "OK", 20); err != nil {
			t.Fatalf("WritePPPResponse() error = %v", err)
		}
		r := bytes.NewReader(w.Bytes())
		ok, msg, ds, err := ReadPPPResponse(r)
		if err != nil {
			t.Errorf("ReadPPPResponse() error = %v", err)
		}
		if !ok {
			t.Errorf("ReadPPPResponse() ok = false, want true")
		}
		if msg != "OK" {
			t.Errorf("ReadPPPResponse() msg = %v, want OK", msg)
		}
		if ds != 20 {
			t.Errorf("ReadPPPResponse() dataStreams = %v, want 20", ds)
		}
	})

	t.Run("response round trip error", func(t *testing.T) {
		w := &bytes.Buffer{}
		if err := WritePPPResponse(w, false, "denied", 0); err != nil {
			t.Fatalf("WritePPPResponse() error = %v", err)
		}
		r := bytes.NewReader(w.Bytes())
		ok, msg, ds, err := ReadPPPResponse(r)
		if err != nil {
			t.Errorf("ReadPPPResponse() error = %v", err)
		}
		if ok {
			t.Errorf("ReadPPPResponse() ok = true, want false")
		}
		if msg != "denied" {
			t.Errorf("ReadPPPResponse() msg = %v, want denied", msg)
		}
		if ds != 0 {
			t.Errorf("ReadPPPResponse() dataStreams = %v, want 0", ds)
		}
	})
}
