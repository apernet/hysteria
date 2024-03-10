package speedtest

import (
	"bytes"
	"testing"
	"time"
)

func TestReadDownloadRequest(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    uint32
		wantErr bool
	}{
		{
			name:    "normal",
			data:    []byte{0x0, 0x1, 0xBD, 0xC2},
			want:    114114,
			wantErr: false,
		},
		{
			name:    "normal zero",
			data:    []byte{0x0, 0x0, 0x0, 0x0},
			want:    0,
			wantErr: false,
		},
		{
			name:    "incomplete",
			data:    []byte{0x0, 0x1, 0x2},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, err := readDownloadRequest(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("readDownloadRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("readDownloadRequest() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteDownloadRequest(t *testing.T) {
	tests := []struct {
		name    string
		l       uint32
		wantW   string
		wantErr bool
	}{
		{
			name:    "normal",
			l:       78909912,
			wantW:   "\x01\x04\xB4\x11\xD8",
			wantErr: false,
		},
		{
			name:    "normal zero",
			l:       0,
			wantW:   "\x01\x00\x00\x00\x00",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := writeDownloadRequest(w, tt.l)
			if (err != nil) != tt.wantErr {
				t.Errorf("writeDownloadRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("writeDownloadRequest() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestReadDownloadResponse(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    bool
		want1   string
		wantErr bool
	}{
		{
			name:    "normal ok",
			data:    []byte{0x0, 0x0, 0x2, 0x41, 0x42},
			want:    true,
			want1:   "AB",
			wantErr: false,
		},
		{
			name:    "normal ok no message",
			data:    []byte{0x0, 0x0, 0x0, 0x0},
			want:    true,
			want1:   "",
			wantErr: false,
		},
		{
			name:    "normal error",
			data:    []byte{0x1, 0x0, 0x2, 0x43, 0x44},
			want:    false,
			want1:   "CD",
			wantErr: false,
		},
		{
			name:    "incomplete",
			data:    []byte{0x0, 0x99, 0x99, 0x45, 0x46, 0x47},
			want:    false,
			want1:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, got1, err := readDownloadResponse(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("readDownloadResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("readDownloadResponse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("readDownloadResponse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestWriteDownloadResponse(t *testing.T) {
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
			name:    "normal ok",
			args:    args{ok: true, msg: "wahaha"},
			wantW:   "\x00\x00\x06wahaha",
			wantErr: false,
		},
		{
			name:    "normal error",
			args:    args{ok: false, msg: "bullbull"},
			wantW:   "\x01\x00\x08bullbull",
			wantErr: false,
		},
		{
			name:    "empty ok",
			args:    args{ok: true, msg: ""},
			wantW:   "\x00\x00\x00",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := writeDownloadResponse(w, tt.args.ok, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("writeDownloadResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("writeDownloadResponse() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestReadUploadRequest(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    uint32
		wantErr bool
	}{
		{
			name:    "normal",
			data:    []byte{0x0, 0x0, 0x26, 0xEE},
			want:    9966,
			wantErr: false,
		},
		{
			name:    "normal zero",
			data:    []byte{0x0, 0x0, 0x0, 0x0},
			want:    0,
			wantErr: false,
		},
		{
			name:    "incomplete",
			data:    []byte{0x1},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, err := readUploadRequest(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("readUploadRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("readUploadRequest() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteUploadRequest(t *testing.T) {
	tests := []struct {
		name    string
		l       uint32
		wantW   string
		wantErr bool
	}{
		{
			name:    "normal",
			l:       2291758882,
			wantW:   "\x02\x88\x99\x77\x22",
			wantErr: false,
		},
		{
			name:    "normal zero",
			l:       0,
			wantW:   "\x02\x00\x00\x00\x00",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := writeUploadRequest(w, tt.l)
			if (err != nil) != tt.wantErr {
				t.Errorf("writeUploadRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("writeUploadRequest() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestReadUploadResponse(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    bool
		want1   string
		wantErr bool
	}{
		{
			name:    "normal ok",
			data:    []byte{0x0, 0x0, 0x2, 0x41, 0x42},
			want:    true,
			want1:   "AB",
			wantErr: false,
		},
		{
			name:    "normal ok no message",
			data:    []byte{0x0, 0x0, 0x0},
			want:    true,
			want1:   "",
			wantErr: false,
		},
		{
			name:    "normal error",
			data:    []byte{0x1, 0x0, 0x2, 0x43, 0x44},
			want:    false,
			want1:   "CD",
			wantErr: false,
		},
		{
			name:    "incomplete",
			data:    []byte{0x0, 0x99, 0x99, 0x45, 0x46, 0x47},
			want:    false,
			want1:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, got1, err := readUploadResponse(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("readUploadResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("readUploadResponse() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("readUploadResponse() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestWriteUploadResponse(t *testing.T) {
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
			name:    "normal ok",
			args:    args{ok: true, msg: "lul"},
			wantW:   "\x00\x00\x03lul",
			wantErr: false,
		},
		{
			name:    "normal error",
			args:    args{ok: false, msg: "notforu"},
			wantW:   "\x01\x00\x07notforu",
			wantErr: false,
		},
		{
			name:    "empty ok",
			args:    args{ok: true, msg: ""},
			wantW:   "\x00\x00\x00",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := writeUploadResponse(w, tt.args.ok, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("writeUploadResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("writeUploadResponse() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func TestReadUploadSummary(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    time.Duration
		want1   uint32
		wantErr bool
	}{
		{
			name:    "normal",
			data:    []byte{0x0, 0x0, 0x14, 0x6E, 0x0, 0x26, 0x25, 0xA0},
			want:    5230 * time.Millisecond,
			want1:   2500000,
			wantErr: false,
		},
		{
			name:    "zero",
			data:    []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			want:    0,
			want1:   0,
			wantErr: false,
		},
		{
			name:    "incomplete",
			data:    []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			want:    0,
			want1:   0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, got1, err := readUploadSummary(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("readUploadSummary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("readUploadSummary() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("readUploadSummary() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestWriteUploadSummary(t *testing.T) {
	type args struct {
		duration time.Duration
		l        uint32
	}
	tests := []struct {
		name    string
		args    args
		wantW   string
		wantErr bool
	}{
		{
			name:    "normal",
			args:    args{duration: 5230 * time.Millisecond, l: 2500000},
			wantW:   "\x00\x00\x14\x6E\x00\x26\x25\xA0",
			wantErr: false,
		},
		{
			name:    "zero",
			args:    args{duration: 0, l: 0},
			wantW:   "\x00\x00\x00\x00\x00\x00\x00\x00",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			err := writeUploadSummary(w, tt.args.duration, tt.args.l)
			if (err != nil) != tt.wantErr {
				t.Errorf("writeUploadSummary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("writeUploadSummary() gotW = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}
