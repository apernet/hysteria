package core

import (
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"testing"
)

func TestClientUDP(t *testing.T) {
	client, err := NewClient("toby.moe:36713", nil, &tls.Config{
		NextProtos: []string{"hysteria"},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{
		EnableDatagrams: true,
	}, 125000, 125000, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialUDP()
	if err != nil {
		t.Fatal("conn DialUDP", err)
	}
	t.Run("8.8.8.8", func(t *testing.T) {
		dnsReq := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01}
		err := conn.WriteTo(dnsReq, "8.8.8.8:53")
		if err != nil {
			t.Error("WriteTo", err)
		}
		buf, _, err := conn.ReadFrom()
		if err != nil {
			t.Error("ReadFrom", err)
		}
		if buf[0] != dnsReq[0] || buf[1] != dnsReq[1] {
			t.Error("invalid response")
		}
	})
	t.Run("1.1.1.1", func(t *testing.T) {
		dnsReq := []byte{0x66, 0x77, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01}
		err := conn.WriteTo(dnsReq, "1.1.1.1:53")
		if err != nil {
			t.Error("WriteTo", err)
		}
		buf, _, err := conn.ReadFrom()
		if err != nil {
			t.Error("ReadFrom", err)
		}
		if buf[0] != dnsReq[0] || buf[1] != dnsReq[1] {
			t.Error("invalid response")
		}
	})
	t.Run("Close", func(t *testing.T) {
		_ = conn.Close()
		_, _, err := conn.ReadFrom()
		if err != ErrClosed {
			t.Error("closed conn not returning the correct error")
		}
	})
}
