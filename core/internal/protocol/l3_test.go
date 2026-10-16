package protocol

import (
	"net/http"
	"testing"
)

func TestL3FragmentRoundTrip(t *testing.T) {
	ip := []byte{0x45, 0x00, 0x00, 0x1c}
	ip = append(ip, make([]byte, 1550-len(ip))...)
	parts := SplitL3(0xABCDE123, ip, 1200)
	if len(parts) != 2 {
		t.Fatalf("fragments = %d, want 2", len(parts))
	}
	var got []byte
	asm := map[uint8][]byte{}
	for _, p := range parts {
		if _, err := ParseUDPMessage(p); err == nil {
			t.Fatal("ParseUDPMessage accepted an L3 datagram")
		}
		f, ok := ParseL3Fragment(p)
		if !ok {
			t.Fatal("ParseL3Fragment rejected a fragment")
		}
		if f.PacketID != 0xABCDE123 || f.FragCount != 2 {
			t.Fatalf("header = %+v", f)
		}
		asm[f.FragID] = f.Data
	}
	got = append(got, asm[0]...)
	got = append(got, asm[1]...)
	if len(got) != len(ip) || got[0] != 0x45 {
		t.Fatalf("reassembled len %d", len(got))
	}
}

func TestL3HeaderRoundTrip(t *testing.T) {
	h := make(http.Header)
	AuthRequestToHeader(h, AuthRequest{Auth: "pw", Rx: 1, L3: true})
	req := AuthRequestFromHeader(h)
	if !req.L3 || req.Auth != "pw" {
		t.Fatalf("request = %+v", req)
	}
	h = make(http.Header)
	AuthResponseToHeader(h, AuthResponse{UDPEnabled: true, L3: true})
	resp := AuthResponseFromHeader(h)
	if !resp.L3 || !resp.UDPEnabled {
		t.Fatalf("response = %+v", resp)
	}
}
