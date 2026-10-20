package server

import (
	"testing"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func TestHubDropsWithoutPeer(t *testing.T) {
	h := newL3Hub()
	if err := h.Send([]byte{0x45, 0x00}); err != nil {
		t.Fatal(err)
	}
	h.close()
	if _, err := h.Receive(); err == nil {
		t.Fatal("receive on a closed hub succeeded")
	} else if _, ok := err.(coreErrs.ClosedError); !ok {
		t.Fatalf("error = %T", err)
	}
}

func TestHubReplacesPeer(t *testing.T) {
	h := newL3Hub()
	old := h.adopt(nil, "old", nil)
	cur := h.adopt(nil, "new", nil)
	if old == nil || cur == nil {
		t.Fatal("adopt failed")
	}
	old.accept(protocol.L3Fragment{PacketID: 1, FragID: 0, FragCount: 1, Data: []byte{0x45}})
	select {
	case pkt := <-h.recv:
		t.Fatalf("replaced peer delivered %d bytes", len(pkt))
	default:
	}
	cur.accept(protocol.L3Fragment{PacketID: 2, FragID: 0, FragCount: 1, Data: []byte{0x45, 0x00}})
	select {
	case pkt := <-h.recv:
		if len(pkt) != 2 || pkt[0] != 0x45 {
			t.Fatalf("packet = %v", pkt)
		}
	case <-time.After(time.Second):
		t.Fatal("current peer packet was not delivered")
	}
}
