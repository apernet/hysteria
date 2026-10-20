package l3

import (
	"bytes"
	"sync/atomic"
	"testing"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/l3frag"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func TestSendEvenSplitAndInterleavedReassembly(t *testing.T) {
	var next atomic.Uint32
	var datagrams [][]byte
	send := func(b []byte) error {
		if len(b) > 1200 {
			return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}
		}
		datagrams = append(datagrams, append([]byte(nil), b...))
		return nil
	}
	pktA := bytes.Repeat([]byte{0x45}, 1600)
	pktB := bytes.Repeat([]byte{0x60}, 1500)
	if err := Send(send, &next, pktA); err != nil {
		t.Fatal(err)
	}
	if err := Send(send, &next, pktB); err != nil {
		t.Fatal(err)
	}
	if len(datagrams) != 4 {
		t.Fatalf("datagrams = %d, want 4", len(datagrams))
	}
	// 1600 bytes, payload budget 1189, two equal pieces of 800.
	f0, ok := protocol.ParseL3Fragment(datagrams[0])
	if !ok || len(f0.Data) != 800 || f0.FragCount != 2 {
		t.Fatalf("first fragment = %+v len %d", f0, len(f0.Data))
	}
	if _, err := protocol.ParseUDPMessage(datagrams[0]); err == nil {
		t.Fatal("UDP parser accepted an L3 datagram")
	}

	asm := &l3frag.Assembler{}
	// A0, B0, B1, A1 — the two packets are in flight together.
	order := []int{0, 2, 3, 1}
	var gotA, gotB []byte
	for _, i := range order {
		f, ok := protocol.ParseL3Fragment(datagrams[i])
		if !ok {
			t.Fatalf("datagram %d is not L3", i)
		}
		got := asm.Feed(f.PacketID, f.FragID, f.FragCount, f.Data)
		if got == nil {
			continue
		}
		switch got[0] {
		case 0x45:
			gotA = got
		case 0x60:
			gotB = got
		}
	}
	if !bytes.Equal(gotA, pktA) || !bytes.Equal(gotB, pktB) {
		t.Fatalf("reassembly A=%d B=%d", len(gotA), len(gotB))
	}
}
