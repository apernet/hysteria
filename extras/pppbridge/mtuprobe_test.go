package pppbridge

import (
	"encoding/binary"
	"math"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unit coverage for mtuprobe.go: the probe wire format, the predicate that
// decides whether probing is worth doing at all, and the high-water mark that
// records which probes came back.
//
// The probe frame is the one thing in this package that shares the PPP data path
// with real traffic while never being PPP, so the two properties that matter are
// symmetric: a probe must always be recognised as a probe, and nothing that is
// not a probe may ever be mistaken for one. A false positive here silently eats a
// user's packet.

// ---------------------------------------------------------------------------
// buildMTUProbe / parseMTUProbe
// ---------------------------------------------------------------------------

func TestBuildMTUProbeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		kind uint8
		seq  uint32
		size int
	}{
		{"request, first sequence number", mtuProbeRequest, 0, 1400},
		{"reply, first sequence number", mtuProbeReply, 0, mtuProbeHeaderLen},
		{"request, sequence 1", mtuProbeRequest, 1, 1200},
		{"reply carries the sequence it answers", mtuProbeReply, 12345, mtuProbeHeaderLen},
		{"sequence number at the uint32 ceiling", mtuProbeRequest, math.MaxUint32, 1500},
		{"one below the uint32 ceiling", mtuProbeReply, math.MaxUint32 - 1, mtuProbeHeaderLen},
		{"high bit set in the sequence", mtuProbeRequest, 0x80000000, 576},
		{"probe at the minimum PPP MTU", mtuProbeRequest, 7, minPPPMTU},
		{"probe at the maximum PPP MTU", mtuProbeRequest, 8, maxPPPMTU},
		{"kind values are carried verbatim", 0xFE, 9, mtuProbeHeaderLen + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := buildMTUProbe(tt.kind, tt.seq, tt.size)

			require.Len(t, f, tt.size, "probe must be padded to exactly the requested size")
			assert.Equal(t, byte(0xFF), f[0], "HDLC address octet")
			assert.Equal(t, byte(0x03), f[1], "HDLC control octet")
			assert.Equal(t, pppProtoMTUProbe, binary.BigEndian.Uint16(f[2:4]),
				"probes ride a private protocol number so pppd never sees them")

			kind, seq, ok := parseMTUProbe(f)
			require.True(t, ok, "a frame built by buildMTUProbe must parse as a probe")
			assert.Equal(t, tt.kind, kind)
			assert.Equal(t, tt.seq, seq)

			// The padding is what gives the probe its size; it must not carry
			// anything that could be read as data.
			for i := mtuProbeHeaderLen; i < len(f); i++ {
				require.Zerof(t, f[i], "padding octet %d is not zero", i)
			}
		})
	}
}

// A probe smaller than its own header is not representable, so buildMTUProbe
// grows it rather than truncating the sequence number it has to carry.
func TestBuildMTUProbeFloorsAtHeaderLength(t *testing.T) {
	for _, size := range []int{math.MinInt32, -1, 0, 1, mtuProbeHeaderLen - 1, mtuProbeHeaderLen} {
		f := buildMTUProbe(mtuProbeReply, 0xAABBCCDD, size)
		require.Len(t, f, mtuProbeHeaderLen, "size %d must be raised to the header length", size)

		kind, seq, ok := parseMTUProbe(f)
		require.True(t, ok)
		assert.Equal(t, mtuProbeReply, kind)
		assert.Equal(t, uint32(0xAABBCCDD), seq, "the sequence number survives the floor")
	}
}

// The probe is a fixed prefix followed by padding: the same kind and sequence
// must produce the same header no matter how big the frame is.
func TestBuildMTUProbeHeaderIsIndependentOfSize(t *testing.T) {
	small := buildMTUProbe(mtuProbeRequest, 424242, mtuProbeHeaderLen)
	large := buildMTUProbe(mtuProbeRequest, 424242, 1400)
	assert.Equal(t, small, large[:mtuProbeHeaderLen])
}

// Everything that is not a probe must be handed on untouched. These are the
// frames that actually travel the data path.
func TestParseMTUProbeRejectsNonProbes(t *testing.T) {
	valid := buildMTUProbe(mtuProbeRequest, 0x01020304, 64)

	tests := []struct {
		name string
		raw  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"one octet", []byte{0xFF}},
		{"address and control only", []byte{0xFF, 0x03}},
		{"header truncated by one octet", valid[:mtuProbeHeaderLen-1]},
		{"header truncated to the protocol field", valid[:4]},
		{"header truncated after the kind", valid[:5]},

		{"missing the address octet", func() []byte {
			b := append([]byte(nil), valid...)
			b[0] = 0x00
			return b
		}()},
		{"missing the control octet", func() []byte {
			b := append([]byte(nil), valid...)
			b[1] = 0x00
			return b
		}()},
		{"protocol-field compressed (no FF 03)", append([]byte{0x40, 0x01, 0x00}, make([]byte, 16)...)},

		{"neighbouring private protocol 0x4000", func() []byte {
			b := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(b[2:4], 0x4000)
			return b
		}()},
		{"neighbouring private protocol 0x4002", func() []byte {
			b := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(b[2:4], 0x4002)
			return b
		}()},
		{"byte-swapped protocol number", func() []byte {
			b := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(b[2:4], 0x0140)
			return b
		}()},

		{"a real LCP Configure-Request", frameLCPConfReq},
		{"a real LCP Echo-Request", frameLCPEchoReq},
		{"a real CHAP frame", frameCHAP},
		{"a real IPCP frame", frameIPCP},
		{"a real IPv4 packet", frameIPv4},
		{"a real IPv6 packet", frameIPv6},
		{"a real multilink fragment", frameMP},
		// A full-size IPv4 packet whose payload happens to contain the probe
		// header further in: only the frame's own header may be consulted.
		{
			"an IPv4 packet containing the probe header as payload",
			append([]byte{0xFF, 0x03, 0x00, 0x21}, buildMTUProbe(mtuProbeRequest, 1, 32)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, seq, ok := parseMTUProbe(tt.raw)
			assert.False(t, ok, "%x must not be taken for an MTU probe", tt.raw)
			assert.Zero(t, kind)
			assert.Zero(t, seq)
		})
	}
}

// Padding beyond the header is ignored: a probe stays a probe whatever the peer
// put in the pad, which is what lets the size be chosen freely.
func TestParseMTUProbeIgnoresPadding(t *testing.T) {
	f := buildMTUProbe(mtuProbeReply, 99, 128)
	for i := mtuProbeHeaderLen; i < len(f); i++ {
		f[i] = 0xA5
	}
	kind, seq, ok := parseMTUProbe(f)
	require.True(t, ok)
	assert.Equal(t, mtuProbeReply, kind)
	assert.Equal(t, uint32(99), seq)
}

func FuzzParseMTUProbe(f *testing.F) {
	f.Add(buildMTUProbe(mtuProbeRequest, 0, 1400))
	f.Add(buildMTUProbe(mtuProbeReply, math.MaxUint32, mtuProbeHeaderLen))
	f.Add(buildMTUProbe(0xFF, 7, 32))
	f.Add(frameLCPConfReq)
	f.Add(frameIPv4)
	f.Add([]byte{0xFF, 0x03, 0x40, 0x01})
	f.Add([]byte{0xFF, 0x03})
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, raw []byte) {
		kind, seq, ok := parseMTUProbe(raw)
		if !ok {
			if kind != 0 || seq != 0 {
				t.Fatalf("rejected frame reported kind=%d seq=%d for %x", kind, seq, raw)
			}
			return
		}
		// Anything shorter than the header cannot carry a sequence number, so
		// it must never be accepted -- accepting it would mean eating a frame
		// that belongs to pppd.
		if len(raw) < mtuProbeHeaderLen {
			t.Fatalf("frame of %d bytes accepted as a probe: %x", len(raw), raw)
		}
		if raw[0] != 0xFF || raw[1] != 0x03 {
			t.Fatalf("accepted a frame without FF 03: %x", raw)
		}
		if got := binary.BigEndian.Uint16(raw[2:4]); got != pppProtoMTUProbe {
			t.Fatalf("accepted protocol %04X as a probe: %x", got, raw)
		}
		// Accepting implies the header round trips.
		if want := buildMTUProbe(kind, seq, len(raw)); !equalPrefix(want, raw, mtuProbeHeaderLen) {
			t.Fatalf("parse/build disagree: %x vs %x", want[:mtuProbeHeaderLen], raw[:mtuProbeHeaderLen])
		}
	})
}

func equalPrefix(a, b []byte, n int) bool {
	if len(a) < n || len(b) < n {
		return false
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// transportMaxFrame / mtuProbeWorthwhile
// ---------------------------------------------------------------------------

// limitedDataIO (bridge_mtu_test.go) is the transport that reports a ceiling.
var _ ppp.MaxFrameSizer = (*limitedDataIO)(nil)

func TestTransportMaxFrame(t *testing.T) {
	t.Run("a transport that cannot report one", func(t *testing.T) {
		// The plain fake deliberately does not implement MaxFrameSizer, which is
		// the case a stream transport presents.
		var io ppp.PPPDataIO = newFakeDataIO()
		_, isSizer := io.(ppp.MaxFrameSizer)
		require.False(t, isSizer, "the plain fake must not report a ceiling")
		assert.Equal(t, 0, transportMaxFrame(io))
	})
	t.Run("a transport that reports one", func(t *testing.T) {
		assert.Equal(t, 1404, transportMaxFrame(&limitedDataIO{fakeDataIO: newFakeDataIO(), limit: 1404}))
	})
}

// Probing costs a full-size frame every interval, so it only pays for itself
// where a narrowing path is invisible: datagrams. Reliable streams are segmented
// by QUIC and report the 64KiB stream ceiling instead, where a smaller path MTU
// is not a black hole.
func TestMTUProbeWorthwhile(t *testing.T) {
	tests := []struct {
		name string
		max  int
		want bool
	}{
		{"no ceiling reported", 0, false},
		{"a nonsensical negative ceiling", -1, false},
		{"a datagram ceiling measured at handshake", 1243, true},
		{"a datagram ceiling after PMTU discovery settles", 1404, true},
		{"a datagram ceiling on a narrow path", minPPPMTU, true},
		{"a ceiling of exactly one octet", 1, true},
		{"a datagram ceiling at the largest PPP frame", maxPPPMTU, true},
		{"one octet above the largest PPP frame", maxPPPMTU + 1, false},
		{"the stream-shaped ceiling", 65535, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &limitedDataIO{fakeDataIO: newFakeDataIO(), limit: tt.max}
			assert.Equal(t, tt.want, mtuProbeWorthwhile(data))
		})
	}

	t.Run("a transport with no ceiling to report", func(t *testing.T) {
		assert.False(t, mtuProbeWorthwhile(newFakeDataIO()),
			"a transport that cannot report a ceiling must not be probed")
	})
}

// ---------------------------------------------------------------------------
// noteProbeReply
// ---------------------------------------------------------------------------

// probeLoop compares lastProbeSeq against the sequence it just sent, so the
// field has to be a high-water mark: a late reply to an older probe must never pull it
// back down and make a live path look dead.
func TestNoteProbeReplyIsMonotonic(t *testing.T) {
	tests := []struct {
		name string
		seqs []uint32
		want uint32
	}{
		{"nothing noted yet", nil, 0},
		{"in order", []uint32{1, 2, 3, 4}, 4},
		{"a stale reply arriving late", []uint32{5, 2, 1, 3}, 5},
		{"the same sequence twice", []uint32{7, 7, 7}, 7},
		{"zero never lowers the mark", []uint32{9, 0, 0}, 9},
		{"the uint32 ceiling", []uint32{math.MaxUint32, 1}, math.MaxUint32},
		{"one below the ceiling then the ceiling", []uint32{math.MaxUint32 - 1, math.MaxUint32}, math.MaxUint32},
		{"strictly decreasing", []uint32{4, 3, 2, 1}, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &relay{}
			for _, seq := range tt.seqs {
				s.noteProbeReply(seq)
			}
			assert.Equal(t, tt.want, s.lastProbeSeq.Load())
		})
	}
}

// relay's receive pump calls noteProbeReply while the probe loop reads the same
// field, and
// a multi-stream transport can deliver replies out of order across streams. Run
// it under -race with concurrent writers and an interleaved reader.
func TestNoteProbeReplyUnderConcurrency(t *testing.T) {
	const (
		writers  = 8
		perRound = 250
	)
	s := &relay{}

	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		var prev uint32
		for {
			select {
			case <-stop:
				return
			default:
			}
			// A concurrent observer must never see the mark go backwards.
			cur := s.lastProbeSeq.Load()
			if cur < prev {
				t.Errorf("high-water mark went backwards: %d -> %d", prev, cur)
				return
			}
			prev = cur
			// Yield, so this loop still interleaves with the writers when the
			// suite is run with GOMAXPROCS=1 instead of monopolising the P.
			runtime.Gosched()
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// Each writer walks its own range in a different direction so the
			// sequences interleave out of order.
			for i := 0; i < perRound; i++ {
				seq := uint32(w*perRound + i)
				if w%2 == 1 {
					seq = uint32(w*perRound + (perRound - 1 - i))
				}
				s.noteProbeReply(seq)
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	readerWG.Wait()

	assert.Equal(t, uint32(writers*perRound-1), s.lastProbeSeq.Load(),
		"the mark must settle on the highest sequence any goroutine noted")
}

// ---------------------------------------------------------------------------
// Probe timing constants
// ---------------------------------------------------------------------------

// relay.probeLoop's schedule comes from these package constants unless a caller
// overrides it through ProbeInterval/ProbeGrace/ProbeFailures, which is how the
// teardown tests reach the decision in milliseconds instead of the ~73 seconds
// the defaults would cost. The defaults themselves are still the production
// policy, and the policy is the part that decides whether a healthy session gets
// killed, so it is worth checking directly.
func TestMTUProbeTimingConstants(t *testing.T) {
	assert.Greater(t, maxMTUProbeFailures, 1,
		"a single lost probe must never tear down a session; datagrams are lossy by design")
	assert.GreaterOrEqual(t, mtuProbeGrace, mtuProbeInterval,
		"the link must have at least one probe interval to come up before full-size frames are demanded")
	assert.Positive(t, mtuProbeInterval)

	// How long a session takes to be declared dead once probes stop coming back.
	// The ticker free-runs -- probeLoop returns to <-ticker.C after each reply
	// window rather than restarting it -- so the rounds are one interval apart and
	// only the last reply window is added on top.
	teardownAfter := mtuProbeGrace + maxMTUProbeFailures*mtuProbeInterval + mtuProbeInterval/2
	assert.Less(t, teardownAfter, 3*time.Minute,
		"a black-holed path must be found in minutes, not in whatever the QUIC idle "+
			"timeout happens to be; currently %s", teardownAfter)
	assert.Greater(t, teardownAfter, mtuProbeGrace,
		"the grace period alone must never be enough to condemn a session")

	assert.Equal(t, 4+1+4, mtuProbeHeaderLen,
		"FF 03 + protocol(2) + kind(1) + sequence(4)")

	// RFC 1661 s2 assigns PPP Protocol field values 4xxx-7xxx to "low volume
	// traffic with no associated NCP", which is exactly what a probe is. Staying
	// inside it means a peer that does not know the number answers with a
	// Protocol-Reject rather than mis-parsing the frame.
	assert.GreaterOrEqual(t, pppProtoMTUProbe, uint16(0x4000))
	assert.LessOrEqual(t, pppProtoMTUProbe, uint16(0x7FFF))

	// The probe frame carries the HDLC address and control octets, so it is not
	// distinguishable from real traffic by shape alone -- only by protocol number.
	// If it ever collided with a protocol pppd uses, the responder in relay.run
	// would start eating that protocol's frames.
	for _, used := range []uint16{pppProtoLCP, pppProtoPAP, pppProtoCHAP, 0x0021, 0x0057, 0x003D, 0x8021} {
		assert.NotEqual(t, used, pppProtoMTUProbe,
			"the probe protocol must not collide with a protocol pppd speaks")
	}
}
