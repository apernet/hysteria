package pppbridge

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
)

// Detecting a path that narrows after the MTU was already agreed.
//
// Nothing else in the stack notices this. quic-go's Path MTU discovery only ever
// searches upward -- CurrentSize() returns the confirmed minimum, which is raised
// on a successful probe and never lowered -- so once the estimate is set it stays
// set. SendDatagram keeps succeeding because quic-go still believes the larger
// size works, and the packets are simply lost on the wire with no ICMP. LCP Echo
// does not help either: echo frames are a few dozen octets and sail through a
// path that only drops large packets.
//
// Measured: on a connection converged at a 1500-byte path, narrowing the path to
// 1300 left the connection healthy and the budget unchanged for over 75 seconds
// while every full-size frame vanished (TestMTUSimulationPathShrinksMidConnection).
//
// So the only way to see it is to probe at the size that actually matters. These
// probes are full-size frames the peer echoes back; losing several in a row means
// the path no longer carries what the PPP link was sized for. The session is then
// torn down so it can be rebuilt -- a fresh QUIC connection restarts discovery
// from the initial packet size and re-converges on the narrower path.
const (
	// A private protocol number in RFC 1661's 0x4000-0x7FFF range, which is
	// reserved for low-volume traffic with no associated NCP. Frames carrying it
	// are consumed by the peer bridge and never reach pppd.
	pppProtoMTUProbe uint16 = 0x4001

	mtuProbeRequest uint8 = 0
	mtuProbeReply   uint8 = 1

	// probe header: FF 03 <proto:2> <kind:1> <seq:4>
	mtuProbeHeaderLen = 4 + 1 + 4

	mtuProbeInterval    = 15 * time.Second
	mtuProbeGrace       = 20 * time.Second
	maxMTUProbeFailures = 3
)

// errPathNarrowed reports that full-size frames stopped getting through.
var errPathNarrowed = errors.New("ppp: path no longer carries the negotiated MTU")

// buildMTUProbe returns a probe frame padded out to size total octets.
func buildMTUProbe(kind uint8, seq uint32, total int) []byte {
	if total < mtuProbeHeaderLen {
		total = mtuProbeHeaderLen
	}
	f := make([]byte, total)
	f[0] = 0xFF
	f[1] = 0x03
	binary.BigEndian.PutUint16(f[2:4], pppProtoMTUProbe)
	f[4] = kind
	binary.BigEndian.PutUint32(f[5:9], seq)
	return f
}

// parseMTUProbe reports whether raw is a probe frame, and if so its kind and
// sequence number.
func parseMTUProbe(raw []byte) (kind uint8, seq uint32, ok bool) {
	if len(raw) < mtuProbeHeaderLen {
		return 0, 0, false
	}
	if raw[0] != 0xFF || raw[1] != 0x03 {
		return 0, 0, false
	}
	if binary.BigEndian.Uint16(raw[2:4]) != pppProtoMTUProbe {
		return 0, 0, false
	}
	return raw[4], binary.BigEndian.Uint32(raw[5:9]), true
}

// transportMaxFrame reports the data transport's current per-frame ceiling, or 0
// when it does not have one to report.
func transportMaxFrame(data ppp.PPPDataIO) int {
	if s, ok := data.(ppp.MaxFrameSizer); ok {
		return s.MaxFrameSize()
	}
	return 0
}

// mtuProbeWorthwhile reports whether the transport has a per-frame ceiling small
// enough for a shrinking path to matter. Reliable streams do not.
func mtuProbeWorthwhile(data ppp.PPPDataIO) bool {
	max := transportMaxFrame(data)
	return max > 0 && max <= maxPPPMTU
}
