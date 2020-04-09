package congestion

import (
	"github.com/lucas-clemente/quic-go/congestion"
	"time"
)

// BrutalSender sends packets at a constant rate and does not react to any changes in the network environment,
// hence the name.
type BrutalSender struct {
	rttStats *congestion.RTTStats
	bps      congestion.ByteCount
}

func NewBrutalSender(bps congestion.ByteCount) *BrutalSender {
	return &BrutalSender{
		bps: bps,
	}
}

func (b *BrutalSender) SetRTTStats(rttStats *congestion.RTTStats) {
	b.rttStats = rttStats
}

func (b *BrutalSender) TimeUntilSend(bytesInFlight congestion.ByteCount) time.Duration {
	return time.Duration(congestion.ByteCount(time.Second) * congestion.MaxPacketSizeIPv4 / (2 * b.bps))
}

func (b *BrutalSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *BrutalSender) GetCongestionWindow() congestion.ByteCount {
	rtt := maxDuration(b.rttStats.LatestRTT(), b.rttStats.SmoothedRTT())
	if rtt <= 0 {
		return 10240
	}
	return b.bps * congestion.ByteCount(rtt) / congestion.ByteCount(time.Second)
}

func (b *BrutalSender) OnPacketSent(sentTime time.Time, bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool) {
}

func (b *BrutalSender) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount, eventTime time.Time) {
}

func (b *BrutalSender) OnPacketLost(number congestion.PacketNumber, lostBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount) {
}

func (b *BrutalSender) InSlowStart() bool {
	return false
}

func (b *BrutalSender) InRecovery() bool {
	return false
}

func (b *BrutalSender) MaybeExitSlowStart() {}

func (b *BrutalSender) OnRetransmissionTimeout(packetsRetransmitted bool) {}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
