package congestion

import (
	"math"
	"time"
)

const maxBurstSize = 10 * maxDatagramSize

type pacer struct {
	bandwidthFunc    func() uint64
	budgetAtLastSent uint64
	lastSentTime     time.Time
}

func newPacer(bandwidthFunc func() uint64) *pacer {
	p := &pacer{
		bandwidthFunc: bandwidthFunc,
	}
	p.budgetAtLastSent = maxBurstSize
	return p
}

func (p *pacer) SentPacket(sendTime time.Time, size uint64) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *pacer) Budget(now time.Time) uint64 {
	if p.lastSentTime.IsZero() {
		return maxBurstSize
	}
	budget := p.budgetAtLastSent + p.bandwidthFunc()*uint64(now.Sub(p.lastSentTime).Nanoseconds())/1e9
	if budget > maxBurstSize {
		return maxBurstSize
	} else {
		return budget
	}
}

func (p *pacer) TimeUntilSend() time.Time {
	if p.budgetAtLastSent >= maxDatagramSize {
		return time.Time{}
	}
	d := time.Duration(math.Ceil(float64(maxDatagramSize-p.budgetAtLastSent)*1e9/float64(p.bandwidthFunc()))) * time.Nanosecond
	if d < time.Millisecond {
		return p.lastSentTime.Add(time.Millisecond)
	} else {
		return p.lastSentTime.Add(d)
	}
}
