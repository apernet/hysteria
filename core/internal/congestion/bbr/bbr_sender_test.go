package bbr

import (
	"testing"

	"github.com/apernet/quic-go/congestion"
	"github.com/stretchr/testify/require"
)

func TestSetMaxDatagramSizeRescalesPacketSizedWindows(t *testing.T) {
	const oldMaxDatagramSize = congestion.ByteCount(1000)
	const newMaxDatagramSize = congestion.ByteCount(1400)
	const initialCongestionWindowPackets = congestion.ByteCount(20)
	const maxCongestionWindowPackets = congestion.ByteCount(80)

	b := newBbrSender(
		DefaultClock{},
		oldMaxDatagramSize,
		initialCongestionWindowPackets*oldMaxDatagramSize,
		maxCongestionWindowPackets*oldMaxDatagramSize,
	)
	b.congestionWindow = b.initialCongestionWindow

	b.SetMaxDatagramSize(newMaxDatagramSize)

	require.Equal(t, initialCongestionWindowPackets*newMaxDatagramSize, b.initialCongestionWindow)
	require.Equal(t, maxCongestionWindowPackets*newMaxDatagramSize, b.maxCongestionWindow)
	require.Equal(t, minCongestionWindowPackets*newMaxDatagramSize, b.minCongestionWindow)
	require.Equal(t, initialCongestionWindowPackets*newMaxDatagramSize, b.congestionWindow)
}

func TestSetMaxDatagramSizeClampsCongestionWindow(t *testing.T) {
	const oldMaxDatagramSize = congestion.ByteCount(1000)
	const newMaxDatagramSize = congestion.ByteCount(1400)

	b := NewBbrSender(DefaultClock{}, oldMaxDatagramSize)
	b.congestionWindow = b.minCongestionWindow + oldMaxDatagramSize
	b.recoveryWindow = b.minCongestionWindow + oldMaxDatagramSize

	b.SetMaxDatagramSize(newMaxDatagramSize)

	require.Equal(t, b.minCongestionWindow, b.congestionWindow)
	require.Equal(t, b.minCongestionWindow, b.recoveryWindow)
}
