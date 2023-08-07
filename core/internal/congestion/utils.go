package congestion

import (
	"github.com/apernet/hysteria/core/internal/congestion/bbr"
	"github.com/apernet/hysteria/core/internal/congestion/brutal"
	"github.com/apernet/hysteria/core/internal/congestion/common"
	"github.com/apernet/quic-go"
)

func UseBBR(conn quic.Connection) {
	conn.SetCongestionControl(bbr.NewBBRSender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
		bbr.InitialCongestionWindow*common.InitMaxDatagramSize,
		bbr.DefaultBBRMaxCongestionWindow*common.InitMaxDatagramSize,
	))
}

func UseBrutal(conn quic.Connection, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx))
}
