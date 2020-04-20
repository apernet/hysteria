package core

import (
	"encoding/binary"
	"github.com/lucas-clemente/quic-go/congestion"
	"time"
)

const controlStreamTimeout = 10 * time.Second

var controlProtocolEndian = binary.BigEndian

type CongestionFactory func(refBPS uint64) congestion.SendAlgorithmWithDebugInfos
