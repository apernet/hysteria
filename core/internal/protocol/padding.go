package protocol

import (
	"math/rand"
	"strings"
)

// padding specifies a half-open range [Min, Max).
type padding struct {
	Min int
	Max int
}

func (p padding) String() string {
	n := p.Min + rand.Intn(p.Max-p.Min)
	return strings.Repeat("a", n) // No need to randomize since everything is encrypted anyway
}

var (
	authRequestPadding  = padding{Min: 256, Max: 2048}
	authResponsePadding = padding{Min: 256, Max: 2048}
	tcpRequestPadding   = padding{Min: 64, Max: 512}
	tcpResponsePadding  = padding{Min: 128, Max: 1024}
	udpRequestPadding   = padding{Min: 64, Max: 512}
	udpResponsePadding  = padding{Min: 128, Max: 1024}
)
