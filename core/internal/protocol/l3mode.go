package protocol

import (
	"strings"

	"github.com/apernet/hysteria/core/v2/errors"
)

const (
	DefaultL3Lanes = 8
	MaxL3Lanes     = 64
)

// NormalizeL3Mode returns datagram when mode is empty.
func NormalizeL3Mode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", L3ModeDatagram:
		return L3ModeDatagram, nil
	case L3ModeStream:
		return L3ModeStream, nil
	default:
		return "", errors.ProtocolError{Message: "invalid l3 mode"}
	}
}

// NormalizeL3Lanes turns an omitted count into the default and caps the rest.
func NormalizeL3Lanes(n int) int {
	if n <= 0 {
		return DefaultL3Lanes
	}
	if n > MaxL3Lanes {
		return MaxL3Lanes
	}
	return n
}
