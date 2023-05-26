package utils

import (
	"errors"
	"strconv"
	"strings"
)

const (
	Byte = 1.0 << (10 * iota)
	Kilobyte
	Megabyte
	Gigabyte
	Terabyte
)

// StringToBps converts a string to a bandwidth value in bytes per second.
// E.g. "100 Mbps", "512 kbps", "1g" are all valid.
func StringToBps(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	spl := 0
	for i, c := range s {
		if c < '0' || c > '9' {
			spl = i
			break
		}
	}
	if spl == 0 {
		// No unit or no value
		return 0, errors.New("invalid format")
	}
	v, err := strconv.ParseUint(s[:spl], 10, 64)
	if err != nil {
		return 0, err
	}
	unit := strings.TrimSpace(s[spl:])

	switch strings.ToLower(unit) {
	case "b", "bps":
		return v * Byte / 8, nil
	case "k", "kb", "kbps":
		return v * Kilobyte / 8, nil
	case "m", "mb", "mbps":
		return v * Megabyte / 8, nil
	case "g", "gb", "gbps":
		return v * Gigabyte / 8, nil
	case "t", "tb", "tbps":
		return v * Terabyte / 8, nil
	default:
		return 0, errors.New("unsupported unit")
	}
}
