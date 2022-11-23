//go:build linux || windows
// +build linux windows

package pmtud

// quic-go's MTU discovery is by default enabled on all platforms. However, we found that it
// does not set DF bit correctly on some platforms (macOS for example), which causes the probe
// packets (which should never be fragmented) to be fragmented and sent anyway. So here in
// Hysteria we only enable it on Linux and Windows for now, where we have tested it and can
// confirm that it works correctly.

const (
	DisablePathMTUDiscovery = false
)
