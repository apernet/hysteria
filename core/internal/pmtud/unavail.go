//go:build !linux && !windows

package pmtud

// quic-go's MTU discovery is enabled by default across all platforms. However, our testing has found that on certain
// platforms (e.g. macOS) the DF bit is not set. As a result, probe packets that should never be fragmented are still
// fragmented and transmitted. So we have decided to enable MTU discovery only on Linux and Windows for now, as we have
// verified its functionality on these platforms.

const (
	DisablePathMTUDiscovery = true
)
