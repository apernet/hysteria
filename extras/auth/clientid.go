package auth

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
)

var (
	clientIDOnce sync.Once
	clientID     string
)

// GetClientID returns a unique client ID based on hardware information.
// The ID is generated once and cached for subsequent calls.
func GetClientID() string {
	clientIDOnce.Do(func() {
		clientID = generateClientID()
	})
	return clientID
}

// generateClientID creates a unique client ID based on available hardware information
func generateClientID() string {
	var identifiers []string

	// Get MAC addresses from all network interfaces
	if interfaces, err := net.Interfaces(); err == nil {
		var macAddresses []string
		for _, iface := range interfaces {
			// Skip loopback and down interfaces
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}
			if len(iface.HardwareAddr) > 0 {
				macAddresses = append(macAddresses, iface.HardwareAddr.String())
			}
		}
		// Sort MAC addresses for consistency
		sort.Strings(macAddresses)
		if len(macAddresses) > 0 {
			identifiers = append(identifiers, strings.Join(macAddresses, ","))
		}
	}

	// Add hostname
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		identifiers = append(identifiers, hostname)
	}

	// Add OS and architecture information
	identifiers = append(identifiers, runtime.GOOS)
	identifiers = append(identifiers, runtime.GOARCH)

	// Combine all identifiers
	combined := strings.Join(identifiers, "|")

	// Generate a hash of the combined identifiers
	hash := sha256.Sum256([]byte(combined))

	// Use first 16 bytes for a shorter ID
	shortHash := md5.Sum(hash[:16])

	return hex.EncodeToString(shortHash[:])
}
