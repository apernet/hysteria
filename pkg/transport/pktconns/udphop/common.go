package udphop

import (
	"net"
	"strconv"
	"strings"
)

const (
	packetQueueSize = 1024
	udpBufferSize   = 2048
)

// parseAddr parses the listen address and returns the host and ports.
// Format: "host:port1,port2,port3,..."
func parseAddr(addr string) (host string, ports []uint16, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	portsStr := strings.Split(portStr, ",")
	if len(portsStr) < 2 {
		return "", nil, net.InvalidAddrError("at least two ports required")
	}
	ports = make([]uint16, len(portsStr))
	for i, p := range portsStr {
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return "", nil, net.InvalidAddrError("invalid port: " + p)
		}
		ports[i] = uint16(port)
	}
	return
}

type udpHopAddr struct {
	listen string
}

func (a *udpHopAddr) Network() string {
	return "udp-hop"
}

func (a *udpHopAddr) String() string {
	return a.listen
}

type udpPacket struct {
	buf  []byte
	n    int
	addr net.Addr
}
