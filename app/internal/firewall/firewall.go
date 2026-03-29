package firewall

import (
	"fmt"
	"net"
	"strings"

	eUtils "github.com/apernet/hysteria/extras/v2/utils"
)

type commandRunner interface {
	LookPath(file string) (string, error)
	Run(name string, args ...string) error
}

func redirectPortUnion(ports eUtils.PortUnion) eUtils.PortUnion {
	if len(ports) == 0 {
		return nil
	}
	redirects := append(eUtils.PortUnion(nil), ports...)
	if redirects[0].Start == redirects[0].End {
		redirects = redirects[1:]
	} else {
		redirects[0].Start++
	}
	return redirects
}

func hashInput(addr *net.UDPAddr, ports eUtils.PortUnion) string {
	return fmt.Sprintf("%s|%d|%s", addr.IP.String(), addr.Port, formatPortUnion(ports))
}

func formatPortUnion(ports eUtils.PortUnion) string {
	var parts []string
	for _, portRange := range ports {
		if portRange.Start == portRange.End {
			parts = append(parts, fmt.Sprintf("%d", portRange.Start))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", portRange.Start, portRange.End))
		}
	}
	return strings.Join(parts, ",")
}
