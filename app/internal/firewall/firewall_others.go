//go:build !linux

package firewall

import (
	"errors"
	"io"
	"net"

	eUtils "github.com/apernet/hysteria/extras/v2/utils"
)

func SetupUDPPortRedirect(listenAddr *net.UDPAddr, ports eUtils.PortUnion) (io.Closer, error) {
	return nil, errors.New("server port-range listening is only supported on Linux")
}
