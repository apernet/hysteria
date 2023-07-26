package outbounds

import (
	"errors"
	"net"
	"strconv"
	"time"
)

type DirectOutboundMode int

const (
	DirectOutboundModeAuto DirectOutboundMode = iota // Dual-stack "happy eyeballs"-like mode
	DirectOutboundMode64                             // Use IPv6 address when available, otherwise IPv4
	DirectOutboundMode46                             // Use IPv4 address when available, otherwise IPv6
	DirectOutboundMode6                              // Use IPv6 only, fail if not available
	DirectOutboundMode4                              // Use IPv4 only, fail if not available

	defaultDialerTimeout = 10 * time.Second
)

// directOutbound is a PluggableOutbound that connects directly to the target
// using the local network (as opposed to using a proxy, for example).
// It prefers to use ResolveInfo in AddrEx if available. But if it's nil,
// it will fall back to resolving Host using Go's built-in DNS resolver.
type directOutbound struct {
	Mode       DirectOutboundMode
	Dialer     *net.Dialer
	DeviceName string // For UDP binding
}

/*
// NewDirectOutboundSimple creates a new directOutbound with the given mode,
// without binding to a specific device. Works on all platforms.
func NewDirectOutboundSimple(mode DirectOutboundMode) PluggableOutbound {
	return &directOutbound{
		Mode: mode,
		Dialer: &net.Dialer{
			Timeout: defaultDialerTimeout,
		},
	}
}
*/

// resolve is our built-in DNS resolver for handling the case when
// AddrEx.ResolveInfo is nil.
func (d *directOutbound) resolve(reqAddr *AddrEx) {
	ips, err := net.LookupIP(reqAddr.Host)
	if err != nil {
		reqAddr.ResolveInfo = &ResolveInfo{Err: err}
		return
	}
	r := &ResolveInfo{}
	for _, ip := range ips {
		if r.IPv4 == nil && ip.To4() != nil {
			r.IPv4 = ip
		}
		if r.IPv6 == nil && ip.To4() == nil {
			// We must NOT use ip.To16() here because it will always
			// return a 16-byte slice, even if the original IP is IPv4.
			r.IPv6 = ip
		}
		if r.IPv4 != nil && r.IPv6 != nil {
			break
		}
	}
	reqAddr.ResolveInfo = r
}

func (d *directOutbound) DialTCP(reqAddr *AddrEx) (net.Conn, error) {
	if reqAddr.ResolveInfo == nil {
		// AddrEx.ResolveInfo is nil (no resolver in the pipeline),
		// we need to resolve the address ourselves.
		d.resolve(reqAddr)
	}
	r := reqAddr.ResolveInfo
	if r.IPv4 == nil && r.IPv6 == nil {
		// ResolveInfo not nil but no address available,
		// this can only mean that the resolver failed.
		// Return the error from the resolver.
		return nil, r.Err
	}
	switch d.Mode {
	case DirectOutboundModeAuto:
		if r.IPv4 != nil && r.IPv6 != nil {
			return d.dualStackDialTCP(r.IPv4, r.IPv6, reqAddr.Port)
		} else if r.IPv4 != nil {
			return d.dialTCP(r.IPv4, reqAddr.Port)
		} else {
			return d.dialTCP(r.IPv6, reqAddr.Port)
		}
	case DirectOutboundMode64:
		if r.IPv6 != nil {
			return d.dialTCP(r.IPv6, reqAddr.Port)
		} else {
			return d.dialTCP(r.IPv4, reqAddr.Port)
		}
	case DirectOutboundMode46:
		if r.IPv4 != nil {
			return d.dialTCP(r.IPv4, reqAddr.Port)
		} else {
			return d.dialTCP(r.IPv6, reqAddr.Port)
		}
	case DirectOutboundMode6:
		if r.IPv6 != nil {
			return d.dialTCP(r.IPv6, reqAddr.Port)
		} else {
			return nil, errors.New("no IPv6 address available")
		}
	case DirectOutboundMode4:
		if r.IPv4 != nil {
			return d.dialTCP(r.IPv4, reqAddr.Port)
		} else {
			return nil, errors.New("no IPv4 address available")
		}
	default:
		return nil, errors.New("invalid DirectOutboundMode")
	}
}

func (d *directOutbound) dialTCP(ip net.IP, port uint16) (net.Conn, error) {
	return d.Dialer.Dial("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
}

type dialResult struct {
	Conn net.Conn
	Err  error
}

// dualStackDialTCP dials the target using both IPv4 and IPv6 addresses simultaneously.
// It returns the first successful connection and drops the other one.
// If both connections fail, it returns the last error.
func (d *directOutbound) dualStackDialTCP(ipv4, ipv6 net.IP, port uint16) (net.Conn, error) {
	ch := make(chan dialResult, 2)
	go func() {
		conn, err := d.dialTCP(ipv4, port)
		ch <- dialResult{Conn: conn, Err: err}
	}()
	go func() {
		conn, err := d.dialTCP(ipv6, port)
		ch <- dialResult{Conn: conn, Err: err}
	}()
	// Get the first result, check if it's successful
	if r := <-ch; r.Err == nil {
		// Yes. Return this and close the other connection when it's done
		go func() {
			r2 := <-ch
			if r2.Conn != nil {
				_ = r2.Conn.Close()
			}
		}()
		return r.Conn, nil
	} else {
		// No. Return the other result, which may or may not be successful
		r2 := <-ch
		return r2.Conn, r2.Err
	}
}

type directOutboundUDPConn struct {
	*directOutbound
	*net.UDPConn
}

func (u *directOutboundUDPConn) ReadFrom(b []byte) (int, *AddrEx, error) {
	n, addr, err := u.UDPConn.ReadFromUDP(b)
	if addr != nil {
		return n, &AddrEx{
			Host: addr.IP.String(),
			Port: uint16(addr.Port),
		}, err
	} else {
		return n, nil, err
	}
}

func (u *directOutboundUDPConn) WriteTo(b []byte, addr *AddrEx) (int, error) {
	if addr.ResolveInfo == nil {
		// Although practically rare, it is possible to send
		// UDP packets to a hostname (instead of an IP address).
		u.directOutbound.resolve(addr)
	}
	r := addr.ResolveInfo
	if r.IPv4 == nil && r.IPv6 == nil {
		return 0, r.Err
	}
	switch u.directOutbound.Mode {
	case DirectOutboundModeAuto:
		// This is a special case.
		// It's not possible to do a "dual stack race dial" for UDP,
		// since UDP is connectionless.
		// For maximum compatibility, we just behave like DirectOutboundMode46.
		if r.IPv4 != nil {
			return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
				IP:   r.IPv4,
				Port: int(addr.Port),
			})
		} else {
			return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
				IP:   r.IPv6,
				Port: int(addr.Port),
			})
		}
	case DirectOutboundMode64:
		if r.IPv6 != nil {
			return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
				IP:   r.IPv6,
				Port: int(addr.Port),
			})
		} else {
			return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
				IP:   r.IPv4,
				Port: int(addr.Port),
			})
		}
	case DirectOutboundMode46:
		if r.IPv4 != nil {
			return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
				IP:   r.IPv4,
				Port: int(addr.Port),
			})
		} else {
			return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
				IP:   r.IPv6,
				Port: int(addr.Port),
			})
		}
	case DirectOutboundMode6:
		if r.IPv6 != nil {
			return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
				IP:   r.IPv6,
				Port: int(addr.Port),
			})
		} else {
			return 0, errors.New("no IPv6 address available")
		}
	case DirectOutboundMode4:
		if r.IPv4 != nil {
			return u.UDPConn.WriteToUDP(b, &net.UDPAddr{
				IP:   r.IPv4,
				Port: int(addr.Port),
			})
		} else {
			return 0, errors.New("no IPv4 address available")
		}
	default:
		return 0, errors.New("invalid DirectOutboundMode")
	}
}

func (u *directOutboundUDPConn) Close() error {
	return u.UDPConn.Close()
}

func (d *directOutbound) ListenUDP() (UDPConn, error) {
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	if d.DeviceName != "" {
		if err := udpConnBindToDevice(c, d.DeviceName); err != nil {
			// Don't forget to close the UDPConn if binding fails
			_ = c.Close()
			return nil, err
		}
	}
	return &directOutboundUDPConn{
		directOutbound: d,
		UDPConn:        c,
	}, nil
}
