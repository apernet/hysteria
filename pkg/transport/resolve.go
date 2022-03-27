package transport

import (
	"errors"
	"fmt"
	"net"
)

var (
	errNoIPv4Addr = errors.New("no IPv4 address")
	errNoIPv6Addr = errors.New("no IPv6 address")
)

func resolveIPAddrWithPreference(address string, preferIPv6 bool, exclusive bool) (*net.IPAddr, error) {
	ips, err := net.LookupIP(address)
	if err != nil {
		return nil, err
	}
	if preferIPv6 {
		for _, ip := range ips {
			if ip.To4() == nil {
				return &net.IPAddr{IP: ip}, nil
			}
		}
		if exclusive {
			return nil, errNoIPv6Addr
		} else {
			return &net.IPAddr{IP: ips[0]}, nil
		}
	} else {
		// prefer IPv4
		for _, ip := range ips {
			if ip.To4() != nil {
				return &net.IPAddr{IP: ip}, nil
			}
		}
		if exclusive {
			return nil, errNoIPv4Addr
		} else {
			return &net.IPAddr{IP: ips[0]}, nil
		}
	}
}

func ResolvePreferenceFromString(preference string) (bool, bool, error) {
	switch preference {
	case "4":
		return false, true, nil
	case "6":
		return true, true, nil
	case "46":
		return false, false, nil
	case "64":
		return true, false, nil
	default:
		return false, false, fmt.Errorf("%s is not a valid preference", preference)
	}
}
