package outbounds

import (
	"errors"
	"net"
	"os"
	"strings"

	"github.com/apernet/hysteria/extras/v2/outbounds/acl"
)

const (
	aclCacheSize = 1024
)

var errRejected = errors.New("rejected")

// aclEngine is a PluggableOutbound that dispatches connections to different
// outbounds based on ACL rules.
// There are 3 built-in outbounds:
// - direct: directOutbound, auto mode
// - reject: reject the connection
// - default: first outbound in the list, or if the list is empty, equal to direct
// If the user-defined outbounds contain any of the above names, they will
// override the built-in outbounds.
type aclEngine struct {
	RuleSet acl.CompiledRuleSet[PluggableOutbound]
	Default PluggableOutbound
}

type OutboundEntry struct {
	Name     string
	Outbound PluggableOutbound
}

func NewACLEngineFromString(rules string, outbounds []OutboundEntry, geoLoader acl.GeoLoader) (PluggableOutbound, error) {
	trs, err := acl.ParseTextRules(rules)
	if err != nil {
		return nil, err
	}
	obMap := outboundsToMap(outbounds)
	rs, err := acl.Compile[PluggableOutbound](trs, obMap, aclCacheSize, geoLoader)
	if err != nil {
		return nil, err
	}
	return &aclEngine{rs, obMap["default"]}, nil
}

func NewACLEngineFromFile(filename string, outbounds []OutboundEntry, geoLoader acl.GeoLoader) (PluggableOutbound, error) {
	bs, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return NewACLEngineFromString(string(bs), outbounds, geoLoader)
}

func outboundsToMap(outbounds []OutboundEntry) map[string]PluggableOutbound {
	obMap := make(map[string]PluggableOutbound)
	for _, ob := range outbounds {
		obMap[strings.ToLower(ob.Name)] = ob.Outbound
	}
	// Add built-in outbounds if not overridden
	if _, ok := obMap["direct"]; !ok {
		obMap["direct"] = NewDirectOutboundSimple(DirectOutboundModeAuto)
	}
	if _, ok := obMap["reject"]; !ok {
		obMap["reject"] = &aclRejectOutbound{}
	}
	if _, ok := obMap["default"]; !ok {
		if len(outbounds) > 0 {
			obMap["default"] = outbounds[0].Outbound
		} else {
			obMap["default"] = obMap["direct"]
		}
	}
	return obMap
}

func (a *aclEngine) handle(reqAddr *AddrEx, proto acl.Protocol) PluggableOutbound {
	hostInfo := acl.HostInfo{Name: reqAddr.Host}
	if reqAddr.ResolveInfo != nil {
		hostInfo.IPv4 = reqAddr.ResolveInfo.IPv4
		hostInfo.IPv6 = reqAddr.ResolveInfo.IPv6
	}
	ob, hijackIP := a.RuleSet.Match(hostInfo, proto, reqAddr.Port)
	if ob == nil {
		// No match, use default outbound
		return a.Default
	}
	if hijackIP != nil {
		// We must rewrite both Host & ResolveInfo,
		// as some outbounds only care about Host.
		reqAddr.Host = hijackIP.String()
		if ip4 := hijackIP.To4(); ip4 != nil {
			reqAddr.ResolveInfo = &ResolveInfo{IPv4: ip4}
		} else {
			reqAddr.ResolveInfo = &ResolveInfo{IPv6: hijackIP}
		}
	}
	return ob
}

func (a *aclEngine) TCP(reqAddr *AddrEx) (net.Conn, error) {
	ob := a.handle(reqAddr, acl.ProtocolTCP)
	return ob.TCP(reqAddr)
}

func (a *aclEngine) UDP(reqAddr *AddrEx) (UDPConn, error) {
	ob := a.handle(reqAddr, acl.ProtocolUDP)
	return ob.UDP(reqAddr)
}

type aclRejectOutbound struct{}

func (a *aclRejectOutbound) TCP(reqAddr *AddrEx) (net.Conn, error) {
	return nil, errRejected
}

func (a *aclRejectOutbound) UDP(reqAddr *AddrEx) (UDPConn, error) {
	return nil, errRejected
}
