//go:build linux

package pppbridge

import (
	"net"
	"syscall"

	"github.com/sagernet/netlink"
	"go.uber.org/zap"
)

type routeState struct {
	logger    *zap.Logger
	hostRoute *netlink.Route
	ipString  string
	gwStr     string
	family    int
	added     bool
}

// ApplyRoutes creates the server host route. Called after CALL_CONNECTED.
func (s *routeState) ApplyRoutes() {
	logRouteTable(s.logger, s.family)

	err := netlink.RouteAdd(s.hostRoute)
	if err != nil && err != syscall.EEXIST {
		s.logger.Warn("failed to add server route",
			zap.String("serverIP", s.ipString),
			zap.Error(err))
		return
	}
	s.added = true
	s.logger.Info("added server route",
		zap.String("serverIP", s.ipString),
		zap.String("gateway", s.gwStr),
		zap.Int("ifIndex", s.hostRoute.LinkIndex))

	logRouteTable(s.logger, s.family)
}

func (s *routeState) Cleanup() {
	if !s.added {
		return
	}
	err := netlink.RouteDel(s.hostRoute)
	if err != nil {
		s.logger.Warn("failed to remove server route",
			zap.String("serverIP", s.ipString),
			zap.Error(err))
	} else {
		s.logger.Info("removed server route",
			zap.String("serverIP", s.ipString))
	}
}

// captureRouteState snapshots the current routing information for the server IP.
// No routes are created here; route creation is deferred to ApplyRoutes.
func captureRouteState(ipStr string, logger *zap.Logger) *routeState {
	serverIP := net.ParseIP(ipStr)
	if serverIP == nil {
		logger.Warn("cannot parse server IP for route pin",
			zap.String("ip", ipStr))
		return nil
	}
	if serverIP.IsLoopback() || serverIP.IsUnspecified() {
		logger.Warn("server IP is loopback/unspecified, skipping route pin",
			zap.String("ip", serverIP.String()))
		return nil
	}
	if ip4 := serverIP.To4(); ip4 != nil {
		serverIP = ip4
	}

	routes, err := netlink.RouteGet(serverIP)
	if err != nil || len(routes) == 0 {
		logger.Warn("failed to query route for server",
			zap.String("serverIP", serverIP.String()),
			zap.Error(err))
		return nil
	}

	if routes[0].Gw == nil {
		logger.Debug("server is directly connected, skipping route pin",
			zap.String("serverIP", serverIP.String()))
		return nil
	}

	family := netlink.FAMILY_V4
	bits := 32
	if serverIP.To4() == nil {
		family = netlink.FAMILY_V6
		bits = 128
	}

	rs := &routeState{
		logger: logger,
		hostRoute: &netlink.Route{
			Dst:       &net.IPNet{IP: serverIP, Mask: net.CIDRMask(bits, bits)},
			Gw:        routes[0].Gw,
			LinkIndex: routes[0].LinkIndex,
		},
		ipString: serverIP.String(),
		gwStr:    routes[0].Gw.String(),
		family:   family,
	}

	logger.Info("captured route state for server",
		zap.String("serverIP", rs.ipString),
		zap.String("gateway", rs.gwStr),
		zap.Int("ifIndex", routes[0].LinkIndex))

	return rs
}

func logRouteTable(logger *zap.Logger, family int) {
	if ce := logger.Check(zap.DebugLevel, "routing table dump"); ce == nil {
		return
	}

	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		logger.Debug("failed to list routes", zap.Error(err))
		return
	}
	for _, r := range routes {
		dst := "<default>"
		if r.Dst != nil {
			dst = r.Dst.String()
		}
		gw := "<none>"
		if r.Gw != nil {
			gw = r.Gw.String()
		}
		logger.Debug("route",
			zap.String("dst", dst),
			zap.String("gw", gw),
			zap.Int("ifIndex", r.LinkIndex),
			zap.Int("priority", r.Priority))
	}
}
