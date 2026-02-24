//go:build windows

package pppbridge

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetBestRoute2            = modiphlpapi.NewProc("GetBestRoute2")
	procCreateIpForwardEntry2    = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2    = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procInitializeIpForwardEntry = modiphlpapi.NewProc("InitializeIpForwardEntry")
	procGetIpForwardTable2       = modiphlpapi.NewProc("GetIpForwardTable2")
	procFreeMibTable             = modiphlpapi.NewProc("FreeMibTable")
)

const (
	afINET  = 2
	afINET6 = 23
)

// sockaddrInet matches SOCKADDR_INET (28 bytes).
// IPv4: family(2) + port(2) + addr(4) + zero(20) = 28
// IPv6: family(2) + port(2) + flowinfo(4) + addr(16) + scopeid(4) = 28
type sockaddrInet [28]byte

type ipAddressPrefix struct {
	Prefix       sockaddrInet
	PrefixLength uint8
	_pad         [3]byte
}

// mibIpforwardRow2 matches MIB_IPFORWARD_ROW2 (104 bytes on x64).
type mibIpforwardRow2 struct {
	InterfaceLuid        uint64
	InterfaceIndex       uint32
	DestinationPrefix    ipAddressPrefix
	NextHop              sockaddrInet
	SitePrefixLength     uint8
	_pad1                [3]byte
	ValidLifetime        uint32
	PreferredLifetime    uint32
	Metric               uint32
	Protocol             uint32
	Loopback             uint8
	AutoconfigureAddress uint8
	Publish              uint8
	Immortal             uint8
	Age                  uint32
	Origin               uint32
}

// mibIpforwardTable2Header is the fixed-size header of MIB_IPFORWARD_TABLE2.
// On x64 there are 4 bytes of padding after NumEntries to align Table[0]
// to the 8-byte boundary required by MIB_IPFORWARD_ROW2 (NET_LUID is uint64).
type mibIpforwardTable2Header struct {
	NumEntries uint32
	_pad       [4]byte
}

// Compile-time size assertions.
var _ [104]byte = [unsafe.Sizeof(mibIpforwardRow2{})]byte{}
var _ [8]byte = [unsafe.Sizeof(mibIpforwardTable2Header{})]byte{}

// ipToSockaddrInet converts a net.IP to the 28-byte SOCKADDR_INET layout.
// Normalizes IPv4-mapped IPv6 addresses to AF_INET.
func ipToSockaddrInet(ip net.IP) (sa sockaddrInet) {
	if ip4 := ip.To4(); ip4 != nil {
		binary.LittleEndian.PutUint16(sa[0:2], afINET)
		copy(sa[4:8], ip4)
	} else if len(ip) == net.IPv6len {
		binary.LittleEndian.PutUint16(sa[0:2], afINET6)
		copy(sa[8:24], ip)
	}
	return
}

func sockaddrFamily(sa *sockaddrInet) uint16 {
	return binary.LittleEndian.Uint16(sa[0:2])
}

func sockaddrIsZero(sa *sockaddrInet) bool {
	for _, b := range sa {
		if b != 0 {
			return false
		}
	}
	return true
}

func sockaddrIPString(sa *sockaddrInet) string {
	fam := sockaddrFamily(sa)
	switch fam {
	case afINET:
		return net.IP(sa[4:8]).String()
	case afINET6:
		return net.IP(sa[8:24]).String()
	}
	return "?"
}

func prefixString(p *ipAddressPrefix) string {
	return fmt.Sprintf("%s/%d", sockaddrIPString(&p.Prefix), p.PrefixLength)
}

type routeState struct {
	mu     sync.Mutex
	logger *zap.Logger

	// Snapshot (captured at dial time before VPN routes exist, read-only after)
	serverIP     string
	serverDest   sockaddrInet
	serverFamily uint16
	ifLuid       uint64
	ifIndex      uint32
	gateway sockaddrInet // gateway to reach server IP

	// Created routes (tracked for cleanup)
	serverRow   mibIpforwardRow2
	serverAdded bool
}

const errorObjectAlreadyExists = 5010

// captureRouteState snapshots the current routing information for the server IP
// while the original Wi-Fi routes still exist. No routes are created here;
// all route creation is deferred to ApplyRoutes (called after CALL_CONNECTED).
func captureRouteState(ipStr string, logger *zap.Logger) *routeState {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		logger.Warn("cannot parse server IP for route pin",
			zap.String("ip", ipStr))
		return nil
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		logger.Warn("server IP is loopback/unspecified, skipping route pin",
			zap.String("ip", ip.String()))
		return nil
	}

	destAddr := ipToSockaddrInet(ip)
	family := sockaddrFamily(&destAddr)
	if family == 0 {
		logger.Warn("unsupported address family for route pin",
			zap.String("ip", ip.String()))
		return nil
	}

	var bestRoute mibIpforwardRow2
	var bestSrc sockaddrInet

	r1, _, _ := procGetBestRoute2.Call(
		0, 0, 0,
		uintptr(unsafe.Pointer(&destAddr)),
		0,
		uintptr(unsafe.Pointer(&bestRoute)),
		uintptr(unsafe.Pointer(&bestSrc)),
	)
	if r1 != 0 {
		logger.Warn("failed to query best route for server",
			zap.String("serverIP", ip.String()),
			zap.Uintptr("error", r1))
		return nil
	}

	if sockaddrIsZero(&bestRoute.NextHop) {
		logger.Info("server is directly connected, skipping route pin",
			zap.String("serverIP", ip.String()))
		return nil
	}

	rs := &routeState{
		logger:       logger,
		serverIP:     ip.String(),
		serverDest:   destAddr,
		serverFamily: family,
		ifLuid:       bestRoute.InterfaceLuid,
		ifIndex:      bestRoute.InterfaceIndex,
		gateway:      bestRoute.NextHop,
	}

	logger.Info("captured route state for server",
		zap.String("serverIP", rs.serverIP),
		zap.String("gateway", sockaddrIPString(&rs.gateway)),
		zap.Uint32("ifIndex", rs.ifIndex))

	return rs
}

// ApplyRoutes creates the server host route on the physical interface.
// Must be called after SSTP CALL_CONNECTED.
func (s *routeState) ApplyRoutes() {
	time.Sleep(2 * time.Second)

	s.mu.Lock()
	defer s.mu.Unlock()

	logRouteTable(s.logger, afINET)
	if s.serverFamily == afINET6 {
		logRouteTable(s.logger, afINET6)
	}

	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&s.serverRow)))
	s.serverRow.InterfaceLuid = s.ifLuid
	s.serverRow.InterfaceIndex = s.ifIndex
	s.serverRow.DestinationPrefix.Prefix = s.serverDest
	if s.serverFamily == afINET {
		s.serverRow.DestinationPrefix.PrefixLength = 32
	} else {
		s.serverRow.DestinationPrefix.PrefixLength = 128
	}
	s.serverRow.NextHop = s.gateway
	s.serverRow.Metric = 5
	s.serverRow.Protocol = 3 // MIB_IPPROTO_NETMGMT

	r1, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&s.serverRow)))
	if r1 != 0 && r1 != errorObjectAlreadyExists {
		s.logger.Warn("failed to add server route",
			zap.String("serverIP", s.serverIP),
			zap.Uintptr("error", r1))
	} else {
		s.serverAdded = true
		s.logger.Info("added server route",
			zap.String("serverIP", s.serverIP),
			zap.String("gateway", sockaddrIPString(&s.gateway)),
			zap.Uint32("ifIndex", s.ifIndex))
	}

	logRouteTable(s.logger, afINET)
	if s.serverFamily == afINET6 {
		logRouteTable(s.logger, afINET6)
	}
}

// Cleanup removes the server host route.
func (s *routeState) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.serverAdded {
		r1, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(&s.serverRow)))
		if r1 != 0 {
			s.logger.Warn("failed to remove server route",
				zap.String("serverIP", s.serverIP),
				zap.Uintptr("error", r1))
		} else {
			s.logger.Info("removed server route",
				zap.String("serverIP", s.serverIP))
		}
	}
}

func logRouteTable(logger *zap.Logger, family uint16) {
	if ce := logger.Check(zap.DebugLevel, "routing table dump"); ce == nil {
		return
	}

	var tablePtr uintptr
	r1, _, _ := procGetIpForwardTable2.Call(
		uintptr(family),
		uintptr(unsafe.Pointer(&tablePtr)),
	)
	if r1 != 0 || tablePtr == 0 {
		logger.Debug("failed to get routing table", zap.Uintptr("error", r1))
		return
	}
	defer procFreeMibTable.Call(tablePtr)

	header := (*mibIpforwardTable2Header)(unsafe.Pointer(tablePtr)) //nolint:unsafeptr // tablePtr is C-heap memory from GetIpForwardTable2
	rowSize := unsafe.Sizeof(mibIpforwardRow2{})

	for i := uint32(0); i < header.NumEntries; i++ {
		row := (*mibIpforwardRow2)(unsafe.Add(unsafe.Pointer(tablePtr), int(unsafe.Sizeof(mibIpforwardTable2Header{}))+int(uintptr(i)*rowSize))) //nolint:unsafeptr // C-heap pointer arithmetic
		logger.Debug("route",
			zap.String("dst", prefixString(&row.DestinationPrefix)),
			zap.String("nextHop", sockaddrIPString(&row.NextHop)),
			zap.Uint32("ifIndex", row.InterfaceIndex),
			zap.Uint32("metric", row.Metric),
			zap.Uint32("protocol", row.Protocol))
	}
}
