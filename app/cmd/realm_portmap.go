package cmd

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/apernet/hysteria/extras/v2/realm"
)

type realmPortMappingConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Timeout  time.Duration `mapstructure:"timeout"`
	Lifetime time.Duration `mapstructure:"lifetime"`
}

// newRealmPortMapper maps localPort on the gateway via UPnP/NAT-PMP.
// Failures are non-fatal by design: it logs a warning and returns nil,
// in which case the realm flow continues with STUN-discovered addresses only.
func newRealmPortMapper(ctx context.Context, realmID string, localPort int, config realmPortMappingConfig) *realm.PortMapper {
	logger.Debug("realm port mapping started",
		zap.String("realm", realmID),
		zap.Int("port", localPort))
	start := time.Now()
	mapper, err := realm.NewPortMapper(ctx, localPort, realm.PortMapConfig{
		Timeout:  config.Timeout,
		Lifetime: config.Lifetime,
	})
	if err != nil {
		logger.Warn("realm port mapping failed; continuing without it",
			zap.String("realm", realmID),
			zap.Error(err))
		return nil
	}
	logger.Debug("realm port mapping added",
		zap.String("realm", realmID),
		zap.String("gateway", mapper.GatewayType()),
		zap.Int("port", localPort),
		zap.String("external", mapper.ExternalAddr().String()),
		zap.String("duration", formatLogDuration(time.Since(start))))
	return mapper
}

// realmPortMapLoop renews the mapping at half its lease lifetime until ctx is
// cancelled, then removes it from the gateway.
func realmPortMapLoop(ctx context.Context, realmID string, mapper *realm.PortMapper) {
	defer func() {
		if err := mapper.Close(); err != nil {
			logger.Debug("realm port mapping removal failed",
				zap.String("realm", realmID),
				zap.Error(err))
		} else {
			logger.Debug("realm port mapping removed", zap.String("realm", realmID))
		}
	}()
	interval := mapper.Lifetime() / 2
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changed, err := mapper.Renew(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// Warn only on the first failure
				if !failing {
					logger.Warn("realm port mapping renewal failed",
						zap.String("realm", realmID),
						zap.Error(err))
					failing = true
				}
				continue
			}
			if failing {
				logger.Info("realm port mapping recovered",
					zap.String("realm", realmID),
					zap.String("external", mapper.ExternalAddr().String()))
				failing = false
			}
			logger.Debug("realm port mapping renewed",
				zap.String("realm", realmID),
				zap.String("external", mapper.ExternalAddr().String()),
				zap.Bool("changed", changed))
		}
	}
}

type cleanupPacketConn struct {
	net.PacketConn
	cleanup func()
}

func (c *cleanupPacketConn) Close() error {
	c.cleanup()
	return c.PacketConn.Close()
}

func mergeMappedAddr(addrs []netip.AddrPort, addr netip.AddrPort) []netip.AddrPort {
	if !addr.IsValid() {
		return addrs
	}
	out := append([]netip.AddrPort(nil), addrs...)
	i, found := slices.BinarySearchFunc(out, addr, func(a, b netip.AddrPort) int {
		return strings.Compare(a.String(), b.String())
	})
	if found {
		return out
	}
	return slices.Insert(out, i, addr)
}
