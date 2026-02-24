//go:build !windows && !linux

package pppbridge

import (
	"go.uber.org/zap"
)

type routeState struct{}

func (s *routeState) ApplyRoutes() {}
func (s *routeState) Cleanup()     {}

func captureRouteState(ipStr string, logger *zap.Logger) *routeState {
	logger.Warn("automatic server route pinning is not supported on this platform")
	return nil
}
