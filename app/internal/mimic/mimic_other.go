//go:build !linux

package mimic

import (
	"errors"
	"net"

	"go.uber.org/zap"
)

type Instance struct{}

func (i *Instance) Close() error { return nil }

func Start(cfg Config, _ Role, _ []*net.UDPAddr, _ *zap.Logger, _ func(error)) (*Instance, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	return nil, errors.New("mimic is only supported on Linux")
}
