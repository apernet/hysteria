package pppbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"go.uber.org/zap"
)

// ServerPPPHandler implements server.PPPRequestHandler.
// It manages pppd sessions with IP allocation and proper lifecycle logging.
type ServerPPPHandler struct {
	PPPDPath   string
	PPPDArgs   []string // Extra args appended to auto-generated ones
	Sudo       bool
	IPv4Pool   *IPPool
	DNS        []string
	MTU        int
	Salamander bool
	Logger     *zap.Logger
}

func (h *ServerPPPHandler) HandlePPP(control io.ReadWriteCloser, dataStreams int, createDataIO func() (ppp.PPPDataIO, error), addr net.Addr, id string) {
	defer control.Close()

	var clientIP, gatewayIP string
	if h.IPv4Pool != nil {
		var err error
		clientIP, err = h.IPv4Pool.Allocate()
		if err != nil {
			h.Logger.Error("PPP request rejected",
				zap.String("addr", addr.String()),
				zap.String("reason", "pool exhausted"))
			_ = writePPPResponse(control, false, "IP pool exhausted", dataStreams)
			return
		}
		defer func() {
			h.IPv4Pool.Release(clientIP)
			h.Logger.Debug("PPP IPv4 released", zap.String("clientIP", clientIP))
		}()
		gatewayIP = h.IPv4Pool.Gateway()
		h.Logger.Debug("PPP IPv4 allocated",
			zap.String("addr", addr.String()),
			zap.String("id", id),
			zap.String("clientIP", clientIP),
			zap.String("gatewayIP", gatewayIP))
	} else {
		h.Logger.Debug("PPP IPv6-only (no IPv4 pool)",
			zap.String("addr", addr.String()),
			zap.String("id", id))
	}

	if err := writePPPResponse(control, true, "OK", dataStreams); err != nil {
		h.Logger.Error("PPP request rejected",
			zap.String("addr", addr.String()),
			zap.String("reason", "failed to write response: "+err.Error()))
		return
	}

	dataIO, err := createDataIO()
	if err != nil {
		h.Logger.Error("PPP data transport setup failed",
			zap.String("addr", addr.String()),
			zap.String("id", id),
			zap.Error(err))
		return
	}
	defer dataIO.Close()

	pppdArgs, mtu := h.buildPPPDArgs(gatewayIP, clientIP, id, addr, dataStreams)
	h.Logger.Debug("PPP spawning pppd",
		zap.String("addr", addr.String()),
		zap.String("id", id),
		zap.String("pppdPath", h.PPPDPath),
		zap.Strings("pppdArgs", pppdArgs),
		zap.Int("dataStreams", dataStreams))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var dialCalled atomic.Bool
	dialFn := func() (io.ReadWriteCloser, ppp.PPPDataIO, func(), error) {
		if !dialCalled.CompareAndSwap(false, true) {
			return nil, nil, nil, permanentDialError{errors.New("one-shot")}
		}
		return control, dataIO, func() { cancel() }, nil
	}

	start := time.Now()
	bridge := &Bridge{
		PPPDPath: h.PPPDPath,
		PPPDArgs: pppdArgs,
		Sudo:     h.Sudo,
		Logger:   h.Logger,
	}

	logFields := []zap.Field{
		zap.String("addr", addr.String()),
		zap.String("id", id),
		zap.Int("dataStreams", dataStreams),
	}
	if clientIP != "" {
		logFields = append(logFields, zap.String("clientIP", clientIP))
	} else {
		logFields = append(logFields, zap.String("mode", "IPv6-only"))
	}
	if mtu > 0 {
		logFields = append(logFields, zap.Int("mtu", mtu))
	}
	h.Logger.Info("PPP session started", logFields...)

	runErr := bridge.Run(ctx, dialFn)

	duration := time.Since(start)
	if runErr != nil {
		h.Logger.Error("PPP pppd exited with error",
			zap.String("addr", addr.String()),
			zap.String("id", id),
			zap.Error(runErr))
	}
	h.Logger.Info("PPP session ended",
		zap.String("addr", addr.String()),
		zap.String("id", id),
		zap.Duration("duration", duration))
}

func (h *ServerPPPHandler) buildPPPDArgs(gatewayIP, clientIP, remoteName string, addr net.Addr, dataStreams int) ([]string, int) {
	var args []string
	var computedMTU int
	if len(h.PPPDArgs) > 0 {
		args = append(args, h.PPPDArgs...)
	} else {
		args = []string{"nodetach", "local", "+ipv6", "require-pap", "multilink", "mpshortseq", "lcp-echo-interval", "0"}
		if gatewayIP != "" {
			args = append(args, fmt.Sprintf("%s:%s", gatewayIP, clientIP))
		}
		for _, dns := range h.DNS {
			args = append(args, "ms-dns", dns)
		}
		mtu := h.MTU
		if mtu == 0 {
			mtu = AutoPPPMTU(MTUParams{
				RemoteAddr:  addr,
				Salamander:  h.Salamander,
				DataStreams: dataStreams,
				Multilink:   true,
			})
		}
		computedMTU = mtu
		mtuStr := fmt.Sprintf("%d", mtu)
		args = append(args, "mtu", mtuStr, "mru", mtuStr)
	}
	if remoteName != "" {
		args = append(args, "remotename", remoteName)
	}
	return args, computedMTU
}
