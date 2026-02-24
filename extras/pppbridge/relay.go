package pppbridge

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/ppp"
	"go.uber.org/zap"
)

const hexHeadMax = 64

// hexHead renders the head of a frame for debug logging, appending a total when
// it truncates. Frames are only ever logged, never inspected.
func hexHead(b []byte) string {
	if len(b) <= hexHeadMax {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%s...(%d total)", hex.EncodeToString(b[:hexHeadMax]), len(b))
}

// relayError says which side of the relay failed. The distinction matters to the
// caller: a dead endpoint means the PPP daemon went away and the whole thing
// should be rebuilt quietly, while a dead transport means the link dropped and
// there may be a reason worth reporting.
type relayError struct {
	fromEndpoint bool
	err          error
}

func (e *relayError) Error() string { return e.err.Error() }
func (e *relayError) Unwrap() error { return e.err }

// relay pumps raw PPP frames between the Hysteria2 transport and an Endpoint.
//
// Both server modes and the client bridge use this: the local mode's Endpoint is
// a pppd over a pty, the LAC's is an L2TP session to an LNS, and the client's is
// its own pppd. Everything that is not "which endpoint" lives here exactly once
// -- the MTU probe protocol, oversize accounting, and the rule that a frame which
// does not fit is a dropped packet while a dead transport ends the session.
type relay struct {
	data ppp.PPPDataIO
	ep   Endpoint

	Logger *zap.Logger

	// ProbeInterval, ProbeGrace and ProbeFailures override the MTU probe
	// schedule; zero selects the package defaults.
	ProbeInterval time.Duration
	ProbeGrace    time.Duration
	ProbeFailures int

	// MTUFixed suppresses the teardown when the probe stops getting answers.
	//
	// Tearing down is only useful if the rebuild can come back smaller, and that
	// needs this process to be the one choosing the MTU. In nospawn mode it is
	// not: pppd is the parent and its MRU came from its own configuration, so a
	// rebuilt session negotiates the identical value and the teardown buys
	// nothing -- while costing a full interface rebuild, which under a multilink
	// bundle takes every other link with it.
	//
	// Not because the probe would fail again. The probe is sized from the
	// transport's live datagram budget, not from the configured MRU, and a fresh
	// QUIC connection restarts path discovery and re-converges on the narrower
	// path -- so its probes would be answered. The point is that pppd would still
	// be framing to the old number. Frames that no longer fit land in the
	// non-fatal oversize branch above, which is where they belong: the operator
	// set the number and owns the consequence, and what is owed them is a clear
	// statement of it rather than a link that will not stay up.
	MTUFixed bool

	// oversizeDropped counts frames the transport refused for being too large.
	// Non-zero means the negotiated PPP MTU exceeds what the path carries, which
	// is otherwise invisible.
	oversizeDropped *atomic.Uint64

	lastProbeSeq atomic.Uint32
	done         chan struct{}
}

func newRelay(data ppp.PPPDataIO, ep Endpoint, logger *zap.Logger, dropped *atomic.Uint64) *relay {
	if dropped == nil {
		dropped = new(atomic.Uint64)
	}
	return &relay{
		data:            data,
		ep:              ep,
		Logger:          logger,
		oversizeDropped: dropped,
		done:            make(chan struct{}),
	}
}

func (r *relay) noteProbeReply(seq uint32) {
	for {
		cur := r.lastProbeSeq.Load()
		if seq <= cur || r.lastProbeSeq.CompareAndSwap(cur, seq) {
			return
		}
	}
}

// run pumps in both directions until one side fails, and returns that error.
// A frame refused for being too large never ends the relay.
func (r *relay) run(ctx context.Context) error {
	errCh := make(chan error, 3)
	defer close(r.done)

	// Transport -> endpoint. MTU probes terminate here rather than reaching the
	// endpoint, which neither pppd nor an LNS would know what to do with.
	go func() {
		for {
			frame, err := r.data.ReceiveData()
			if err != nil {
				errCh <- &relayError{err: err}
				return
			}
			if kind, seq, ok := parseMTUProbe(frame); ok {
				switch kind {
				case mtuProbeRequest:
					// The reply is small on purpose: what is being established is
					// that the large one arrived.
					if serr := r.data.SendData(buildMTUProbe(mtuProbeReply, seq, mtuProbeHeaderLen)); serr != nil &&
						!ppp.IsFrameTooLarge(serr) {
						errCh <- &relayError{err: serr}
						return
					}
				case mtuProbeReply:
					r.noteProbeReply(seq)
				}
				continue
			}
			if ce := r.Logger.Check(zap.DebugLevel, "relay: transport -> endpoint"); ce != nil {
				ce.Write(zap.Int("bytes", len(frame)), zap.String("hex", hexHead(frame)))
			}
			if err := r.ep.SendPPP(frame); err != nil {
				errCh <- &relayError{fromEndpoint: true, err: err}
				return
			}
		}
	}()

	// Endpoint -> transport.
	go func() {
		var oversize uint64
		for {
			frame, err := r.ep.RecvPPP()
			if err != nil {
				errCh <- &relayError{fromEndpoint: true, err: err}
				return
			}
			if ce := r.Logger.Check(zap.DebugLevel, "relay: endpoint -> transport"); ce != nil {
				ce.Write(zap.Int("bytes", len(frame)), zap.String("hex", hexHead(frame)))
			}
			if err := r.data.SendData(frame); err != nil {
				if ppp.IsFrameTooLarge(err) {
					// A packet to drop, not a session to end. The peer is entitled
					// to send up to the MRU it was given, which it may not have
					// honoured, and tearing down on the first full-size download
					// would make the link flap instead of degrade.
					r.oversizeDropped.Add(1)
					if oversize == 0 {
						r.Logger.Warn("PPP frame exceeds the transport limit, dropping; "+
							"the negotiated MTU is too large for this path",
							zap.Error(err), zap.Int("bytes", len(frame)))
					} else if ce := r.Logger.Check(zap.DebugLevel, "oversize frame dropped"); ce != nil {
						ce.Write(zap.Error(err), zap.Uint64("count", oversize))
					}
					oversize++
					continue
				}
				errCh <- &relayError{err: err}
				return
			}
		}
	}()

	if mtuProbeWorthwhile(r.data) {
		go r.probeLoop(errCh)
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// probeLoop sends a full-size frame periodically and requires the peer to echo
// it. Several unanswered in a row means the path stopped carrying what the PPP
// link was negotiated for -- which nothing else in the stack can see, because
// quic-go never lowers its MTU estimate and LCP Echo is small enough to pass a
// path that only drops large packets.
func (r *relay) probeLoop(errCh chan<- error) {
	interval, grace, allowed := mtuProbeInterval, mtuProbeGrace, maxMTUProbeFailures
	if r.ProbeInterval > 0 {
		interval = r.ProbeInterval
	}
	if r.ProbeGrace > 0 {
		grace = r.ProbeGrace
	}
	if r.ProbeFailures > 0 {
		allowed = r.ProbeFailures
	}

	select {
	case <-time.After(grace):
	case <-r.done:
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var seq uint32
	var failures int
	for {
		select {
		case <-r.done:
			return
		case <-ticker.C:
		}

		size := transportMaxFrame(r.data)
		if size <= 0 || size > maxPPPMTU {
			continue
		}
		seq++
		if err := r.data.SendData(buildMTUProbe(mtuProbeRequest, seq, size)); err != nil {
			// Inconclusive, not fatal: a refusal means the transport already knows
			// the size does not fit, and any other error may be momentary. Giving
			// up would leave the session running with black-hole detection off.
			if ce := r.Logger.Check(zap.DebugLevel, "MTU probe send failed"); ce != nil {
				ce.Write(zap.Error(err), zap.Uint32("seq", seq))
			}
			continue
		}

		select {
		case <-r.done:
			return
		case <-time.After(interval / 2):
		}

		if r.lastProbeSeq.Load() >= seq {
			failures = 0
			continue
		}
		failures++
		r.Logger.Warn("full-size MTU probe unanswered",
			zap.Uint32("seq", seq), zap.Int("size", size), zap.Int("consecutive", failures))
		if failures >= allowed {
			if r.MTUFixed {
				// Said once, then the probe keeps running: the path may widen
				// again, and if it does the next answered probe resets failures
				// and this goes quiet without anyone intervening.
				r.Logger.Error("path no longer carries the configured MTU; full-size packets "+
					"are being lost. Lower the mtu option for this interface",
					zap.Int("probeSize", size))
				failures = 0
				continue
			}
			r.Logger.Error("path no longer carries the negotiated MTU, tearing down the session "+
				"so it can be rebuilt at the smaller size",
				zap.Int("probeSize", size))
			select {
			case errCh <- &relayError{err: errPathNarrowed}:
			default:
			}
			return
		}
	}
}
