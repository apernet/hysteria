package pppbridge

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/apernet/hysteria/core/v2/ppp"
	"github.com/apernet/hysteria/extras/v2/l2tp"

	"go.uber.org/zap"
)

// L2TPPPPHandler implements server.PPPRequestHandler for L2TP mode.
// It negotiates LCP/auth with the client's pppd, looks up the realm,
// creates an L2TP session to the appropriate LNS, and bridges PPP frames.
type L2TPPPPHandler struct {
	TunnelManager *l2tp.TunnelManager
	RealmRouter   *l2tp.RealmRouter
	LoadBalancer  *l2tp.LoadBalancer
	Logger        *zap.Logger
}

func (h *L2TPPPPHandler) HandlePPP(
	control io.ReadWriteCloser,
	dataStreams int,
	createDataIO func() (ppp.PPPDataIO, error),
	addr net.Addr,
	id string,
) {
	defer control.Close()

	// Accept the PPP request at Hysteria level
	if err := writePPPResponse(control, true, "OK", dataStreams); err != nil {
		h.Logger.Error("failed to write PPP response", zap.Error(err))
		return
	}

	// LCP negotiation + authentication
	info, bufReader, err := NegotiateLCP(control, h.Logger)
	if err != nil {
		h.Logger.Warn("LCP negotiation failed",
			zap.String("addr", addr.String()),
			zap.String("id", id),
			zap.Error(err))
		return
	}

	h.Logger.Debug("LCP negotiation completed",
		zap.String("username", info.AuthName),
		zap.Uint16("authType", info.AuthType))

	// Realm lookup
	group := h.RealmRouter.Match(info.Realm)
	if group == "" {
		h.Logger.Warn("realm not found",
			zap.String("username", info.AuthName),
			zap.String("realm", info.Realm))
		_ = SendAuthResult(control, info, false)
		return
	}

	// Pick LNS (sticky by endpoint discriminator for MLPPP, round-robin otherwise)
	lnsConfig, ok := h.LoadBalancer.PickSticky(group, info.AuthName, info.EndpointDiscriminator)
	if !ok {
		h.Logger.Warn("no LNS available in group",
			zap.String("group", group))
		_ = SendAuthResult(control, info, false)
		return
	}

	h.Logger.Debug("LNS selection",
		zap.String("group", group),
		zap.String("selectedLNS", lnsConfig.Address))

	// Create L2TP session (tunnel established on demand)
	session, err := h.TunnelManager.CreateSession(lnsConfig.Address, lnsConfig.Secret, info, id)
	if err != nil {
		h.Logger.Warn("L2TP session creation failed",
			zap.String("lns", lnsConfig.Address),
			zap.String("username", info.AuthName),
			zap.String("realm", info.Realm),
			zap.Error(err))
		_ = SendAuthResult(control, info, false)
		return
	}
	defer session.Close()

	// Auth success
	if err := SendAuthResult(control, info, true); err != nil {
		h.Logger.Error("failed to send auth result", zap.Error(err))
		return
	}

	// Activate data transport
	dataIO, err := createDataIO()
	if err != nil {
		h.Logger.Error("failed to create data IO", zap.Error(err))
		return
	}
	defer dataIO.Close()

	h.Logger.Info("PPP L2TP session active",
		zap.String("addr", addr.String()),
		zap.String("id", id),
		zap.String("username", info.AuthName),
		zap.String("lns", lnsConfig.Address))

	// Bridge loop: 3 goroutines
	errCh := make(chan error, 3)

	// Goroutine A: Control stream -> L2TP
	go func() {
		var hdlcBuf []byte
		buf := make([]byte, 4096)
		for {
			nr, err := bufReader.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			hdlcBuf = append(hdlcBuf, buf[:nr]...)
			for {
				frame, rest, ok := extractHDLCFrame(hdlcBuf)
				if !ok {
					break
				}
				hdlcBuf = rest
				rawPPP, decErr := decodeHDLCFramePayload(frame)
				if decErr != nil {
					continue
				}
				proto, payload := parsePPPFrame(rawPPP)
				if proto == 0 {
					continue
				}
				if err := session.SendPPP(proto, payload); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	// Goroutine B: PPPDataIO -> L2TP
	go func() {
		for {
			rawPPP, err := dataIO.ReceiveData()
			if err != nil {
				errCh <- err
				return
			}
			proto, payload := parsePPPFrame(rawPPP)
			if proto == 0 {
				continue
			}
			if err := session.SendPPP(proto, payload); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Goroutine C: L2TP -> Hysteria
	go func() {
		for {
			proto, payload, err := session.RecvPPP()
			if err != nil {
				errCh <- err
				return
			}
			// Prepend FF 03 + protocol
			rawPPP := make([]byte, 4+len(payload))
			rawPPP[0] = 0xFF
			rawPPP[1] = 0x03
			binary.BigEndian.PutUint16(rawPPP[2:4], proto)
			copy(rawPPP[4:], payload)

			if isControlFrame(rawPPP) {
				hdlcFrame := EncodeHDLC(rawPPP)
				if _, err := control.Write(hdlcFrame); err != nil {
					errCh <- err
					return
				}
			} else {
				if err := dataIO.SendData(rawPPP); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	// Wait for first error
	<-errCh
}
