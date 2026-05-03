package realm

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const defaultServerPunchEventBuffer = 16

type ServerPuncher struct {
	conn *PunchPacketConn

	mu       sync.Mutex
	attempts map[string]chan PunchPacketEvent
}

func NewServerPuncher(ctx context.Context, conn *PunchPacketConn) (*ServerPuncher, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: conn is nil", ErrInvalidPunchAttempt)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p := &ServerPuncher{
		conn:     conn,
		attempts: make(map[string]chan PunchPacketEvent),
	}
	go p.dispatch(ctx)
	return p, nil
}

// Respond runs the server side of a punch attempt. It sends hello packets,
// acks inbound hellos, and returns as soon as it sees a valid punch packet.
// If none arrive before timeout, it returns ErrPunchTimeout.
func (p *ServerPuncher) Respond(ctx context.Context, attemptID string, localAddrs, peerAddrs []netip.AddrPort, meta PunchMetadata, config PunchConfig) (PunchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if attemptID == "" {
		return PunchResult{}, fmt.Errorf("%w: id is required", ErrInvalidPunchAttempt)
	}
	if _, _, err := decodePunchMetadata(meta); err != nil {
		return PunchResult{}, err
	}
	candidates := candidatePunchAddrs(localAddrs, peerAddrs, localAddrFamily(p.conn.LocalAddr()))
	if len(candidates) == 0 {
		return PunchResult{}, fmt.Errorf("%w: no compatible peer addresses", ErrInvalidPunchConfig)
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultPunchTimeout
	}
	if timeout < 0 {
		return PunchResult{}, fmt.Errorf("%w: timeout must not be negative", ErrInvalidPunchConfig)
	}
	interval := config.Interval
	if interval == 0 {
		interval = defaultPunchInterval
	}
	if interval <= 0 {
		return PunchResult{}, fmt.Errorf("%w: interval must be positive", ErrInvalidPunchConfig)
	}

	events, err := p.addAttempt(attemptID, meta)
	if err != nil {
		return PunchResult{}, err
	}
	defer p.removeAttempt(attemptID)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	sendPunchPackets(p.conn, candidates, meta, PunchPacketHello)

	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return PunchResult{}, ErrPunchTimeout
			}
			return PunchResult{}, ctx.Err()
		case <-ticker.C:
			sendPunchPackets(p.conn, candidates, meta, PunchPacketHello)
		case ev := <-events:
			if ev.Packet.Type == PunchPacketHello {
				sendPunchPacket(p.conn, ev.From, meta, PunchPacketAck)
			}
			return PunchResult{
				PeerAddr: ev.From,
				Packet:   ev.Packet,
			}, nil
		}
	}
}

func (p *ServerPuncher) dispatch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-p.conn.Events():
			p.mu.Lock()
			ch := p.attempts[ev.AttemptID]
			p.mu.Unlock()
			if ch == nil {
				continue
			}
			select {
			case ch <- ev:
			default:
			}
		}
	}
}

func (p *ServerPuncher) addAttempt(id string, meta PunchMetadata) (<-chan PunchPacketEvent, error) {
	ch := make(chan PunchPacketEvent, defaultServerPunchEventBuffer)
	p.mu.Lock()
	if _, exists := p.attempts[id]; exists {
		p.mu.Unlock()
		return nil, fmt.Errorf("%w: duplicate id", ErrInvalidPunchAttempt)
	}
	p.attempts[id] = ch
	p.mu.Unlock()

	if err := p.conn.AddPunchAttempt(id, meta); err != nil {
		p.mu.Lock()
		delete(p.attempts, id)
		p.mu.Unlock()
		return nil, err
	}
	return ch, nil
}

func (p *ServerPuncher) removeAttempt(id string) {
	p.conn.RemovePunchAttempt(id)
	p.mu.Lock()
	delete(p.attempts, id)
	p.mu.Unlock()
}
