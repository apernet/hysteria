package ppp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	corePPP "github.com/apernet/hysteria/core/v2/ppp"

	"github.com/apernet/quic-go"
)

// DebugLogFunc is an optional callback for debug-level logging.
// If nil, no debug logging is performed.
type DebugLogFunc func(msg string, fields ...any)

// DatagramIO implements PPPDataIO using QUIC datagrams.
// Used on both server and client side (with a dispatcher channel).
type DatagramIO struct {
	conn   *quic.Conn
	recvCh <-chan []byte
	done   chan struct{}
	once   sync.Once
}

func NewDatagramIO(conn *quic.Conn, recvCh <-chan []byte) corePPP.PPPDataIO {
	return &DatagramIO{conn: conn, recvCh: recvCh, done: make(chan struct{})}
}

func (d *DatagramIO) SendData(frame []byte) error {
	err := d.conn.SendDatagram(frame)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return &corePPP.FrameTooLargeError{
			FrameSize: len(frame),
			MaxSize:   int(tooLarge.MaxDatagramPayloadSize),
		}
	}
	return err
}

// sizeProbe is larger than any QUIC packet can ever be (MaxPacketBufferSize is
// 1452), so SendDatagram always rejects it and reports the current ceiling
// instead of queueing anything. It returns before copying the payload, so this
// costs nothing beyond the shared buffer.
var sizeProbe = make([]byte, 2048)

// MaxFrameSize reports the largest frame that would be accepted right now. The
// value grows as Path MTU discovery probes the path, so callers that need a
// stable answer should poll until it stops changing.
func (d *DatagramIO) MaxFrameSize() int {
	err := d.conn.SendDatagram(sizeProbe)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return int(tooLarge.MaxDatagramPayloadSize)
	}
	return 0
}

func (d *DatagramIO) ReceiveData() ([]byte, error) {
	select {
	case msg, ok := <-d.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-d.done:
		return nil, io.EOF
	}
}

func (d *DatagramIO) Close() error {
	d.once.Do(func() { close(d.done) })
	return nil
}

// MultiStreamIO implements PPPDataIO using N parallel QUIC streams
// with length-prefix framing and per-flow hashing.
type MultiStreamIO struct {
	streams []*quic.Stream
	// writeMu[i] guards streams[i]. A frame goes out as a length prefix followed
	// by the payload, so two senders interleaving on one stream would leave the
	// receiver parsing payload octets as a length -- unrecoverable for the life of
	// the stream. The bridge has several concurrent senders, so this is reachable.
	writeMu       []sync.Mutex
	recvCh        chan []byte
	debugLog      DebugLogFunc
	once          sync.Once
	done          chan struct{}
	activeReaders atomic.Int32
}

func NewMultiStreamIO(streams []*quic.Stream, debugLog DebugLogFunc) corePPP.PPPDataIO {
	m := &MultiStreamIO{
		streams:  streams,
		writeMu:  make([]sync.Mutex, len(streams)),
		recvCh:   make(chan []byte, 256),
		debugLog: debugLog,
		done:     make(chan struct{}),
	}
	m.activeReaders.Store(int32(len(streams)))
	for i, s := range streams {
		go m.readLoop(i, s)
	}
	return m
}

func (m *MultiStreamIO) readLoop(idx int, s *quic.Stream) {
	defer func() {
		if m.activeReaders.Add(-1) == 0 {
			m.Close()
		}
	}()
	hdr := make([]byte, 2)
	for {
		if _, err := io.ReadFull(s, hdr); err != nil {
			return
		}
		frameLen := int(binary.BigEndian.Uint16(hdr))
		frame := make([]byte, frameLen)
		if _, err := io.ReadFull(s, frame); err != nil {
			return
		}
		select {
		case m.recvCh <- frame:
		case <-m.done:
			return
		}
	}
}

// MaxFrameSize reports the ceiling imposed by the 16-bit length prefix. A
// reliable stream has no per-frame limit of its own.
func (m *MultiStreamIO) MaxFrameSize() int { return math.MaxUint16 }

func (m *MultiStreamIO) SendData(frame []byte) error {
	// The length prefix is 16 bits. Without this guard the cast below truncates
	// silently and the receiver desynchronises for the life of the stream.
	if len(frame) > math.MaxUint16 {
		return &corePPP.FrameTooLargeError{FrameSize: len(frame), MaxSize: math.MaxUint16}
	}
	idx := flowHash(frame, len(m.streams), m.debugLog)
	hdr := [2]byte{}
	binary.BigEndian.PutUint16(hdr[:], uint16(len(frame)))
	m.writeMu[idx].Lock()
	defer m.writeMu[idx].Unlock()
	if _, err := m.streams[idx].Write(hdr[:]); err != nil {
		return err
	}
	_, err := m.streams[idx].Write(frame)
	return err
}

func (m *MultiStreamIO) ReceiveData() ([]byte, error) {
	select {
	case frame, ok := <-m.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return frame, nil
	case <-m.done:
		return nil, io.EOF
	}
}

func (m *MultiStreamIO) Close() error {
	m.once.Do(func() {
		select {
		case <-m.done:
		default:
			close(m.done)
		}
	})
	for _, s := range m.streams {
		_ = s.Close()
	}
	return nil
}

// CollectDataStreams waits for N data streams to arrive on the channel
// and returns a MultiStreamIO wrapping them.
func CollectDataStreams(ch <-chan *quic.Stream, n int, timeout time.Duration, debugLog DebugLogFunc) (corePPP.PPPDataIO, error) {
	streams := make([]*quic.Stream, 0, n)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for len(streams) < n {
		select {
		case s, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("data stream channel closed, got %d/%d", len(streams), n)
			}
			streams = append(streams, s)
		case <-timer.C:
			for _, s := range streams {
				_ = s.Close()
			}
			return nil, fmt.Errorf("timed out waiting for data streams, got %d/%d", len(streams), n)
		}
	}
	return NewMultiStreamIO(streams, debugLog), nil
}

// DatagramBudget reports the largest datagram payload conn will accept right
// now, or 0 if datagrams are unavailable. The value tracks Path MTU discovery,
// which starts at quic-go's initial packet size and grows as the path is probed.
func DatagramBudget(conn *quic.Conn) int {
	err := conn.SendDatagram(sizeProbe)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return int(tooLarge.MaxDatagramPayloadSize)
	}
	return 0
}

// StableDatagramBudget waits for DatagramBudget to stop growing and returns it.
//
// Path MTU discovery probes every few round trips, so the budget right after the
// handshake is well below what the path really carries -- on a 1500-byte path it
// starts around 1243 and settles near 1404. Sizing PPP against the early value
// wastes the path permanently; sizing it against an assumed final value drops
// every full-size frame until discovery catches up. Waiting is the way out, and
// it is free here: pppd is retransmitting its Configure-Request on a 3s restart
// timer with ten attempts, so a couple of seconds is invisible to it.
//
// Returns the last observed value even if it never settles within timeout.
func StableDatagramBudget(conn *quic.Conn, settle, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	poll := 20 * time.Millisecond
	last := DatagramBudget(conn)
	stableSince := time.Now()
	keepalive := make([]byte, 16)
	for time.Now().Before(deadline) {
		// Discovery only advances when packets are acknowledged: probes go out
		// every few round trips and a probe that is never ACKed teaches it
		// nothing. On an otherwise idle connection the budget therefore stalls
		// partway up the ramp and looks settled. Keep a trickle of traffic going
		// so what we observe is convergence rather than silence.
		_ = conn.SendDatagram(keepalive)
		time.Sleep(poll)
		cur := DatagramBudget(conn)
		if cur != last {
			last = cur
			stableSince = time.Now()
			continue
		}
		if time.Since(stableSince) >= settle {
			break
		}
	}
	return last
}
