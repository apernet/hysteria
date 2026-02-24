package ppp

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
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
	return d.conn.SendDatagram(frame)
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
	streams  []*quic.Stream
	recvCh   chan []byte
	debugLog DebugLogFunc
	once     sync.Once
	done     chan struct{}
}

func NewMultiStreamIO(streams []*quic.Stream, debugLog DebugLogFunc) corePPP.PPPDataIO {
	m := &MultiStreamIO{
		streams:  streams,
		recvCh:   make(chan []byte, 256),
		debugLog: debugLog,
		done:     make(chan struct{}),
	}
	for i, s := range streams {
		go m.readLoop(i, s)
	}
	return m
}

func (m *MultiStreamIO) readLoop(idx int, s *quic.Stream) {
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

func (m *MultiStreamIO) SendData(frame []byte) error {
	idx := flowHash(frame, len(m.streams), m.debugLog)
	hdr := [2]byte{}
	binary.BigEndian.PutUint16(hdr[:], uint16(len(frame)))
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
