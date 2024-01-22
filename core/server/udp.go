package server

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/internal/frag"
	"github.com/apernet/hysteria/core/internal/protocol"
	"github.com/apernet/hysteria/core/internal/utils"
)

const (
	idleCleanupInterval = 1 * time.Second
)

type udpIO interface {
	ReceiveMessage() (*protocol.UDPMessage, error)
	SendMessage([]byte, *protocol.UDPMessage) error
	UDP(reqAddr string) (UDPConn, error)
}

type udpEventLogger interface {
	New(sessionID uint32, reqAddr string)
	Close(sessionID uint32, err error)
}

type udpSessionEntry struct {
	ID      uint32
	Conn    UDPConn
	D       *frag.Defragger
	Last    *utils.AtomicTime
	Timeout bool // true if the session is closed due to timeout
}

// Feed feeds a UDP message to the session.
// If the message itself is a complete message, or it completes a fragmented message,
// the message is written to the session's UDP connection, and the number of bytes
// written is returned.
// Otherwise, 0 and nil are returned.
func (e *udpSessionEntry) Feed(msg *protocol.UDPMessage) (int, error) {
	e.Last.Set(time.Now())
	dfMsg := e.D.Feed(msg)
	if dfMsg == nil {
		return 0, nil
	}
	return e.Conn.WriteTo(dfMsg.Data, dfMsg.Addr)
}

// ReceiveLoop receives incoming UDP packets, packs them into UDP messages,
// and sends using the provided io.
// Exit and returns error when either the underlying UDP connection returns
// error (e.g. closed), or the provided io returns error when sending.
func (e *udpSessionEntry) ReceiveLoop(io udpIO) error {
	udpBuf := make([]byte, protocol.MaxUDPSize)
	msgBuf := make([]byte, protocol.MaxUDPSize)
	for {
		udpN, rAddr, err := e.Conn.ReadFrom(udpBuf)
		if err != nil {
			return err
		}
		e.Last.Set(time.Now())

		msg := &protocol.UDPMessage{
			SessionID: e.ID,
			PacketID:  0,
			FragID:    0,
			FragCount: 1,
			Addr:      rAddr,
			Data:      udpBuf[:udpN],
		}
		err = sendMessageAutoFrag(io, msgBuf, msg)
		if err != nil {
			return err
		}
	}
}

// sendMessageAutoFrag tries to send a UDP message as a whole first,
// but if it fails due to quic.ErrMessageTooLarge, it tries again by
// fragmenting the message.
func sendMessageAutoFrag(io udpIO, buf []byte, msg *protocol.UDPMessage) error {
	err := io.SendMessage(buf, msg)
	var errTooLarge *quic.DatagramTooLargeError
	if errors.As(err, &errTooLarge) {
		// Message too large, try fragmentation
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := frag.FragUDPMessage(msg, int(errTooLarge.MaxDataLen))
		for _, fMsg := range fMsgs {
			err := io.SendMessage(buf, &fMsg)
			if err != nil {
				return err
			}
		}
		return nil
	} else {
		return err
	}
}

// udpSessionManager manages the lifecycle of UDP sessions.
// Each UDP session is identified by a SessionID, and corresponds to a UDP connection.
// A UDP session is created when a UDP message with a new SessionID is received.
// Similar to standard NAT, a UDP session is destroyed when no UDP message is received
// for a certain period of time (specified by idleTimeout).
type udpSessionManager struct {
	io          udpIO
	eventLogger udpEventLogger
	idleTimeout time.Duration

	mutex sync.RWMutex
	m     map[uint32]*udpSessionEntry
}

func newUDPSessionManager(io udpIO, eventLogger udpEventLogger, idleTimeout time.Duration) *udpSessionManager {
	return &udpSessionManager{
		io:          io,
		eventLogger: eventLogger,
		idleTimeout: idleTimeout,
		m:           make(map[uint32]*udpSessionEntry),
	}
}

// Run runs the session manager main loop.
// Exit and returns error when the underlying io returns error (e.g. closed).
func (m *udpSessionManager) Run() error {
	stopCh := make(chan struct{})
	go m.idleCleanupLoop(stopCh)
	defer close(stopCh)
	defer m.cleanup(false)

	for {
		msg, err := m.io.ReceiveMessage()
		if err != nil {
			return err
		}
		m.feed(msg)
	}
}

func (m *udpSessionManager) idleCleanupLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(idleCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.cleanup(true)
		case <-stopCh:
			return
		}
	}
}

func (m *udpSessionManager) cleanup(idleOnly bool) {
	// We use RLock here as we are only scanning the map, not deleting from it.
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	now := time.Now()
	for _, entry := range m.m {
		if !idleOnly || now.Sub(entry.Last.Get()) > m.idleTimeout {
			entry.Timeout = true
			_ = entry.Conn.Close()
			// Closing the connection here will cause the ReceiveLoop to exit,
			// and the session will be removed from the map there.
		}
	}
}

func (m *udpSessionManager) feed(msg *protocol.UDPMessage) {
	m.mutex.RLock()
	entry := m.m[msg.SessionID]
	m.mutex.RUnlock()

	// Create a new session if not exists
	if entry == nil {
		m.eventLogger.New(msg.SessionID, msg.Addr)
		conn, err := m.io.UDP(msg.Addr)
		if err != nil {
			m.eventLogger.Close(msg.SessionID, err)
			return
		}
		entry = &udpSessionEntry{
			ID:   msg.SessionID,
			Conn: conn,
			D:    &frag.Defragger{},
			Last: utils.NewAtomicTime(time.Now()),
		}
		// Start the receive loop for this session
		go func() {
			err := entry.ReceiveLoop(m.io)
			if !entry.Timeout {
				_ = entry.Conn.Close()
				m.eventLogger.Close(entry.ID, err)
			} else {
				// Connection already closed by timeout cleanup,
				// no need to close again here.
				// Use nil error to indicate timeout.
				m.eventLogger.Close(entry.ID, nil)
			}
			// Remove the session from the map
			m.mutex.Lock()
			delete(m.m, entry.ID)
			m.mutex.Unlock()
		}()
		// Insert the session into the map
		m.mutex.Lock()
		m.m[msg.SessionID] = entry
		m.mutex.Unlock()
	}

	// Feed the message to the session
	// Feed (send) errors are ignored for now,
	// as some are temporary (e.g. invalid address)
	_, _ = entry.Feed(msg)
}

func (m *udpSessionManager) Count() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.m)
}
