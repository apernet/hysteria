package pppbridge

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// IPC message types for MLPPP fragment exchange
const (
	ipcMsgTXFragment byte = 0x01 // master -> worker: send this fragment on your link
	ipcMsgRXFragment byte = 0x02 // worker -> master: received this fragment from my link
	ipcMsgLinkStatus byte = 0x03 // bidirectional: link up/down
	ipcMsgStart      byte = 0x04 // master -> worker: LCP relay done, start negotiation (MRRU 2B + shortSeq 1B)
	ipcMsgRegister   byte = 0x05 // worker -> master: registration with MTU (2B big-endian uint16)
	ipcMsgLinkReady  byte = 0x06 // worker -> master: server-side LCP+PAP complete, ready for fragments
)

func ipcSocketPath(discriminator string) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("hysteria-sstp-%s.sock", discriminator))
}

// IPCServer manages worker connections for the MLPPP master.
type IPCServer struct {
	ln   net.Listener
	path string

	mu           sync.RWMutex
	workers      []*IPCConn
	workerMTUs   []int       // per-worker MTU values (parallel to workers)
	workerActive []bool      // per-worker: true after worker sends ipcMsgLinkReady
	startMsg     *IPCMessage // cached start message for late-joining workers

	RxCh chan IPCMessage
}

// IPCConn wraps a net.Conn with length-prefixed message framing.
type IPCConn struct {
	conn net.Conn
	mu   sync.Mutex
}

// IPCMessage is a message exchanged over the IPC channel.
type IPCMessage struct {
	Type    byte
	Payload []byte
	From    *IPCConn
}

// TryBecomeMaster attempts to create the IPC endpoint for the given
// discriminator. Returns (true, server) if this process becomes the master,
// or (false, nil) if another master is already running.
func TryBecomeMaster(discriminator string) (bool, *IPCServer, error) {
	path := ipcSocketPath(discriminator)

	ln, err := net.Listen("unix", path)
	if err == nil {
		srv := &IPCServer{
			ln:   ln,
			path: path,
			RxCh: make(chan IPCMessage, 256),
		}
		return true, srv, nil
	}

	// Listen failed -- check if a living master owns the socket
	conn, dialErr := net.DialTimeout("unix", path, 500*time.Millisecond)
	if dialErr != nil {
		// Stale socket, remove and retry
		os.Remove(path)
		ln, err = net.Listen("unix", path)
		if err != nil {
			return false, nil, fmt.Errorf("failed to create IPC endpoint: %w", err)
		}
		srv := &IPCServer{
			ln:   ln,
			path: path,
			RxCh: make(chan IPCMessage, 256),
		}
		return true, srv, nil
	}
	conn.Close()
	return false, nil, nil
}

// AcceptWorkers accepts worker connections in a loop. Call in a goroutine.
func (s *IPCServer) AcceptWorkers(logger *zap.Logger) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		w := &IPCConn{conn: conn}

		// Read registration message from worker (contains MTU).
		// If the read fails, this is likely a liveness probe from
		// TryBecomeMaster rather than a real worker -- discard it.
		regMsg, regErr := ipcRead(conn)
		if regErr != nil {
			conn.Close()
			continue
		}
		workerMTU := 0
		if regMsg.Type == ipcMsgRegister && len(regMsg.Payload) >= 2 {
			workerMTU = int(binary.BigEndian.Uint16(regMsg.Payload[0:2]))
		}

		s.mu.Lock()
		linkIndex := len(s.workers) + 1
		s.workers = append(s.workers, w)
		s.workerMTUs = append(s.workerMTUs, workerMTU)
		s.workerActive = append(s.workerActive, false)
		totalLinks := 1 + len(s.workers)
		cached := s.startMsg
		s.mu.Unlock()

		_ = w.SendTo(IPCMessage{
			Type:    ipcMsgLinkStatus,
			Payload: []byte{byte(linkIndex), byte(totalLinks)},
		})
		if cached != nil {
			_ = w.SendTo(*cached)
		}
		logger.Info("MLPPP bundle updated",
			zap.Int("newWorkerLink", linkIndex),
			zap.Int("totalLinks", totalLinks),
			zap.Int("workerMTU", workerMTU))
		go s.readFromWorker(w, logger)
	}
}

// Broadcast sends a message to all currently connected workers and caches
// start messages for late-joining workers.
func (s *IPCServer) Broadcast(msg IPCMessage) {
	s.mu.Lock()
	if msg.Type == ipcMsgStart {
		s.startMsg = &msg
	}
	workers := make([]*IPCConn, len(s.workers))
	copy(workers, s.workers)
	s.mu.Unlock()
	for _, w := range workers {
		_ = w.SendTo(msg)
	}
}

func (s *IPCServer) readFromWorker(w *IPCConn, logger *zap.Logger) {
	defer func() {
		s.removeWorker(w)
		logger.Info("MLPPP worker disconnected")
	}()
	for {
		msg, err := ipcRead(w.conn)
		if err != nil {
			return
		}
		if msg.Type == ipcMsgLinkReady {
			s.mu.Lock()
			for i, ww := range s.workers {
				if ww == w {
					s.workerActive[i] = true
					break
				}
			}
			s.mu.Unlock()
			logger.Info("MLPPP worker link ready")
			continue
		}
		msg.From = w
		select {
		case s.RxCh <- msg:
		default:
		}
	}
}

func (s *IPCServer) removeWorker(w *IPCConn) {
	w.conn.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ww := range s.workers {
		if ww == w {
			s.workers = append(s.workers[:i], s.workers[i+1:]...)
			s.workerMTUs = append(s.workerMTUs[:i], s.workerMTUs[i+1:]...)
			s.workerActive = append(s.workerActive[:i], s.workerActive[i+1:]...)
			return
		}
	}
}

// Workers returns a snapshot of the current worker list.
func (s *IPCServer) Workers() []*IPCConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*IPCConn, len(s.workers))
	copy(out, s.workers)
	return out
}

// NumLinks returns the total number of links (1 for master's own + workers).
func (s *IPCServer) NumLinks() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return 1 + len(s.workers)
}

// ActiveWorkers returns a snapshot of workers that have signalled link-ready.
func (s *IPCServer) ActiveWorkers() []*IPCConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*IPCConn
	for i, w := range s.workers {
		if s.workerActive[i] {
			out = append(out, w)
		}
	}
	return out
}

// ActiveNumLinks returns 1 (master) + count of active (link-ready) workers.
func (s *IPCServer) ActiveNumLinks() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 1
	for _, active := range s.workerActive {
		if active {
			n++
		}
	}
	return n
}

// MinMTU returns the minimum MTU across the master and all workers.
func (s *IPCServer) MinMTU(masterMTU int) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	minVal := masterMTU
	for _, m := range s.workerMTUs {
		if m > 0 && m < minVal {
			minVal = m
		}
	}
	return minVal
}

// Close shuts down the IPC server and cleans up the socket file.
func (s *IPCServer) Close() {
	s.ln.Close()
	os.Remove(s.path)
}

// SendTo sends a message to a specific worker.
func (c *IPCConn) SendTo(msg IPCMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ipcWrite(c.conn, msg)
}

// ipcRead reads one length-prefixed message from the connection.
func ipcRead(r io.Reader) (IPCMessage, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return IPCMessage{}, err
	}
	msgType := hdr[0]
	length := binary.BigEndian.Uint16(hdr[1:3])
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return IPCMessage{}, err
		}
	}
	return IPCMessage{Type: msgType, Payload: payload}, nil
}

// ipcWrite writes one length-prefixed message to the connection.
func ipcWrite(w io.Writer, msg IPCMessage) error {
	hdr := [3]byte{msg.Type, 0, 0}
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(msg.Payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(msg.Payload) > 0 {
		if _, err := w.Write(msg.Payload); err != nil {
			return err
		}
	}
	return nil
}

// IPCClient connects to the master as a worker.
type IPCClient struct {
	conn net.Conn
	mu   sync.Mutex
}

// DialMaster connects to the MLPPP master's IPC endpoint.
func DialMaster(discriminator string) (*IPCClient, error) {
	path := ipcSocketPath(discriminator)
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, err
	}
	return &IPCClient{conn: conn}, nil
}

// SendRegister sends the worker's MTU to the master during IPC handshake.
// Must be called before ReadWelcome.
func (c *IPCClient) SendRegister(mtu int) error {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, uint16(mtu))
	return ipcWrite(c.conn, IPCMessage{Type: ipcMsgRegister, Payload: payload})
}

// ReadWelcome reads the initial link status message from the master,
// returning this worker's link index and the current total link count.
func (c *IPCClient) ReadWelcome() (linkIndex, totalLinks int, err error) {
	msg, err := c.Read()
	if err != nil {
		return 0, 0, err
	}
	if msg.Type != ipcMsgLinkStatus || len(msg.Payload) < 2 {
		return 0, 0, fmt.Errorf("unexpected welcome message type %d", msg.Type)
	}
	return int(msg.Payload[0]), int(msg.Payload[1]), nil
}

// WaitForStart blocks until the master sends ipcMsgStart, returning the
// negotiated MRRU and shortSeq flag.
func (c *IPCClient) WaitForStart() (mrru uint16, shortSeq bool, err error) {
	for {
		msg, err := ipcRead(c.conn)
		if err != nil {
			return 0, false, err
		}
		if msg.Type == ipcMsgStart && len(msg.Payload) >= 3 {
			mrru = binary.BigEndian.Uint16(msg.Payload[0:2])
			shortSeq = msg.Payload[2] != 0
			return mrru, shortSeq, nil
		}
	}
}

// Read reads the next IPC message from the master.
func (c *IPCClient) Read() (IPCMessage, error) {
	return ipcRead(c.conn)
}

// Send writes an IPC message to the master.
func (c *IPCClient) Send(msg IPCMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ipcWrite(c.conn, msg)
}

// Close closes the IPC connection.
func (c *IPCClient) Close() error {
	return c.conn.Close()
}
