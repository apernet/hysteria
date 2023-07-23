package server

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/internal/protocol"
	"go.uber.org/goleak"
)

type echoUDPConnPkt struct {
	Data  []byte
	Addr  string
	Close bool
}

type echoUDPConn struct {
	PktCh chan echoUDPConnPkt
}

func (c *echoUDPConn) ReadFrom(b []byte) (int, string, error) {
	pkt := <-c.PktCh
	if pkt.Close {
		return 0, "", errors.New("closed")
	}
	n := copy(b, pkt.Data)
	return n, pkt.Addr, nil
}

func (c *echoUDPConn) WriteTo(b []byte, addr string) (int, error) {
	nb := make([]byte, len(b))
	copy(nb, b)
	c.PktCh <- echoUDPConnPkt{
		Data: nb,
		Addr: addr,
	}
	return len(b), nil
}

func (c *echoUDPConn) Close() error {
	c.PktCh <- echoUDPConnPkt{
		Close: true,
	}
	return nil
}

type udpsmMockIO struct {
	ReceiveCh <-chan *protocol.UDPMessage
	SendCh    chan<- *protocol.UDPMessage
}

func (io *udpsmMockIO) ReceiveMessage() (*protocol.UDPMessage, error) {
	m := <-io.ReceiveCh
	if m == nil {
		return nil, errors.New("closed")
	}
	return m, nil
}

func (io *udpsmMockIO) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	nMsg := *msg
	nMsg.Data = make([]byte, len(msg.Data))
	copy(nMsg.Data, msg.Data)
	io.SendCh <- &nMsg
	return nil
}

func (io *udpsmMockIO) DialUDP(reqAddr string) (UDPConn, error) {
	return &echoUDPConn{
		PktCh: make(chan echoUDPConnPkt, 10),
	}, nil
}

type udpsmMockEventNew struct {
	SessionID uint32
	ReqAddr   string
}

type udpsmMockEventClosed struct {
	SessionID uint32
	Err       error
}

type udpsmMockEventLogger struct {
	NewCh    chan<- udpsmMockEventNew
	ClosedCh chan<- udpsmMockEventClosed
}

func (l *udpsmMockEventLogger) New(sessionID uint32, reqAddr string) {
	l.NewCh <- udpsmMockEventNew{sessionID, reqAddr}
}

func (l *udpsmMockEventLogger) Closed(sessionID uint32, err error) {
	l.ClosedCh <- udpsmMockEventClosed{sessionID, err}
}

func TestUDPSessionManager(t *testing.T) {
	msgReceiveCh := make(chan *protocol.UDPMessage, 10)
	msgSendCh := make(chan *protocol.UDPMessage, 10)
	io := &udpsmMockIO{
		ReceiveCh: msgReceiveCh,
		SendCh:    msgSendCh,
	}
	eventNewCh := make(chan udpsmMockEventNew, 10)
	eventClosedCh := make(chan udpsmMockEventClosed, 10)
	eventLogger := &udpsmMockEventLogger{
		NewCh:    eventNewCh,
		ClosedCh: eventClosedCh,
	}
	sm := newUDPSessionManager(io, eventLogger, 2*time.Second)
	go sm.Run()

	ms := []*protocol.UDPMessage{
		{
			SessionID: 1234,
			PacketID:  0,
			FragID:    0,
			FragCount: 1,
			Addr:      "example.com:5353",
			Data:      []byte("hello"),
		},
		{
			SessionID: 5678,
			PacketID:  0,
			FragID:    0,
			FragCount: 1,
			Addr:      "example.com:9999",
			Data:      []byte("goodbye"),
		},
		{
			SessionID: 1234,
			PacketID:  0,
			FragID:    0,
			FragCount: 1,
			Addr:      "example.com:5353",
			Data:      []byte(" world"),
		},
		{
			SessionID: 5678,
			PacketID:  0,
			FragID:    0,
			FragCount: 1,
			Addr:      "example.com:9999",
			Data:      []byte(" girl"),
		},
	}
	for _, m := range ms {
		msgReceiveCh <- m
	}
	// New event order should be consistent
	newEvent := <-eventNewCh
	if newEvent.SessionID != 1234 || newEvent.ReqAddr != "example.com:5353" {
		t.Error("unexpected new event value")
	}
	newEvent = <-eventNewCh
	if newEvent.SessionID != 5678 || newEvent.ReqAddr != "example.com:9999" {
		t.Error("unexpected new event value")
	}
	// Message order is not guaranteed
	msgMap := make(map[string]bool)
	for i := 0; i < 4; i++ {
		msg := <-msgSendCh
		msgMap[fmt.Sprintf("%d:%s:%s", msg.SessionID, msg.Addr, string(msg.Data))] = true
	}
	if !(msgMap["1234:example.com:5353:hello"] &&
		msgMap["5678:example.com:9999:goodbye"] &&
		msgMap["1234:example.com:5353: world"] &&
		msgMap["5678:example.com:9999: girl"]) {
		t.Error("unexpected message value")
	}
	// Timeout check
	startTime := time.Now()
	closedMap := make(map[uint32]bool)
	for i := 0; i < 2; i++ {
		closedEvent := <-eventClosedCh
		closedMap[closedEvent.SessionID] = true
	}
	if !(closedMap[1234] && closedMap[5678]) {
		t.Error("unexpected closed event value", closedMap)
	}
	if time.Since(startTime) < 2*time.Second || time.Since(startTime) > 4*time.Second {
		t.Error("unexpected timeout duration")
	}

	// Goroutine leak check
	msgReceiveCh <- nil
	time.Sleep(1 * time.Second) // Wait for internal routines to exit
	goleak.VerifyNone(t)
}
