package client

import (
	"errors"
	"fmt"
	io2 "io"
	"testing"
	"time"

	coreErrs "github.com/apernet/hysteria/core/errors"
	"github.com/apernet/hysteria/core/internal/protocol"
	"go.uber.org/goleak"
)

type udpEchoIO struct {
	MsgCh   chan *protocol.UDPMessage
	CloseCh chan struct{}
}

func (io *udpEchoIO) ReceiveMessage() (*protocol.UDPMessage, error) {
	select {
	case m := <-io.MsgCh:
		return m, nil
	case <-io.CloseCh:
		return nil, errors.New("closed")
	}
}

func (io *udpEchoIO) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	nMsg := *msg
	nMsg.Data = make([]byte, len(msg.Data))
	copy(nMsg.Data, msg.Data)
	io.MsgCh <- &nMsg
	return nil
}

func (io *udpEchoIO) Close() {
	close(io.CloseCh)
}

func TestUDPSessionManager(t *testing.T) {
	io := &udpEchoIO{
		MsgCh:   make(chan *protocol.UDPMessage, 10),
		CloseCh: make(chan struct{}),
	}
	sm := newUDPSessionManager(io)

	rChan := make(chan error, 5)

	for i := 0; i < 5; i++ {
		go func(id int) {
			conn, err := sm.NewUDP()
			if err != nil {
				rChan <- err
				return
			}
			defer conn.Close()

			addr := fmt.Sprintf("wow.com:%d", id)
			for j := 0; j < 2; j++ {
				s := fmt.Sprintf("hello %d %d", id, j)
				err = conn.Send([]byte(s), addr)
				if err != nil {
					rChan <- err
					return
				}
				bs, addr, err := conn.Receive()
				if err != nil {
					rChan <- err
					return
				}
				if string(bs) != s || addr != addr {
					rChan <- fmt.Errorf("unexpected message: %s %s", bs, addr)
					return
				}
			}
			rChan <- nil // Success
		}(i)
	}

	// Check the results
	for i := 0; i < 5; i++ {
		err := <-rChan
		if err != nil {
			t.Fatal(err)
		}
	}

	// Leak checks
	// Create another UDP session
	conn, err := sm.NewUDP()
	if err != nil {
		t.Fatal(err)
	}
	io.Close()
	time.Sleep(1 * time.Second) // Give some time for the goroutines to exit
	_, _, err = conn.Receive()
	if err != io2.EOF {
		t.Fatal("expected EOF after closing io")
	}
	_, err = sm.NewUDP()
	if !errors.Is(err, coreErrs.ClosedError{}) {
		t.Fatal("expected ClosedError after closing io")
	}
	if sm.Count() != 0 {
		t.Error("session count should be 0")
	}
	goleak.VerifyNone(t)
}
