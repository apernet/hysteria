package client

import (
	"errors"
	io2 "io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/goleak"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

func TestUDPSessionManager(t *testing.T) {
	io := newMockUDPIO(t)
	receiveCh := make(chan *protocol.UDPMessage, 4)
	io.EXPECT().ReceiveMessage().RunAndReturn(func() (*protocol.UDPMessage, error) {
		m := <-receiveCh
		if m == nil {
			return nil, errors.New("closed")
		}
		return m, nil
	})
	sm := newUDPSessionManager(io)

	// Test UDP session IO
	udpConn1, err := sm.NewUDP()
	assert.NoError(t, err)
	udpConn2, err := sm.NewUDP()
	assert.NoError(t, err)

	msg1 := &protocol.UDPMessage{
		SessionID: 1,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "random.site.com:9000",
		Data:      []byte("hello friend"),
	}
	io.EXPECT().SendMessage(mock.Anything, msg1).Return(nil).Once()
	err = udpConn1.Send(msg1.Data, msg1.Addr)
	assert.NoError(t, err)

	msg2 := &protocol.UDPMessage{
		SessionID: 2,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "another.site.org:8000",
		Data:      []byte("mr robot"),
	}
	io.EXPECT().SendMessage(mock.Anything, msg2).Return(nil).Once()
	err = udpConn2.Send(msg2.Data, msg2.Addr)
	assert.NoError(t, err)

	respMsg1 := &protocol.UDPMessage{
		SessionID: 1,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      msg1.Addr,
		Data:      []byte("goodbye captain price"),
	}
	receiveCh <- respMsg1
	data, addr, err := udpConn1.Receive()
	assert.NoError(t, err)
	assert.Equal(t, data, respMsg1.Data)
	assert.Equal(t, addr, respMsg1.Addr)

	respMsg2 := &protocol.UDPMessage{
		SessionID: 2,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      msg2.Addr,
		Data:      []byte("white rose"),
	}
	receiveCh <- respMsg2
	data, addr, err = udpConn2.Receive()
	assert.NoError(t, err)
	assert.Equal(t, data, respMsg2.Data)
	assert.Equal(t, addr, respMsg2.Addr)

	respMsg3 := &protocol.UDPMessage{
		SessionID: 55, // Bogus session ID that doesn't exist
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "burgerking.com:27017",
		Data:      []byte("impossible whopper"),
	}
	receiveCh <- respMsg3
	// No test for this, just make sure it doesn't panic

	// Test close UDP connection unblocks Receive()
	errChan := make(chan error, 1)
	go func() {
		_, _, err := udpConn1.Receive()
		errChan <- err
	}()
	assert.NoError(t, udpConn1.Close())
	assert.Equal(t, <-errChan, io2.EOF)

	// Test close IO unblocks Receive() and blocks new UDP creation
	errChan = make(chan error, 1)
	go func() {
		_, _, err := udpConn2.Receive()
		errChan <- err
	}()
	close(receiveCh)
	assert.Equal(t, <-errChan, io2.EOF)
	_, err = sm.NewUDP()
	assert.Equal(t, err, coreErrs.ClosedError{})

	// Leak checks
	time.Sleep(1 * time.Second)
	assert.Zero(t, sm.Count(), "session count should be 0")
	goleak.VerifyNone(t)
}
