package client

import (
	"errors"
	io2 "io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/goleak"

	coreErrs "github.com/apernet/hysteria/core/errors"
	"github.com/apernet/hysteria/core/internal/protocol"
	"github.com/apernet/hysteria/extras/outbounds"
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
	msg1_host, msg1_port, err := net.SplitHostPort(msg1.Addr)
	assert.NoError(t, err)
	msg1_portInt, err := strconv.Atoi(msg1_port)
	assert.NoError(t, err)
	addr := &outbounds.AddrEx{
		Host: msg1_host,
		Port: uint16(msg1_portInt),
	}
	io.EXPECT().SendMessage(mock.Anything, msg1).Return(nil).Once()
	_, err = udpConn1.WriteTo(msg1.Data, addr)
	assert.NoError(t, err)

	msg2 := &protocol.UDPMessage{
		SessionID: 2,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      "another.site.org:8000",
		Data:      []byte("mr robot"),
	}
	msg2_host, msg2_port, err := net.SplitHostPort(msg2.Addr)
	assert.NoError(t, err)
	msg2_portInt, err := strconv.Atoi(msg2_port)
	assert.NoError(t, err)
	addr = &outbounds.AddrEx{
		Host: msg2_host,
		Port: uint16(msg2_portInt),
	}
	io.EXPECT().SendMessage(mock.Anything, msg2).Return(nil).Once()
	_, err = udpConn2.WriteTo(msg2.Data, addr)
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
	buf := make([]byte, udpBufferSize)
	n, addr, err := udpConn1.ReadFrom(buf)
	assert.NoError(t, err)
	assert.Equal(t, buf[:n], respMsg1.Data)
	assert.Equal(t, addr.Host, msg1_host)
	assert.Equal(t, int(addr.Port), msg1_portInt)

	respMsg2 := &protocol.UDPMessage{
		SessionID: 2,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      msg2.Addr,
		Data:      []byte("white rose"),
	}
	receiveCh <- respMsg2
	n, addr, err = udpConn2.ReadFrom(buf)
	assert.NoError(t, err)
	assert.Equal(t, buf[:n], respMsg2.Data)
	assert.Equal(t, addr.Host, msg2_host)
	assert.Equal(t, int(addr.Port), msg2_portInt)

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
		buf := make([]byte, udpBufferSize)
		_, _, err := udpConn1.ReadFrom(buf)
		errChan <- err
	}()
	assert.NoError(t, udpConn1.Close())
	assert.Equal(t, <-errChan, io2.EOF)

	// Test close IO unblocks Receive() and blocks new UDP creation
	errChan = make(chan error, 1)
	go func() {
		buf := make([]byte, udpBufferSize)
		_, _, err := udpConn2.ReadFrom(buf)
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
