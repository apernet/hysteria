package outbounds

import (
	"errors"
	"net"
	"reflect"
	"testing"
)

var errWrongAddr = errors.New("wrong addr")

type mockPluggableOutbound struct{}

func (m *mockPluggableOutbound) DialTCP(reqAddr *AddrEx) (net.Conn, error) {
	if !reflect.DeepEqual(reqAddr, &AddrEx{
		Host:        "correct_host_1",
		Port:        34567,
		ResolveInfo: nil,
	}) {
		return nil, errWrongAddr
	}
	return nil, nil
}

func (m *mockPluggableOutbound) ListenUDP() (UDPConn, error) {
	return &mockUDPConn{}, nil
}

type mockUDPConn struct{}

func (u *mockUDPConn) ReadFrom(b []byte) (int, *AddrEx, error) {
	for i := range b {
		b[i] = 1
	}
	return len(b), &AddrEx{
		Host:        "correct_host_2",
		Port:        54321,
		ResolveInfo: nil,
	}, nil
}

func (u *mockUDPConn) WriteTo(b []byte, addr *AddrEx) (int, error) {
	if !reflect.DeepEqual(addr, &AddrEx{
		Host:        "correct_host_3",
		Port:        22334,
		ResolveInfo: nil,
	}) {
		return 0, errWrongAddr
	}
	return len(b), nil
}

func (u *mockUDPConn) Close() error {
	return nil
}

func TestPluggableOutboundAdapter(t *testing.T) {
	adapter := &PluggableOutboundAdapter{
		PluggableOutbound: &mockPluggableOutbound{},
	}
	// DialTCP with correct addr
	_, err := adapter.DialTCP("correct_host_1:34567")
	if err != nil {
		t.Fatal("DialTCP with correct addr failed", err)
	}
	// DialTCP with wrong addr
	_, err = adapter.DialTCP("wrong_host_1:34567")
	if err != errWrongAddr {
		t.Fatal("DialTCP with wrong addr should fail, got", err)
	}
	// ListenUDP
	uConn, err := adapter.ListenUDP()
	if err != nil {
		t.Fatal("ListenUDP failed", err)
	}
	// ReadFrom
	b := make([]byte, 10)
	n, addr, err := uConn.ReadFrom(b)
	if err != nil {
		t.Fatal("ReadFrom failed", err)
	}
	if n != 10 || addr != "correct_host_2:54321" {
		t.Fatalf("ReadFrom got wrong result, n: %d, addr: %s", n, addr)
	}
	// WriteTo with correct addr
	n, err = uConn.WriteTo(b, "correct_host_3:22334")
	if err != nil {
		t.Fatal("WriteTo with correct addr failed", err)
	}
	if n != 10 {
		t.Fatalf("WriteTo with correct addr got wrong result, n: %d", n)
	}
	// WriteTo with wrong addr
	n, err = uConn.WriteTo(b, "wrong_host_3:22334")
	if err != errWrongAddr {
		t.Fatal("WriteTo with wrong addr should fail, got", err)
	}
	// Close
	err = uConn.Close()
	if err != nil {
		t.Fatal("Close failed", err)
	}
}
