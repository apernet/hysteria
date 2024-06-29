package sniff

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/quic-go"
)

var _ server.RequestHook = (*Sniffer)(nil)

// Sniffer is a server core RequestHook that performs packet inspection and possibly
// rewrites the request address based on what's in the protocol header.
// This is mainly for inbounds that inherently cannot get domain information (e.g. TUN),
// in which case sniffing can restore the domains and apply ACLs correctly.
// Currently supports HTTP, HTTPS (TLS) and QUIC.
type Sniffer struct {
	Timeout       time.Duration
	RewriteDomain bool // Whether to rewrite the address even when it's already a domain
}

func (h *Sniffer) isDomain(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return net.ParseIP(host) == nil
}

func (h *Sniffer) isHTTP(buf []byte) bool {
	if len(buf) < 3 {
		return false
	}
	// First 3 bytes should be English letters (whatever HTTP method)
	for _, b := range buf[:3] {
		if (b < 'A' || b > 'Z') && (b < 'a' || b > 'z') {
			return false
		}
	}
	return true
}

func (h *Sniffer) isTLS(buf []byte) bool {
	if len(buf) < 3 {
		return false
	}
	return buf[0] >= 0x16 && buf[0] <= 0x17 &&
		buf[1] == 0x03 && buf[2] <= 0x09
}

func (h *Sniffer) Check(isUDP bool, reqAddr string) bool {
	// @ means it's internal (e.g. speed test)
	return !strings.HasPrefix(reqAddr, "@") && !isUDP && (h.RewriteDomain || !h.isDomain(reqAddr))
}

func (h *Sniffer) TCP(stream quic.Stream, reqAddr *string) ([]byte, error) {
	err := stream.SetReadDeadline(time.Now().Add(h.Timeout))
	if err != nil {
		return nil, err
	}
	// Make sure to reset the deadline after sniffing
	defer stream.SetReadDeadline(time.Time{})
	// Read 3 bytes to determine the protocol
	pre := make([]byte, 3)
	n, err := io.ReadFull(stream, pre)
	if err != nil {
		// Not enough within the timeout, just return what we have
		return pre[:n], nil
	}
	if h.isHTTP(pre) {
		fConn := &fakeConn{Stream: stream, Pre: pre}
		req, _ := http.ReadRequest(bufio.NewReader(fConn))
		if req != nil && req.Host != "" {
			_, port, err := net.SplitHostPort(*reqAddr)
			if err != nil {
				return nil, err
			}
			*reqAddr = net.JoinHostPort(req.Host, port)
		}
		return fConn.Buffer, nil
	} else if h.isTLS(pre) {
		fConn := &fakeConn{Stream: stream, Pre: pre}
		var clientHello *tls.ClientHelloInfo
		_ = tls.Server(fConn, &tls.Config{
			GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				clientHello = info
				return nil, nil
			},
		}).HandshakeContext(context.Background())
		if clientHello != nil && clientHello.ServerName != "" {
			_, port, err := net.SplitHostPort(*reqAddr)
			if err != nil {
				return nil, err
			}
			*reqAddr = net.JoinHostPort(clientHello.ServerName, port)
		}
		return fConn.Buffer, nil
	} else {
		// Unrecognized protocol, just return what we have
		return pre, nil
	}
}

func (h *Sniffer) UDP(data []byte, reqAddr *string) error {
	return nil
}

type fakeConn struct {
	Stream quic.Stream
	Pre    []byte
	Buffer []byte
}

func (c *fakeConn) Read(b []byte) (n int, err error) {
	if len(c.Pre) > 0 {
		n = copy(b, c.Pre)
		c.Pre = c.Pre[n:]
		c.Buffer = append(c.Buffer, b[:n]...)
		return n, nil
	}
	n, err = c.Stream.Read(b)
	if n > 0 {
		c.Buffer = append(c.Buffer, b[:n]...)
	}
	return n, err
}

func (c *fakeConn) Write(b []byte) (n int, err error) {
	// Do not write anything, pretend it's successful
	return len(b), nil
}

func (c *fakeConn) Close() error {
	// Do not close the stream
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr {
	// Doesn't matter
	return nil
}

func (c *fakeConn) RemoteAddr() net.Addr {
	// Doesn't matter
	return nil
}

func (c *fakeConn) SetDeadline(t time.Time) error {
	return c.Stream.SetReadDeadline(t)
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	return c.Stream.SetReadDeadline(t)
}

func (c *fakeConn) SetWriteDeadline(t time.Time) error {
	return c.Stream.SetWriteDeadline(t)
}
