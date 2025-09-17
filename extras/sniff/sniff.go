package sniff

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/apernet/hysteria/core/v2/server"
	quicInternal "github.com/apernet/hysteria/extras/v2/sniff/internal/quic"
	"github.com/apernet/hysteria/extras/v2/utils"
)

const (
	sniffDefaultTimeout = 4 * time.Second
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
	TCPPorts      utils.PortUnion
	UDPPorts      utils.PortUnion
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
	if strings.HasPrefix(reqAddr, "@") {
		return false
	}
	host, port, err := net.SplitHostPort(reqAddr)
	if err != nil {
		return false
	}
	if !h.RewriteDomain && net.ParseIP(host) == nil {
		// Is a domain and domain rewriting is disabled
		return false
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if isUDP {
		return h.UDPPorts == nil || h.UDPPorts.Contains(uint16(portNum))
	} else {
		return h.TCPPorts == nil || h.TCPPorts.Contains(uint16(portNum))
	}
}

func (h *Sniffer) TCP(stream server.HyStream, reqAddr *string) ([]byte, error) {
	var err error
	if h.Timeout == 0 {
		err = stream.SetReadDeadline(time.Now().Add(sniffDefaultTimeout))
	} else {
		err = stream.SetReadDeadline(time.Now().Add(h.Timeout))
	}
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
		// HTTP
		tr := &teeReader{Stream: stream, Pre: pre}
		req, _ := http.ReadRequest(bufio.NewReader(tr))
		if req != nil && req.Host != "" {
			// req.Host can be host:port, in which case we need to extract the host part
			host, _, err := net.SplitHostPort(req.Host)
			if err != nil {
				// No port, just use the whole string
				host = req.Host
			}
			_, port, err := net.SplitHostPort(*reqAddr)
			if err != nil {
				return nil, err
			}
			*reqAddr = net.JoinHostPort(host, port)
		}
		return tr.Buffer(), nil
	} else if h.isTLS(pre) {
		// TLS
		// Need to read 2 more bytes (content length)
		pre = append(pre, make([]byte, 2)...)
		n, err = io.ReadFull(stream, pre[3:])
		if err != nil {
			// Not enough within the timeout, just return what we have
			return pre[:3+n], nil
		}
		contentLength := int(pre[3])<<8 | int(pre[4])
		pre = append(pre, make([]byte, contentLength)...)
		n, err = io.ReadFull(stream, pre[5:])
		if err != nil {
			// Not enough within the timeout, just return what we have
			return pre[:5+n], nil
		}
		clientHello := utls.UnmarshalClientHello(pre[5:])
		if clientHello != nil && clientHello.ServerName != "" {
			_, port, err := net.SplitHostPort(*reqAddr)
			if err != nil {
				return nil, err
			}
			*reqAddr = net.JoinHostPort(clientHello.ServerName, port)
		}
		return pre, nil
	} else {
		// Unrecognized protocol, just return what we have
		return pre, nil
	}
}

func (h *Sniffer) UDP(data []byte, reqAddr *string) error {
	pl, err := quicInternal.ReadCryptoPayload(data)
	if err != nil || len(pl) < 4 || pl[0] != 0x01 {
		// Unrecognized protocol, incomplete payload or not a client hello
		return nil
	}
	clientHello := utls.UnmarshalClientHello(pl)
	if clientHello != nil && clientHello.ServerName != "" {
		_, port, err := net.SplitHostPort(*reqAddr)
		if err != nil {
			return err
		}
		*reqAddr = net.JoinHostPort(clientHello.ServerName, port)
	}
	return nil
}

type teeReader struct {
	Stream server.HyStream
	Pre    []byte

	buf []byte
}

func (c *teeReader) Read(b []byte) (n int, err error) {
	if len(c.Pre) > 0 {
		n = copy(b, c.Pre)
		c.Pre = c.Pre[n:]
		c.buf = append(c.buf, b[:n]...)
		return n, nil
	}
	n, err = c.Stream.Read(b)
	if n > 0 {
		c.buf = append(c.buf, b[:n]...)
	}
	return n, err
}

func (c *teeReader) Buffer() []byte {
	return append(c.Pre, c.buf...)
}
