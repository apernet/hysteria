package outbounds

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	httpRequestTimeout = 10 * time.Second
)

var (
	errHTTPUDPNotSupported   = errors.New("UDP not supported by HTTP proxy")
	errHTTPUnsupportedScheme = errors.New("unsupported scheme for HTTP proxy (use http:// or https://)")
)

type errHTTPRequestFailed struct {
	Status int
}

func (e errHTTPRequestFailed) Error() string {
	return fmt.Sprintf("HTTP request failed: %d", e.Status)
}

// httpOutbound is a PluggableOutbound that connects to the target using
// an HTTP/HTTPS proxy server (that supports the CONNECT method).
// HTTP proxies don't support UDP by design, so this outbound will reject
// any UDP request with errHTTPUDPNotSupported.
// Since HTTP proxies support using either IP or domain name as the target
// address, it will ignore ResolveInfo in AddrEx and always only use Host.
type httpOutbound struct {
	Dialer     *net.Dialer
	Addr       string
	HTTPS      bool
	Insecure   bool
	ServerName string
	BasicAuth  string // This is after Base64 encoding
}

func NewHTTPOutbound(proxyURL string, insecure bool) (PluggableOutbound, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errHTTPUnsupportedScheme
	}
	addr := u.Host
	if u.Port() == "" {
		if u.Scheme == "http" {
			addr = net.JoinHostPort(u.Host, "80")
		} else {
			addr = net.JoinHostPort(u.Host, "443")
		}
	}
	var basicAuth string
	if u.User != nil {
		username := u.User.Username()
		password, _ := u.User.Password()
		basicAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}
	return &httpOutbound{
		Dialer:     &net.Dialer{Timeout: defaultDialerTimeout},
		Addr:       addr,
		HTTPS:      u.Scheme == "https",
		Insecure:   insecure,
		ServerName: u.Hostname(),
		BasicAuth:  basicAuth,
	}, nil
}

func (o *httpOutbound) dial() (net.Conn, error) {
	conn, err := o.Dialer.Dial("tcp", o.Addr)
	if err != nil {
		return nil, err
	}
	if o.HTTPS {
		// Wrap the connection with TLS if the proxy is HTTPS.
		conn = tls.Client(conn, &tls.Config{
			InsecureSkipVerify: o.Insecure,
			ServerName:         o.Addr,
		})
	}
	return conn, nil
}

func (o *httpOutbound) addrExToRequest(reqAddr *AddrEx) (*http.Request, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Host: net.JoinHostPort(reqAddr.Host, strconv.Itoa(int(reqAddr.Port))),
		},
		Header: http.Header{
			"Proxy-Connection": []string{"Keep-Alive"},
		},
	}
	if o.BasicAuth != "" {
		req.Header.Add("Proxy-Authorization", o.BasicAuth)
	}
	return req, nil
}

func (o *httpOutbound) TCP(reqAddr *AddrEx) (net.Conn, error) {
	req, err := o.addrExToRequest(reqAddr)
	if err != nil {
		return nil, err
	}
	conn, err := o.dial()
	if err != nil {
		return nil, err
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(httpRequestTimeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	bufReader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(bufReader, req)
	if resp != nil {
		// Don't need response body here.
		_ = resp.Body.Close()
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, errHTTPRequestFailed{resp.StatusCode}
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if bufReader.Buffered() > 0 {
		// There is still data in the buffered reader.
		// We need to get it out and put it into a cachedConn,
		// so that handleConnect can read it.
		data := make([]byte, bufReader.Buffered())
		_, err := io.ReadFull(bufReader, data)
		if err != nil {
			// Read from buffer failed, is this possible?
			_ = conn.Close()
			return nil, err
		}
		cachedConn := &cachedConn{
			Conn:   conn,
			Buffer: *bytes.NewBuffer(data),
		}
		return cachedConn, nil
	} else {
		return conn, nil
	}
}

func (o *httpOutbound) UDP(reqAddr *AddrEx) (UDPConn, error) {
	return nil, errHTTPUDPNotSupported
}

// cachedConn is a net.Conn wrapper that first Read()s from a buffer,
// and then from the underlying net.Conn when the buffer is drained.
type cachedConn struct {
	net.Conn
	Buffer bytes.Buffer
}

func (c *cachedConn) Read(b []byte) (int, error) {
	if c.Buffer.Len() > 0 {
		n, err := c.Buffer.Read(b)
		if err == io.EOF {
			// Buffer is drained, hide it from the caller
			err = nil
		}
		return n, err
	}
	return c.Conn.Read(b)
}
