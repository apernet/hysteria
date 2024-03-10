package speedtest

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type Client struct {
	Conn net.Conn
}

// Download requests the server to send l bytes of data.
// The callback function cb is called every second with the time since the last call,
// and the number of bytes received in that time.
func (c *Client) Download(l uint32, cb func(time.Duration, uint32, bool)) error {
	err := writeDownloadRequest(c.Conn, l)
	if err != nil {
		return err
	}
	ok, msg, err := readDownloadResponse(c.Conn)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("server rejected download request: %s", msg)
	}
	var counter uint32
	stopChan := make(chan struct{})
	defer close(stopChan)
	// Call the callback function every second,
	// with the time since the last call and the number of bytes received in that time.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		t := time.Now()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				cb(time.Since(t), atomic.SwapUint32(&counter, 0), false)
				t = time.Now()
			}
		}
	}()
	buf := make([]byte, chunkSize)
	startTime := time.Now()
	remaining := l
	for remaining > 0 {
		n := remaining
		if n > chunkSize {
			n = chunkSize
		}
		rn, err := c.Conn.Read(buf[:n])
		remaining -= uint32(rn)
		atomic.AddUint32(&counter, uint32(rn))
		if err != nil && !(remaining == 0 && err == io.EOF) {
			return err
		}
	}
	// One last call to the callback function to report the total time and bytes received.
	cb(time.Since(startTime), l, true)
	return nil
}

// Upload requests the server to receive l bytes of data.
// The callback function cb is called every second with the time since the last call,
// and the number of bytes sent in that time.
func (c *Client) Upload(l uint32, cb func(time.Duration, uint32, bool)) error {
	err := writeUploadRequest(c.Conn, l)
	if err != nil {
		return err
	}
	ok, msg, err := readUploadResponse(c.Conn)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("server rejected upload request: %s", msg)
	}
	var counter uint32
	stopChan := make(chan struct{})
	defer close(stopChan)
	// Call the callback function every second,
	// with the time since the last call and the number of bytes sent in that time.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		t := time.Now()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				cb(time.Since(t), atomic.SwapUint32(&counter, 0), false)
				t = time.Now()
			}
		}
	}()
	buf := make([]byte, chunkSize)
	remaining := l
	for remaining > 0 {
		n := remaining
		if n > chunkSize {
			n = chunkSize
		}
		_, err := c.Conn.Write(buf[:n])
		if err != nil {
			return err
		}
		remaining -= n
		atomic.AddUint32(&counter, n)
	}
	// Now we should receive the upload summary from the server.
	elapsed, received, err := readUploadSummary(c.Conn)
	if err != nil {
		return err
	}
	// One last call to the callback function to report the total time and bytes sent.
	cb(elapsed, received, true)
	return nil
}
