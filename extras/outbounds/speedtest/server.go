package speedtest

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	chunkSize = 64 * 1024
)

// NewServerConn creates a new "pseudo" connection that implements the speed test protocol.
// It's called "pseudo" because it's not a real TCP connection - everything is done in memory.
func NewServerConn() net.Conn {
	rConn, iConn := net.Pipe() // return conn & internal conn
	// Start the server logic
	go server(iConn)
	return rConn
}

func server(conn net.Conn) error {
	defer conn.Close()
	// First byte determines the request type
	var typ [1]byte
	if _, err := io.ReadFull(conn, typ[:]); err != nil {
		return err
	}
	switch typ[0] {
	case typeDownload:
		return handleDownload(conn)
	case typeUpload:
		return handleUpload(conn)
	default:
		return fmt.Errorf("unknown request type: %d", typ[0])
	}
}

// handleDownload reads the download request and sends the requested amount of data.
func handleDownload(conn net.Conn) error {
	l, err := readDownloadRequest(conn)
	if err != nil {
		return err
	}
	err = writeDownloadResponse(conn, true, "OK")
	if err != nil {
		return err
	}
	buf := make([]byte, chunkSize)
	// Fill the buffer with random data.
	// For now, we only do it once and repeat the same data for performance reasons.
	_, err = rand.Read(buf)
	if err != nil {
		return err
	}
	remaining := l
	for remaining > 0 {
		n := remaining
		if n > chunkSize {
			n = chunkSize
		}
		_, err := conn.Write(buf[:n])
		if err != nil {
			return err
		}
		remaining -= n
	}
	return nil
}

// handleUpload reads the upload request, reads & discards the requested amount of data,
// and sends the upload summary.
func handleUpload(conn net.Conn) error {
	l, err := readUploadRequest(conn)
	if err != nil {
		return err
	}
	err = writeUploadResponse(conn, true, "OK")
	if err != nil {
		return err
	}
	buf := make([]byte, chunkSize)
	startTime := time.Now()
	remaining := l
	for remaining > 0 {
		n := remaining
		if n > chunkSize {
			n = chunkSize
		}
		rn, err := conn.Read(buf[:n])
		remaining -= uint32(rn)
		if err != nil && !(remaining == 0 && err == io.EOF) {
			return err
		}
	}
	return writeUploadSummary(conn, time.Since(startTime), l)
}
