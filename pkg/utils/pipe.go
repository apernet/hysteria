package utils

import (
	"io"
	"net"
	"time"
)

const PipeBufferSize = 65536

func Pipe(src, dst io.ReadWriter) error {
	buf := make([]byte, PipeBufferSize)
	for {
		rn, err := src.Read(buf)
		if rn > 0 {
			_, err := dst.Write(buf[:rn])
			if err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	}
}

func Pipe2Way(rw1, rw2 io.ReadWriter) error {
	errChan := make(chan error, 2)
	go func() {
		errChan <- Pipe(rw2, rw1)
	}()
	go func() {
		errChan <- Pipe(rw1, rw2)
	}()
	// We only need the first error
	return <-errChan
}

func PipePairWithTimeout(conn *net.TCPConn, stream io.ReadWriteCloser, timeout time.Duration) error {
	errChan := make(chan error, 2)
	// TCP to stream
	go func() {
		buf := make([]byte, PipeBufferSize)
		for {
			if timeout != 0 {
				_ = conn.SetDeadline(time.Now().Add(timeout))
			}
			rn, err := conn.Read(buf)
			if rn > 0 {
				_, err := stream.Write(buf[:rn])
				if err != nil {
					errChan <- err
					return
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	// Stream to TCP
	go func() {
		buf := make([]byte, PipeBufferSize)
		for {
			rn, err := stream.Read(buf)
			if rn > 0 {
				_, err := conn.Write(buf[:rn])
				if err != nil {
					errChan <- err
					return
				}
				if timeout != 0 {
					_ = conn.SetDeadline(time.Now().Add(timeout))
				}
			}
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	return <-errChan
}
