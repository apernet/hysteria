package utils

import (
	"io"
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
