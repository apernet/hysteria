package utils

import (
	"io"
	"sync/atomic"
)

const PipeBufferSize = 65536

func Pipe(src, dst io.ReadWriter, atomicCounter *uint64) error {
	buf := make([]byte, PipeBufferSize)
	for {
		rn, err := src.Read(buf)
		if rn > 0 {
			wn, err := dst.Write(buf[:rn])
			if atomicCounter != nil {
				atomic.AddUint64(atomicCounter, uint64(wn))
			}
			if err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	}
}

func PipePair(rw1, rw2 io.ReadWriter, rw1WriteCounter, rw2WriteCounter *uint64) error {
	errChan := make(chan error, 2)
	go func() {
		errChan <- Pipe(rw2, rw1, rw1WriteCounter)
	}()
	go func() {
		errChan <- Pipe(rw1, rw2, rw2WriteCounter)
	}()
	// We only need the first error
	return <-errChan
}
