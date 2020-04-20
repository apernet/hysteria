package utils

import (
	"io"
	"sync/atomic"
)

const pipeBufferSize = 65536

func Pipe(src, dst io.ReadWriter, atomicCounter *uint64) error {
	buf := make([]byte, pipeBufferSize)
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
