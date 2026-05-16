package server

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkCopyBufferLog(b *testing.B) {
	srcData := make([]byte, 1024*1024) // 1MB
	for i := range srcData {
		srcData[i] = byte(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		src := bytes.NewReader(srcData)
		dst := io.Discard
		copyBufferLog(dst, src, func(n uint64) bool { return true })
	}
}
