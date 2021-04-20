package obfs

import (
	"crypto/sha256"
	"math/rand"
	"sync"
	"time"
)

// [salt(16)][obfuscated payload]

type XPlusObfuscator struct {
	Key     []byte
	RandSrc *rand.Rand

	lk sync.Mutex
}

func NewXPlusObfuscator(key []byte) *XPlusObfuscator {
	return &XPlusObfuscator{
		Key:     key,
		RandSrc: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (x *XPlusObfuscator) Deobfuscate(in []byte, out []byte) int {
	pLen := len(in) - 16
	if pLen <= 0 || len(out) < pLen {
		// Invalid
		return 0
	}
	key := sha256.Sum256(append(x.Key, in[:16]...))
	// Deobfuscate the payload
	for i, c := range in[16:] {
		out[i] = c ^ key[i%sha256.Size]
	}
	return pLen
}

func (x *XPlusObfuscator) Obfuscate(p []byte) []byte {
	pLen := len(p)
	buf := make([]byte, 16+pLen)
	x.lk.Lock()
	_, _ = x.RandSrc.Read(buf[:16]) // salt
	x.lk.Unlock()
	// Obfuscate the payload
	key := sha256.Sum256(append(x.Key, buf[:16]...))
	for i, c := range p {
		buf[i+16] = c ^ key[i%sha256.Size]
	}
	return buf
}
