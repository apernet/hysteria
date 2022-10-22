package obfs

import (
	"crypto/sha256"
	"math/rand"
	"sync"
	"time"
)

type Obfuscator interface {
	Deobfuscate(in []byte, out []byte) int
	Obfuscate(in []byte, out []byte) int
}

const xpSaltLen = 16

// XPlusObfuscator obfuscates payload using one-time keys generated from hashing a pre-shared key and random salt.
// Packet format: [salt][obfuscated payload]
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
	outLen := len(in) - xpSaltLen
	if outLen <= 0 || len(out) < outLen {
		return 0
	}
	key := sha256.Sum256(append(x.Key, in[:xpSaltLen]...))
	for i, c := range in[xpSaltLen:] {
		out[i] = c ^ key[i%sha256.Size]
	}
	return outLen
}

func (x *XPlusObfuscator) Obfuscate(in []byte, out []byte) int {
	outLen := len(in) + xpSaltLen
	if len(out) < outLen {
		return 0
	}
	x.lk.Lock()
	_, _ = x.RandSrc.Read(out[:xpSaltLen])
	x.lk.Unlock()
	key := sha256.Sum256(append(x.Key, out[:xpSaltLen]...))
	for i, c := range in {
		out[i+xpSaltLen] = c ^ key[i%sha256.Size]
	}
	return outLen
}
