package obfs

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

const (
	smPSKMinLen = 4
	smSaltLen   = 8
	smKeyLen    = blake2b.Size256
)

var _ obfuscator = (*salamanderObfuscator)(nil)

var ErrPSKTooShort = fmt.Errorf("PSK must be at least %d bytes", smPSKMinLen)

// salamanderObfuscator is an obfuscator that obfuscates each packet with
// the BLAKE2b-256 hash of a pre-shared key combined with a random salt.
// Packet format: [8-byte salt][payload]
type salamanderObfuscator struct {
	PSK     []byte
	RandSrc *rand.Rand

	lk       sync.Mutex
	keyInput []byte
}

func newSalamanderObfuscator(psk []byte) (*salamanderObfuscator, error) {
	if len(psk) < smPSKMinLen {
		return nil, ErrPSKTooShort
	}
	pskCopy := append([]byte(nil), psk...)
	keyInput := make([]byte, len(pskCopy)+smSaltLen)
	copy(keyInput, pskCopy)
	return &salamanderObfuscator{
		PSK:      pskCopy,
		RandSrc:  rand.New(rand.NewSource(time.Now().UnixNano())),
		keyInput: keyInput,
	}, nil
}

// WrapPacketConnSalamander wraps conn with Salamander obfuscation: each
// outbound packet is XOR'd with BLAKE2b-256(PSK || random salt) and the
// 8-byte salt is prepended on the wire.
func WrapPacketConnSalamander(conn net.PacketConn, psk []byte) (net.PacketConn, error) {
	ob, err := newSalamanderObfuscator(psk)
	if err != nil {
		return nil, err
	}
	return wrapPacketConn(conn, ob), nil
}

func (o *salamanderObfuscator) Obfuscate(in, out []byte) int {
	outLen := len(in) + smSaltLen
	if len(out) < outLen {
		return 0
	}
	o.lk.Lock()
	_, _ = o.RandSrc.Read(out[:smSaltLen])
	key := o.keyLocked(out[:smSaltLen])
	o.lk.Unlock()
	for i, c := range in {
		out[i+smSaltLen] = c ^ key[i%smKeyLen]
	}
	return outLen
}

func (o *salamanderObfuscator) Deobfuscate(in, out []byte) int {
	outLen := len(in) - smSaltLen
	if outLen <= 0 || len(out) < outLen {
		return 0
	}
	o.lk.Lock()
	key := o.keyLocked(in[:smSaltLen])
	o.lk.Unlock()
	for i, c := range in[smSaltLen:] {
		out[i] = c ^ key[i%smKeyLen]
	}
	return outLen
}

func (o *salamanderObfuscator) keyLocked(salt []byte) [smKeyLen]byte {
	copy(o.keyInput[len(o.PSK):], salt[:smSaltLen])
	return blake2b.Sum256(o.keyInput)
}
