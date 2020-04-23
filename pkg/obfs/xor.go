package obfs

type XORObfuscator []byte

func (x XORObfuscator) Deobfuscate(buf []byte, n int) int {
	l := len(x)
	for i := range buf {
		buf[i] ^= x[i%l]
	}
	return n
}

func (x XORObfuscator) Obfuscate(p []byte) []byte {
	np := make([]byte, len(p))
	l := len(x)
	for i := range p {
		np[i] = p[i] ^ x[i%l]
	}
	return np
}
