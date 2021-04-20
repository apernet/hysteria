package obfs

type XORObfuscator []byte

func (x XORObfuscator) Deobfuscate(in []byte, out []byte) int {
	l := len(x)
	for i := range in {
		out[i] = in[i] ^ x[i%l]
	}
	return len(in)
}

func (x XORObfuscator) Obfuscate(p []byte) []byte {
	np := make([]byte, len(p))
	l := len(x)
	for i := range p {
		np[i] = p[i] ^ x[i%l]
	}
	return np
}
