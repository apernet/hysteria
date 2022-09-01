package obfs

type DummyObfuscator struct{}

func NewDummyObfuscator() *DummyObfuscator {
	return &DummyObfuscator{}
}

func (x *DummyObfuscator) Deobfuscate(in []byte, out []byte) int {
	pLen := len(in)
	if pLen <= 0 || len(out) < pLen {
		// Invalid
		return 0
	}
	copy(out, in)
	return pLen
}

func (x *DummyObfuscator) Obfuscate(in []byte, out []byte) int {
	return copy(out, in)
}
