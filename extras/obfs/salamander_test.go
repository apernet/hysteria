package obfs

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func BenchmarkSalamanderObfuscator_Obfuscate(b *testing.B) {
	o, _ := NewSalamanderObfuscator([]byte("average_password"))
	in := make([]byte, 1200)
	_, _ = rand.Read(in)
	out := make([]byte, 2048)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.Obfuscate(in, out)
	}
}

func BenchmarkSalamanderObfuscator_Deobfuscate(b *testing.B) {
	o, _ := NewSalamanderObfuscator([]byte("average_password"))
	in := make([]byte, 1200)
	_, _ = rand.Read(in)
	out := make([]byte, 2048)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		o.Deobfuscate(in, out)
	}
}

func TestSalamanderObfuscator(t *testing.T) {
	o, _ := NewSalamanderObfuscator([]byte("average_password"))
	in := make([]byte, 1200)
	oOut := make([]byte, 2048)
	dOut := make([]byte, 2048)
	for i := 0; i < 1000; i++ {
		_, _ = rand.Read(in)
		n := o.Obfuscate(in, oOut)
		if n == 0 {
			t.Fatal("Failed to obfuscate")
		}
		if n != len(in)+smSaltLen {
			t.Fatal("Wrong obfuscated length")
		}
		n = o.Deobfuscate(oOut[:n], dOut)
		if n == 0 {
			t.Fatal("Failed to deobfuscate")
		}
		if n != len(in) {
			t.Fatal("Wrong deobfuscated length")
		}
		if !bytes.Equal(in, dOut[:n]) {
			t.Fatal("Deobfuscated data mismatch")
		}
	}
}
