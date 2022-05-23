//go:build !linux

package tunconf

func SetAddress(name string, ip, mask []byte) error { return nil }
