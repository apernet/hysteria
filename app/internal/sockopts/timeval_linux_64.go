//go:build linux && (amd64 || arm64 || loong64 || mips64 || mips64le || ppc64 || ppc64le || riscv64 || s390x || sparc64)

package sockopts

import (
	"golang.org/x/sys/unix"
)

func unixTimeval() unix.Timeval {
	timeUsec := fdControlUnixTimeout.Microseconds()
	return unix.Timeval{
		Sec:  timeUsec / 1e6,
		Usec: timeUsec % 1e6,
	}
}
