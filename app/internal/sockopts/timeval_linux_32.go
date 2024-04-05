//go:build linux && (386 || arm || mips || mipsle || ppc)

package sockopts

import (
	"golang.org/x/sys/unix"
)

func unixTimeval() unix.Timeval {
	timeUsec := fdControlUnixTimeout.Microseconds()
	return unix.Timeval{
		Sec:  int32(timeUsec / 1e6),
		Usec: int32(timeUsec % 1e6),
	}
}
