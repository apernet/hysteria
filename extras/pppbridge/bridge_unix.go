//go:build !windows

package pppbridge

import (
	"io"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
)

const bridgeIOMode = "pty"

func (b *Bridge) startProcess(cmd *exec.Cmd) (childReader io.Reader, childWriter io.WriteCloser, cleanup func(), err error) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, nil, nil, err
	}
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		tty.Close()
		ptmx.Close()
		return nil, nil, nil, err
	}
	tty.Close()
	return ptmx, ptmx, func() { ptmx.Close() }, nil
}
