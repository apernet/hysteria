//go:build linux

package sockopts

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func Test_fdControlUnixSocketImpl(t *testing.T) {
	sockPath := "./fd_control_unix_socket_test.sock"
	defer os.Remove(sockPath)

	// Run test server
	cmd := exec.Command("python", "fd_control_unix_socket_test.py", sockPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if !assert.NoError(t, err) {
		return
	}
	defer cmd.Process.Kill()

	// Wait for the server to start
	time.Sleep(1 * time.Second)

	so := SocketOptions{
		FdControlUnixSocket: &sockPath,
	}
	conn, err := so.ListenUDP()
	if !assert.NoError(t, err) {
		return
	}
	defer conn.Close()

	err = controlUDPConn(conn.(*net.UDPConn), func(fd int) (err error) {
		rcvbuf, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err != nil {
			return err
		}
		// The test server called setsockopt(fd, SOL_SOCKET, SO_RCVBUF, 2500),
		// and kernel will double this value for getsockopt().
		assert.Equal(t, 5000, rcvbuf)
		return err
	})
	assert.NoError(t, err)
}
