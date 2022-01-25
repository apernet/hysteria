package auth

import (
	"github.com/sirupsen/logrus"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

type CmdAuthProvider struct {
	Cmd string
}

func (p *CmdAuthProvider) Auth(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string) {
	cmd := exec.Command(p.Cmd, addr.String(), string(auth), strconv.Itoa(int(sSend)), strconv.Itoa(int(sRecv)))
	out, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return false, strings.TrimSpace(string(out))
		} else {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Error("Failed to execute auth command")
			return false, "internal error"
		}
	} else {
		return true, strings.TrimSpace(string(out))
	}
}
