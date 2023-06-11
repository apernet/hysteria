package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

type CmdAuthProvider struct {
	Cmd string
}

func (p *CmdAuthProvider) Auth(addr net.Addr, auth []byte, sSend, sRecv uint64) (bool, string) {
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

type HTTPAuthProvider struct {
	Client *http.Client
	URL    string
}

type authReq struct {
	Addr    string `json:"addr"`
	Payload []byte `json:"payload"`
	Send    uint64 `json:"send"`
	Recv    uint64 `json:"recv"`
}

type authResp struct {
	OK  bool   `json:"ok"`
	Msg string `json:"msg"`
}

func (p *HTTPAuthProvider) Auth(addr net.Addr, auth []byte, sSend, sRecv uint64) (bool, string) {
	jbs, err := json.Marshal(&authReq{
		Addr:    addr.String(),
		Payload: auth,
		Send:    sSend,
		Recv:    sRecv,
	})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Error("Failed to marshal auth request")
		return false, "internal error"
	}
	resp, err := p.Client.Post(p.URL, "application/json", bytes.NewBuffer(jbs))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Error("Failed to send auth request")
		return false, "internal error"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logrus.WithFields(logrus.Fields{
			"code": resp.StatusCode,
		}).Error("Invalid status code from auth server")
		return false, "internal error"
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Error("Failed to read auth response")
		return false, "internal error"
	}
	var ar authResp
	err = json.Unmarshal(data, &ar)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Error("Failed to unmarshal auth response")
		return false, "internal error"
	}
	return ar.OK, ar.Msg
}
