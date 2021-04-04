package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
)

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

func (p *HTTPAuthProvider) Auth(addr net.Addr, auth []byte, sSend uint64, sRecv uint64) (bool, string) {
	jbs, err := json.Marshal(&authReq{
		Addr:    addr.String(),
		Payload: auth,
		Send:    sSend,
		Recv:    sRecv,
	})
	if err != nil {
		return false, "Internal error"
	}
	resp, err := p.Client.Post(p.URL, "application/json", bytes.NewBuffer(jbs))
	if err != nil {
		return false, "Internal error"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "Auth endpoint error"
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, "Auth endpoint error"
	}
	var ar authResp
	err = json.Unmarshal(data, &ar)
	if err != nil {
		return false, "Auth endpoint error"
	}
	return ar.OK, ar.Msg
}
