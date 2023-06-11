package auth

import (
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/apernet/hysteria/core/cs"
	"github.com/yosuke-furukawa/json5/encoding/json5"
)

func PasswordAuthFunc(rawMsg json5.RawMessage) (cs.ConnectFunc, error) {
	var pwds []string
	err := json5.Unmarshal(rawMsg, &pwds)
	if err != nil {
		// not a string list, legacy format?
		var pwdConfig map[string]string
		err = json5.Unmarshal(rawMsg, &pwdConfig)
		if err != nil || len(pwdConfig["password"]) == 0 {
			// still no, invalid config
			return nil, errors.New("invalid config")
		}
		// yes it is
		pwds = []string{pwdConfig["password"]}
	}
	return func(addr net.Addr, auth []byte, sSend, sRecv uint64) (bool, string) {
		for _, pwd := range pwds {
			if string(auth) == pwd {
				return true, "Welcome"
			}
		}
		return false, "Wrong password"
	}, nil
}

func ExternalAuthFunc(rawMsg json5.RawMessage) (cs.ConnectFunc, error) {
	var extConfig map[string]string
	err := json5.Unmarshal(rawMsg, &extConfig)
	if err != nil {
		return nil, errors.New("invalid config")
	}
	if len(extConfig["http"]) != 0 {
		hp := &HTTPAuthProvider{
			Client: &http.Client{
				Timeout: 10 * time.Second,
			},
			URL: extConfig["http"],
		}
		return hp.Auth, nil
	} else if len(extConfig["cmd"]) != 0 {
		cp := &CmdAuthProvider{
			Cmd: extConfig["cmd"],
		}
		return cp.Auth, nil
	} else {
		return nil, errors.New("invalid config")
	}
}
