package auth

import (
	"net"

	"github.com/apernet/hysteria/core/v2/server"
)

var _ server.Authenticator = &PasswordAuthenticator{}

// PasswordAuthenticator is a simple authenticator that checks the password against a single string.
type PasswordAuthenticator struct {
	Password string
}

func (a *PasswordAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	if auth == a.Password {
		return true, "user"
	} else {
		return false, ""
	}
}
