package auth

import (
	"net"
	"strings"

	"github.com/apernet/hysteria/core/server"
)

const (
	userPassSeparator = ":"
)

var _ server.Authenticator = &UserPassAuthenticator{}

// UserPassAuthenticator checks the provided auth string against a map of username/password pairs.
// The format of the auth string must be "username:password".
type UserPassAuthenticator struct {
	Users map[string]string
}

func (a *UserPassAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string) {
	u, p, ok := splitUserPass(auth)
	if !ok {
		return false, ""
	}
	rp, ok := a.Users[u]
	if !ok || rp != p {
		return false, ""
	}
	return true, u
}

func splitUserPass(auth string) (user, pass string, ok bool) {
	rs := strings.SplitN(auth, userPassSeparator, 2)
	if len(rs) != 2 {
		return "", "", false
	}
	return rs[0], rs[1], true
}
