package realm

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	SchemeHTTPS = "realm"
	SchemeHTTP  = "realm+http"

	defaultHTTPSPort = "443"
	defaultHTTPPort  = "80"
)

var (
	ErrInvalidScheme = errors.New("invalid realm address scheme")
	ErrInvalidAddr   = errors.New("invalid realm address")
)

// Addr is a parsed Hysteria Realms rendezvous address.
type Addr struct {
	// Scheme is either SchemeHTTPS or SchemeHTTP.
	Scheme string
	// HTTP scheme used to contact the rendezvous server: "https" or "http".
	RendezvousScheme string
	Token            string
	Host             string
	Port             string
	HostPort         string
	RealmID          string
	// LocalPort is the requested local UDP source port from the "lport" query
	// param. 0 means unset (use an ephemeral port).
	LocalPort int
	Params    url.Values
}

// ParseAddr parses realm and realm+http addresses.
func ParseAddr(s string) (*Addr, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAddr, err)
	}

	rendezvousScheme, defaultPort, err := schemeInfo(u.Scheme)
	if err != nil {
		return nil, err
	}
	if u.Opaque != "" || u.Host == "" {
		return nil, fmt.Errorf("%w: rendezvous host is required", ErrInvalidAddr)
	}
	if u.User == nil {
		return nil, fmt.Errorf("%w: realm token is required", ErrInvalidAddr)
	}
	token, err := url.PathUnescape(u.User.String())
	if err != nil || token == "" {
		return nil, fmt.Errorf("%w: realm token is required", ErrInvalidAddr)
	}
	if u.RawQuery != "" && u.ForceQuery {
		return nil, fmt.Errorf("%w: empty query marker is not supported", ErrInvalidAddr)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return nil, fmt.Errorf("%w: fragment is not supported", ErrInvalidAddr)
	}

	realmID, err := parseRealmID(u)
	if err != nil {
		return nil, err
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: rendezvous host is required", ErrInvalidAddr)
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	if err := validatePort(port); err != nil {
		return nil, err
	}
	hostPort := net.JoinHostPort(host, port)
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		return nil, fmt.Errorf("%w: invalid rendezvous host or port", ErrInvalidAddr)
	}

	params := cloneValues(u.Query())
	localPort, err := parseLocalPort(params["lport"])
	if err != nil {
		return nil, err
	}

	return &Addr{
		Scheme:           u.Scheme,
		RendezvousScheme: rendezvousScheme,
		Token:            token,
		Host:             host,
		Port:             port,
		HostPort:         hostPort,
		RealmID:          realmID,
		LocalPort:        localPort,
		Params:           params,
	}, nil
}

func parseLocalPort(values []string) (int, error) {
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) > 1 {
		return 0, fmt.Errorf("%w: lport must be specified at most once", ErrInvalidAddr)
	}
	p, err := strconv.Atoi(values[0])
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("%w: lport must be an integer in 1-65535", ErrInvalidAddr)
	}
	return p, nil
}

func validatePort(port string) error {
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return fmt.Errorf("%w: invalid rendezvous port", ErrInvalidAddr)
	}
	return nil
}

// BaseURL returns the base URL for the rendezvous server.
func (a *Addr) BaseURL() *url.URL {
	if a == nil {
		return nil
	}
	return &url.URL{
		Scheme: a.RendezvousScheme,
		Host:   a.HostPort,
	}
}

func schemeInfo(scheme string) (httpScheme, defaultPort string, err error) {
	switch scheme {
	case SchemeHTTPS:
		return "https", defaultHTTPSPort, nil
	case SchemeHTTP:
		return "http", defaultHTTPPort, nil
	default:
		return "", "", ErrInvalidScheme
	}
}

func parseRealmID(u *url.URL) (string, error) {
	if u.Path == "" || u.Path == "/" {
		return "", fmt.Errorf("%w: realm id is required", ErrInvalidAddr)
	}
	trimmed := strings.TrimPrefix(u.EscapedPath(), "/")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", fmt.Errorf("%w: realm id must be a single path segment", ErrInvalidAddr)
	}
	realmID, err := url.PathUnescape(trimmed)
	if err != nil || realmID == "" || strings.Contains(realmID, "/") {
		return "", fmt.Errorf("%w: realm id must be a single path segment", ErrInvalidAddr)
	}
	return realmID, nil
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, values := range v {
		out[k] = append([]string(nil), values...)
	}
	return out
}
