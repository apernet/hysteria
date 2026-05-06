package realm

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAddr(t *testing.T) {
	tests := []struct {
		name             string
		raw              string
		rendezvousScheme string
		host             string
		port             string
		hostPort         string
		token            string
		realmID          string
		stunParam        string
		expectedBaseURL  string
	}{
		{
			name:             "https default port",
			raw:              "realm://secret@example.com/my-realm?stun=stun.example.com:3478",
			rendezvousScheme: "https",
			host:             "example.com",
			port:             "443",
			hostPort:         "example.com:443",
			token:            "secret",
			realmID:          "my-realm",
			stunParam:        "stun.example.com:3478",
			expectedBaseURL:  "https://example.com:443",
		},
		{
			name:             "http default port",
			raw:              "realm+http://secret@example.com/my-realm",
			rendezvousScheme: "http",
			host:             "example.com",
			port:             "80",
			hostPort:         "example.com:80",
			token:            "secret",
			realmID:          "my-realm",
			expectedBaseURL:  "http://example.com:80",
		},
		{
			name:             "explicit ipv6 port",
			raw:              "realm://s3cr3t@[2001:db8::1]:8443/realm",
			rendezvousScheme: "https",
			host:             "2001:db8::1",
			port:             "8443",
			hostPort:         "[2001:db8::1]:8443",
			token:            "s3cr3t",
			realmID:          "realm",
			expectedBaseURL:  "https://[2001:db8::1]:8443",
		},
		{
			name:             "escaped token and realm",
			raw:              "realm://token%3Avalue@example.com/realm%20id",
			rendezvousScheme: "https",
			host:             "example.com",
			port:             "443",
			hostPort:         "example.com:443",
			token:            "token:value",
			realmID:          "realm id",
			expectedBaseURL:  "https://example.com:443",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := ParseAddr(tc.raw)
			require.NoError(t, err)
			assert.Equal(t, tc.rendezvousScheme, addr.RendezvousScheme)
			assert.Equal(t, tc.host, addr.Host)
			assert.Equal(t, tc.port, addr.Port)
			assert.Equal(t, tc.hostPort, addr.HostPort)
			assert.Equal(t, tc.token, addr.Token)
			assert.Equal(t, tc.realmID, addr.RealmID)
			assert.Equal(t, tc.stunParam, addr.Params.Get("stun"))
			assert.Equal(t, tc.expectedBaseURL, addr.BaseURL().String())
		})
	}
}

func TestParseAddrLocalPort(t *testing.T) {
	addr, err := ParseAddr("realm://secret@example.com/realm?lport=4433")
	require.NoError(t, err)
	assert.Equal(t, 4433, addr.LocalPort)

	addr, err = ParseAddr("realm://secret@example.com/realm")
	require.NoError(t, err)
	assert.Equal(t, 0, addr.LocalPort)
}

func TestParseAddrInvalid(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		err  error
	}{
		{name: "unsupported scheme", raw: "hysteria2://secret@example.com/realm", err: ErrInvalidScheme},
		{name: "missing token", raw: "realm://example.com/realm", err: ErrInvalidAddr},
		{name: "missing host", raw: "realm://secret@/realm", err: ErrInvalidAddr},
		{name: "missing realm", raw: "realm://secret@example.com", err: ErrInvalidAddr},
		{name: "extra path segment", raw: "realm://secret@example.com/realm/extra", err: ErrInvalidAddr},
		{name: "escaped slash in realm", raw: "realm://secret@example.com/realm%2Fextra", err: ErrInvalidAddr},
		{name: "invalid port", raw: "realm://secret@example.com:70000/realm", err: ErrInvalidAddr},
		{name: "fragment", raw: "realm://secret@example.com/realm#frag", err: ErrInvalidAddr},
		{name: "lport not a number", raw: "realm://secret@example.com/realm?lport=abc", err: ErrInvalidAddr},
		{name: "lport zero", raw: "realm://secret@example.com/realm?lport=0", err: ErrInvalidAddr},
		{name: "lport too high", raw: "realm://secret@example.com/realm?lport=65536", err: ErrInvalidAddr},
		{name: "lport repeated", raw: "realm://secret@example.com/realm?lport=1234&lport=2345", err: ErrInvalidAddr},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAddr(tc.raw)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.err), "expected %v, got %v", tc.err, err)
		})
	}
}
