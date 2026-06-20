package trafficlogger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apernet/hysteria/extras/v2/outbounds"
)

const testSecret = "s3cr3t"

func doReq(t *testing.T, h http.Handler, method, path, secret, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if secret != "" {
		req.Header.Set("Authorization", secret)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestOutboundAPI(t *testing.T) {
	puo := outbounds.NewPerUserOutbounds()
	srv := NewTrafficStatsServerWithOutbounds(testSecret, puo)

	// Unauthorized without the secret.
	rec := doReq(t, srv, http.MethodGet, "/outbound", "", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// Empty to start.
	rec = doReq(t, srv, http.MethodGet, "/outbound", testSecret, "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{}`, rec.Body.String())

	// Upsert two users; bob is "direct" (a no-op removal here).
	body := `{"alice":{"type":"socks5","addr":"1.1.1.1:1080","username":"u","password":"p"},"bob":{"type":"direct"}}`
	rec = doReq(t, srv, http.MethodPost, "/outbound", testSecret, body)
	require.Equal(t, http.StatusOK, rec.Code)

	assert.NotNil(t, puo.Outbound("alice"))
	assert.Nil(t, puo.Outbound("bob"))

	// GET must not leak the password, but keeps addr/username.
	rec = doReq(t, srv, http.MethodGet, "/outbound", testSecret, "")
	require.Equal(t, http.StatusOK, rec.Code)
	var got map[string]outboundConfig
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, outboundConfig{Type: "socks5", Addr: "1.1.1.1:1080", Username: "u"}, got["alice"])
	assert.Empty(t, got["alice"].Password)

	// Bad request: socks5 without addr.
	rec = doReq(t, srv, http.MethodPost, "/outbound", testSecret, `{"carol":{"type":"socks5"}}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Unsupported type.
	rec = doReq(t, srv, http.MethodPost, "/outbound", testSecret, `{"carol":{"type":"vmess"}}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// DELETE reverts alice to fallback.
	rec = doReq(t, srv, http.MethodDelete, "/outbound", testSecret, `["alice"]`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, puo.Outbound("alice"))
}

func TestOutboundAPIDisabled(t *testing.T) {
	// Without a registry, /outbound is not exposed.
	srv := NewTrafficStatsServer(testSecret)
	rec := doReq(t, srv, http.MethodGet, "/outbound", testSecret, "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
