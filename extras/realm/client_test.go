package realm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientMethods(t *testing.T) {
	var seen []string
	meta := PunchMetadata{
		Nonce: "00112233445566778899aabbccddeeff",
		Obfs:  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/realm":
			require.Equal(t, "Bearer realm-token", r.Header.Get("Authorization"))
			var req addressRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			assert.Equal(t, []string{"203.0.113.10:4433"}, req.Addresses)
			writeJSON(t, w, http.StatusOK, RegisterResponse{SessionID: "session-token", TTL: 60})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/realm/connect":
			require.Equal(t, "Bearer realm-token", r.Header.Get("Authorization"))
			var req ConnectRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			assert.Equal(t, []string{"198.51.100.20:4433"}, req.Addresses)
			assert.Equal(t, meta, req.PunchMetadata)
			writeJSON(t, w, http.StatusOK, ConnectResponse{
				Addresses:     []string{"203.0.113.10:4433"},
				PunchMetadata: req.PunchMetadata,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/realm/heartbeat":
			require.Equal(t, "Bearer session-token", r.Header.Get("Authorization"))
			var req HeartbeatRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			assert.Equal(t, []string{"203.0.113.11:4433"}, req.Addresses)
			writeJSON(t, w, http.StatusOK, HeartbeatResponse{TTL: 60})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/realm":
			require.Equal(t, "Bearer session-token", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, "realm-token")
	ctx := context.Background()

	registerResp, err := c.Register(ctx, "realm", []string{"203.0.113.10:4433"})
	require.NoError(t, err)
	assert.Equal(t, "session-token", registerResp.SessionID)
	assert.Equal(t, 60, registerResp.TTL)

	connectResp, err := c.Connect(ctx, "realm", ConnectRequest{
		Addresses:     []string{"198.51.100.20:4433"},
		PunchMetadata: meta,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"203.0.113.10:4433"}, connectResp.Addresses)
	assert.Equal(t, meta, connectResp.PunchMetadata)

	heartbeatResp, err := c.Heartbeat(ctx, "realm", "session-token", HeartbeatRequest{
		Addresses: []string{"203.0.113.11:4433"},
	})
	require.NoError(t, err)
	assert.Equal(t, 60, heartbeatResp.TTL)

	require.NoError(t, c.Deregister(ctx, "realm", "session-token"))

	assert.Equal(t, []string{
		"POST /v1/realm Bearer realm-token",
		"POST /v1/realm/connect Bearer realm-token",
		"POST /v1/realm/heartbeat Bearer session-token",
		"DELETE /v1/realm Bearer session-token",
	}, seen)
}

func TestClientStatusError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusConflict, ErrorResponse{
			Error:   "realm_taken",
			Message: "realm already registered",
		})
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, "realm-token")
	_, err := c.Register(context.Background(), "realm", []string{"203.0.113.10:4433"})
	require.Error(t, err)
	var statusErr *StatusError
	require.True(t, errors.As(err, &statusErr))
	assert.Equal(t, http.StatusConflict, statusErr.StatusCode)
	assert.Equal(t, "realm_taken", statusErr.Response.Error)
}

func TestClientEvents(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/realm/events", r.URL.Path)
		require.Equal(t, "Bearer session-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, ": comment\n\n")
		_, _ = fmt.Fprint(w, "event: ignored\ndata: {}\n\n")
		_, _ = fmt.Fprint(w, "event: punch\ndata: {\"addresses\":[\"198.51.100.20:4433\"],\"nonce\":\"00112233445566778899aabbccddeeff\",\"obfs\":\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"}\n\n")
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, "realm-token")
	events, err := c.Events(context.Background(), "realm", "session-token")
	require.NoError(t, err)
	defer events.Close()

	ev, err := events.Next()
	require.NoError(t, err)
	assert.Equal(t, []string{"198.51.100.20:4433"}, ev.Addresses)
	assert.Equal(t, "00112233445566778899aabbccddeeff", ev.Nonce)
	assert.Equal(t, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", ev.Obfs)
}

func TestNewPunchMetadata(t *testing.T) {
	meta, err := NewPunchMetadata()
	require.NoError(t, err)
	assert.Len(t, meta.Nonce, PunchNonceSize*2)
	assert.Len(t, meta.Obfs, PunchObfsKeySize*2)
	assert.Regexp(t, "^[0-9a-f]+$", meta.Nonce)
	assert.Regexp(t, "^[0-9a-f]+$", meta.Obfs)
}

func TestNewClientFromAddr(t *testing.T) {
	addr, err := ParseAddr("realm+http://token@example.com/realm")
	require.NoError(t, err)
	c, err := NewClientFromAddr(addr, nil)
	require.NoError(t, err)
	assert.Equal(t, "http://example.com:80", c.baseURL.String())
	assert.Equal(t, "token", c.token)
}

func newTestClient(t *testing.T, rawURL, token string) *Client {
	t.Helper()
	baseURL, err := url.Parse(rawURL)
	require.NoError(t, err)
	c, err := NewClient(ClientConfig{
		BaseURL: baseURL,
		Token:   token,
	})
	require.NoError(t, err)
	return c
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	require.NoError(t, json.NewEncoder(w).Encode(v))
}
