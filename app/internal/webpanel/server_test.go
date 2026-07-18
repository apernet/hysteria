package webpanel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPanelRouteAndPasswordAuth(t *testing.T) {
	configPath := writeTestConfig(t, "listen: :8443\nauth:\n  type: password\n  password: old\n")
	handler, err := New(Config{
		ConfigPath: configPath,
		Path:       "/hidden-panel",
		Password:   "secret",
		Validate:   func([]byte) error { return nil },
	})
	require.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)

	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/hidden-panel/api/state", nil)
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)

	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/hidden-panel/api/login", strings.NewReader(`{"password":"secret"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	cookies := res.Result().Cookies()
	require.Len(t, cookies, 1)

	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/hidden-panel/api/state", nil)
	req.AddCookie(cookies[0])
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
}

func TestPanelCookieAndIPWhitelist(t *testing.T) {
	configPath := writeTestConfig(t, "listen: :8443\n")
	handler, err := New(Config{
		ConfigPath:  configPath,
		Path:        "/panel",
		Cookie:      CookieConfig{Name: "gate", Value: "open"},
		IPWhitelist: []string{"192.0.2.0/24"},
		Validate:    func([]byte) error { return nil },
	})
	require.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/panel/api/state", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.AddCookie(&http.Cookie{Name: "gate", Value: "open"})
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)

	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/panel/api/state", nil)
	req.RemoteAddr = "192.0.2.44:1234"
	req.AddCookie(&http.Cookie{Name: "gate", Value: "open"})
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
}

func TestPanelSaveRawConfig(t *testing.T) {
	configPath := writeTestConfig(t, "listen: :8443\n")
	handler, err := New(Config{
		ConfigPath: configPath,
		Path:       "/panel",
		Cookie:     CookieConfig{Name: "gate", Value: "open"},
		Validate: func(data []byte) error {
			if strings.Contains(string(data), "bad: [") {
				return os.ErrInvalid
			}
			return nil
		},
	})
	require.NoError(t, err)

	body := strings.NewReader(`{"config":"listen: :9443\n"}`)
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/panel/api/config", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hysteria-Panel", "1")
	req.AddCookie(&http.Cookie{Name: "gate", Value: "open"})
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	require.Equal(t, "listen: :9443\n", string(mustReadFile(t, configPath)))

	body = strings.NewReader(`{"config":"bad: [\n"}`)
	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/panel/api/config", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hysteria-Panel", "1")
	req.AddCookie(&http.Cookie{Name: "gate", Value: "open"})
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusBadRequest, res.Code)
}

func TestPanelSaveCommonSettings(t *testing.T) {
	configPath := writeTestConfig(t, "listen: :8443\nauth:\n  type: password\n  password: old\n")
	handler, err := New(Config{
		ConfigPath: configPath,
		Path:       "/panel",
		Cookie:     CookieConfig{Name: "gate", Value: "open"},
		Validate:   func([]byte) error { return nil },
	})
	require.NoError(t, err)

	settings := CommonSettings{
		Listen: ":9443",
		Auth: AuthSettings{
			Type:     "password",
			Password: "new",
		},
		Bandwidth: BandwidthSettings{
			Up:   "100 mbps",
			Down: "200 mbps",
		},
		DisableUDP:     true,
		UDPIdleTimeout: "60s",
	}
	payload, err := json.Marshal(settings)
	require.NoError(t, err)

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/panel/api/settings", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hysteria-Panel", "1")
	req.AddCookie(&http.Cookie{Name: "gate", Value: "open"})
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	updated := mustReadFile(t, configPath)
	common, err := extractCommonSettings(updated)
	require.NoError(t, err)
	require.Equal(t, ":9443", common.Listen)
	require.Equal(t, "new", common.Auth.Password)
	require.Equal(t, "100 mbps", common.Bandwidth.Up)
	require.True(t, common.DisableUDP)
}

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func mustReadFile(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filename)
	require.NoError(t, err)
	return data
}
