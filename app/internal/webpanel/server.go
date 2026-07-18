package webpanel

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	defaultPanelPath  = "/panel"
	defaultCookieName = "hysteria_panel"
	maxConfigBytes    = 4 << 20
)

// Config controls the local web panel. Password, Cookie.Value, IPWhitelist, and
// Path can be combined to make the panel harder to discover or access.
type Config struct {
	ConfigPath  string
	Path        string
	Password    string
	Cookie      CookieConfig
	IPWhitelist []string
	Validate    func([]byte) error
}

type CookieConfig struct {
	Name   string
	Value  string
	Secure bool
}

type Server struct {
	config       Config
	rootPath     string
	cookieName   string
	sessionValue string
	whitelist    []netip.Prefix
	mu           sync.Mutex
}

func New(config Config) (*Server, error) {
	if config.ConfigPath == "" {
		return nil, errors.New("empty config path")
	}
	rootPath, err := normalizePanelPath(config.Path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	cookieName := strings.TrimSpace(config.Cookie.Name)
	if cookieName == "" {
		cookieName = defaultCookieName
	}
	whitelist, err := parseIPWhitelist(config.IPWhitelist)
	if err != nil {
		return nil, err
	}
	hasGuard := config.Password != "" || config.Cookie.Value != "" || len(whitelist) > 0 ||
		(rootPath != defaultPanelPath && rootPath != "/")
	if !hasGuard {
		return nil, errors.New("web panel must set password, cookie.value, ipWhitelist, or a non-default path")
	}
	sessionValue := config.Cookie.Value
	if sessionValue == "" && config.Password != "" {
		sessionValue = generateSessionValue(config.ConfigPath, config.Password)
	}
	if config.Validate == nil {
		config.Validate = func([]byte) error { return nil }
	}
	return &Server{
		config:       config,
		rootPath:     rootPath,
		cookieName:   cookieName,
		sessionValue: sessionValue,
		whitelist:    whitelist,
	}, nil
}

func normalizePanelPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return defaultPanelPath, nil
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = path.Clean(p)
	if p == "." || p == "" {
		return "", errors.New("empty path")
	}
	return p, nil
}

func parseIPWhitelist(entries []string) ([]netip.Prefix, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid ipWhitelist entry %q: %w", entry, err)
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid ipWhitelist entry %q: %w", entry, err)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

func generateSessionValue(configPath, password string) string {
	mac := hmac.New(sha256.New, []byte(password))
	_, _ = mac.Write([]byte("hysteria-web-panel\x00"))
	_, _ = mac.Write([]byte(configPath))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !s.clientIPAllowed(r) {
		http.NotFound(w, r)
		return
	}
	relPath, ok := s.trimRootPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if relPath == "/" {
		s.serveIndex(w)
		return
	}
	switch relPath {
	case "/api/login":
		s.handleLogin(w, r)
	case "/api/logout":
		s.handleLogout(w, r)
	case "/api/state":
		s.requireAuth(w, r, s.handleState)
	case "/api/config":
		s.requireAuth(w, r, s.handleConfig)
	case "/api/settings":
		s.requireAuth(w, r, s.handleSettings)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) trimRootPath(reqPath string) (string, bool) {
	if s.rootPath == "/" {
		return reqPath, true
	}
	if reqPath == s.rootPath {
		return "/", true
	}
	prefix := s.rootPath + "/"
	if strings.HasPrefix(reqPath, prefix) {
		return "/" + strings.TrimPrefix(reqPath, prefix), true
	}
	return "", false
}

func (s *Server) clientIPAllowed(r *http.Request) bool {
	if len(s.whitelist) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, prefix := range s.whitelist {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !s.authorized(r) {
		writeJSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	next(w, r)
}

func (s *Server) authorized(r *http.Request) bool {
	if s.sessionValue != "" && cookieValueEqual(r, s.cookieName, s.sessionValue) {
		return true
	}
	return s.config.Password == "" && s.config.Cookie.Value == ""
}

func cookieValueEqual(r *http.Request, name, want string) bool {
	cookie, err := r.Cookie(name)
	if err != nil {
		return false
	}
	return constantTimeStringEqual(cookie.Value, want)
}

func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) serveIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.config.Password == "" {
		writeJSONError(w, http.StatusForbidden, "password login is disabled")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !constantTimeStringEqual(req.Password, s.config.Password) {
		writeJSONError(w, http.StatusUnauthorized, "invalid password")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    s.sessionValue,
		Path:     s.rootPath,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.config.Cookie.Secure,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     s.rootPath,
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.config.Cookie.Secure,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	raw, err := s.readConfig()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	common, err := extractCommonSettings(raw)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":   true,
		"configPath":      s.config.ConfigPath,
		"config":          string(raw),
		"common":          common,
		"restartRequired": true,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		raw, err := s.readConfig()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"config": string(raw)})
	case http.MethodPut:
		if !hasMutationHeader(r) {
			writeJSONError(w, http.StatusForbidden, "missing mutation header")
			return
		}
		var req struct {
			Config string `json:"config"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		backupPath, err := s.saveConfig([]byte(req.Config))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":              true,
			"backupPath":      backupPath,
			"restartRequired": true,
		})
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !hasMutationHeader(r) {
		writeJSONError(w, http.StatusForbidden, "missing mutation header")
		return
	}
	var req CommonSettings
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := s.readConfig()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, err := applyCommonSettings(raw, req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	backupPath, err := s.saveConfig(updated)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"backupPath":      backupPath,
		"restartRequired": true,
	})
}

func hasMutationHeader(r *http.Request) bool {
	return r.Header.Get("X-Hysteria-Panel") == "1"
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxConfigBytes)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func (s *Server) readConfig() ([]byte, error) {
	return os.ReadFile(s.config.ConfigPath)
}

func (s *Server) saveConfig(data []byte) (string, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return "", errors.New("empty config")
	}
	if err := s.config.Validate(data); err != nil {
		return "", fmt.Errorf("invalid config: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeConfigFile(s.config.ConfigPath, data)
}

func writeConfigFile(filename string, data []byte) (string, error) {
	info, err := os.Stat(filename)
	if err != nil {
		return "", err
	}
	mode := info.Mode().Perm()
	dir := filepath.Dir(filename)
	base := filepath.Base(filename)
	backupPath := filepath.Join(dir, fmt.Sprintf("%s.%s.bak", base, time.Now().Format("20060102-150405")))
	if oldData, err := os.ReadFile(filename); err == nil {
		if err := os.WriteFile(backupPath, oldData, mode); err != nil {
			return "", err
		}
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, filename); err == nil {
		cleanupTmp = false
		return backupPath, nil
	} else if runtime.GOOS != "windows" {
		return "", err
	}
	replaceBackup := filename + ".replace"
	_ = os.Remove(replaceBackup)
	if err := os.Rename(filename, replaceBackup); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, filename); err != nil {
		_ = os.Rename(replaceBackup, filename)
		return "", err
	}
	cleanupTmp = false
	_ = os.Remove(replaceBackup)
	return backupPath, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"ok":    false,
		"error": message,
	})
}

type CommonSettings struct {
	Listen         string               `json:"listen"`
	TLS            TLSSettings          `json:"tls"`
	Auth           AuthSettings         `json:"auth"`
	Obfs           ObfsSettings         `json:"obfs"`
	Bandwidth      BandwidthSettings    `json:"bandwidth"`
	Congestion     CongestionSettings   `json:"congestion"`
	DisableUDP     bool                 `json:"disableUDP"`
	UDPIdleTimeout string               `json:"udpIdleTimeout"`
	SpeedTest      bool                 `json:"speedTest"`
	Resolver       ResolverSettings     `json:"resolver"`
	Sniff          SniffSettings        `json:"sniff"`
	ACL            ACLSettings          `json:"acl"`
	TrafficStats   TrafficStatsSettings `json:"trafficStats"`
	Masquerade     MasqueradeSettings   `json:"masquerade"`
}

type TLSSettings struct {
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	SNIGuard string `json:"sniGuard"`
	ClientCA string `json:"clientCA"`
}

type AuthSettings struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type ObfsSettings struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type BandwidthSettings struct {
	Up   string `json:"up"`
	Down string `json:"down"`
}

type CongestionSettings struct {
	Type       string `json:"type"`
	BBRProfile string `json:"bbrProfile"`
}

type ResolverSettings struct {
	Type     string `json:"type"`
	Addr     string `json:"addr"`
	Timeout  string `json:"timeout"`
	SNI      string `json:"sni"`
	Insecure bool   `json:"insecure"`
}

type SniffSettings struct {
	Enable        bool   `json:"enable"`
	Timeout       string `json:"timeout"`
	RewriteDomain bool   `json:"rewriteDomain"`
	TCPPorts      string `json:"tcpPorts"`
	UDPPorts      string `json:"udpPorts"`
}

type ACLSettings struct {
	File    string `json:"file"`
	Inline  string `json:"inline"`
	GeoIP   string `json:"geoip"`
	GeoSite string `json:"geosite"`
}

type TrafficStatsSettings struct {
	Listen string `json:"listen"`
	Secret string `json:"secret"`
}

type MasqueradeSettings struct {
	Type          string `json:"type"`
	FileDir       string `json:"fileDir"`
	ProxyURL      string `json:"proxyURL"`
	ProxyInsecure bool   `json:"proxyInsecure"`
	StringContent string `json:"stringContent"`
}

func extractCommonSettings(raw []byte) (CommonSettings, error) {
	configMap, err := parseYAMLMap(raw)
	if err != nil {
		return CommonSettings{}, err
	}
	var s CommonSettings
	s.Listen = asString(configMap["listen"])
	tlsMap := asMap(configMap["tls"])
	s.TLS = TLSSettings{
		Cert:     asString(tlsMap["cert"]),
		Key:      asString(tlsMap["key"]),
		SNIGuard: asString(tlsMap["sniGuard"]),
		ClientCA: asString(tlsMap["clientCA"]),
	}
	authMap := asMap(configMap["auth"])
	s.Auth = AuthSettings{
		Type:     asString(authMap["type"]),
		Password: asString(authMap["password"]),
	}
	obfsMap := asMap(configMap["obfs"])
	obfsType := asString(obfsMap["type"])
	s.Obfs = ObfsSettings{
		Type:     obfsType,
		Password: obfsPassword(obfsMap, obfsType),
	}
	bwMap := asMap(configMap["bandwidth"])
	s.Bandwidth = BandwidthSettings{
		Up:   asString(bwMap["up"]),
		Down: asString(bwMap["down"]),
	}
	congestionMap := asMap(configMap["congestion"])
	s.Congestion = CongestionSettings{
		Type:       asString(congestionMap["type"]),
		BBRProfile: asString(congestionMap["bbrProfile"]),
	}
	s.DisableUDP = asBool(configMap["disableUDP"])
	s.UDPIdleTimeout = asString(configMap["udpIdleTimeout"])
	s.SpeedTest = asBool(configMap["speedTest"])
	resolverMap := asMap(configMap["resolver"])
	resolverType := asString(resolverMap["type"])
	resolverSub := resolverTypedMap(resolverMap, resolverType)
	s.Resolver = ResolverSettings{
		Type:     resolverType,
		Addr:     asString(resolverSub["addr"]),
		Timeout:  asString(resolverSub["timeout"]),
		SNI:      asString(resolverSub["sni"]),
		Insecure: asBool(resolverSub["insecure"]),
	}
	sniffMap := asMap(configMap["sniff"])
	s.Sniff = SniffSettings{
		Enable:        asBool(sniffMap["enable"]),
		Timeout:       asString(sniffMap["timeout"]),
		RewriteDomain: asBool(sniffMap["rewriteDomain"]),
		TCPPorts:      asString(sniffMap["tcpPorts"]),
		UDPPorts:      asString(sniffMap["udpPorts"]),
	}
	aclMap := asMap(configMap["acl"])
	s.ACL = ACLSettings{
		File:   asString(aclMap["file"]),
		Inline: strings.Join(asStringSlice(aclMap["inline"]), "\n"),
		GeoIP:  asString(aclMap["geoip"]),
		GeoSite: asString(aclMap["geosite"]),
	}
	statsMap := asMap(configMap["trafficStats"])
	s.TrafficStats = TrafficStatsSettings{
		Listen: asString(statsMap["listen"]),
		Secret: asString(statsMap["secret"]),
	}
	masqMap := asMap(configMap["masquerade"])
	s.Masquerade = MasqueradeSettings{
		Type:          asString(masqMap["type"]),
		FileDir:       asString(asMap(masqMap["file"])["dir"]),
		ProxyURL:      asString(asMap(masqMap["proxy"])["url"]),
		ProxyInsecure: asBool(asMap(masqMap["proxy"])["insecure"]),
		StringContent: asString(asMap(masqMap["string"])["content"]),
	}
	return s, nil
}

func applyCommonSettings(raw []byte, settings CommonSettings) ([]byte, error) {
	configMap, err := parseYAMLMap(raw)
	if err != nil {
		return nil, err
	}
	setString(configMap, "listen", settings.Listen)
	tlsMap := ensureMap(configMap, "tls")
	setString(tlsMap, "cert", settings.TLS.Cert)
	setString(tlsMap, "key", settings.TLS.Key)
	setString(tlsMap, "sniGuard", settings.TLS.SNIGuard)
	setString(tlsMap, "clientCA", settings.TLS.ClientCA)

	authMap := ensureMap(configMap, "auth")
	setString(authMap, "type", settings.Auth.Type)
	setString(authMap, "password", settings.Auth.Password)

	obfsMap := ensureMap(configMap, "obfs")
	setString(obfsMap, "type", settings.Obfs.Type)
	setObfsPassword(obfsMap, settings.Obfs.Type, settings.Obfs.Password)

	bwMap := ensureMap(configMap, "bandwidth")
	setString(bwMap, "up", settings.Bandwidth.Up)
	setString(bwMap, "down", settings.Bandwidth.Down)

	congestionMap := ensureMap(configMap, "congestion")
	setString(congestionMap, "type", settings.Congestion.Type)
	setString(congestionMap, "bbrProfile", settings.Congestion.BBRProfile)

	setBool(configMap, "disableUDP", settings.DisableUDP)
	setString(configMap, "udpIdleTimeout", settings.UDPIdleTimeout)
	setBool(configMap, "speedTest", settings.SpeedTest)

	resolverMap := ensureMap(configMap, "resolver")
	setString(resolverMap, "type", settings.Resolver.Type)
	if key := resolverKey(settings.Resolver.Type); key != "" {
		resolverSub := ensureMap(resolverMap, key)
		setString(resolverSub, "addr", settings.Resolver.Addr)
		setString(resolverSub, "timeout", settings.Resolver.Timeout)
		setString(resolverSub, "sni", settings.Resolver.SNI)
		setBool(resolverSub, "insecure", settings.Resolver.Insecure)
	}

	sniffMap := ensureMap(configMap, "sniff")
	setBool(sniffMap, "enable", settings.Sniff.Enable)
	setString(sniffMap, "timeout", settings.Sniff.Timeout)
	setBool(sniffMap, "rewriteDomain", settings.Sniff.RewriteDomain)
	setString(sniffMap, "tcpPorts", settings.Sniff.TCPPorts)
	setString(sniffMap, "udpPorts", settings.Sniff.UDPPorts)

	aclMap := ensureMap(configMap, "acl")
	setString(aclMap, "file", settings.ACL.File)
	setString(aclMap, "geoip", settings.ACL.GeoIP)
	setString(aclMap, "geosite", settings.ACL.GeoSite)
	inline := splitLines(settings.ACL.Inline)
	if len(inline) > 0 {
		aclMap["inline"] = inline
	} else {
		delete(aclMap, "inline")
	}

	statsMap := ensureMap(configMap, "trafficStats")
	setString(statsMap, "listen", settings.TrafficStats.Listen)
	setString(statsMap, "secret", settings.TrafficStats.Secret)

	masqMap := ensureMap(configMap, "masquerade")
	setString(masqMap, "type", settings.Masquerade.Type)
	setString(ensureMap(masqMap, "file"), "dir", settings.Masquerade.FileDir)
	proxyMap := ensureMap(masqMap, "proxy")
	setString(proxyMap, "url", settings.Masquerade.ProxyURL)
	setBool(proxyMap, "insecure", settings.Masquerade.ProxyInsecure)
	setString(ensureMap(masqMap, "string"), "content", settings.Masquerade.StringContent)

	pruneEmptyMaps(configMap)
	out, err := yaml.Marshal(configMap)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func parseYAMLMap(raw []byte) (map[string]any, error) {
	var configMap map[string]any
	if err := yaml.Unmarshal(raw, &configMap); err != nil {
		return nil, err
	}
	if configMap == nil {
		configMap = make(map[string]any)
	}
	return configMap, nil
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func ensureMap(m map[string]any, key string) map[string]any {
	if child, ok := m[key].(map[string]any); ok {
		return child
	}
	child := make(map[string]any)
	m[key] = child
	return child
}

func setString(m map[string]any, key, value string) {
	if strings.TrimSpace(value) == "" {
		delete(m, key)
		return
	}
	m[key] = value
}

func setBool(m map[string]any, key string, value bool) {
	if !value {
		delete(m, key)
		return
	}
	m[key] = true
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, bool:
		return fmt.Sprint(t)
	default:
		return ""
	}
}

func asBool(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	if s, ok := v.(string); ok {
		return strings.EqualFold(s, "true") || s == "1"
	}
	return false
}

func asStringSlice(v any) []string {
	values, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if s := asString(value); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func obfsPassword(obfsMap map[string]any, obfsType string) string {
	if key := obfsKey(obfsType); key != "" {
		if password := asString(asMap(obfsMap[key])["password"]); password != "" {
			return password
		}
	}
	if password := asString(asMap(obfsMap["salamander"])["password"]); password != "" {
		return password
	}
	return asString(asMap(obfsMap["gecko"])["password"])
}

func setObfsPassword(obfsMap map[string]any, obfsType, password string) {
	key := obfsKey(obfsType)
	if key == "" {
		if strings.TrimSpace(password) == "" {
			return
		}
		key = "salamander"
	}
	setString(ensureMap(obfsMap, key), "password", password)
}

func obfsKey(obfsType string) string {
	switch strings.ToLower(obfsType) {
	case "salamander":
		return "salamander"
	case "gecko":
		return "gecko"
	default:
		return ""
	}
}

func resolverTypedMap(resolverMap map[string]any, resolverType string) map[string]any {
	if key := resolverKey(resolverType); key != "" {
		return asMap(resolverMap[key])
	}
	return map[string]any{}
}

func resolverKey(resolverType string) string {
	switch strings.ToLower(resolverType) {
	case "tcp":
		return "tcp"
	case "udp":
		return "udp"
	case "tls", "tcp-tls":
		return "tls"
	case "https", "http":
		return "https"
	default:
		return ""
	}
}

func pruneEmptyMaps(m map[string]any) bool {
	for key, value := range m {
		child, ok := value.(map[string]any)
		if !ok {
			continue
		}
		if pruneEmptyMaps(child) {
			delete(m, key)
		}
	}
	return len(m) == 0
}
