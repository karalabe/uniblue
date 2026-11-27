// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karalabe/uniblue/docs"
	"github.com/karalabe/uniblue/internal/blast"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/risk"
)

// Browser session cookie lifetime/capacity and per-IP brute-force lockout
// schedule: 5 failed token attempts within 15 minutes trigger a 15-minute
// lockout that doubles on consecutive lockouts up to 1 hour.
const (
	sessionCookieName = "uniblue_session"
	sessionTTL        = 30 * 24 * time.Hour
	maxActiveSessions = 1024

	authMaxFailedAttempts  = 5
	authFailureWindow      = 15 * time.Minute
	authLockoutDuration    = 15 * time.Minute
	authMaxLockoutDuration = 1 * time.Hour
	authMaxTrackedClients  = 1024
)

// sessionData is the persisted JSON representation of active browser sessions.
// Session cookies are independent random secrets; only their SHA-256 digests
// and Unix expiration timestamps are stored alongside the active API token digest.
type sessionData struct {
	TokenHash string           `json:"token_hash"`
	Expires   map[string]int64 `json:"expires"`
}

// sessionStore manages persisted HttpOnly browser sessions bound to the active
// API token, invalidating saved sessions automatically if the token rotates.
type sessionStore struct {
	mu    sync.Mutex
	path  string
	data  sessionData
	nowFn func() time.Time
}

func (s *sessionStore) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

func sessionDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *sessionStore) configure(path, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if path != s.path {
		s.path = path
		s.data = sessionData{}
	}
	return s.bindLocked(token)
}

func (s *sessionStore) loadLocked() error {
	if s.data.Expires != nil || s.path == "" {
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var data sessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return err
	}
	if data.TokenHash == "" || data.Expires == nil || len(data.Expires) > maxActiveSessions {
		return errors.New("invalid session store")
	}
	s.data = data
	return nil
}

// bindLocked discards sessions when the configured API token changes.
func (s *sessionStore) bindLocked(token string) error {
	if err := s.loadLocked(); err != nil {
		return err
	}
	hash := sessionDigest(token)
	if s.data.Expires == nil {
		s.data = sessionData{TokenHash: hash, Expires: make(map[string]int64)}
	} else if s.data.TokenHash != hash {
		return s.commitLocked(sessionData{TokenHash: hash, Expires: make(map[string]int64)})
	}
	return nil
}

// commitLocked publishes a mutation in memory only after the atomic file
// replacement succeeds. A failed logout can therefore be retried.
func (s *sessionStore) commitLocked(next sessionData) error {
	if s.path != "" {
		dir := filepath.Dir(s.path)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(dir, ".uniblue-sessions-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if err = json.NewEncoder(tmp).Encode(next); err == nil {
			err = tmp.Sync()
		}
		closeErr := tmp.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err := os.Rename(tmp.Name(), s.path); err != nil {
			return err
		}
	}
	s.data = next
	return nil
}

// create generates a random 256-bit session cookie, prunes expired entries
// (evicting the oldest active session if maxActiveSessions is reached), and
// atomically persists the updated store.
func (s *sessionStore) create(token string) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	cookie := hex.EncodeToString(raw[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.bindLocked(token); err != nil {
		return "", err
	}
	now := s.now()
	next := sessionData{TokenHash: s.data.TokenHash, Expires: maps.Clone(s.data.Expires)}
	var oldest string
	for key, expiry := range next.Expires {
		if expiry <= now.Unix() {
			delete(next.Expires, key)
		} else if oldest == "" || expiry < next.Expires[oldest] {
			oldest = key
		}
	}
	if len(next.Expires) >= maxActiveSessions {
		delete(next.Expires, oldest)
	}
	next.Expires[sessionDigest(cookie)] = now.Add(sessionTTL).Unix()
	if err := s.commitLocked(next); err != nil {
		return "", err
	}
	return cookie, nil
}

// lookup verifies cookie against the active API token and expiration under
// s.mu, optionally revoking the session and committing the change atomically.
func (s *sessionStore) lookup(cookie, token string, revoke bool) (bool, error) {
	if len(cookie) != 64 || token == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return false, err
	}
	if s.data.TokenHash != sessionDigest(token) {
		return false, nil
	}
	key := sessionDigest(cookie)
	exp, ok := s.data.Expires[key]
	if !ok || exp <= s.now().Unix() {
		return false, nil
	}
	if revoke {
		next := sessionData{TokenHash: s.data.TokenHash, Expires: maps.Clone(s.data.Expires)}
		delete(next.Expires, key)
		if err := s.commitLocked(next); err != nil {
			return false, err
		}
	}
	return true, nil
}

type authAttemptState struct {
	failures    int
	lockouts    int
	windowStart time.Time
	lockedUntil time.Time
	lastSeen    time.Time
}

// authFailureLimiter tracks failed dashboard/API authentication attempts per
// remote IP and temporarily locks out clients after repeated invalid tokens.
type authFailureLimiter struct {
	mu      sync.Mutex
	clients map[string]authAttemptState
	nowFn   func() time.Time
}

func (l *authFailureLimiter) now() time.Time {
	if l.nowFn != nil {
		return l.nowFn()
	}
	return time.Now()
}

// verifyToken checks lockout state, performs a constant-time comparison against
// token, and records failed attempts under a single lock so concurrent requests
// cannot race past authMaxFailedAttempts.
func (l *authFailureLimiter) verifyToken(ip, candidate, token string) (valid bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	st, ok := l.clients[ip]
	if now.Before(st.lockedUntil) {
		return false, st.lockedUntil.Sub(now)
	}
	if candidate != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
		return true, 0
	}
	if l.clients == nil {
		l.clients = make(map[string]authAttemptState)
	}
	if ok {
		if st.windowStart.IsZero() || now.Sub(st.windowStart) > authFailureWindow {
			st.failures = 0
			st.windowStart = now
		}
	} else {
		if len(l.clients) >= authMaxTrackedClients {
			l.evictStaleLocked(now)
		}
		st.windowStart = now
	}
	st.failures++
	st.lastSeen = now
	if st.failures >= authMaxFailedAttempts {
		st.lockouts++
		dur := authLockoutDuration << min(st.lockouts-1, 4)
		if dur > authMaxLockoutDuration {
			dur = authMaxLockoutDuration
		}
		st.lockedUntil = now.Add(dur)
		st.failures = 0
		l.clients[ip] = st
		return false, dur
	}
	l.clients[ip] = st
	return false, 0
}

// evictStaleLocked bounds the tracked-IP map to authMaxTrackedClients, pruning
// expired records first and preferring to evict the oldest unlocked entry;
// when every tracked entry is locked, it evicts the oldest locked entry.
func (l *authFailureLimiter) evictStaleLocked(now time.Time) {
	for k, st := range l.clients {
		if !now.Before(st.lockedUntil) && now.Sub(st.lastSeen) > authFailureWindow {
			delete(l.clients, k)
		}
	}
	if len(l.clients) < authMaxTrackedClients {
		return
	}
	// Prefer evicting the oldest UNLOCKED entry; fall back to the oldest
	// locked entry only if every tracked entry is currently locked.
	var oldestUnlockedKey string
	var oldestUnlockedTime time.Time
	var oldestLockedKey string
	var oldestLockedTime time.Time
	for k, st := range l.clients {
		if now.Before(st.lockedUntil) {
			if oldestLockedKey == "" || st.lastSeen.Before(oldestLockedTime) {
				oldestLockedKey = k
				oldestLockedTime = st.lastSeen
			}
		} else {
			if oldestUnlockedKey == "" || st.lastSeen.Before(oldestUnlockedTime) {
				oldestUnlockedKey = k
				oldestUnlockedTime = st.lastSeen
			}
		}
	}
	if oldestUnlockedKey != "" {
		delete(l.clients, oldestUnlockedKey)
	} else if oldestLockedKey != "" {
		delete(l.clients, oldestLockedKey)
	}
}

// clientRemoteIP extracts and normalizes the peer IP from r.RemoteAddr,
// stripping any port, IPv6 brackets, or IPv4-mapped IPv6 prefix.
func clientRemoteIP(r *http.Request) string {
	raw := strings.TrimSpace(r.RemoteAddr)
	if raw == "" {
		return "unknown"
	}
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

// apiError is the uniform JSON error envelope returned by all /api/v1/* endpoints.
type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// HealthResponse is the lightweight liveness and scan-watchdog payload served by
// GET /api/v1/health.
type HealthResponse struct {
	// Status is "ok", "scanning" (during the initial baseline), or "degraded" (when LastScanError is non-empty).
	Status string `json:"status"`
	// Site is the UniFi site name monitored by this server.
	Site string `json:"site"`
	// ControllerType identifies the detected UniFi API mode (e.g., "integration-v1", "unifi-os").
	ControllerType string `json:"controller_type,omitempty"`
	// StartedAt records when the server started.
	StartedAt time.Time `json:"started_at"`
	// UpdatedAt records when the published state snapshot last changed.
	UpdatedAt time.Time `json:"updated_at"`
	// LastFullScanAt records when the most recent full LAN reconciliation completed.
	LastFullScanAt time.Time `json:"last_full_scan_at,omitempty"`
	// LastScanError holds the most recent full-scan error message, cleared on the next successful full scan.
	LastScanError string `json:"last_scan_error,omitempty"`
	// Scanning reports whether a full or targeted host scan is currently running.
	Scanning bool `json:"scanning"`
	// EventMode describes the active UniFi ingestion or export mode ("websocket", "poll-<interval>", or "demo").
	EventMode string `json:"event_mode"`
	// CVELoaded reports whether CVE data is available in the snapshot (demo mode sets this with synthetic data without a local cache).
	CVELoaded bool `json:"cve_loaded"`
	// ClientCount is the number of active UniFi clients in the latest snapshot.
	ClientCount int `json:"client_count"`
	// FindingCount is the total number of findings in the latest risk report.
	FindingCount int `json:"finding_count"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiError{Error: code, Message: message})
}

func writeAuthLockedResponse(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int(retryAfter.Round(time.Second).Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "too many failed authentication attempts; try again later")
}

// Serve starts the HTTP server for the built-in web UI, JSON API, and SSE event
// stream, shutting down gracefully when ctx is cancelled.
func (e *Engine) Serve(ctx context.Context) error {
	addr := e.opts.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:8080"
		e.opts.ListenAddr = addr
	}

	if !isLoopbackListenAddr(addr) && e.effectiveAPIToken() == "" {
		e.logger.Warn("uniblue web UI listening on non-loopback address without UNIBLUE_API_TOKEN; set UNIBLUE_API_TOKEN to require bearer auth on /api/v1/*", "listen", addr)
	}

	mux := e.Handler()
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	errCh := make(chan error, 1)
	go func() {
		e.logger.Info("uniblue web UI listening", "url", "http://"+ln.Addr().String())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			_ = srv.Close()
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// Handler builds the HTTP router for UniBlue's live dashboard and /api/v1/*
// endpoints wrapped with Host (DNS-rebinding), Origin/Sec-Fetch-Site (CSRF),
// and optional Bearer token / HttpOnly session cookie protection.
func (e *Engine) Handler() http.Handler {
	// Store sessions in a sibling .sessions.json file alongside e.cfg.State.Path.
	// Initializing here also invalidates saved sessions if the server starts with
	// a rotated API token.
	var path string
	if e.cfg != nil && e.cfg.State.Path != "" {
		path = e.cfg.State.Path + ".sessions.json"
	}
	if err := e.sessions.configure(path, e.effectiveAPIToken()); err != nil {
		e.logger.Error("failed to initialize sessions", "err", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", e.handleIndex)
	mux.HandleFunc("GET /api/v1/health", e.handleHealth)
	mux.HandleFunc("GET /api/v1/session", e.handleSessionGet)
	mux.HandleFunc("POST /api/v1/session", e.handleSessionCreate)
	mux.HandleFunc("DELETE /api/v1/session", e.handleSessionDelete)
	mux.HandleFunc("GET /api/v1/state", e.handleState)
	mux.HandleFunc("GET /api/v1/findings", e.handleFindings)
	mux.HandleFunc("GET /api/v1/blast", e.handleBlast)
	mux.HandleFunc("GET /api/v1/cves", e.handleCVEs)
	mux.HandleFunc("GET /api/v1/hosts", e.handleHosts)
	mux.HandleFunc("GET /api/v1/hosts/{id}", e.handleHostByID)
	mux.HandleFunc("GET /api/v1/hosts/{id}/blast", e.handleHostBlast)
	mux.HandleFunc("GET /api/v1/devices", e.handleDevices)
	mux.HandleFunc("GET /api/v1/devices/{id}", e.handleDeviceByID)
	mux.HandleFunc("GET /api/v1/isolation", e.handleIsolation)
	mux.HandleFunc("GET /api/v1/events", e.handleEventsList)
	mux.HandleFunc("GET /api/v1/events/stream", e.handleEventsStream)
	mux.HandleFunc("POST /api/v1/scans", e.handleScans)
	mux.HandleFunc("POST /api/v1/hosts/{id}/scan", e.handleHostScan)
	mux.HandleFunc("GET /assets/logo-light.svg", serveEmbeddedSVG("logo-header-light.svg"))
	mux.HandleFunc("GET /assets/logo-dark.svg", serveEmbeddedSVG("logo-header-dark.svg"))
	mux.HandleFunc("GET /assets/favicon.svg", serveEmbeddedSVG("logo-light.svg"))
	mux.HandleFunc("GET /favicon.ico", serveEmbeddedSVG("logo-light.svg"))

	// Intercept unmatched /api/* paths so API clients always receive structured
	// JSON 405 Method Not Allowed or 404 Not Found envelopes instead of plain-text
	// ServeMux errors.
	jsonFallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if _, pat := mux.Handler(r); pat == "" {
				for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
					if m == r.Method {
						continue
					}
					probeReq := r.Clone(r.Context())
					probeReq.Method = m
					if _, altPat := mux.Handler(probeReq); altPat != "" {
						writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", fmt.Sprintf("method %s not allowed on %s", r.Method, r.URL.Path))
						return
					}
				}
				writeAPIError(w, http.StatusNotFound, "not_found", "endpoint not found")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
	return e.protectHTTP(jsonFallback)
}

func (e *Engine) effectiveAPIToken() string {
	if tok := strings.TrimSpace(e.opts.APIToken); tok != "" {
		return tok
	}
	return strings.TrimSpace(os.Getenv("UNIBLUE_API_TOKEN"))
}

func (e *Engine) effectiveAllowedHosts() []string {
	var out []string
	for _, h := range e.opts.AllowedHosts {
		if t := strings.TrimSpace(h); t != "" {
			out = append(out, t)
		}
	}
	if env := strings.TrimSpace(os.Getenv("UNIBLUE_ALLOWED_HOSTS")); env != "" {
		for _, part := range strings.Split(env, ",") {
			if t := strings.TrimSpace(part); t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

func isLoopbackListenAddr(addr string) bool {
	if strings.TrimSpace(addr) == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return isLoopbackHostName(host)
}

func isLoopbackHostName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// isAllowedLANHostName reports whether host is a literal IP address, localhost,
// a local LAN suffix (.local, .lan, .home, .internal, .home.arpa), or a
// single-label hostname, preventing external DNS-rebinding domains on non-loopback
// listeners.
func isAllowedLANHostName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	if h == "" {
		return false
	}
	if isLoopbackHostName(h) {
		return true
	}
	if net.ParseIP(h) != nil {
		return true
	}
	if strings.HasSuffix(h, ".localhost") ||
		strings.HasSuffix(h, ".local") ||
		strings.HasSuffix(h, ".lan") ||
		strings.HasSuffix(h, ".home") ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".home.arpa") {
		return true
	}
	if !strings.Contains(h, ".") {
		for i := 0; i < len(h); i++ {
			c := h[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		return h[0] != '-' && h[len(h)-1] != '-'
	}
	return false
}

// matchesAllowedHost checks hostHeader against explicit reverse-proxy allowlist
// entries, normalizing URL prefixes, trailing slashes/dots, and optional ports.
func matchesAllowedHost(hostHeader string, allowed []string) bool {
	raw := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostHeader), "."))
	if raw == "" || len(allowed) == 0 {
		return false
	}
	reqHost := strings.ToLower(strings.TrimSuffix(requestHostName(raw), "."))
	for _, entry := range allowed {
		e := strings.ToLower(strings.TrimSpace(entry))
		if e == "" {
			continue
		}
		if strings.Contains(e, "://") {
			if u, err := url.Parse(e); err == nil && u.Host != "" {
				e = strings.ToLower(u.Host)
			}
		}
		e = strings.TrimSuffix(strings.TrimSuffix(e, "/"), ".")
		if e == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(e); err == nil {
			if raw == e {
				return true
			}
			continue
		}
		if reqHost == strings.Trim(e, "[]") {
			return true
		}
	}
	return false
}

func requestHostName(hostHeader string) string {
	h := strings.TrimSpace(hostHeader)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(h, "[]")
}

// authenticateAPI validates a browser HttpOnly session cookie first (clearing
// invalid or expired cookies) before falling back to Bearer token auth guarded
// by the per-IP failure limiter. When handled is true, an error or 429 lockout
// response has already been written to w.
func (e *Engine) authenticateAPI(w http.ResponseWriter, r *http.Request, tok string) (authenticated, handled bool) {
	if ck, err := r.Cookie(sessionCookieName); err == nil && ck.Value != "" {
		valid, err := e.sessions.lookup(ck.Value, tok, false)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "session_error", "failed to read session")
			return false, true
		}
		if valid {
			return true, false
		}
		clearSessionCookie(w, r)
	}
	candidate, ok := strings.CutPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
	if !ok {
		return false, false
	}
	valid, retryAfter := e.authLimiter.verifyToken(clientRemoteIP(r), strings.TrimSpace(candidate), tok)
	if retryAfter > 0 {
		writeAuthLockedResponse(w, retryAfter)
		return false, true
	}
	return valid, false
}

// protectHTTP rejects DNS-rebinding Host headers on both loopback and LAN
// listeners (honoring UNIBLUE_ALLOWED_HOSTS for reverse proxies), blocks
// cross-origin / cross-site browser requests (especially mutating CSRF calls),
// and enforces Bearer token or HttpOnly session cookie auth on /api/v1/* when
// UNIBLUE_API_TOKEN is set.
func (e *Engine) protectHTTP(next http.Handler) http.Handler {
	loopbackOnly := isLoopbackListenAddr(e.opts.ListenAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAPI := strings.HasPrefix(r.URL.Path, "/api/")
		writeErr := func(status int, code, msg string) {
			if isAPI {
				writeAPIError(w, status, code, msg)
				return
			}
			http.Error(w, msg, status)
		}

		allowedHosts := e.effectiveAllowedHosts()
		if r.Host != "" && !matchesAllowedHost(r.Host, allowedHosts) {
			hostName := requestHostName(r.Host)
			if loopbackOnly {
				if !isLoopbackHostName(hostName) {
					writeErr(http.StatusForbidden, "forbidden_host", "forbidden host header")
					return
				}
			} else if !isAllowedLANHostName(hostName) {
				writeErr(http.StatusForbidden, "forbidden_host", "forbidden host header")
				return
			}
		}

		if isAPI || (r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions) {
			if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
				parsedOrigin, err := url.Parse(origin)
				if err != nil || parsedOrigin.Host == "" ||
					(!strings.EqualFold(parsedOrigin.Host, r.Host) && !matchesAllowedHost(parsedOrigin.Host, allowedHosts)) {
					writeErr(http.StatusForbidden, "forbidden_origin", "forbidden cross-origin request")
					return
				}
			}
			if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs != "" && sfs != "same-origin" && sfs != "none" {
				writeErr(http.StatusForbidden, "forbidden_cross_site", "forbidden cross-site request")
				return
			}
		}

		// Allow /api/v1/session through the middleware auth gate because its
		// handlers manage login, auth status checks, and cookie revocation directly.
		isSessionEndpoint := r.URL.Path == "/api/v1/session" &&
			(r.Method == http.MethodGet || r.Method == http.MethodPost || r.Method == http.MethodDelete)
		if isAPI && !isSessionEndpoint {
			if tok := e.effectiveAPIToken(); tok != "" {
				authenticated, handled := e.authenticateAPI(w, r, tok)
				if handled {
					return
				}
				if !authenticated {
					w.Header().Set("WWW-Authenticate", `Bearer realm="uniblue"`)
					writeAPIError(w, http.StatusUnauthorized, "unauthorized", "valid bearer token or session cookie required")
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isSecureRequest reports whether the request arrived over TLS directly or
// behind an HTTPS-terminating reverse proxy (via X-Forwarded-Proto).
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecureRequest(r),
		MaxAge:   -1,
	})
}

func (e *Engine) handleSessionGet(w http.ResponseWriter, r *http.Request) {
	tok := e.effectiveAPIToken()
	if tok == "" {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "required": false})
		return
	}

	authenticated, handled := e.authenticateAPI(w, r, tok)
	if !handled {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": authenticated, "required": true})
	}
}

// handleSessionCreate verifies the submitted Bearer or JSON API token under
// the per-IP failure limiter and issues a persisted HttpOnly session cookie.
func (e *Engine) handleSessionCreate(w http.ResponseWriter, r *http.Request) {
	tok := e.effectiveAPIToken()
	if tok == "" {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "required": false})
		return
	}

	var cand string
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if strings.HasPrefix(auth, prefix) {
		cand = strings.TrimSpace(auth[len(prefix):])
	}
	if cand == "" && r.Body != nil {
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err == nil {
			cand = strings.TrimSpace(body.Token)
		}
	}

	valid, retryAfter := e.authLimiter.verifyToken(clientRemoteIP(r), cand, tok)
	if retryAfter > 0 {
		writeAuthLockedResponse(w, retryAfter)
		return
	}
	if !valid {
		w.Header().Set("WWW-Authenticate", `Bearer realm="uniblue"`)
		writeAPIError(w, http.StatusUnauthorized, "invalid_token", "invalid API token")
		return
	}

	sessionID, err := e.sessions.create(tok)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "session_error", "failed to create session")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   isSecureRequest(r),
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "required": true})
}

func (e *Engine) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookieName); err == nil && ck.Value != "" {
		if _, err := e.sessions.lookup(ck.Value, e.effectiveAPIToken(), true); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "session_error", "failed to revoke session")
			return
		}
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

// RenderStaticHTML renders a self-contained, offline interactive HTML snapshot
// of the full UniBlue console (with embedded logos and baked JSON state) for
// `uniblue topology -out` and `uniblue demo -out`.
func RenderStaticHTML(w io.Writer, snap StateSnapshot) error {
	rawState, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal static state: %w", err)
	}
	// Escape closing script sequences safely inside inline JSON script tag.
	safeJSON := strings.ReplaceAll(string(rawState), "</", `<\/`)

	html := string(dashboardHTML)
	if light, err := fs.ReadFile(docs.LogoFS, "logo-header-light.svg"); err == nil && len(light) > 0 {
		uri := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(light)
		html = strings.ReplaceAll(html, `src="/assets/logo-light.svg"`, `src="`+uri+`"`)
	}
	if dark, err := fs.ReadFile(docs.LogoFS, "logo-header-dark.svg"); err == nil && len(dark) > 0 {
		uri := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(dark)
		html = strings.ReplaceAll(html, `srcset="/assets/logo-dark.svg"`, `srcset="`+uri+`"`)
	}

	// Inject the static JSON blob immediately before the first <script> tag;
	// dashboardHTML keeps the main app script as its first <script> element so
	// uniblue-static-state is present in the DOM before boot code executes.
	tag := `<script id="uniblue-static-state" type="application/json">` + safeJSON + `</script>` + "\n<script>"
	html = strings.Replace(html, "<script>", tag, 1)

	_, err = io.Copy(w, bytes.NewBufferString(html))
	return err
}

func (e *Engine) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(dashboardHTML)
}

func (e *Engine) handleHealth(w http.ResponseWriter, _ *http.Request) {
	snap := e.Snapshot()
	status := "ok"
	switch {
	case snap.LastScanError != "":
		status = "degraded"
	case snap.Scanning && snap.LastFullScanAt.IsZero():
		status = "scanning"
	}
	clientCount := snap.Report.ClientCount
	if clientCount == 0 && len(snap.Clients) > 0 {
		clientCount = len(snap.Clients)
	}
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:         status,
		Site:           snap.Site,
		ControllerType: snap.ControllerType,
		StartedAt:      snap.StartedAt,
		UpdatedAt:      snap.UpdatedAt,
		LastFullScanAt: snap.LastFullScanAt,
		LastScanError:  snap.LastScanError,
		Scanning:       snap.Scanning,
		EventMode:      snap.EventMode,
		CVELoaded:      snap.CVELoaded,
		ClientCount:    clientCount,
		FindingCount:   len(snap.Report.Findings),
	})
}

func (e *Engine) handleState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, e.Snapshot())
}

// handleFindings serves GET /api/v1/findings with optional minimum severity,
// category, and host query filters.
func (e *Engine) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var (
		hasMinSev bool
		minSev    checks.Severity
	)
	if rawSev := strings.TrimSpace(q.Get("severity")); rawSev != "" {
		parsed, err := checks.ParseSeverity(rawSev)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_parameter", err.Error())
			return
		}
		hasMinSev = true
		minSev = parsed
	}
	hostFilter := strings.TrimSpace(q.Get("host"))
	catFilter := strings.TrimSpace(q.Get("category"))

	snap := e.Snapshot()
	out := make([]checks.Finding, 0, len(snap.Report.Findings))
	for _, f := range snap.Report.Findings {
		if hasMinSev && f.EffectiveSeverity < minSev {
			continue
		}
		if catFilter != "" && !strings.EqualFold(f.Category, catFilter) {
			continue
		}
		if hostFilter != "" && !clientMatchesIdentifier(f.Client, hostFilter) &&
			!strings.EqualFold(f.Client.DisplayName(), hostFilter) {
			continue
		}
		out = append(out, f)
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out})
}

// handleCVEs serves GET /api/v1/cves with optional minimum severity, KEV-only,
// and host filters applied to both exact and potential CVE product rollups.
func (e *Engine) handleCVEs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var (
		hasMinSev bool
		minSev    checks.Severity
	)
	if rawSev := strings.TrimSpace(q.Get("severity")); rawSev != "" {
		parsed, err := checks.ParseSeverity(rawSev)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_parameter", err.Error())
			return
		}
		hasMinSev = true
		minSev = parsed
	}
	kevOnly := false
	if rawKEV := strings.TrimSpace(q.Get("kev")); rawKEV != "" {
		parsed, err := strconv.ParseBool(rawKEV)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_parameter", "invalid kev boolean parameter")
			return
		}
		kevOnly = parsed
	}
	hostFilter := strings.TrimSpace(q.Get("host"))

	snap := e.Snapshot()
	hostAliases := resolveHostFilterAliases(snap, hostFilter)

	filterSummaries := func(in []cve.ProductSummary) []cve.ProductSummary {
		out := make([]cve.ProductSummary, 0, len(in))
		for _, s := range in {
			if hasMinSev && s.MaxSeverity < minSev {
				continue
			}
			if kevOnly && s.KEVCount == 0 {
				continue
			}
			if hostFilter != "" && !matchesCVESummaryHost(s, hostFilter, hostAliases) {
				continue
			}
			out = append(out, s)
		}
		return out
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"loaded":    snap.CVELoaded,
		"exact":     filterSummaries(snap.ExactCVEs),
		"potential": filterSummaries(snap.PotentialCVEs),
	})
}

// resolveHostFilterAliases expands a host query (IP, MAC, entity ID, or display
// name) into the lowercase set of matching names and IPv4/IPv6 addresses across
// clients and host entities so CVE rollups match regardless of identifier form.
func resolveHostFilterAliases(snap StateSnapshot, hostFilter string) map[string]struct{} {
	if hostFilter == "" {
		return nil
	}
	aliases := map[string]struct{}{
		strings.ToLower(hostFilter): {},
	}
	for _, cv := range snap.Clients {
		if clientMatchesIdentifier(cv.Client, hostFilter) || strings.EqualFold(cv.Client.DisplayName(), hostFilter) {
			if cv.Client.DisplayName() != "" {
				aliases[strings.ToLower(cv.Client.DisplayName())] = struct{}{}
			}
			for _, ip := range cv.Client.AllIPs() {
				aliases[strings.ToLower(ip)] = struct{}{}
			}
		}
	}
	if snap.View != nil {
		for _, ent := range snap.View.Entities {
			if ent == nil || ent.Kind != "host" {
				continue
			}
			if entityMatchesIdentifier(*ent, hostFilter) {
				if ent.Label != "" {
					aliases[strings.ToLower(ent.Label)] = struct{}{}
				}
				if ent.IP != "" {
					aliases[strings.ToLower(ent.IP)] = struct{}{}
				}
				for _, ip6 := range ent.IPv6 {
					if ip6 != "" {
						aliases[strings.ToLower(ip6)] = struct{}{}
					}
				}
			}
		}
	}
	return aliases
}

func matchesCVESummaryHost(s cve.ProductSummary, hostFilter string, aliases map[string]struct{}) bool {
	if strings.EqualFold(s.Product.HostIP, hostFilter) || strings.EqualFold(s.Product.HostName, hostFilter) {
		return true
	}
	if _, ok := aliases[strings.ToLower(s.Product.HostIP)]; ok {
		return true
	}
	if _, ok := aliases[strings.ToLower(s.Product.HostName)]; ok {
		return true
	}
	return false
}

// collectHostEntities returns all host entities sorted worst-verdict-first then
// alphabetically, preferring finalized PresentationModel entities and falling
// back to snap.Clients before the first presentation model is built.
func collectHostEntities(snap StateSnapshot) []Entity {
	var hosts []Entity
	if snap.View != nil && len(snap.View.Entities) > 0 {
		for _, ent := range snap.View.Entities {
			if ent != nil && ent.Kind == "host" {
				hosts = append(hosts, *ent)
			}
		}
	} else {
		for _, cv := range snap.Clients {
			state := VerdictOK
			if cv.FindingCount > 0 {
				state = VerdictExposed
			} else if cv.LastScannedAt == nil && !cv.Skipped {
				state = VerdictUnknown
			}
			hosts = append(hosts, Entity{
				ID:          hostEntityID(cv.Client),
				Kind:        "host",
				Label:       cv.Client.DisplayName(),
				Role:        string(cv.Class.Category),
				State:       state,
				MaxSeverity: cv.MaxSeverity,
				ScannedAt:   cv.LastScannedAt,
				Skipped:     cv.Skipped,
				SkipReason:  cv.SkipReason,
				NetworkID:   cv.Client.NetworkID,
				NetworkName: cv.Client.NetworkName,
				IP:          cv.Client.IP,
				IPv6:        cv.Client.IPv6,
				MAC:         cv.Client.MAC,
				Vendor:      cv.Class.Vendor,
				IsWired:     cv.Client.IsWired,
			})
		}
	}
	sort.Slice(hosts, func(i, j int) bool {
		ri, rj := verdictRank(hosts[i].State), verdictRank(hosts[j].State)
		if ri != rj {
			return ri > rj
		}
		if hosts[i].Label != hosts[j].Label {
			return strings.ToLower(hosts[i].Label) < strings.ToLower(hosts[j].Label)
		}
		return hosts[i].ID < hosts[j].ID
	})
	return hosts
}

func entityMatchesIdentifier(ent Entity, query string) bool {
	q := strings.TrimSpace(query)
	if q == "" {
		return false
	}
	if strings.EqualFold(ent.ID, q) {
		return true
	}
	if ent.MAC != "" && strings.EqualFold(ent.MAC, q) {
		return true
	}
	if ent.IP != "" && strings.EqualFold(ent.IP, q) {
		return true
	}
	for _, ip6 := range ent.IPv6 {
		if strings.EqualFold(ip6, q) {
			return true
		}
	}
	return false
}

// handleHosts serves GET /api/v1/hosts with optional vlan, role, and verdict
// state query filters.
func (e *Engine) handleHosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	vlanFilter := strings.TrimSpace(q.Get("vlan"))
	roleFilter := strings.TrimSpace(q.Get("role"))
	stateFilter := strings.ToLower(strings.TrimSpace(q.Get("state")))
	if stateFilter != "" {
		switch VerdictState(stateFilter) {
		case VerdictOK, VerdictUnknown, VerdictReview, VerdictExposed:
		default:
			writeAPIError(w, http.StatusBadRequest, "invalid_parameter", fmt.Sprintf("unknown state %q (expected ok, unknown, review, or exposed)", stateFilter))
			return
		}
	}

	hosts := collectHostEntities(e.Snapshot())
	out := make([]Entity, 0, len(hosts))
	for _, h := range hosts {
		if stateFilter != "" && string(h.State) != stateFilter {
			continue
		}
		if vlanFilter != "" && !strings.EqualFold(h.NetworkName, vlanFilter) && !strings.EqualFold(h.NetworkID, vlanFilter) {
			continue
		}
		if roleFilter != "" && !strings.EqualFold(h.Role, roleFilter) {
			continue
		}
		out = append(out, h)
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}

// collectDeviceEntities returns all UniFi infrastructure device entities from
// snap.View sorted worst-verdict-first then alphabetically by label.
func collectDeviceEntities(snap StateSnapshot) []Entity {
	var devices []Entity
	if snap.View != nil && len(snap.View.Entities) > 0 {
		for _, ent := range snap.View.Entities {
			if ent != nil && ent.Kind == "device" {
				devices = append(devices, *ent)
			}
		}
	}
	sort.Slice(devices, func(i, j int) bool {
		ri, rj := verdictRank(devices[i].State), verdictRank(devices[j].State)
		if ri != rj {
			return ri > rj
		}
		if label := strings.Compare(strings.ToLower(devices[i].Label), strings.ToLower(devices[j].Label)); label != 0 {
			return label < 0
		}
		return devices[i].ID < devices[j].ID
	})
	return devices
}

func deviceMatchesIdentifier(ent Entity, snap StateSnapshot, query string) bool {
	if entityMatchesIdentifier(ent, query) {
		return true
	}
	// Gateway findings (such as WAN firewall or SSH checks) may reference the
	// gateway's external WAN IP in addition to its LAN management IP.
	if strings.EqualFold(ent.Role, "gateway") && snap.Report.UniFiPosture != nil && snap.Report.UniFiPosture.Health != nil {
		if wanIP := strings.TrimSpace(snap.Report.UniFiPosture.Health.WANIP); wanIP != "" && strings.EqualFold(wanIP, strings.TrimSpace(query)) {
			return true
		}
	}
	return false
}

func (e *Engine) handleHostByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_parameter", "host identifier is required")
		return
	}
	host, ok := resolveHostEntity(e.Snapshot(), id)
	if !ok {
		writeAPIError(w, http.StatusNotFound, "not_found", fmt.Sprintf("host %q not found", id))
		return
	}
	writeJSON(w, http.StatusOK, host)
}

// resolveHostEntity resolves id against LAN clients first and then UniFi
// infrastructure devices (including the gateway's external WAN IP).
func resolveHostEntity(snap StateSnapshot, id string) (Entity, bool) {
	for _, h := range collectHostEntities(snap) {
		if entityMatchesIdentifier(h, id) {
			return h, true
		}
	}
	for _, d := range collectDeviceEntities(snap) {
		if deviceMatchesIdentifier(d, snap, id) {
			return d, true
		}
	}
	return Entity{}, false
}

// resolveBlastHost maps a host or device identifier to its canonical
// blast-simulation asset key and optional UniFi device entity, checking live
// clients and infrastructure devices first, then simulation nodes, and finally
// offline port-forward backend IPs that have no inventory drawer.
func resolveBlastHost(snap StateSnapshot, id string) (string, *Entity) {
	id = strings.TrimSpace(id)
	if id == "" || strings.EqualFold(id, "host:ip/") {
		return "", nil
	}
	for _, cv := range snap.Clients {
		cl := cv.Client
		host := Entity{ID: hostEntityID(cl), MAC: cl.MAC, IP: cl.IP, IPv6: cl.IPv6}
		if strings.EqualFold(cl.ID, id) || entityMatchesIdentifier(host, id) {
			key := cmp.Or(config.CanonicalMAC(cl.MAC), cl.ID, cl.PrimaryIP())
			if snap.View != nil && cl.MAC != "" {
				return key, snap.View.Entities[devEntityID(cl.MAC)]
			}
			return key, nil
		}
	}
	if snap.View == nil {
		return "", nil
	}
	for _, d := range collectDeviceEntities(snap) {
		if strings.EqualFold(d.controllerID, id) || deviceMatchesIdentifier(d, snap, id) {
			return cmp.Or(config.CanonicalMAC(d.MAC), d.controllerID, d.IP), &d
		}
	}
	report := snap.View.Blast
	if report == nil {
		return "", nil
	}
	if report.Simulation != nil {
		for _, n := range report.Simulation.Nodes {
			h := Entity{ID: n.EntityID, MAC: n.ID, IP: n.IP, Label: n.Name, Role: n.Role}
			if n.IsDevice && deviceMatchesIdentifier(h, snap, id) {
				return n.ID, &h
			}
			if entityMatchesIdentifier(h, id) {
				return n.ID, nil
			}
		}
	}
	// Offline forwarding targets have an IP asset key but no inventory drawer.
	if ip, err := netip.ParseAddr(id); err == nil {
		key := ip.Unmap().String()
		if slices.ContainsFunc(report.Exposures, func(x blast.Exposure) bool { return x.Asset == key }) ||
			slices.ContainsFunc(report.Actions, func(a blast.Action) bool { return a.TargetsAsset(key) }) {
			return key, nil
		}
	}
	return "", nil
}

// deviceInfraBlast selects infrastructure compromise reports belonging to a
// single device, matching the logical Controller scope by HostedOnID and
// hardware scopes by canonical TargetID (falling back to device label/ID).
func deviceInfraBlast(reports []blast.InfraReport, device *Entity, key string) []blast.InfraReport {
	out := []blast.InfraReport{}
	matchesDevice := func(s string) bool {
		return device != nil && s != "" && (strings.EqualFold(s, cmp.Or(device.Label, device.Model)) || strings.EqualFold(s, device.ID) ||
			strings.EqualFold(s, device.controllerID) || strings.EqualFold(s, key))
	}
	for _, r := range reports {
		if r.Scope == "Controller" {
			if strings.EqualFold(r.HostedOnID, key) {
				out = append(out, r)
			}
		} else if strings.EqualFold(r.TargetID, key) || r.TargetID == "" && matchesDevice(r.Target) {
			out = append(out, r)
		}
	}
	return out
}

// handleBlast serves the ranked queue and assessments from a single scan.
// The full graph is opt-in so polling the queue does not transfer every route.
func (e *Engine) handleBlast(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	lane := blast.Lane(strings.ToLower(strings.TrimSpace(q.Get("lane"))))
	switch lane {
	case "", blast.LaneFixNow, blast.LaneReduceExposure, blast.LaneVerify:
	default:
		writeAPIError(w, http.StatusBadRequest, "invalid_parameter", fmt.Sprintf("unknown action lane %q", lane))
		return
	}
	priority := blast.Priority(strings.ToUpper(strings.TrimSpace(q.Get("priority"))))
	switch priority {
	case "", blast.P1, blast.P2, blast.P3, blast.P4, blast.P5:
	default:
		writeAPIError(w, http.StatusBadRequest, "invalid_parameter", fmt.Sprintf("unknown priority %q", priority))
		return
	}
	var includeSimulation bool
	if q.Has("include_simulation") {
		switch strings.ToLower(strings.TrimSpace(q.Get("include_simulation"))) {
		case "true", "1":
			includeSimulation = true
		case "false", "0":
		default:
			writeAPIError(w, http.StatusBadRequest, "invalid_parameter", "include_simulation must be true, false, 1, or 0")
			return
		}
	}
	writeJSON(w, http.StatusOK, siteBlast(e.Snapshot(), lane, priority, strings.TrimSpace(q.Get("host")), includeSimulation))
}

// siteBlastResponse adds scan metadata and infrastructure scopes to the software exposure report.
type siteBlastResponse struct {
	// Report contains the selected actions, exposures, egress assessments and optional graph.
	blast.Report
	// Site identifies the inventory used to assess exposure.
	Site string `json:"site"`
	// UpdatedAt timestamps the assessment and its optional graph.
	UpdatedAt time.Time `json:"updated_at"`
	// InfraBlast describes the selected infrastructure compromise scopes.
	InfraBlast []blast.InfraReport `json:"infra_blast"`
}

// siteBlast filters one published snapshot without changing the dashboard's shared slices.
func siteBlast(snap StateSnapshot, lane blast.Lane, priority blast.Priority, hostID string, includeSimulation bool) siteBlastResponse {
	out := siteBlastResponse{
		Site: snap.Site, UpdatedAt: snap.UpdatedAt, InfraBlast: []blast.InfraReport{},
		Report: blast.Report{Actions: []blast.Action{}, Exposures: []blast.Exposure{}, Cloud: []blast.ClientEgress{}},
	}
	if snap.View == nil {
		return out
	}
	report := snap.View.Blast
	if includeSimulation && report != nil {
		out.Simulation = report.Simulation
		if out.Simulation != nil && out.Simulation.Edges == nil {
			graph := *out.Simulation
			graph.Edges = []blast.SimEdge{}
			out.Simulation = &graph
		}
	}
	var key string
	if hostID != "" {
		var device *Entity
		key, device = resolveBlastHost(snap, hostID)
		if key == "" {
			return out
		}
		out.InfraBlast = deviceInfraBlast(snap.View.InfraBlast, device, key)
	} else {
		out.InfraBlast = append(out.InfraBlast, snap.View.InfraBlast...)
	}
	if report == nil {
		return out
	}
	matches := func(l blast.Lane, p blast.Priority) bool {
		return (lane == "" || l == lane) && (priority == "" || p == priority)
	}
	for _, a := range report.Actions {
		if matches(a.Lane, a.HighestTierReduced) && (key == "" || a.TargetsAsset(key)) {
			out.Actions = append(out.Actions, a)
		}
	}
	for _, x := range report.Exposures {
		if matches(x.Lane, x.Priority) && (key == "" || x.Asset == key) {
			out.Exposures = append(out.Exposures, x)
		}
	}
	for _, c := range report.Cloud {
		if key == "" || c.Asset == key {
			out.Cloud = append(out.Cloud, c)
		}
	}
	return out
}

// validateBlastFixes accepts controls anywhere on the graph so callers can
// reuse the same hypothetical changes when switching hosts.
func validateBlastFixes(graph *blast.Simulation, fixes []string) error {
	if len(fixes) == 0 {
		return nil
	}
	valid := make(map[string]bool)
	if graph != nil {
		for _, e := range graph.Edges {
			for _, id := range e.CutIDs {
				valid[id] = true
			}
		}
		for _, n := range graph.Nodes {
			for _, id := range n.EgressCutIDs {
				valid[id] = true
			}
		}
	}
	for _, id := range fixes {
		if id == "" || !valid[id] {
			return fmt.Errorf("unknown simulation fix %q", id)
		}
	}
	return nil
}

// handleHostBlast evaluates hypothetical cuts against the published graph and
// includes the corresponding actions in their original remediation order.
func (e *Engine) handleHostBlast(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_parameter", err.Error())
		return
	}
	mode, err := blast.ParseSimulationMode(q.Get("mode"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_parameter", err.Error())
		return
	}
	id := r.PathValue("id")
	snap := e.Snapshot()
	var graph *blast.Simulation
	if snap.View != nil && snap.View.Blast != nil {
		graph = snap.View.Blast.Simulation
	}
	fixes := q["fix"]
	if err := validateBlastFixes(graph, fixes); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_parameter", err.Error())
		return
	}
	key, device := resolveBlastHost(snap, id)
	if key == "" {
		writeAPIError(w, http.StatusNotFound, "not_found", fmt.Sprintf("host %q not found", id))
		return
	}
	sim, ok := graph.SimulateHost(key, mode, fixes)
	if !ok {
		writeAPIError(w, http.StatusNotFound, "not_found", fmt.Sprintf("blast simulation unavailable for host %q", id))
		return
	}
	actions := []blast.Action{}
	for _, a := range snap.View.Blast.Actions {
		if slices.Contains(sim.RelevantFixes, a.ID) || slices.Contains(sim.AppliedFixes, a.ID) {
			actions = append(actions, a)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"site": snap.Site, "updated_at": snap.UpdatedAt, "simulation": sim,
		"relevant_actions": actions, "infra_blast": deviceInfraBlast(snap.View.InfraBlast, device, key),
	})
}

func (e *Engine) handleDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	roleFilter := strings.TrimSpace(q.Get("role"))
	stateFilter := strings.ToLower(strings.TrimSpace(q.Get("state")))
	if stateFilter != "" {
		switch VerdictState(stateFilter) {
		case VerdictOK, VerdictUnknown, VerdictReview, VerdictExposed:
		default:
			writeAPIError(w, http.StatusBadRequest, "invalid_parameter", fmt.Sprintf("unknown state %q (expected ok, unknown, review, or exposed)", stateFilter))
			return
		}
	}

	devices := collectDeviceEntities(e.Snapshot())
	out := make([]Entity, 0, len(devices))
	for _, d := range devices {
		if stateFilter != "" && string(d.State) != stateFilter {
			continue
		}
		if roleFilter != "" && !strings.EqualFold(d.Role, roleFilter) {
			continue
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (e *Engine) handleDeviceByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_parameter", "device identifier is required")
		return
	}
	snap := e.Snapshot()
	for _, d := range collectDeviceEntities(snap) {
		if deviceMatchesIdentifier(d, snap, id) {
			writeJSON(w, http.StatusOK, d)
			return
		}
	}
	writeAPIError(w, http.StatusNotFound, "not_found", fmt.Sprintf("device %q not found", id))
}

// handleIsolation serves GET /api/v1/isolation with optional verdict, source,
// and dest filters, recomputing summary verdict counts over the filtered cells.
func (e *Engine) handleIsolation(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	verdictFilter := strings.ToLower(strings.TrimSpace(q.Get("verdict")))
	if verdictFilter != "" {
		switch risk.IsolationVerdict(verdictFilter) {
		case risk.IsolationApproved, risk.IsolationBlockedOK, risk.IsolationViolation, risk.IsolationBrokenDependency, risk.IsolationUnknown:
		default:
			writeAPIError(w, http.StatusBadRequest, "invalid_parameter", fmt.Sprintf("unknown isolation verdict %q", verdictFilter))
			return
		}
	}
	srcFilter := strings.TrimSpace(q.Get("source"))
	dstFilter := strings.TrimSpace(q.Get("dest"))

	snap := e.Snapshot()
	if snap.Report.Isolation == nil {
		writeJSON(w, http.StatusOK, risk.IsolationMatrix{Cells: []risk.IsolationCell{}})
		return
	}

	out := risk.IsolationMatrix{Cells: make([]risk.IsolationCell, 0, len(snap.Report.Isolation.Cells))}
	for _, cell := range snap.Report.Isolation.Cells {
		if verdictFilter != "" && string(cell.Verdict) != verdictFilter {
			continue
		}
		if srcFilter != "" && !strings.EqualFold(cell.SourceZone, srcFilter) && !strings.EqualFold(cell.SourceNetwork, srcFilter) {
			continue
		}
		if dstFilter != "" && !strings.EqualFold(cell.DestZone, dstFilter) && !strings.EqualFold(cell.DestNetwork, dstFilter) {
			continue
		}
		out.Cells = append(out.Cells, cell)
		switch cell.Verdict {
		case risk.IsolationApproved:
			out.ApprovedCount++
		case risk.IsolationBlockedOK:
			out.BlockedOKCount++
		case risk.IsolationViolation:
			out.ViolationCount++
		case risk.IsolationBrokenDependency:
			out.BrokenDepCount++
		case risk.IsolationUnknown:
			out.UnknownCount++
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleEventsList serves GET /api/v1/events with optional since_id, limit,
// severity, and comma-separated type filters over the recent event history.
func (e *Engine) handleEventsList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var sinceID int64
	if rawSince := strings.TrimSpace(q.Get("since_id")); rawSince != "" {
		parsed, err := strconv.ParseInt(rawSince, 10, 64)
		if err != nil || parsed < 0 {
			writeAPIError(w, http.StatusBadRequest, "invalid_parameter", "since_id must be a non-negative integer")
			return
		}
		sinceID = parsed
	}
	limit := 50
	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed < 1 || parsed > maxEventHistory {
			writeAPIError(w, http.StatusBadRequest, "invalid_parameter", fmt.Sprintf("limit must be between 1 and %d", maxEventHistory))
			return
		}
		limit = parsed
	}
	var (
		hasMinSev bool
		minSev    checks.Severity
	)
	if rawSev := strings.TrimSpace(q.Get("severity")); rawSev != "" {
		parsed, err := checks.ParseSeverity(rawSev)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_parameter", err.Error())
			return
		}
		hasMinSev = true
		minSev = parsed
	}
	var allowedTypes map[string]struct{}
	if rawType := strings.TrimSpace(q.Get("type")); rawType != "" {
		allowedTypes = make(map[string]struct{})
		for _, part := range strings.Split(rawType, ",") {
			if t := strings.ToLower(strings.TrimSpace(part)); t != "" {
				allowedTypes[t] = struct{}{}
			}
		}
	}

	snap := e.Snapshot()
	out := make([]LiveEvent, 0, min(limit, len(snap.Events)))
	for _, ev := range snap.Events {
		if sinceID > 0 && ev.ID <= sinceID {
			continue
		}
		if len(allowedTypes) > 0 {
			if _, ok := allowedTypes[strings.ToLower(ev.Type)]; !ok {
				continue
			}
		}
		if hasMinSev {
			sev, err := checks.ParseSeverity(ev.Severity)
			if err != nil || sev < minSev {
				continue
			}
		}
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

// handleEventsStream serves GET /api/v1/events/stream over Server-Sent Events,
// replaying missed events after Last-Event-ID (or last_event_id) without
// duplicates and sending 15-second comment pings to keep proxies alive.
func (e *Engine) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "streaming_unsupported", "streaming unsupported")
		return
	}

	var lastEventID int64
	rawLast := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if rawLast == "" {
		rawLast = strings.TrimSpace(r.URL.Query().Get("last_event_id"))
	}
	if rawLast != "" {
		if parsed, err := strconv.ParseInt(rawLast, 10, 64); err == nil && parsed > 0 {
			lastEventID = parsed
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	replay, ch, unsub := e.SubscribeWithReplay(lastEventID)
	defer unsub()

	// Send initial comment so proxies/browsers mark the stream connected immediately.
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	var lastSentID int64
	for _, ev := range replay {
		raw, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		_, _ = fmt.Fprintf(w, "id: %d\nevent: uniblue\ndata: %s\n\n", ev.ID, raw)
		if ev.ID > lastSentID {
			lastSentID = ev.ID
		}
	}
	if len(replay) > 0 {
		flusher.Flush()
	}

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case ev := <-ch:
			if ev.ID <= lastSentID {
				continue
			}
			raw, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "id: %d\nevent: uniblue\ndata: %s\n\n", ev.ID, raw)
			lastSentID = ev.ID
			flusher.Flush()
		}
	}
}

func (e *Engine) handleScans(w http.ResponseWriter, r *http.Request) {
	var host string
	if r.Body != nil {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_request", "failed to read request body")
			return
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			var body struct {
				Host string `json:"host"`
			}
			if err := json.Unmarshal(raw, &body); err != nil {
				writeAPIError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			host = strings.TrimSpace(body.Host)
		}
	}
	if host != "" {
		e.queueHostScanResponse(w, host)
		return
	}
	e.TriggerFullRescan()
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "queued",
		"scope":  "full",
	})
}

func (e *Engine) handleHostScan(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_parameter", "host identifier is required")
		return
	}
	e.queueHostScanResponse(w, id)
}

func (e *Engine) queueHostScanResponse(w http.ResponseWriter, target string) {
	cl, st := e.triggerHostRescanStatus(target)
	switch st {
	case hostRescanNotFound:
		writeAPIError(w, http.StatusNotFound, "not_found", fmt.Sprintf("host %q not found", target))
		return
	case hostRescanQueueFull:
		writeAPIError(w, http.StatusServiceUnavailable, "queue_full", "host scan queue is full; try again shortly")
		return
	}
	resp := map[string]string{
		"status": "queued",
		"scope":  "host",
		"target": hostEntityID(cl),
	}
	if ip := cl.PrimaryIP(); ip != "" {
		resp["ip"] = ip
	}
	writeJSON(w, http.StatusAccepted, resp)
}

func serveEmbeddedSVG(name string) http.HandlerFunc {
	data, _ := fs.ReadFile(docs.LogoFS, name)
	return func(w http.ResponseWriter, _ *http.Request) {
		if len(data) == 0 {
			http.NotFound(w, nil)
			return
		}
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	}
}
