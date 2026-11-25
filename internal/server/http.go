// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
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
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karalabe/uniblue/docs"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/risk"
)

const (
	sessionCookieName = "uniblue_session"
	sessionTTL        = 30 * 24 * time.Hour
	maxActiveSessions = 256

	authMaxFailedAttempts  = 5
	authFailureWindow      = 15 * time.Minute
	authLockoutDuration    = 15 * time.Minute
	authMaxLockoutDuration = 1 * time.Hour
	authMaxTrackedClients  = 1024
)

type sessionEntry struct {
	tokenHash [32]byte
	createdAt time.Time
	expiresAt time.Time
}

// sessionStore holds per-login random HttpOnly session tokens in memory with
// bounded capacity, expiry, and explicit revocation on logout.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]sessionEntry
	nowFn    func() time.Time
}

func (s *sessionStore) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

func (s *sessionStore) create(apiToken string) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	id := hex.EncodeToString(raw[:])
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[string]sessionEntry)
	}
	for k, entry := range s.sessions {
		if !now.Before(entry.expiresAt) {
			delete(s.sessions, k)
		}
	}
	for len(s.sessions) >= maxActiveSessions {
		var oldestKey string
		var oldestTime time.Time
		for k, entry := range s.sessions {
			if oldestKey == "" || entry.createdAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = entry.createdAt
			}
		}
		if oldestKey == "" {
			break
		}
		delete(s.sessions, oldestKey)
	}
	s.sessions[id] = sessionEntry{
		tokenHash: sha256.Sum256([]byte(apiToken)),
		createdAt: now,
		expiresAt: now.Add(sessionTTL),
	}
	return id, nil
}

func (s *sessionStore) validate(sessionID, apiToken string) bool {
	if sessionID == "" || apiToken == "" {
		return false
	}
	now := s.now()
	wantHash := sha256.Sum256([]byte(apiToken))

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) == 0 {
		return false
	}
	entry, ok := s.sessions[sessionID]
	if !ok {
		return false
	}
	if !now.Before(entry.expiresAt) {
		delete(s.sessions, sessionID)
		return false
	}
	if subtle.ConstantTimeCompare(entry.tokenHash[:], wantHash[:]) != 1 {
		delete(s.sessions, sessionID)
		return false
	}
	return true
}

func (s *sessionStore) revoke(sessionID string) {
	if sessionID == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
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

func (l *authFailureLimiter) checkLocked(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.clients == nil {
		return false, 0
	}
	st, ok := l.clients[ip]
	if !ok {
		return false, 0
	}
	now := l.now()
	if now.Before(st.lockedUntil) {
		return true, st.lockedUntil.Sub(now)
	}
	return false, 0
}

func (l *authFailureLimiter) recordFailure(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.clients == nil {
		l.clients = make(map[string]authAttemptState)
	}
	now := l.now()
	st, ok := l.clients[ip]
	if ok {
		if now.Before(st.lockedUntil) {
			return true, st.lockedUntil.Sub(now)
		}
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
		return true, dur
	}
	l.clients[ip] = st
	return false, 0
}

func (l *authFailureLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.clients != nil {
		delete(l.clients, ip)
	}
}

func (l *authFailureLimiter) evictStaleLocked(now time.Time) {
	for k, st := range l.clients {
		if !now.Before(st.lockedUntil) && now.Sub(st.lastSeen) > authFailureWindow {
			delete(l.clients, k)
		}
	}
	if len(l.clients) < authMaxTrackedClients {
		return
	}
	var oldestKey string
	var oldestTime time.Time
	for k, st := range l.clients {
		if oldestKey == "" || st.lastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = st.lastSeen
		}
	}
	if oldestKey != "" {
		delete(l.clients, oldestKey)
	}
}

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
	Status         string    `json:"status"`
	Site           string    `json:"site"`
	ControllerType string    `json:"controller_type,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	LastFullScanAt time.Time `json:"last_full_scan_at,omitempty"`
	LastScanError  string    `json:"last_scan_error,omitempty"`
	Scanning       bool      `json:"scanning"`
	EventMode      string    `json:"event_mode"`
	CVELoaded      bool      `json:"cve_loaded"`
	ClientCount    int       `json:"client_count"`
	FindingCount   int       `json:"finding_count"`
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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", e.handleIndex)
	mux.HandleFunc("GET /api/v1/health", e.handleHealth)
	mux.HandleFunc("GET /api/v1/session", e.handleSessionGet)
	mux.HandleFunc("POST /api/v1/session", e.handleSessionCreate)
	mux.HandleFunc("DELETE /api/v1/session", e.handleSessionDelete)
	mux.HandleFunc("GET /api/v1/state", e.handleState)
	mux.HandleFunc("GET /api/v1/findings", e.handleFindings)
	mux.HandleFunc("GET /api/v1/cves", e.handleCVEs)
	mux.HandleFunc("GET /api/v1/hosts", e.handleHosts)
	mux.HandleFunc("GET /api/v1/hosts/{id}", e.handleHostByID)
	mux.HandleFunc("GET /api/v1/isolation", e.handleIsolation)
	mux.HandleFunc("GET /api/v1/events", e.handleEventsList)
	mux.HandleFunc("GET /api/v1/events/stream", e.handleEventsStream)
	mux.HandleFunc("POST /api/v1/scans", e.handleScans)
	mux.HandleFunc("POST /api/v1/hosts/{id}/scan", e.handleHostScan)
	mux.HandleFunc("GET /assets/logo-light.svg", serveEmbeddedSVG("logo-header-light.svg"))
	mux.HandleFunc("GET /assets/logo-dark.svg", serveEmbeddedSVG("logo-header-dark.svg"))
	mux.HandleFunc("GET /assets/favicon.svg", serveEmbeddedSVG("logo-light.svg"))
	mux.HandleFunc("GET /favicon.ico", serveEmbeddedSVG("logo-light.svg"))

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

func (e *Engine) hasValidAPIAuth(r *http.Request, tok string) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if strings.HasPrefix(auth, prefix) {
		cand := strings.TrimSpace(auth[len(prefix):])
		if subtle.ConstantTimeCompare([]byte(cand), []byte(tok)) == 1 {
			return true
		}
	}
	if ck, err := r.Cookie(sessionCookieName); err == nil && ck.Value != "" {
		if e.sessions.validate(ck.Value, tok) {
			return true
		}
	}
	return false
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

		isSessionEndpoint := r.URL.Path == "/api/v1/session" &&
			(r.Method == http.MethodGet || r.Method == http.MethodPost || r.Method == http.MethodDelete)
		if isAPI && !isSessionEndpoint {
			if tok := e.effectiveAPIToken(); tok != "" {
				ip := clientRemoteIP(r)
				if locked, retryAfter := e.authLimiter.checkLocked(ip); locked {
					writeAuthLockedResponse(w, retryAfter)
					return
				}
				if !e.hasValidAPIAuth(r, tok) {
					// Count failed attempts only when the client actually sent
					// an invalid credential (Bearer token or session cookie), so
					// unauthenticated initial page loads prompting for login
					// never trigger a lockout. Clear stale/invalid cookies so
					// browsers with a rotated token do not keep resending them.
					hasBearer := strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
					ck, ckErr := r.Cookie(sessionCookieName)
					hasBadCookie := ckErr == nil && ck.Value != ""
					if hasBadCookie {
						clearSessionCookie(w, r)
					}
					if hasBearer || hasBadCookie {
						if locked, retryAfter := e.authLimiter.recordFailure(ip); locked {
							writeAuthLockedResponse(w, retryAfter)
							return
						}
					}
					w.Header().Set("WWW-Authenticate", `Bearer realm="uniblue"`)
					writeAPIError(w, http.StatusUnauthorized, "unauthorized", "valid bearer token or session cookie required")
					return
				}
				e.authLimiter.reset(ip)
			}
		}

		next.ServeHTTP(w, r)
	})
}

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

	hasBearer := strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
	ck, ckErr := r.Cookie(sessionCookieName)
	hasCookie := ckErr == nil && ck.Value != ""

	ip := clientRemoteIP(r)
	if hasBearer || hasCookie {
		if locked, retryAfter := e.authLimiter.checkLocked(ip); locked {
			writeAuthLockedResponse(w, retryAfter)
			return
		}
		if e.hasValidAPIAuth(r, tok) {
			e.authLimiter.reset(ip)
			writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "required": true})
			return
		}
		if hasCookie {
			clearSessionCookie(w, r)
		}
		if locked, retryAfter := e.authLimiter.recordFailure(ip); locked {
			writeAuthLockedResponse(w, retryAfter)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false, "required": true})
}

func (e *Engine) handleSessionCreate(w http.ResponseWriter, r *http.Request) {
	tok := e.effectiveAPIToken()
	if tok == "" {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "required": false})
		return
	}

	ip := clientRemoteIP(r)
	if locked, retryAfter := e.authLimiter.checkLocked(ip); locked {
		writeAuthLockedResponse(w, retryAfter)
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
	if cand == "" || subtle.ConstantTimeCompare([]byte(cand), []byte(tok)) != 1 {
		if locked, retryAfter := e.authLimiter.recordFailure(ip); locked {
			writeAuthLockedResponse(w, retryAfter)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="uniblue"`)
		writeAPIError(w, http.StatusUnauthorized, "invalid_token", "invalid API token")
		return
	}

	e.authLimiter.reset(ip)

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
		e.sessions.revoke(ck.Value)
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

// RenderStaticHTML renders a self-contained, offline interactive HTML snapshot
// of the full UniBlue console (with embedded logos and baked JSON state) for
// `uniblue topology -out topology.html`.
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

func (e *Engine) handleHostByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_parameter", "host identifier is required")
		return
	}
	for _, h := range collectHostEntities(e.Snapshot()) {
		if entityMatchesIdentifier(h, id) {
			writeJSON(w, http.StatusOK, h)
			return
		}
	}
	writeAPIError(w, http.StatusNotFound, "not_found", fmt.Sprintf("host %q not found", id))
}

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
