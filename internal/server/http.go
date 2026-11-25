// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"context"
	"crypto/hmac"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karalabe/uniblue/docs"
)

const (
	sessionCookieName = "uniblue_session"

	authMaxFailedAttempts  = 5
	authFailureWindow      = 15 * time.Minute
	authLockoutDuration    = 15 * time.Minute
	authMaxLockoutDuration = 1 * time.Hour
	authMaxTrackedClients  = 1024
)

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

func writeAuthLockedResponse(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int(retryAfter.Round(time.Second).Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "too many failed authentication attempts; try again later",
	})
}

// Serve starts the HTTP server for the built-in web UI, JSON API, live SVG
// topology endpoint, and SSE event stream, shutting down gracefully when ctx is
// cancelled.
func (e *Engine) Serve(ctx context.Context) error {
	addr := e.opts.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:8080"
		e.opts.ListenAddr = addr
	}

	if !isLoopbackListenAddr(addr) && e.effectiveAPIToken() == "" {
		e.logger.Warn("uniblue web UI listening on non-loopback address without UNIBLUE_API_TOKEN; set UNIBLUE_API_TOKEN to require bearer auth on /api/*", "listen", addr)
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

// Handler builds the HTTP router for UniBlue's live dashboard and APIs wrapped
// with Host (DNS-rebinding), Origin/Sec-Fetch-Site (CSRF), and optional Bearer
// token / HttpOnly session cookie protection.
func (e *Engine) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", e.handleIndex)
	mux.HandleFunc("POST /api/auth", e.handleAuth)
	mux.HandleFunc("GET /api/state", e.handleState)
	mux.HandleFunc("GET /api/events", e.handleEventsSSE)
	mux.HandleFunc("POST /api/rescan", e.handleRescan)
	mux.HandleFunc("GET /assets/logo-light.svg", serveEmbeddedSVG("logo-header-light.svg"))
	mux.HandleFunc("GET /assets/logo-dark.svg", serveEmbeddedSVG("logo-header-dark.svg"))
	mux.HandleFunc("GET /assets/favicon.svg", serveEmbeddedSVG("logo-light.svg"))
	mux.HandleFunc("GET /favicon.ico", serveEmbeddedSVG("logo-light.svg"))
	return e.protectHTTP(mux)
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

func sessionCookieValue(apiToken string) string {
	mac := hmac.New(sha256.New, []byte(apiToken))
	_, _ = mac.Write([]byte("uniblue-web-session-v1"))
	return hex.EncodeToString(mac.Sum(nil))
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

func hasValidAPIAuth(r *http.Request, tok string) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if strings.HasPrefix(auth, prefix) {
		cand := strings.TrimSpace(auth[len(prefix):])
		if subtle.ConstantTimeCompare([]byte(cand), []byte(tok)) == 1 {
			return true
		}
	}
	if ck, err := r.Cookie(sessionCookieName); err == nil && ck.Value != "" {
		want := sessionCookieValue(tok)
		if subtle.ConstantTimeCompare([]byte(ck.Value), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

// protectHTTP rejects DNS-rebinding Host headers on both loopback and LAN
// listeners (honoring UNIBLUE_ALLOWED_HOSTS for reverse proxies), blocks
// cross-origin / cross-site browser requests (especially POST /api/rescan CSRF),
// and enforces Bearer token or HttpOnly session cookie auth on /api/* when
// UNIBLUE_API_TOKEN is set.
func (e *Engine) protectHTTP(next http.Handler) http.Handler {
	loopbackOnly := isLoopbackListenAddr(e.opts.ListenAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedHosts := e.effectiveAllowedHosts()
		if r.Host != "" && !matchesAllowedHost(r.Host, allowedHosts) {
			hostName := requestHostName(r.Host)
			if loopbackOnly {
				if !isLoopbackHostName(hostName) {
					http.Error(w, "forbidden host header", http.StatusForbidden)
					return
				}
			} else if !isAllowedLANHostName(hostName) {
				http.Error(w, "forbidden host header", http.StatusForbidden)
				return
			}
		}

		isAPI := strings.HasPrefix(r.URL.Path, "/api/")
		if isAPI || (r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions) {
			if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
				parsedOrigin, err := url.Parse(origin)
				if err != nil || parsedOrigin.Host == "" ||
					(!strings.EqualFold(parsedOrigin.Host, r.Host) && !matchesAllowedHost(parsedOrigin.Host, allowedHosts)) {
					http.Error(w, "forbidden cross-origin request", http.StatusForbidden)
					return
				}
			}
			if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs != "" && sfs != "same-origin" && sfs != "none" {
				http.Error(w, "forbidden cross-site request", http.StatusForbidden)
				return
			}
		}

		if isAPI && !(r.Method == http.MethodPost && r.URL.Path == "/api/auth") {
			if tok := e.effectiveAPIToken(); tok != "" {
				ip := clientRemoteIP(r)
				if locked, retryAfter := e.authLimiter.checkLocked(ip); locked {
					writeAuthLockedResponse(w, retryAfter)
					return
				}
				if !hasValidAPIAuth(r, tok) {
					// Count failed attempts only when the client actually sent
					// an invalid credential (Bearer token or session cookie), so
					// unauthenticated initial page loads prompting for login
					// never trigger a lockout. Clear stale/invalid cookies so
					// browsers with a rotated token do not keep resending them.
					hasBearer := strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
					ck, ckErr := r.Cookie(sessionCookieName)
					hasBadCookie := ckErr == nil && ck.Value != ""
					if hasBadCookie {
						http.SetCookie(w, &http.Cookie{
							Name:     sessionCookieName,
							Value:    "",
							Path:     "/",
							HttpOnly: true,
							SameSite: http.SameSiteStrictMode,
							Secure:   r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https"),
							MaxAge:   -1,
						})
					}
					if hasBearer || hasBadCookie {
						if locked, retryAfter := e.authLimiter.recordFailure(ip); locked {
							writeAuthLockedResponse(w, retryAfter)
							return
						}
					}
					w.Header().Set("WWW-Authenticate", `Bearer realm="uniblue"`)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				e.authLimiter.reset(ip)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (e *Engine) handleAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	tok := e.effectiveAPIToken()
	if tok == "" {
		_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "required": false})
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
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
		return
	}

	e.authLimiter.reset(ip)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionCookieValue(tok),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https"),
		MaxAge:   30 * 24 * 3600,
	})
	_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "required": true})
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

func (e *Engine) handleState(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	_ = enc.Encode(e.Snapshot())
}

func (e *Engine) handleEventsSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := e.Subscribe()
	defer unsub()

	// Send initial comment so proxies/browsers mark the stream connected immediately.
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

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
			raw, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "id: %d\nevent: uniblue\ndata: %s\n\n", ev.ID, raw)
			flusher.Flush()
		}
	}
}

func (e *Engine) handleRescan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if ip := strings.TrimSpace(r.URL.Query().Get("ip")); ip != "" {
		switch e.triggerHostRescanStatus(ip) {
		case hostRescanNotFound:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "not_found"})
			return
		case hostRescanQueueFull:
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "queue_full"})
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "queued", "ip": ip})
		return
	}
	e.TriggerFullRescan()
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "queued", "scope": "full"})
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
