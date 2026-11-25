// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/karalabe/uniblue/docs"
)

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
// token protection.
func (e *Engine) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", e.handleIndex)
	mux.HandleFunc("GET /api/state", e.handleState)
	mux.HandleFunc("GET /api/events", e.handleEventsSSE)
	mux.HandleFunc("POST /api/rescan", e.handleRescan)
	mux.HandleFunc("GET /assets/logo-light.svg", serveEmbeddedSVG("logo-horizontal-light.svg"))
	mux.HandleFunc("GET /assets/logo-dark.svg", serveEmbeddedSVG("logo-horizontal-dark.svg"))
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
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
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

// protectHTTP rejects DNS-rebinding Host headers on loopback listeners, blocks
// cross-origin / cross-site browser requests (especially POST /api/rescan CSRF),
// and enforces Bearer token authentication on /api/* when UNIBLUE_API_TOKEN is set.
func (e *Engine) protectHTTP(next http.Handler) http.Handler {
	loopbackOnly := isLoopbackListenAddr(e.opts.ListenAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loopbackOnly && r.Host != "" && !isLoopbackHostName(requestHostName(r.Host)) {
			http.Error(w, "forbidden host header", http.StatusForbidden)
			return
		}

		isAPI := strings.HasPrefix(r.URL.Path, "/api/")
		if isAPI || (r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions) {
			if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
				parsedOrigin, err := url.Parse(origin)
				if err != nil || !strings.EqualFold(parsedOrigin.Host, r.Host) {
					http.Error(w, "forbidden cross-origin request", http.StatusForbidden)
					return
				}
			}
			if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs != "" && sfs != "same-origin" && sfs != "none" {
				http.Error(w, "forbidden cross-site request", http.StatusForbidden)
				return
			}
		}

		if isAPI {
			if tok := e.effectiveAPIToken(); tok != "" {
				auth := strings.TrimSpace(r.Header.Get("Authorization"))
				const prefix = "Bearer "
				if !strings.HasPrefix(auth, prefix) ||
					subtle.ConstantTimeCompare([]byte(strings.TrimSpace(auth[len(prefix):])), []byte(tok)) != 1 {
					w.Header().Set("WWW-Authenticate", `Bearer realm="uniblue"`)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
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
	if light, err := fs.ReadFile(docs.LogoFS, "logo-horizontal-light.svg"); err == nil && len(light) > 0 {
		uri := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(light)
		html = strings.ReplaceAll(html, `src="/assets/logo-light.svg"`, `src="`+uri+`"`)
	}
	if dark, err := fs.ReadFile(docs.LogoFS, "logo-horizontal-dark.svg"); err == nil && len(dark) > 0 {
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
