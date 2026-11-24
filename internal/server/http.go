package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"time"

	"github.com/karalabe/uniblue/docs"
	"github.com/karalabe/uniblue/internal/topology"
)

// Serve starts the HTTP server for the built-in web UI, JSON API, live SVG
// topology endpoint, and SSE event stream, shutting down gracefully when ctx is
// cancelled.
func (e *Engine) Serve(ctx context.Context) error {
	addr := e.opts.ListenAddr
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	mux := e.Handler()
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
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
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// Handler builds the HTTP router for UniBlue's live dashboard and APIs.
func (e *Engine) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", e.handleIndex)
	mux.HandleFunc("GET /api/state", e.handleState)
	mux.HandleFunc("GET /api/topology.svg", e.handleTopologySVG)
	mux.HandleFunc("GET /api/events", e.handleEventsSSE)
	mux.HandleFunc("POST /api/rescan", e.handleRescan)
	mux.HandleFunc("GET /assets/logo-light.svg", serveEmbeddedSVG("logo-horizontal-light.svg"))
	mux.HandleFunc("GET /assets/logo-dark.svg", serveEmbeddedSVG("logo-horizontal-dark.svg"))
	return mux
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

func (e *Engine) handleTopologySVG(w http.ResponseWriter, _ *http.Request) {
	snap := e.Snapshot()
	if snap.Topology == nil {
		http.Error(w, "topology not ready yet", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := topology.RenderSVG(w, snap.Topology); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
	if ip := r.URL.Query().Get("ip"); ip != "" {
		if !e.TriggerHostRescan(ip) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"status":"not_found"}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprintf(w, `{"status":"queued","ip":%q}`, ip)
		return
	}
	e.TriggerFullRescan()
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"queued","scope":"full"}`))
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
