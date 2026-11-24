// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/topology"
	"github.com/karalabe/uniblue/internal/unifi"
)

func newTestEngine() *Engine {
	snap := &unifi.Snapshot{
		Site:           "default",
		ControllerType: "integration-v1",
		Clients: []unifi.Client{
			{
				MAC:         "aa:bb:cc:dd:ee:01",
				Name:        "workstation-1",
				IP:          "192.0.2.10",
				NetworkName: "Default",
			},
		},
	}
	eng := &Engine{
		eventMode:      "poll-5s",
		snap:           snap,
		fullRescanCh:   make(chan string, 1),
		hostScanCh:     make(chan unifi.Client, 4),
		missingClients: make(map[string]missingClient),
		subscribers:    make(map[chan LiveEvent]struct{}),
		current: StateSnapshot{
			StartedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
			EventMode:      "poll-5s",
			Site:           "default",
			ControllerType: "integration-v1",
			Topology: &topology.Model{
				Site: "default",
				VLANs: []topology.VLANGroup{
					{
						Name:     "Default",
						Subnet:   "192.0.2.0/24",
						ZoneName: "Internal",
						Clients: []topology.ClientNode{
							{Name: "workstation-1", IP: "192.0.2.10", MAC: "aa:bb:cc:dd:ee:01", Placement: topology.PlacementOK},
						},
					},
				},
			},
		},
	}
	return eng
}

func TestHTTPHandlers(t *testing.T) {
	eng := newTestEngine()
	h := eng.Handler()

	// GET / serves the self-contained dashboard HTML.
	t.Run("index", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET / status = %d, want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Fatalf("GET / content-type = %q, want text/html", ct)
		}
		if !strings.Contains(rec.Body.String(), "UniBlue") || !strings.Contains(rec.Body.String(), "/api/events") {
			t.Fatalf("GET / missing expected dashboard markup")
		}
	})

	// Unknown root subpaths return 404.
	t.Run("not_found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET /does-not-exist status = %d, want 404", rec.Code)
		}
	})

	// Embedded theme-specific SVG logos are served with image/svg+xml.
	for _, path := range []string{"/assets/logo-light.svg", "/assets/logo-dark.svg"} {
		t.Run("asset_"+path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200", path, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "image/svg+xml") {
				t.Fatalf("GET %s content-type = %q, want image/svg+xml", path, ct)
			}
			if !strings.Contains(rec.Body.String(), "<svg") {
				t.Fatalf("GET %s did not return SVG payload", path)
			}
		})
	}

	// GET /api/state returns the live StateSnapshot JSON.
	t.Run("state", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/state", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/state status = %d, want 200", rec.Code)
		}
		var got StateSnapshot
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode /api/state: %v", err)
		}
		if got.Site != "default" || got.EventMode != "poll-5s" {
			t.Fatalf("unexpected state: %+v", got)
		}
	})

	// RenderStaticHTML produces a self-contained offline HTML report with embedded state.
	t.Run("static_html_export", func(t *testing.T) {
		var buf strings.Builder
		if err := RenderStaticHTML(&buf, eng.Snapshot()); err != nil {
			t.Fatalf("RenderStaticHTML: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, `id="uniblue-static-state"`) || !strings.Contains(out, "workstation-1") {
			t.Fatalf("RenderStaticHTML missing embedded state or client name")
		}
	})

	// POST /api/rescan queues full or single-host rescans and rejects unknown IPs.
	t.Run("rescan", func(t *testing.T) {
		// Full rescan
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/rescan", nil))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("POST /api/rescan status = %d, want 202", rec.Code)
		}
		select {
		case <-eng.fullRescanCh:
		default:
			t.Fatalf("expected full rescan signal to be queued")
		}

		// Known host rescan
		recHost := httptest.NewRecorder()
		h.ServeHTTP(recHost, httptest.NewRequest(http.MethodPost, "/api/rescan?ip=192.0.2.10", nil))
		if recHost.Code != http.StatusAccepted {
			t.Fatalf("POST /api/rescan?ip=192.0.2.10 status = %d, want 202", recHost.Code)
		}
		select {
		case cl := <-eng.hostScanCh:
			if cl.IP != "192.0.2.10" {
				t.Fatalf("queued host IP = %q, want 192.0.2.10", cl.IP)
			}
		default:
			t.Fatalf("expected host rescan to be queued")
		}

		// Unknown host rescan returns 404
		recUnknown := httptest.NewRecorder()
		h.ServeHTTP(recUnknown, httptest.NewRequest(http.MethodPost, "/api/rescan?ip=192.0.2.99", nil))
		if recUnknown.Code != http.StatusNotFound {
			t.Fatalf("POST /api/rescan unknown IP status = %d, want 404", recUnknown.Code)
		}
	})
}

func TestEventsSSE(t *testing.T) {
	eng := newTestEngine()
	srv := httptest.NewServer(eng.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/events", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /api/events: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/events status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("GET /api/events content-type = %q, want text/event-stream", ct)
	}

	br := bufio.NewReader(resp.Body)
	// First line should be the ": connected" keepalive comment.
	firstLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read initial SSE comment: %v", err)
	}
	if !strings.HasPrefix(firstLine, ": connected") {
		t.Fatalf("first SSE line = %q, want ': connected'", firstLine)
	}
	// Consume blank line separating comment frame.
	_, _ = br.ReadString('\n')

	// Emit a live event and confirm it arrives over SSE.
	eng.emit(LiveEvent{
		Type:     "client_joined",
		Severity: "info",
		Host:     "sensor-1",
		IP:       "192.0.2.55",
		Summary:  "sensor-1 joined IoT (192.0.2.55)",
	})

	var eventName, dataLine string
	for range 5 {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE event line: %v", err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "event: ") {
			eventName = strings.TrimPrefix(line, "event: ")
		}
		if strings.HasPrefix(line, "data: ") {
			dataLine = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if eventName != "uniblue" {
		t.Fatalf("SSE event name = %q, want 'uniblue'", eventName)
	}
	var got LiveEvent
	if err := json.Unmarshal([]byte(dataLine), &got); err != nil {
		t.Fatalf("unmarshal SSE payload %q: %v", dataLine, err)
	}
	if got.Type != "client_joined" || got.IP != "192.0.2.55" || got.ID == 0 {
		t.Fatalf("unexpected SSE event: %+v", got)
	}
}
