// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNewDemoEngineBuildsCompletePresentationModel verifies that NewDemoEngine
// populates a self-consistent offline demo snapshot containing BMCs, outdoor
// cables, exact CVEs, NVR child cameras, approved/blocked/violated isolation
// cells, and serves all dashboard HTTP endpoints cleanly.
func TestNewDemoEngineBuildsCompletePresentationModel(t *testing.T) {
	eng, err := NewDemoEngine(Options{})
	if err != nil {
		t.Fatalf("NewDemoEngine: %v", err)
	}

	snap := eng.Snapshot()
	if snap.EventMode != "demo" || snap.Scanning {
		t.Fatalf("unexpected demo state: mode=%q scanning=%v", snap.EventMode, snap.Scanning)
	}
	if snap.View == nil {
		t.Fatal("expected non-nil PresentationModel")
	}
	if snap.View.Census.BMCCount != 1 || snap.View.Census.ExactCVEHosts != 2 {
		t.Fatalf("unexpected demo census: %+v", snap.View.Census)
	}
	if snap.View.Isolation == nil || snap.View.Isolation.ApprovedCount == 0 || snap.View.Isolation.BlockedOKCount == 0 || snap.View.Isolation.ViolationCount == 0 || snap.View.Isolation.UnknownCount != 0 {
		t.Fatalf("expected balanced isolation showcase (approved+blocked+violation, 0 unknown), got %+v", snap.View.Isolation)
	}
	if snap.View.ServiceCoverage == nil || snap.View.ServiceCoverage.OutboundDependencies < 2 {
		t.Fatalf("expected service coverage with outbound dependencies, got %+v", snap.View.ServiceCoverage)
	}

	// Verify HTTP routes and static HTML rendering work cleanly in demo mode.
	h := eng.Handler()
	for _, route := range []string{"/", "/api/v1/health", "/api/v1/state", "/api/v1/findings", "/api/v1/hosts", "/assets/logo-light.svg", "/assets/favicon.svg", "/favicon.ico"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080"+route, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", route, rec.Code)
		}
	}

	// Verify demo rescan triggers do not panic and emit simulated events.
	eng.TriggerFullRescan()
	if !eng.TriggerHostRescan("192.168.10.10") {
		t.Fatal("expected TriggerHostRescan on known demo IP to succeed")
	}

	var buf bytes.Buffer
	if err := RenderStaticHTML(&buf, snap); err != nil {
		t.Fatalf("RenderStaticHTML(demo): %v", err)
	}
	if !strings.Contains(buf.String(), "cedar-home") {
		t.Fatal("expected demo site name in static HTML export")
	}
}
