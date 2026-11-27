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
	"slices"
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
	if snap.View.Isolation == nil || snap.View.Isolation.ApprovedCount == 0 || snap.View.Isolation.BlockedOKCount == 0 || snap.View.Isolation.ViolationCount == 0 || snap.View.Isolation.UnknownCount == 0 {
		t.Fatalf("expected balanced isolation showcase (approved, blocked, violation, and unverified paths), got %+v", snap.View.Isolation)
	}
	if snap.View.ServiceCoverage == nil || snap.View.ServiceCoverage.OutboundDependencies < 2 {
		t.Fatalf("expected service coverage with outbound dependencies, got %+v", snap.View.ServiceCoverage)
	}
	if snap.View.Blast == nil || len(snap.View.Blast.Actions) == 0 {
		t.Fatalf("expected populated 3-lane blast action queue in demo view, got %+v", snap.View.Blast)
	}
	sim := snap.View.Blast.Simulation
	if sim == nil || len(sim.Nodes) < 2 || len(sim.Edges) == 0 {
		t.Fatal("demo simulator has no selectable paths")
	}
	drawers := make(map[string]bool)
	for _, n := range sim.Nodes {
		if snap.View.Entities[n.EntityID] == nil {
			t.Errorf("simulator node %q has no drawer for %q", n.Name, n.EntityID)
		}
		drawers[n.ID] = true
	}
	lanes := map[string]int{}
	priorities := 0
	var hasHighProfile, hasDemoKEV bool
	for _, a := range snap.View.Blast.Actions {
		if strings.Contains(a.ID, "UB-UNIFI-") {
			t.Fatalf("synthetic controller posture finding leaked into blast action queue: %+v", a)
		}
		lanes[string(a.Lane)]++
		if priorities < 3 && a.HighestTierReduced != "" && a.Lane != "verify" {
			priorities++
			if a.Reason == "" || !slices.ContainsFunc(a.AffectedAssets, func(id string) bool { return drawers[id] }) {
				t.Errorf("Checkup priority %q needs a reason and a device drawer", a.Title)
			}
		}
		if a.HighProfile {
			hasHighProfile = true
		}
		if strings.Contains(a.ID, "CVE-2024-6387") {
			hasDemoKEV = true
		}
	}
	if priorities != 3 {
		t.Errorf("demo Checkup shows %d top priorities, want 3", priorities)
	}
	if lanes["fix-now"] == 0 || lanes["reduce-exposure"] == 0 {
		t.Fatalf("expected fix-now and reduce-exposure demo actions, got lanes=%+v", lanes)
	}
	if !hasHighProfile {
		t.Fatalf("expected at least one high-profile target signal on demo actions, got %+v", snap.View.Blast.Actions)
	}
	if !hasDemoKEV {
		t.Fatalf("expected demo CVE-2024-6387 KEV patch action derived from shared demo CVE matches, got %+v", snap.View.Blast.Actions)
	}
	if len(snap.View.InfraBlast) < 2 {
		t.Fatalf("expected per-device infrastructure what-if reports in demo view, got %d", len(snap.View.InfraBlast))
	}
	if len(snap.View.Queue) == 0 || len(snap.View.Entities) == 0 {
		t.Fatalf("expected existing queue and entity details to remain intact alongside action queue")
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
	html := buf.String()
	for _, want := range []string{"cedar-home", `"blast":`, `"simulation":`, `id="view-blast"`, `"infra_blast":`, `"target_id":"controller"`, `"CVE-2024-6387"`, `"act:wan-pf:pf-https"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected %q in static HTML export", want)
		}
	}
}
