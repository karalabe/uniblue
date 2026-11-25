// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestHTTPProtectionHostOriginTokenAndRescanResponses verifies DNS-rebinding
// Host protection, cross-origin POST CSRF blocking, Bearer token enforcement
// (#26), 503 queue-full response (#38), and valid JSON marshaling (#41).
func TestHTTPProtectionHostOriginTokenAndRescanResponses(t *testing.T) {
	eng := NewDemoEngineForTest(t)
	eng.opts.ListenAddr = "127.0.0.1:8080"
	h := eng.Handler()

	// 1. Spoofed Host header on loopback listener must be rejected (403).
	req := httptest.NewRequest(http.MethodGet, "http://rebind.evil.example/api/state", nil)
	req.Host = "rebind.evil.example:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for spoofed Host header, got %d", rec.Code)
	}

	// 2. Cross-origin POST /api/rescan must be rejected (403).
	reqCSRF := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/rescan", nil)
	reqCSRF.Host = "127.0.0.1:8080"
	reqCSRF.Header.Set("Origin", "https://evil.example")
	recCSRF := httptest.NewRecorder()
	h.ServeHTTP(recCSRF, reqCSRF)
	if recCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin POST /api/rescan, got %d", recCSRF.Code)
	}

	// 3. Same-origin POST /api/rescan succeeds.
	reqOK := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/rescan", nil)
	reqOK.Host = "127.0.0.1:8080"
	reqOK.Header.Set("Origin", "http://127.0.0.1:8080")
	recOK := httptest.NewRecorder()
	h.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for same-origin POST /api/rescan, got %d", recOK.Code)
	}

	// 4. Optional Bearer token protects /api/* endpoints.
	eng.opts.APIToken = "secret-token"
	hTok := eng.Handler()
	reqNoAuth := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/state", nil)
	reqNoAuth.Host = "127.0.0.1:8080"
	recNoAuth := httptest.NewRecorder()
	hTok.ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when APIToken required and absent, got %d", recNoAuth.Code)
	}
	reqAuth := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/state", nil)
	reqAuth.Host = "127.0.0.1:8080"
	reqAuth.Header.Set("Authorization", "Bearer secret-token")
	recAuth := httptest.NewRecorder()
	hTok.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid Bearer token, got %d", recAuth.Code)
	}

	// 5. Full host-scan queue returns 503 Service Unavailable (not 404).
	liveEng := &Engine{
		demoMode:    false,
		hostScanCh:  make(chan hostScanTask, 1),
		subscribers: make(map[chan LiveEvent]struct{}),
		snap: &unifi.Snapshot{
			Clients: []unifi.Client{{MAC: "02:aa:00:00:00:01", IP: "192.0.2.10", Name: "host1"}},
		},
	}
	liveEng.hostScanCh <- hostScanTask{} // fill queue
	recFull := httptest.NewRecorder()
	liveEng.handleRescan(recFull, httptest.NewRequest(http.MethodPost, "/api/rescan?ip=192.0.2.10", nil))
	if recFull.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when hostScanCh is full, got %d", recFull.Code)
	}
}

// NewDemoEngineForTest constructs a demo Engine for HTTP handler tests.
func NewDemoEngineForTest(t *testing.T) *Engine {
	t.Helper()
	eng, err := NewDemoEngine(Options{})
	if err != nil {
		t.Fatalf("NewDemoEngine: %v", err)
	}
	return eng
}

// TestEngineBaselinePreservationFirstForwardDetectionAndConcurrency verifies
// that startup recompute before baseline does not wipe persisted host findings
// (#23), adding the first port forward on an empty site fires policy_changed
// (#24), concurrent recomputeAndPublish calls stay serialized without corrupting
// state.json (#25), and policy signatures are order-independent & complete
// (#34, #35).
func TestEngineBaselinePreservationFirstForwardDetectionAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	// Seed persisted baseline containing an existing host finding.
	seedState := &risk.State{
		UpdatedAt: time.Now().UTC(),
		Findings: map[string]checks.Severity{
			"UB-0022|02:aa:bb:00:00:01|6379": checks.SeverityHigh,
		},
		TrustedClients: map[string]string{"02:aa:bb:00:00:01": "redis-box"},
	}
	if err := risk.SaveState(statePath, seedState); err != nil {
		t.Fatalf("SaveState seed: %v", err)
	}

	var webhookHits atomic.Int32
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer whSrv.Close()

	cfg := config.Default()
	cfg.UniFi.URL = "https://192.0.2.1"
	cfg.UniFi.APIKey = "test"
	cfg.State.Path = statePath
	cfg.Notify.WebhookURL = whSrv.URL
	cfg.Notify.Format = "json"

	eng, err := NewEngine(cfg, nil, []int{6379}, Options{SkipCVE: true})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "Main", VLAN: "1", Subnet: "192.0.2.1/24", Purpose: "corporate", ZoneName: "Internal"},
		},
		Clients: []unifi.Client{
			{MAC: "02:aa:bb:00:00:01", IP: "192.0.2.10", Name: "redis-box", NetworkName: "Main"},
		},
	}
	eng.mu.Lock()
	eng.snap = snap
	eng.lastFwdSig = portForwardSignature(nil)
	eng.lastPolicySig = firewallPolicySignature(nil)
	eng.sigsInitialized = true
	eng.mu.Unlock()

	// #23: Pre-baseline recompute must NOT wipe uniblue-state.json or send alerts.
	eng.recomputeAndPublish(context.Background(), false, nil)
	loaded, err := risk.LoadState(statePath)
	if err != nil || loaded.Findings["UB-0022|02:aa:bb:00:00:01|6379"] != checks.SeverityHigh {
		t.Fatalf("pre-baseline recompute wiped persisted host finding: loaded=%+v err=%v", loaded, err)
	}
	if webhookHits.Load() != 0 {
		t.Fatalf("expected 0 webhooks before baseline completes, got %d", webhookHits.Load())
	}

	// #24: Adding the very first port forward (from empty) must emit policy_changed.
	snapWithFwd := *snap
	snapWithFwd.PortForwards = []unifi.PortForward{
		{ID: "pf1", Name: "RDP", Enabled: true, Proto: "tcp", DstPort: "3389", FwdIP: "192.0.2.10", FwdPort: "3389", Src: "any"},
	}
	eng.applySnapshotDelta(context.Background(), &snapWithFwd, time.Now().UTC())
	foundPolicyEvent := false
	for _, ev := range eng.Snapshot().Events {
		if ev.Type == "policy_changed" {
			foundPolicyEvent = true
			break
		}
	}
	if !foundPolicyEvent {
		t.Fatalf("expected policy_changed event when first port forward is added, got %+v", eng.Snapshot().Events)
	}

	// #25: Concurrent recomputes after baseline must not corrupt state.json or race.
	eng.mu.Lock()
	eng.baselineComplete = true
	eng.profilesByMAC["02:aa:bb:00:00:01"] = probe.HostProfile{Client: snap.Clients[0], ScannedAt: time.Now().UTC()}
	eng.mu.Unlock()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			eng.recomputeAndPublish(context.Background(), false, nil)
		}()
	}
	wg.Wait()
	if _, err := risk.LoadState(statePath); err != nil {
		t.Fatalf("state.json corrupted after concurrent recomputes: %v", err)
	}

	// #34 + #35: firewallPolicySignature skips SYSTEM_DEFINED, sorts deterministically,
	// and captures MACs/NegatePort/UnsupportedSelector.
	pA := unifi.FirewallPolicy{ID: "a", Name: "A", Enabled: true, Origin: "USER_DEFINED", Source: unifi.PolicyEndpoint{MACs: []string{"02:00:00:00:00:01"}}}
	pB := unifi.FirewallPolicy{ID: "b", Name: "B", Enabled: true, Origin: "USER_DEFINED", Destination: unifi.PolicyEndpoint{NegatePort: true}}
	pSys := unifi.FirewallPolicy{ID: "s", Name: "Sys", Enabled: true, Origin: "SYSTEM_DEFINED"}
	sig1 := firewallPolicySignature([]unifi.FirewallPolicy{pA, pB, pSys})
	sig2 := firewallPolicySignature([]unifi.FirewallPolicy{pB, pA})
	if sig1 != sig2 {
		t.Fatalf("expected order-independent USER_DEFINED signature, got %q vs %q", sig1, sig2)
	}
	pA2 := pA
	pA2.Source.MACs = []string{"02:00:00:00:00:02"}
	if firewallPolicySignature([]unifi.FirewallPolicy{pA2, pB}) == sig1 {
		t.Fatal("expected MAC filter edit to change firewallPolicySignature")
	}
}

// TestAnomalyTrackerTransientFeedHistoryRefreshAndPortBaseline verifies that
// transient settings/VPN unavailability does not emit false config_drift or VPN
// disconnect alerts (#21), knownHistory refreshes to avoid 30-day false wakeups
// and repeated medium swaps (#22), and port baselines avoid repeated PoE/MAC
// surge alerts (#32).
func TestAnomalyTrackerTransientFeedHistoryRefreshAndPortBaseline(t *testing.T) {
	now := time.Now().UTC()
	at := newAnomalyTracker()

	snapOK := &unifi.Snapshot{
		SecuritySettings: &unifi.SiteSecuritySettings{UPnPEnabled: false, SSHEnabled: false},
		WLANs:            []unifi.WLANConfig{{ID: "w1", Name: "Home", Enabled: true, Security: "wpapsk"}},
		Health: &unifi.SystemHealth{
			VPNConnections: []unifi.VPNConnection{{ID: "v1", User: "alice"}},
		},
		Clients: []unifi.Client{{MAC: "02:aa:00:00:00:01", Name: "desktop", IsWired: true, LastSeen: now.Unix()}},
		Visibility: &unifi.SiteVisibility{
			SettingsAvailable: true,
			WLANsAvailable:    true,
			VPNAvailable:      true,
		},
	}
	ports := map[string]portLiveState{
		"sw|2": {DeviceName: "SW", PortIdx: 2, Zone: "internal", Up: true, MACTableCount: 3, PoEPowerWatts: 6.0},
	}
	at.Seed(snapOK, ports, now)

	// #21: Transient fetch failure (SettingsAvailable=false, VPNAvailable=false) must emit 0 drift/VPN events.
	snapFail := &unifi.Snapshot{
		Health:     &unifi.SystemHealth{},
		Visibility: &unifi.SiteVisibility{SettingsAvailable: false, WLANsAvailable: false, VPNAvailable: false},
	}
	if evs := at.EvaluateSiteTelemetry(snapFail, nil); len(evs) != 0 {
		t.Fatalf("expected 0 events on transient unavailable telemetry, got %+v", evs)
	}

	// #22: Refreshing live clients updates knownHistory so reconnects 31 days later do not false-alert.
	later := now.Add(31 * 24 * time.Hour)
	snapLater := &unifi.Snapshot{
		Clients: []unifi.Client{{MAC: "02:aa:00:00:00:01", Name: "desktop", IsWired: true, LastSeen: later.Unix()}},
	}
	at.EvaluateSiteTelemetry(snapLater, nil)
	if evs := at.EvaluateClientJoinAnomalies(snapLater.Clients[0], later.Add(time.Minute)); len(evs) != 0 {
		t.Fatalf("expected 0 dormant wakeup events after history refresh, got %+v", evs)
	}

	// #32: Link-up repopulating a known 3-MAC mini-switch port must NOT raise port_mac_surge.
	downPorts := map[string]portLiveState{
		"sw|2": {DeviceName: "SW", PortIdx: 2, Zone: "internal", Up: false, MACTableCount: 0, PoEPowerWatts: 0},
	}
	upPorts := map[string]portLiveState{
		"sw|2": {DeviceName: "SW", PortIdx: 2, Zone: "internal", Up: true, MACTableCount: 3, PoEPowerWatts: 6.0},
	}
	for _, ev := range at.EvaluatePortAnomalies(downPorts, upPorts) {
		if ev.Type == "port_mac_surge" {
			t.Fatalf("unexpected port_mac_surge on link-up of known multi-MAC port: %+v", ev)
		}
	}
}
