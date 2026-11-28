// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/blast"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestHTTPProtectionHostOriginTokenAndRescanResponses verifies DNS-rebinding
// Host protection on both loopback and non-loopback listeners, reverse-proxy
// AllowedHosts support, cross-origin POST CSRF blocking, Bearer token and
// HttpOnly session cookie authentication via /api/v1/session, uniform JSON
// error envelopes, and 503 queue-full responses.
func TestHTTPProtectionHostOriginTokenAndRescanResponses(t *testing.T) {
	eng := NewDemoEngineForTest(t)
	eng.opts.ListenAddr = "127.0.0.1:8080"
	h := eng.Handler()

	// 1. Spoofed Host header on loopback listener must be rejected (JSON 403).
	req := httptest.NewRequest(http.MethodGet, "http://rebind.evil.example/api/v1/state", nil)
	req.Host = "rebind.evil.example:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for spoofed Host header, got %d", rec.Code)
	}
	var hostErr apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &hostErr); err != nil || hostErr.Error != "forbidden_host" {
		t.Fatalf("expected JSON forbidden_host error, got %q (%v)", rec.Body.String(), err)
	}

	// 2. Non-loopback listener (0.0.0.0:8080) without a token must still reject
	// external DNS-rebinding Host headers while allowing literal IPs and LAN names.
	engLAN := NewDemoEngineForTest(t)
	engLAN.opts.ListenAddr = "0.0.0.0:8080"
	hLAN := engLAN.Handler()
	for _, tc := range []struct {
		method string
		path   string
		host   string
		want   int
	}{
		{http.MethodGet, "/api/v1/state", "rebind.evil.example:8080", http.StatusForbidden},
		{http.MethodPost, "/api/v1/scans", "rebind.evil.example:8080", http.StatusForbidden},
		{http.MethodGet, "/api/v1/state", "192.168.1.50:8080", http.StatusOK},
		{http.MethodGet, "/api/v1/state", "[fd00::50]:8080", http.StatusOK},
		{http.MethodGet, "/api/v1/state", "uniblue.local:8080", http.StatusOK},
		{http.MethodGet, "/api/v1/state", "uniblue.lan", http.StatusOK},
		{http.MethodGet, "/api/v1/state", "uniblue", http.StatusOK},
	} {
		r := httptest.NewRequest(tc.method, "http://127.0.0.1"+tc.path, nil)
		r.Host = tc.host
		w := httptest.NewRecorder()
		hLAN.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("non-loopback %s %s Host=%q: got %d, want %d", tc.method, tc.path, tc.host, w.Code, tc.want)
		}
	}

	// 3. Cross-origin POST /api/v1/scans must be rejected (403).
	reqCSRF := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/scans", nil)
	reqCSRF.Host = "127.0.0.1:8080"
	reqCSRF.Header.Set("Origin", "https://evil.example")
	recCSRF := httptest.NewRecorder()
	h.ServeHTTP(recCSRF, reqCSRF)
	if recCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin POST /api/v1/scans, got %d", recCSRF.Code)
	}

	// 4. Same-origin POST /api/v1/scans succeeds.
	reqOK := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/scans", nil)
	reqOK.Host = "127.0.0.1:8080"
	reqOK.Header.Set("Origin", "http://127.0.0.1:8080")
	recOK := httptest.NewRecorder()
	h.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for same-origin POST /api/v1/scans, got %d", recOK.Code)
	}

	// 5. Reverse-proxy AllowedHosts supports both Host-preserving (Caddy) and
	// Host-rewriting (nginx) proxies on loopback listeners while still rejecting
	// unlisted origins.
	engProxy := NewDemoEngineForTest(t)
	engProxy.opts.ListenAddr = "127.0.0.1:8080"
	engProxy.opts.AllowedHosts = []string{"uniblue.example.com"}
	hProxy := engProxy.Handler()

	reqCaddy := httptest.NewRequest(http.MethodGet, "http://uniblue.example.com/api/v1/state", nil)
	reqCaddy.Host = "uniblue.example.com"
	reqCaddy.Header.Set("Origin", "https://uniblue.example.com")
	recCaddy := httptest.NewRecorder()
	hProxy.ServeHTTP(recCaddy, reqCaddy)
	if recCaddy.Code != http.StatusOK {
		t.Fatalf("expected 200 for Host-preserving reverse proxy, got %d", recCaddy.Code)
	}

	reqNginx := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/scans", nil)
	reqNginx.Host = "127.0.0.1:8080"
	reqNginx.Header.Set("Origin", "https://uniblue.example.com")
	recNginx := httptest.NewRecorder()
	hProxy.ServeHTTP(recNginx, reqNginx)
	if recNginx.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for Host-rewriting reverse proxy scan, got %d", recNginx.Code)
	}

	reqEvilOrigin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/scans", nil)
	reqEvilOrigin.Host = "127.0.0.1:8080"
	reqEvilOrigin.Header.Set("Origin", "https://attacker.example")
	recEvilOrigin := httptest.NewRecorder()
	hProxy.ServeHTTP(recEvilOrigin, reqEvilOrigin)
	if recEvilOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unlisted Origin even with AllowedHosts, got %d", recEvilOrigin.Code)
	}

	// 6. Optional Bearer token and POST /api/v1/session HttpOnly session cookie protect /api/v1/*.
	eng.opts.APIToken = "secret-token"
	hTok := eng.Handler()
	reqNoAuth := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/state", nil)
	reqNoAuth.Host = "127.0.0.1:8080"
	recNoAuth := httptest.NewRecorder()
	hTok.ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when APIToken required and absent, got %d", recNoAuth.Code)
	}
	var unauthErr apiError
	if err := json.Unmarshal(recNoAuth.Body.Bytes(), &unauthErr); err != nil || unauthErr.Error != "unauthorized" {
		t.Fatalf("expected JSON unauthorized error, got %q", recNoAuth.Body.String())
	}

	// GET /api/v1/session reports unauthenticated cleanly without triggering auth errors.
	reqSessCheck := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/session", nil)
	reqSessCheck.Host = "127.0.0.1:8080"
	recSessCheck := httptest.NewRecorder()
	hTok.ServeHTTP(recSessCheck, reqSessCheck)
	if recSessCheck.Code != http.StatusOK || !strings.Contains(recSessCheck.Body.String(), `"authenticated":false`) {
		t.Fatalf("expected 200 authenticated=false from GET /api/v1/session, got %d %s", recSessCheck.Code, recSessCheck.Body.String())
	}

	reqAuth := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/state", nil)
	reqAuth.Host = "127.0.0.1:8080"
	reqAuth.Header.Set("Authorization", "Bearer secret-token")
	recAuth := httptest.NewRecorder()
	hTok.ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid Bearer token, got %d", recAuth.Code)
	}

	// Bad token to POST /api/v1/session returns 401.
	reqBadLogin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/session", strings.NewReader(`{"token":"wrong"}`))
	reqBadLogin.Host = "127.0.0.1:8080"
	recBadLogin := httptest.NewRecorder()
	hTok.ServeHTTP(recBadLogin, reqBadLogin)
	if recBadLogin.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad /api/v1/session token, got %d", recBadLogin.Code)
	}

	// Valid token to POST /api/v1/session issues HttpOnly; SameSite=Strict session cookie.
	reqLogin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/session", strings.NewReader(`{"token":"secret-token"}`))
	reqLogin.Host = "127.0.0.1:8080"
	recLogin := httptest.NewRecorder()
	hTok.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid /api/v1/session token, got %d", recLogin.Code)
	}
	cookies := recLogin.Result().Cookies()
	var sessCookie *http.Cookie
	for _, ck := range cookies {
		if ck.Name == sessionCookieName {
			sessCookie = ck
		}
	}
	if sessCookie == nil || !sessCookie.HttpOnly || sessCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected HttpOnly SameSite=Strict session cookie, got %+v", cookies)
	}
	if sessCookie.Value == "secret-token" {
		t.Fatal("session cookie must not store raw plaintext API token")
	}
	reqCookieState := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/state", nil)
	reqCookieState.Host = "127.0.0.1:8080"
	reqCookieState.AddCookie(sessCookie)
	recCookieState := httptest.NewRecorder()
	hTok.ServeHTTP(recCookieState, reqCookieState)
	if recCookieState.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET /api/v1/state with session cookie, got %d", recCookieState.Code)
	}

	// 7. Full host-scan queue returns 503 Service Unavailable (not 404).
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
	liveEng.Handler().ServeHTTP(recFull, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/hosts/192.0.2.10/scan", nil))
	if recFull.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when hostScanCh is full, got %d", recFull.Code)
	}
	var queueErr apiError
	if err := json.Unmarshal(recFull.Body.Bytes(), &queueErr); err != nil || queueErr.Error != "queue_full" {
		t.Fatalf("expected JSON queue_full error, got %q", recFull.Body.String())
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
// that startup recompute before baseline does not wipe persisted host findings,
// adding the first port forward on an empty site fires policy_changed,
// concurrent recomputeAndPublish calls stay serialized without corrupting
// state.json, and policy signatures are order-independent and complete.
func TestEngineBaselinePreservationFirstForwardDetectionAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	// Seed persisted baseline containing an existing host finding.
	seedState := &risk.State{
		ScoringVersion: risk.CurrentScoringVersion,
		UpdatedAt:      time.Now().UTC(),
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
	eng.fwdSigInit = true
	eng.policySigInit = true
	eng.mu.Unlock()

	// Pre-baseline recompute must not wipe uniblue-state.json or send alerts.
	eng.recomputeAndPublish(context.Background(), false, nil)
	loaded, err := risk.LoadState(statePath)
	if err != nil || loaded.Findings["UB-0022|02:aa:bb:00:00:01|6379"] != checks.SeverityHigh {
		t.Fatalf("pre-baseline recompute wiped persisted host finding: loaded=%+v err=%v", loaded, err)
	}
	if webhookHits.Load() != 0 {
		t.Fatalf("expected 0 webhooks before baseline completes, got %d", webhookHits.Load())
	}

	// Adding the very first port forward (from empty) must emit policy_changed.
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

	// Concurrent recomputes after baseline must not corrupt state.json or race.
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

	// firewallPolicySignature skips SYSTEM_DEFINED, sorts deterministically,
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
// disconnect alerts, knownHistory refreshes to avoid 30-day false wakeups and
// repeated medium swaps, port baselines silence legit multi-MAC ports while
// still catching inline mini-switches inserted across a link-down, VPN counter
// fallback works on controllers without v2 VPN connections, and owned radio
// BSSID matching requires exact MAC/BSSID matches.
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
		"sw|3": {DeviceName: "SW", PortIdx: 3, Zone: "internal", Up: true, MACTableCount: 1},
	}
	at.Seed(snapOK, ports, now)

	// Transient fetch failure (SettingsAvailable=false, VPNAvailable=false) must emit 0 drift/VPN events.
	snapFail := &unifi.Snapshot{
		Health:     &unifi.SystemHealth{},
		Visibility: &unifi.SiteVisibility{SettingsAvailable: false, WLANsAvailable: false, VPNAvailable: false},
	}
	if evs := at.EvaluateSiteTelemetry(snapFail, nil); len(evs) != 0 {
		t.Fatalf("expected 0 events on transient unavailable telemetry, got %+v", evs)
	}

	// Refreshing live clients updates knownHistory so reconnects 31 days later do not false-alert.
	later := now.Add(31 * 24 * time.Hour)
	snapLater := &unifi.Snapshot{
		Clients: []unifi.Client{{MAC: "02:aa:00:00:00:01", Name: "desktop", IsWired: true, LastSeen: later.Unix()}},
	}
	at.EvaluateSiteTelemetry(snapLater, nil)
	if evs := at.EvaluateClientJoinAnomalies(snapLater.Clients[0], later.Add(time.Minute)); len(evs) != 0 {
		t.Fatalf("expected 0 dormant wakeup events after history refresh, got %+v", evs)
	}

	// Link-up repopulating a known 3-MAC mini-switch port must NOT raise port_mac_surge,
	// whereas a mini-switch inserted across a link-down on a single-MAC port MUST alert.
	downPorts := map[string]portLiveState{
		"sw|2": {DeviceName: "SW", PortIdx: 2, Zone: "internal", Up: false, MACTableCount: 0, PoEPowerWatts: 0},
		"sw|3": {DeviceName: "SW", PortIdx: 3, Zone: "internal", Up: false, MACTableCount: 0},
	}
	upPorts := map[string]portLiveState{
		"sw|2": {DeviceName: "SW", PortIdx: 2, Zone: "internal", Up: true, MACTableCount: 3, PoEPowerWatts: 6.0},
		"sw|3": {DeviceName: "SW", PortIdx: 3, Zone: "internal", Up: true, MACTableCount: 2},
	}
	var port2Surge, port3Surge bool
	for _, ev := range at.EvaluatePortAnomalies(downPorts, upPorts) {
		if ev.Type == "port_mac_surge" && ev.Host == "SW Port 2" {
			port2Surge = true
		}
		if ev.Type == "port_mac_surge" && ev.Host == "SW Port 3" && ev.Severity == "high" {
			port3Surge = true
		}
	}
	if port2Surge {
		t.Fatal("unexpected port_mac_surge on link-up of known 3-MAC port")
	}
	if !port3Surge {
		t.Fatal("expected high port_mac_surge when inline mini-switch inserted across link-down on single-MAC port")
	}

	// Controller without v2 VPN endpoint (VPNAvailable=false) must still fire
	// stat/health ActiveVPNUsers fallback transitions (0 -> 1 -> 0).
	atLegacyVPN := newAnomalyTracker()
	atLegacyVPN.Seed(&unifi.Snapshot{
		Health:     &unifi.SystemHealth{ActiveVPNUsers: 0},
		Visibility: &unifi.SiteVisibility{VPNAvailable: false},
	}, nil, now)
	evsUp := atLegacyVPN.EvaluateSiteTelemetry(&unifi.Snapshot{
		Health:     &unifi.SystemHealth{ActiveVPNUsers: 1},
		Visibility: &unifi.SiteVisibility{VPNAvailable: false},
	}, nil)
	evsDown := atLegacyVPN.EvaluateSiteTelemetry(&unifi.Snapshot{
		Health:     &unifi.SystemHealth{ActiveVPNUsers: 0},
		Visibility: &unifi.SiteVisibility{VPNAvailable: false},
	}, nil)
	if len(evsUp) != 1 || evsUp[0].Type != "vpn_session_changed" || len(evsDown) != 1 || evsDown[0].Type != "vpn_session_changed" {
		t.Fatalf("expected 2 vpn_session_changed fallback events, got up=%+v down=%+v", evsUp, evsDown)
	}

	// Owned radio BSSID check must require exact AP MAC/BSSID match and reject clones.
	owned := map[string]struct{}{
		"24:5a:4c:11:22:33": {},
		"24:5a:4c:11:22:34": {}, // explicit VAP BSSID
	}
	if !isOwnedRadioBSSID(unifi.RogueAP{BSSID: "24:5a:4c:11:22:33", OUI: "Ubiquiti Inc."}, owned) {
		t.Fatal("expected exact owned AP MAC to be recognized")
	}
	if !isOwnedRadioBSSID(unifi.RogueAP{BSSID: "24:5a:4c:11:22:34", OUI: "Ubiquiti Inc."}, owned) {
		t.Fatal("expected exact owned VAP BSSID to be recognized")
	}
	for _, clone := range []unifi.RogueAP{
		{BSSID: "26:5a:4c:11:22:33", OUI: "Ubiquiti Inc."}, // LAA bit flip
		{BSSID: "25:5a:4c:11:22:33", OUI: "Ubiquiti Inc."}, // low nibble flip
		{BSSID: "24:5a:4c:11:22:99", OUI: "Ubiquiti Inc."}, // last-octet near clone
		{BSSID: "24:5a:4c:11:22:33", OUI: "Ubiquiti Inc.", IsRogue: true},
	} {
		if isOwnedRadioBSSID(clone, owned) {
			t.Fatalf("clone/rogue BSSID %+v must not be treated as owned radio", clone)
		}
	}
}

// TestWebhookFailureDoesNotSpamFindingNewOrBlockRecompute verifies that a
// failing or slow webhook endpoint does not block recomputeAndPublish, persists
// state.json, and emits finding_new exactly once across repeated recomputes.
func TestWebhookFailureDoesNotSpamFindingNewOrBlockRecompute(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	var hits atomic.Int32
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer whSrv.Close()

	cfg := config.Default()
	cfg.UniFi.URL = "https://192.0.2.1"
	cfg.UniFi.APIKey = "test"
	cfg.State.Path = statePath
	cfg.Notify.WebhookURL = whSrv.URL
	cfg.Notify.Format = "json"

	eng, err := NewEngine(cfg, nil, nil, Options{SkipCVE: true})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.webhookRetryBase = 5 * time.Second

	cl := unifi.Client{MAC: "02:aa:bb:00:00:05", IP: "192.0.2.50", Name: "nas", NetworkName: "Main"}
	snap := &unifi.Snapshot{
		Site:     "default",
		Networks: []unifi.Network{{ID: "n1", Name: "Main", Subnet: "192.0.2.1/24", Purpose: "corporate", ZoneName: "Internal"}},
		Clients:  []unifi.Client{cl},
	}
	eng.mu.Lock()
	eng.snap = snap
	eng.baselineComplete = true
	eng.prevRiskState = &risk.State{ScoringVersion: risk.CurrentScoringVersion, UpdatedAt: time.Now().UTC(), Findings: map[string]checks.Severity{}}
	eng.profilesByMAC[clientKey(cl)] = probe.HostProfile{Client: cl, ScannedAt: time.Now().UTC()}
	eng.findingsByMAC[clientKey(cl)] = []checks.Finding{
		{CheckID: "UB-0001", Title: "Telnet open", EffectiveSeverity: checks.SeverityHigh, Client: cl, Port: 23},
	}
	eng.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	for range 4 {
		eng.recomputeAndPublish(ctx, false, nil)
	}
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("recomputeAndPublish appears to have blocked on slow webhook (%v)", elapsed)
	}

	findingNewCount := 0
	for _, ev := range eng.Snapshot().Events {
		if ev.Type == "finding_new" {
			findingNewCount++
		}
	}
	if findingNewCount != 1 {
		t.Fatalf("expected finding_new to fire exactly once across 4 recomputes, got %d", findingNewCount)
	}
	loaded, err := risk.LoadState(statePath)
	if err != nil || len(loaded.Findings) == 0 {
		t.Fatalf("expected state.json baseline to persist despite webhook failure: loaded=%+v err=%v", loaded, err)
	}
}

// TestPreserveUnavailableTelemetryAndFullScanGhostEviction verifies that
// transient settings/WLAN/port-profile fetch errors preserve last-known values
// (preventing false port_config_changed or dropped posture findings) and that
// full-scan adoption evicts clients that departed while in leave-grace.
func TestPreserveUnavailableTelemetryAndFullScanGhostEviction(t *testing.T) {
	prevSnap := &unifi.Snapshot{
		Site:             "default",
		SecuritySettings: &unifi.SiteSecuritySettings{SSHEnabled: true, SSHPasswordAuth: true, UPnPEnabled: true},
		WLANs:            []unifi.WLANConfig{{ID: "w1", Name: "Home", Enabled: true, Security: "wpapsk"}},
		Devices: []unifi.Device{
			{
				MAC: "aa:00:00:00:00:02", Name: "Switch", Type: "usw",
				Ports: []unifi.SwitchPort{
					{PortIdx: 1, Enabled: true, Up: true, NativeNetworkName: "IoT", TaggedVLANMgmt: "block_all", PortConfID: "prof-iot", ProfileManaged: true, PortSecurityEnabled: true},
				},
			},
		},
		Visibility: &unifi.SiteVisibility{SettingsAvailable: true, WLANsAvailable: true, PortProfilesAvailable: true},
	}

	// Simulate transient failure of settings, WLANs, and rest/portconf where
	// profile-derived port fields fall back while direct per-port fields stay unchanged.
	failSnap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{
				MAC: "aa:00:00:00:00:02", Name: "Switch", Type: "usw",
				Ports: []unifi.SwitchPort{
					{PortIdx: 1, Enabled: true, Up: true, NativeNetworkName: "", TaggedVLANMgmt: "auto", PortConfID: "prof-iot", ProfileManaged: true, PortSecurityEnabled: true},
				},
			},
		},
		Visibility: &unifi.SiteVisibility{SettingsAvailable: false, WLANsAvailable: false, PortProfilesAvailable: false},
	}

	preserveUnavailableTelemetry(prevSnap, failSnap)
	if failSnap.SecuritySettings == nil || !failSnap.SecuritySettings.UPnPEnabled {
		t.Fatalf("expected last-known SecuritySettings preserved, got %+v", failSnap.SecuritySettings)
	}
	if len(failSnap.WLANs) != 1 || failSnap.WLANs[0].Name != "Home" {
		t.Fatalf("expected last-known WLANs preserved, got %+v", failSnap.WLANs)
	}
	p := failSnap.Devices[0].Ports[0]
	if p.NativeNetworkName != "IoT" || p.TaggedVLANMgmt != "block_all" || !p.PortSecurityEnabled {
		t.Fatalf("expected last-known switch port profile config preserved, got %+v", p)
	}

	// Verify applySnapshotDelta emits 0 port_config_changed on transient portconf failure.
	cfg := config.Default()
	cfg.UniFi.URL = "https://192.0.2.1"
	cfg.UniFi.APIKey = "test"
	eng, err := NewEngine(cfg, nil, nil, Options{SkipCVE: true})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.mu.Lock()
	eng.snap = prevSnap
	eng.lastPorts = snapshotPortStates(prevSnap, cfg.Network)
	eng.anomalies.Seed(prevSnap, eng.lastPorts, time.Now().UTC())
	eng.mu.Unlock()
	eng.applySnapshotDelta(context.Background(), failSnap, time.Now().UTC())
	for _, ev := range eng.Snapshot().Events {
		if ev.Type == "port_config_changed" || ev.Type == "config_drift" {
			t.Fatalf("unexpected false drift event on transient portconf/settings failure: %+v", ev)
		}
	}

	// Direct live per-port changes during a portconf outage (e.g., disabling MAC
	// lock or changing Enabled / explicit non-empty NativeNetworkName) MUST NOT
	// be masked and MUST emit port_config_changed.
	directChangeSnap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{
				MAC: "aa:00:00:00:00:02", Name: "Switch", Type: "usw",
				Ports: []unifi.SwitchPort{
					{PortIdx: 1, Enabled: false, Up: true, NativeNetworkName: "Management", TaggedVLANMgmt: "auto", PortSecurityEnabled: false},
				},
			},
		},
		Visibility: &unifi.SiteVisibility{SettingsAvailable: false, WLANsAvailable: false, PortProfilesAvailable: false},
	}
	eng.applySnapshotDelta(context.Background(), directChangeSnap, time.Now().UTC().Add(5*time.Second))
	foundPortChanged := false
	for _, ev := range eng.Snapshot().Events {
		if ev.Type == "port_config_changed" {
			foundPortChanged = true
		}
	}
	if !foundPortChanged {
		t.Fatalf("expected port_config_changed for direct per-port change during portconf outage, got %+v", eng.Snapshot().Events)
	}
	changedPort := eng.snap.Devices[0].Ports[0]
	if changedPort.Enabled || changedPort.PortSecurityEnabled || changedPort.NativeNetworkName != "Management" || changedPort.TaggedVLANMgmt != "auto" {
		t.Fatalf("expected direct manual per-port edits preserved live, got %+v", changedPort)
	}

	// Verify runFullScan adoption keeps briefly dozing Wi-Fi clients (<60s)
	// intact while evicting Wi-Fi clients whose leave-grace has elapsed.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "tok"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/device", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/networkconf", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"_id":"n1","name":"Main","purpose":"corporate","ip_subnet":"192.0.2.1/24"}]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/portforward", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	mux.HandleFunc("/proxy/network/api/s/default/rest/setting", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	cfg2 := config.Default()
	cfg2.UniFi.URL = srv.URL
	cfg2.UniFi.Username = "uniblue"
	cfg2.UniFi.Password = "secret"
	cfg2.UniFi.InsecureSkipVerify = true
	cfg2.State.Path = filepath.Join(t.TempDir(), "state.json")
	eng2, err := NewEngine(cfg2, nil, nil, Options{SkipCVE: true})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	dozingPhone := unifi.Client{MAC: "02:cc:dd:ee:ff:01", IP: "192.0.2.77", Name: "dozing-phone", NetworkName: "Main", IsWired: false}
	gonePhone := unifi.Client{MAC: "02:cc:dd:ee:ff:02", IP: "192.0.2.78", Name: "departed-phone", NetworkName: "Main", IsWired: false}
	nowUTC := time.Now().UTC()
	eng2.mu.Lock()
	eng2.snap = &unifi.Snapshot{
		Site:             "default",
		SecuritySettings: &unifi.SiteSecuritySettings{UPnPEnabled: true},
		Visibility:       &unifi.SiteVisibility{SettingsAvailable: true},
	}
	eng2.missingClients[clientKey(dozingPhone)] = missingClient{client: dozingPhone, since: nowUTC.Add(-20 * time.Second)}
	eng2.profilesByMAC[clientKey(dozingPhone)] = probe.HostProfile{Client: dozingPhone, ScannedAt: nowUTC}
	eng2.findingsByMAC[clientKey(dozingPhone)] = []checks.Finding{
		{CheckID: "UB-0002", Title: "Dozing host finding", EffectiveSeverity: checks.SeverityMedium, Client: dozingPhone, Port: 80},
	}
	eng2.missingClients[clientKey(gonePhone)] = missingClient{client: gonePhone, since: nowUTC.Add(-defaultLeaveGrace - 5*time.Second)}
	eng2.profilesByMAC[clientKey(gonePhone)] = probe.HostProfile{Client: gonePhone, ScannedAt: nowUTC}
	eng2.findingsByMAC[clientKey(gonePhone)] = []checks.Finding{
		{CheckID: "UB-0001", Title: "Ghost finding", EffectiveSeverity: checks.SeverityHigh, Client: gonePhone, Port: 23},
	}
	eng2.mu.Unlock()

	if err := eng2.runFullScan(context.Background(), "reconcile"); err != nil {
		t.Fatalf("runFullScan: %v", err)
	}
	snapOut := eng2.Snapshot()
	for _, f := range snapOut.Report.Findings {
		if f.CheckID == "UB-0001" {
			t.Fatalf("expired leave-grace ghost finding lingered after full-scan snapshot adoption: %+v", f)
		}
	}
	eng2.mu.RLock()
	_, dozingStillTracked := eng2.missingClients[clientKey(dozingPhone)]
	_, dozingHasProfile := eng2.profilesByMAC[clientKey(dozingPhone)]
	_, dozingHasFindings := eng2.findingsByMAC[clientKey(dozingPhone)]
	eng2.mu.RUnlock()
	if !dozingStillTracked || !dozingHasProfile || !dozingHasFindings {
		t.Fatalf("20s dozing Wi-Fi client should survive full-scan adoption: tracked=%v profile=%v findings=%v",
			dozingStillTracked, dozingHasProfile, dozingHasFindings)
	}
	foundUPnP := false
	for _, f := range snapOut.Report.Findings {
		if f.CheckID == "UB-UNIFI-UPNP-ENABLED" {
			foundUPnP = true
		}
	}
	if !foundUPnP {
		t.Fatalf("expected preserved UPnP finding during full-scan settings 500, got %+v", snapOut.Report.Findings)
	}
	var sawGoneLeft, sawDozingLeft bool
	for _, ev := range snapOut.Events {
		if ev.Type == "client_left" && ev.Host == "departed-phone" {
			sawGoneLeft = true
		}
		if ev.Type == "client_left" && ev.Host == "dozing-phone" {
			sawDozingLeft = true
		}
	}
	if !sawGoneLeft {
		t.Fatalf("expected client_left event for expired leave-grace client, got %+v", snapOut.Events)
	}
	if sawDozingLeft {
		t.Fatalf("did not expect premature client_left for 20s dozing Wi-Fi client, got %+v", snapOut.Events)
	}
}

// TestClientSkipReasonAndIPv6ClassLookup verifies canonical exclude_ips matching,
// public/out-of-subnet skip reasons matching the probe IP guard, and IPv6-only
// client classification lookup by MAC fallback.
func TestClientSkipReasonAndIPv6ClassLookup(t *testing.T) {
	siteSubnets := snapshotSubnets(&unifi.Snapshot{Networks: []unifi.Network{{IPv6Subnet: "fd00::/64", IPv6Subnets: []string{"2001:db8:1::7/64"}}}})
	excluded := map[string]struct{}{
		"2001:0db8:0000:0000::0050": {},
		"::ffff:192.168.1.10":       {},
	}

	if r := clientSkipReason(unifi.Client{IPv6: []string{"2001:db8::50"}}, excluded, siteSubnets); !strings.Contains(r, "Excluded") {
		t.Fatalf("expected non-canonical IPv6 exclude_ips match, got %q", r)
	}
	if r := clientSkipReason(unifi.Client{IP: "192.168.1.10"}, excluded, siteSubnets); !strings.Contains(r, "Excluded") {
		t.Fatalf("expected IPv4-mapped exclude_ips match, got %q", r)
	}
	if r := clientSkipReason(unifi.Client{IP: "203.0.113.10"}, nil, siteSubnets); r == "" {
		t.Fatal("expected public IPv4 outside site subnets to be skipped")
	}
	if r := clientSkipReason(unifi.Client{IPv6: []string{"2001:db8:99::50"}}, nil, siteSubnets); r == "" {
		t.Fatal("expected GUA IPv6 outside site subnets to be skipped")
	}
	if r := clientSkipReason(unifi.Client{IPv6: []string{"2001:db8:1::50"}}, nil, siteSubnets); r != "" {
		t.Fatalf("expected GUA IPv6 inside site ipv6_subnet to be probeable, got skip=%q", r)
	}
	if r := clientSkipReason(unifi.Client{IPv6: []string{"2001:db8:99::50", "fd12:3456::25"}}, nil, siteSubnets); r != "" {
		t.Fatalf("expected IPv6-only host with out-of-subnet GUA and allowed ULA to be probeable, got skip=%q", r)
	}
	if r := clientSkipReason(unifi.Client{IP: "192.168.1.25"}, nil, siteSubnets); r != "" {
		t.Fatalf("expected RFC1918 host to be probeable, got skip=%q", r)
	}

	// IPv6-only client keyed by MAC in classify.ClassifyAll must resolve its class.
	v6BMC := unifi.Client{MAC: "02:bb:cc:00:00:01", IPv6: []string{"fd00:10::5"}}
	classes := map[string]classify.Result{
		"02:bb:cc:00:00:01": {Category: classify.CategoryBMC, Role: "Server BMC"},
	}
	if got := lookupClientClass(classes, v6BMC); got.Category != classify.CategoryBMC {
		t.Fatalf("expected IPv6-only BMC classification via MAC fallback, got %+v", got)
	}
}

// TestHTTPAuthBruteForceLockout verifies per-address throttling of token
// attempts while authenticated browser sessions continue to work.
func TestHTTPAuthBruteForceLockout(t *testing.T) {
	eng := NewDemoEngineForTest(t)
	eng.opts.ListenAddr = "0.0.0.0:8080"
	eng.opts.APIToken = "super-secret-token"
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	eng.authLimiter.nowFn = func() time.Time { return now }
	eng.sessions.nowFn = func() time.Time { return now }
	h := eng.Handler()

	// Unauthenticated GET /api/v1/state without Authorization header never locks out.
	for i := 0; i < 8; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8080/api/v1/state", nil)
		req.RemoteAddr = "10.0.0.50:40000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401 for unauthenticated page check, got %d", i+1, rec.Code)
		}
	}

	// Obtain a valid session cookie for 10.0.0.50 before bad login attempts occur.
	reqInit := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:8080/api/v1/session", strings.NewReader(`{"token":"super-secret-token"}`))
	reqInit.RemoteAddr = "10.0.0.50:39999"
	recInit := httptest.NewRecorder()
	h.ServeHTTP(recInit, reqInit)
	if recInit.Code != http.StatusOK {
		t.Fatalf("initial login expected 200, got %d", recInit.Code)
	}
	var validCookie *http.Cookie
	for _, ck := range recInit.Result().Cookies() {
		if ck.Name == sessionCookieName {
			validCookie = ck
		}
	}
	if validCookie == nil {
		t.Fatal("expected session cookie from initial login")
	}

	// 4 bad POST /api/v1/session attempts return 401; the 5th triggers 429 lockout.
	for i := 1; i <= authMaxFailedAttempts; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:8080/api/v1/session", strings.NewReader(`{"token":"wrong"}`))
		req.RemoteAddr = "10.0.0.50:40001"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		want := http.StatusUnauthorized
		if i == authMaxFailedAttempts {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("bad login %d: expected %d, got %d", i, want, rec.Code)
		}
		if want == http.StatusTooManyRequests && rec.Header().Get("Retry-After") == "" {
			t.Fatal("expected Retry-After header on 429 lockout response")
		}
	}

	// While locked out, further POST /api/v1/session attempts from the same IP
	// (including IPv4-mapped form) are rejected with 429 to throttle guessing.
	for _, remote := range []string{"10.0.0.50:55555", "[::ffff:10.0.0.50]:55556"} {
		req := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:8080/api/v1/session", strings.NewReader(`{"token":"super-secret-token"}`))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("remote %s login while locked out: expected 429, got %d", remote, rec.Code)
		}
	}

	// Correct and incorrect Bearer credentials receive the same lockout response.
	for _, path := range []string{"/api/v1/state", "/api/v1/session"} {
		for _, candidate := range []string{"super-secret-token", "wrong"} {
			req := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8080"+path, nil)
			req.RemoteAddr = "10.0.0.50:55557"
			req.Header.Set("Authorization", "Bearer "+candidate)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("locked Bearer on %s returned %d, want 429", path, rec.Code)
			}
		}
	}
	for _, path := range []string{"/api/v1/state", "/api/v1/session"} {
		req := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8080"+path, nil)
		req.RemoteAddr = "10.0.0.50:55558"
		req.AddCookie(validCookie)
		req.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || (path == "/api/v1/session" && !strings.Contains(rec.Body.String(), `"authenticated":true`)) {
			t.Fatalf("valid session during lockout on %s: got %d", path, rec.Code)
		}
	}

	// Another IP is unaffected and can authenticate normally.
	reqOther := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:8080/api/v1/session", strings.NewReader(`{"token":"super-secret-token"}`))
	reqOther.RemoteAddr = "10.0.0.51:12345"
	recOther := httptest.NewRecorder()
	h.ServeHTTP(recOther, reqOther)
	if recOther.Code != http.StatusOK {
		t.Fatalf("different IP expected 200, got %d", recOther.Code)
	}

	// After lockout expires, valid login succeeds and resets state.
	now = now.Add(authLockoutDuration + time.Second)
	reqUnlock := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:8080/api/v1/session", strings.NewReader(`{"token":"super-secret-token"}`))
	reqUnlock.RemoteAddr = "10.0.0.50:60000"
	recUnlock := httptest.NewRecorder()
	h.ServeHTTP(recUnlock, reqUnlock)
	if recUnlock.Code != http.StatusOK {
		t.Fatalf("after lockout expiry expected 200, got %d", recUnlock.Code)
	}

	// Bad Bearer tokens count toward lockout, and a valid Bearer token from a
	// legitimate client on the same IP does NOT reset the failure counter.
	for i := 0; i < authMaxFailedAttempts-1; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8080/api/v1/state", nil)
		req.RemoteAddr = "10.0.0.52:1000"
		req.Header.Set("Authorization", "Bearer bad-guess")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("bad bearer %d: expected 401, got %d", i+1, rec.Code)
		}
	}
	reqGood := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8080/api/v1/state", nil)
	reqGood.RemoteAddr = "10.0.0.52:1001"
	reqGood.Header.Set("Authorization", "Bearer super-secret-token")
	recGood := httptest.NewRecorder()
	h.ServeHTTP(recGood, reqGood)
	if recGood.Code != http.StatusOK {
		t.Fatalf("valid bearer before threshold expected 200, got %d", recGood.Code)
	}
	// The 5th bad attempt MUST still trigger 429 (valid Bearer did not reset it).
	reqFifthBad := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8080/api/v1/state", nil)
	reqFifthBad.RemoteAddr = "10.0.0.52:1002"
	reqFifthBad.Header.Set("Authorization", "Bearer bad-again")
	recFifthBad := httptest.NewRecorder()
	h.ServeHTTP(recFifthBad, reqFifthBad)
	if recFifthBad.Code != http.StatusTooManyRequests {
		t.Fatalf("5th bad bearer after valid bearer expected 429, got %d", recFifthBad.Code)
	}

	// Stale/invalid session cookies are cleared cleanly without triggering lockout
	// (so multiple browser tabs after token rotation never lock out the user).
	for i := 1; i <= authMaxFailedAttempts+2; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:8080/api/v1/state", nil)
		req.RemoteAddr = "10.0.0.53:1000"
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "stale-cookie"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("stale cookie %d: expected 401, got %d", i, rec.Code)
		}
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].MaxAge >= 0 {
			t.Fatalf("stale cookie was not cleared: %v", cookies)
		}
	}

	// Lock one IPv6 host and sign in from its neighbor in the same subnet.
	for i := 1; i <= authMaxFailedAttempts+1; i++ {
		candidate := "wrong"
		remote := "[2001:db8:abcd:1::10]:40000"
		want := http.StatusUnauthorized
		if i == authMaxFailedAttempts {
			want = http.StatusTooManyRequests
		} else if i > authMaxFailedAttempts {
			remote = "[2001:db8:abcd:1::11]:40000"
			candidate = eng.opts.APIToken
			want = http.StatusOK
		}
		req := httptest.NewRequest(http.MethodPost, "http://192.168.1.10:8080/api/v1/session", strings.NewReader(fmt.Sprintf(`{"token":%q}`, candidate)))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("IPv6 login %d from %s: got %d, want %d", i, remote, rec.Code, want)
		}
	}
}

// writeTestCVEShard seeds a local nginx feed so tests exercise matching without a sync.
func writeTestCVEShard(cacheDir string, recs []cve.Record, stats *cve.CacheStats) error {
	vendorsDir := filepath.Join(cacheDir, "vendors")
	if err := os.MkdirAll(vendorsDir, 0o755); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(vendorsDir, "f5.json.gz"))
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	if err := json.NewEncoder(gz).Encode(recs); err != nil {
		_ = gz.Close()
		_ = f.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	rawStats, err := json.Marshal(stats)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(cacheDir, "stats.json"), rawStats, 0o644)
}

// TestBackgroundCVESyncAutoLoadsAndSkipsUnchanged verifies that cveSyncLoop
// populates an initially empty CVE cache, publishes exact CVE matches without
// restart, stays quiet when feeds are unchanged, and re-correlates when new
// CVEs arrive.
func TestBackgroundCVESyncAutoLoadsAndSkipsUnchanged(t *testing.T) {
	eng := NewDemoEngineForTest(t)
	cacheDir := t.TempDir()
	eng.cfg.CVE.CacheDir = cacheDir
	eng.cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	eng.opts.CVERefreshInterval = 20 * time.Millisecond
	eng.mu.Lock()
	eng.cveCache = nil
	eng.cveIdent = nil
	amp := unifi.Client{MAC: "aa:bb:cc:dd:ee:01", Name: "LivingRoomAmp", IP: "10.0.30.50", NetworkName: "IoT"}
	eng.snap.Clients = append(eng.snap.Clients, amp)
	eng.profilesByMAC[clientKey(amp)] = probe.HostProfile{
		Client:    amp,
		OpenPorts: []int{80},
		HTTP: map[int]probe.HTTPBanner{
			80: {Server: "nginx/1.26.3"},
		},
		ScannedAt: time.Now().UTC(),
	}
	eng.mu.Unlock()

	t1 := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 1, 11, 0, 0, 0, time.UTC)
	rec1 := cve.Record{
		ID:       "CVE-2026-99991",
		Severity: checks.SeverityHigh,
		CVSS:     7.5,
		Matches: []cve.CPEMatch{{
			Part: "a", Vendor: "f5", Product: "nginx",
			StartIncl: "1.26.0", EndExcl: "1.26.4",
		}},
	}
	rec2 := cve.Record{
		ID:       "CVE-2026-99992",
		Severity: checks.SeverityCritical,
		CVSS:     9.8,
		Matches: []cve.CPEMatch{{
			Part: "a", Vendor: "f5", Product: "nginx",
			StartIncl: "1.26.0", EndExcl: "1.26.4",
		}},
	}
	stats1 := &cve.CacheStats{
		SyncedAt: t1, TotalCVEs: 1, IndexedCPECVEs: 1, VendorCount: 1,
		KEVSHA: "kev-v1", YearSHAs: map[string]string{"2026": "sha-v1"},
	}
	stats2 := &cve.CacheStats{
		SyncedAt: t2, TotalCVEs: 2, IndexedCPECVEs: 2, VendorCount: 1,
		KEVSHA: "kev-v1", YearSHAs: map[string]string{"2026": "sha-v2"},
	}

	var calls atomic.Int32
	step2Done := make(chan struct{})
	step3Done := make(chan struct{})
	eng.cveSyncFn = func(_ context.Context, _ *cve.Cache) (*cve.CacheStats, error) {
		switch calls.Add(1) {
		case 1:
			if err := writeTestCVEShard(cacheDir, []cve.Record{rec1}, stats1); err != nil {
				return nil, err
			}
			return stats1, nil
		case 2:
			close(step2Done)
			return stats1, nil
		case 3:
			if err := writeTestCVEShard(cacheDir, []cve.Record{rec1, rec2}, stats2); err != nil {
				return nil, err
			}
			close(step3Done)
			return stats2, nil
		default:
			return stats2, nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		eng.cveSyncLoop(ctx)
	}()

	// Wait until step 2 (unchanged tick) completes.
	select {
	case <-step2Done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for second CVE sync check")
	}
	// Give the loop a moment to process step 2 without emitting a second event.
	time.Sleep(15 * time.Millisecond)

	// Wait until step 3 (updated feed) triggers and publishes.
	select {
	case <-step3Done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for third CVE sync check")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snap := eng.Snapshot()
		if snap.CVELoaded {
			for _, ex := range snap.ExactCVEs {
				if ex.Product.HostName == "LivingRoomAmp" && ex.TotalCVEs == 2 {
					cancel()
					<-done
					syncedEvents := 0
					for _, ev := range snap.Events {
						if ev.Type == "cve_synced" {
							syncedEvents++
						}
					}
					if syncedEvents != 2 {
						t.Fatalf("expected exactly 2 cve_synced events (initial load + changed feed, skipping unchanged tick), got %d", syncedEvents)
					}
					return
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("expected nginx ExactCVEs with TotalCount=2 after background sync, got CVELoaded=%v ExactCVEs=%+v",
		eng.Snapshot().CVELoaded, eng.Snapshot().ExactCVEs)
}

// TestWebhookRetryPreservesIDAndResigns verifies that Engine.drainWebhooks
// keeps the exact same webhook-id across retry attempts while signing each
// attempt with a valid Standard Webhooks HMAC-SHA256 signature.
func TestWebhookRetryPreservesIDAndResigns(t *testing.T) {
	rawKey := []byte("hermes-webhook-signing-key-32bytes")
	secret := "whsec_" + base64.StdEncoding.EncodeToString(rawKey)

	type attempt struct {
		id   string
		ts   int64
		sig  string
		body []byte
	}
	var mu sync.Mutex
	var attempts []attempt
	doneCh := make(chan struct{})

	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts, _ := strconv.ParseInt(r.Header.Get("webhook-timestamp"), 10, 64)
		mu.Lock()
		attempts = append(attempts, attempt{
			id:   r.Header.Get("webhook-id"),
			ts:   ts,
			sig:  r.Header.Get("webhook-signature"),
			body: body,
		})
		n := len(attempts)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		if n == 2 {
			close(doneCh)
		}
	}))
	defer whSrv.Close()

	cfg := config.Default()
	cfg.UniFi.URL = "https://192.0.2.1"
	cfg.UniFi.APIKey = "test"
	cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	cfg.Notify.WebhookURL = whSrv.URL
	cfg.Notify.WebhookSecret = secret
	cfg.Notify.Format = "json"

	eng, err := NewEngine(cfg, nil, nil, Options{SkipCVE: true})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.webhookRetryBase = 15 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eng.enqueueWebhook(ctx, pendingWebhook{
		site: "default",
		diff: risk.Diff{
			NewFindings: []checks.Finding{{
				CheckID:           "UB-0001",
				Title:             "Telnet open",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{IP: "192.0.2.50", Name: "nas"},
			}},
		},
	})

	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for webhook retry delivery")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(attempts) != 2 {
		t.Fatalf("expected 2 webhook attempts, got %d", len(attempts))
	}
	if !strings.HasPrefix(attempts[0].id, "msg_") || attempts[0].id != attempts[1].id {
		t.Fatalf("expected identical msg_* webhook-id across retry, got %q and %q", attempts[0].id, attempts[1].id)
	}
	if attempts[1].ts < attempts[0].ts {
		t.Fatalf("expected non-decreasing timestamp on retry, got %d then %d", attempts[0].ts, attempts[1].ts)
	}
	for i, a := range attempts {
		mac := hmac.New(sha256.New, rawKey)
		_, _ = mac.Write([]byte(a.id + "." + strconv.FormatInt(a.ts, 10) + "."))
		_, _ = mac.Write(a.body)
		want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if a.sig != want {
			t.Fatalf("attempt %d signature mismatch: got %q want %q", i+1, a.sig, want)
		}
	}
}

// TestIPv6OnlyClientJoinTriggersImmediateScan verifies that applySnapshotDelta
// queues an immediate targeted scan when an IPv6-only client joins or changes
// its IPv6 address (even when Client.IP is empty).
func TestIPv6OnlyClientJoinTriggersImmediateScan(t *testing.T) {
	eng := NewDemoEngineForTest(t)
	eng.cfg.State.Path = filepath.Join(t.TempDir(), "state.json")

	baseSnap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "net-iot", Name: "IoT", VLAN: "20", Subnet: "10.0.20.1/24", IPv6Subnet: "fd00:20::1/64", Purpose: "corporate", ZoneName: "IoT"},
		},
		Clients: []unifi.Client{},
	}
	eng.mu.Lock()
	eng.snap = baseSnap
	eng.mu.Unlock()

	v6Client := unifi.Client{
		MAC:         "02:66:77:88:99:01",
		Name:        "matter-sensor",
		IPv6:        []string{"fd00:20::42"},
		NetworkID:   "net-iot",
		NetworkName: "IoT",
		IsWired:     false,
	}
	joinSnap := &unifi.Snapshot{
		Site:     "default",
		Networks: baseSnap.Networks,
		Clients:  []unifi.Client{v6Client},
	}
	toScan := eng.applySnapshotDelta(context.Background(), joinSnap, time.Now().UTC())
	if len(toScan) != 1 || toScan[0].client.MAC != v6Client.MAC || toScan[0].client.PrimaryIP() != "fd00:20::42" {
		t.Fatalf("expected IPv6-only client join to queue immediate scan, got %+v", toScan)
	}
	foundJoined := false
	for _, ev := range eng.Snapshot().Events {
		if ev.Type == "client_joined" && ev.IP == "fd00:20::42" && strings.Contains(ev.Summary, "queuing security scan") {
			foundJoined = true
		}
	}
	if !foundJoined {
		t.Fatalf("expected client_joined event with IPv6 address and scan queued, got %+v", eng.Snapshot().Events)
	}

	// Updating the IPv6 address on the IPv6-only client must also re-queue a scan.
	movedClient := v6Client
	movedClient.IPv6 = []string{"fd00:20::99"}
	moveSnap := &unifi.Snapshot{
		Site:     "default",
		Networks: baseSnap.Networks,
		Clients:  []unifi.Client{movedClient},
	}
	toScanMove := eng.applySnapshotDelta(context.Background(), moveSnap, time.Now().UTC().Add(time.Second))
	if len(toScanMove) != 1 || toScanMove[0].client.PrimaryIP() != "fd00:20::99" {
		t.Fatalf("expected IPv6 address change to re-queue scan, got %+v", toScanMove)
	}
}

// TestClientIPv4Flapping follows a lease change through the first bounce,
// subsequent quiet polls, and a move to another VLAN.
func TestClientIPv4Flapping(t *testing.T) {
	const a, b, c = "192.0.2.10", "192.0.2.11", "192.0.2.12"
	cfg := config.Default()
	cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	e, err := NewEngine(cfg, nil, nil, Options{SkipCVE: true})
	if err != nil {
		t.Fatal(err)
	}
	cl := unifi.Client{MAC: "02:00:00:00:ab:01", Name: "bridge", NetworkName: "Default", IP: a}
	now := time.Now()
	e.snap = &unifi.Snapshot{Clients: []unifi.Client{cl}}
	e.baselineComplete = true
	poll := func(ip string) []hostScanTask {
		cl.IP = ip
		now = now.Add(5 * time.Second)
		return e.applySnapshotDelta(t.Context(), &unifi.Snapshot{Clients: []unifi.Client{cl}}, now)
	}
	cache := func() {
		e.profilesByMAC[cl.MAC] = probe.HostProfile{Client: cl, ProbeIP: cl.IP, ScannedAt: now}
		e.findingsByMAC[cl.MAC] = []checks.Finding{{Client: cl, CheckID: "bridge-service"}}
	}
	wantMove := func(ip string) {
		t.Helper()
		tasks := poll(ip)
		if len(tasks) != 1 || tasks[0].client.IP != ip || tasks[0].client.NetworkName != cl.NetworkName || !tasks[0].retryOnEmpty {
			t.Fatalf("move to %s/%s queued %+v", ip, cl.NetworkName, tasks)
		}
		if _, ok := e.profilesByMAC[cl.MAC]; ok || len(e.findingsByMAC[cl.MAC]) != 0 {
			t.Fatal("move retained stale scan results")
		}
		ev := e.events[0]
		if ev.Type != "client_moved" || ev.Severity != "medium" || ev.IP != ip {
			t.Fatalf("move event = %+v", ev)
		}
	}

	cache()
	wantMove(b)
	cache()
	updated := e.current.UpdatedAt
	state, err := os.Stat(cfg.State.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{b, a, b, a} {
		if tasks := poll(ip); len(tasks) != 0 {
			t.Fatalf("poll of %s queued %+v", ip, tasks)
		}
		if e.snap.Clients[0].IP != ip || !e.current.UpdatedAt.Equal(updated) {
			t.Fatalf("poll of %s lost the current address or republished the dashboard", ip)
		}
		hp := e.profilesByMAC[cl.MAC]
		fl := e.findingsByMAC[cl.MAC]
		if hp.Client.IP != ip || hp.ProbeIP != b || len(fl) != 1 || fl[0].Client.IP != b {
			t.Fatalf("poll of %s lost the probe of %s: profile %+v, findings %+v", ip, b, hp, fl)
		}
	}
	after, err := os.Stat(cfg.State.Path)
	if err != nil || !os.SameFile(state, after) {
		t.Fatalf("quiet polls replaced the saved state: %v", err)
	}
	if len(e.events) != 2 {
		t.Fatalf("expected one move and one notice, got %+v", e.events)
	}
	ev := e.events[0]
	if ev.Type != "client_multi_ip" || ev.Severity != "info" || ev.SubjectID != hostEntityID(cl) ||
		!strings.Contains(ev.Summary, cl.NetworkName) || !strings.Contains(ev.Summary, a) || !strings.Contains(ev.Summary, b) {
		t.Fatalf("multi-address notice = %+v", ev)
	}

	target, status := e.triggerHostRescanStatus(strings.ToUpper(cl.MAC))
	if status != hostRescanQueued || target.IP != a {
		t.Fatalf("recheck after quiet bounce resolved %q, status %v", target.IP, status)
	}
	if task := <-e.hostScanCh; task.client.IP != a || task.client.MAC != cl.MAC {
		t.Fatalf("recheck queued %+v", task)
	}

	wantMove(c)
	eventCount := len(e.events)
	for _, ip := range []string{a, b, c} {
		if tasks := poll(ip); len(tasks) != 0 || len(e.events) != eventCount {
			t.Fatalf("known address %s queued %+v, events %+v", ip, tasks, e.events)
		}
	}

	cl.NetworkName = "IoT"
	wantMove(b)
	if e.ipv4ByMAC[cl.MAC] != nil {
		t.Fatal("VLAN move retained the old address set")
	}
	wantMove(a)
	if tasks := poll(b); len(tasks) != 0 {
		t.Fatalf("return on IoT queued %+v", tasks)
	}
	// A brief Wi-Fi absence keeps the host in leave grace, but a returning
	// client must establish its address history again.
	e.applySnapshotDelta(t.Context(), &unifi.Snapshot{}, now)
	if e.ipv4ByMAC[cl.MAC] != nil {
		t.Fatal("missing Wi-Fi client retained its address history")
	}
	wantMove(a)
	wantMove(b)
}

// TestClientIPv4FlapLimits verifies that old leases and long runs of new
// addresses cannot keep a client exempt from normal move handling.
func TestClientIPv4FlapLimits(t *testing.T) {
	e := new(Engine)
	cl := unifi.Client{MAC: "02:00:00:00:ab:01", NetworkName: "Default", IP: "192.0.2.1"}
	now := time.Now()
	change := func(ip string, wantSuppress bool) {
		t.Helper()
		prev := cl
		cl.IP = ip
		suppressed, _ := e.recordIPv4Change(cl.MAC, prev, cl, now)
		if got := len(e.ipv4ByMAC[cl.MAC].seen); suppressed != wantSuppress || got > maxClientIPv4s {
			t.Fatalf("%s -> %s: suppressed=%t, tracked=%d", prev.IP, ip, suppressed, got)
		}
	}
	change("192.0.2.2", false)
	change("192.0.2.1", true)
	now = now.Add(ipv4FlapWindow + time.Second)
	change("192.0.2.2", false)
	change("192.0.2.1", true)
	for i := 3; i <= maxClientIPv4s+1; i++ {
		change(fmt.Sprintf("192.0.2.%d", i), false)
	}
	change("192.0.2.1", false)
}

// TestClientIPv4FlapAttachmentMove checks that a return to a familiar IP on a
// different attachment gets a fresh scan, even when the network name stays the same.
func TestClientIPv4FlapAttachmentMove(t *testing.T) {
	const a, b = "192.0.2.10", "192.0.2.11"
	for _, tc := range []struct {
		name  string
		wired bool
		move  func(*unifi.Client)
	}{
		{"AP roam", false, func(c *unifi.Client) { c.APMAC = "02:00:00:00:00:02" }},
		{"switch port", true, func(c *unifi.Client) { c.SwitchPort++ }},
		{"switch MAC", true, func(c *unifi.Client) { c.SwitchMAC = "02:00:00:00:00:02" }},
		{"medium", false, func(c *unifi.Client) { c.IsWired = true }},
		{"network ID", true, func(c *unifi.Client) { c.NetworkID = "second" }},
		{"VLAN", true, func(c *unifi.Client) { c.VLAN = "20" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
			e, err := NewEngine(cfg, nil, nil, Options{SkipCVE: true})
			if err != nil {
				t.Fatal(err)
			}
			cl := unifi.Client{MAC: "02:00:00:00:ab:01", IP: a, IsWired: tc.wired, NetworkID: "first", VLAN: "10"}
			if cl.IsWired {
				cl.SwitchMAC, cl.SwitchPort = "02:00:00:00:ab:cd", 1
			} else {
				cl.APMAC = "02:00:00:00:ab:cd"
			}
			e.snap = &unifi.Snapshot{Clients: []unifi.Client{cl}}
			poll := func() []hostScanTask {
				return e.applySnapshotDelta(t.Context(), &unifi.Snapshot{Clients: []unifi.Client{cl}}, time.Now())
			}
			cl.IP = b
			poll()
			cl.APMAC, cl.SwitchMAC = strings.ToUpper(cl.APMAC), strings.ToUpper(cl.SwitchMAC)
			cl.IP = a
			if tasks := poll(); len(tasks) != 0 {
				t.Fatalf("return to same attachment queued %+v", tasks)
			}
			scanned := probe.HostProfile{Client: cl, ProbeIP: a}
			tc.move(&cl)
			cl.IP = b
			if tasks := poll(); len(tasks) != 1 || attachmentOf(tasks[0].client) != attachmentOf(cl) ||
				e.events[0].Type != "client_moved" || e.ipv4ByMAC[cl.MAC] != nil {
				t.Fatalf("move queued %+v, events %+v, tracker %+v", tasks, e.events, e.ipv4ByMAC)
			}
			if e.storeHostScan(cl.MAC, cl, scanned, nil, time.Now()) {
				t.Fatal("accepted sibling scan from previous attachment")
			}
		})
	}
}

// TestClientRoamKeepsScan checks that a Wi-Fi roam or a switch port report
// that keeps the address and network is not a move and keeps the last scan.
func TestClientRoamKeepsScan(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wired bool
		roam  func(*unifi.Client)
	}{
		{"AP roam", false, func(c *unifi.Client) { c.APMAC = "02:00:00:00:00:02" }},
		{"switch port", true, func(c *unifi.Client) { c.SwitchPort = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
			e, err := NewEngine(cfg, nil, nil, Options{SkipCVE: true})
			if err != nil {
				t.Fatal(err)
			}
			cl := unifi.Client{MAC: "02:00:00:00:ab:01", IP: "192.0.2.10", IsWired: tc.wired, NetworkID: "first", NetworkName: "Default"}
			if cl.IsWired {
				cl.SwitchMAC, cl.SwitchPort = "02:00:00:00:ab:cd", 1
			} else {
				cl.APMAC = "02:00:00:00:ab:cd"
			}
			e.snap = &unifi.Snapshot{Clients: []unifi.Client{cl}}
			scanned := probe.HostProfile{Client: cl, ProbeIP: cl.IP, ScannedAt: time.Now()}
			e.profilesByMAC[cl.MAC] = scanned
			e.findingsByMAC[cl.MAC] = []checks.Finding{{Client: cl, CheckID: "bridge-service"}}
			tc.roam(&cl)
			if tasks := e.applySnapshotDelta(t.Context(), &unifi.Snapshot{Clients: []unifi.Client{cl}}, time.Now()); len(tasks) != 0 || len(e.events) != 0 {
				t.Fatalf("roam queued %+v, events %+v", tasks, e.events)
			}
			if hp := e.profilesByMAC[cl.MAC]; attachmentOf(hp.Client) != attachmentOf(cl) || len(e.findingsByMAC[cl.MAC]) != 1 {
				t.Fatalf("roam lost the scan: profile %+v, findings %+v", hp, e.findingsByMAC[cl.MAC])
			}
			scanned.ScannedAt = time.Now()
			if !e.storeHostScan(cl.MAC, cl, scanned, nil, time.Now()) {
				t.Fatal("rejected a scan that started before the roam")
			}
		})
	}
}

// TestClientIPv4FlapKeepsCVEs follows a sibling's scan through dashboard
// publication, webhook diffing and reassignment of the observed address.
func TestClientIPv4FlapKeepsCVEs(t *testing.T) {
	cfg := config.Default()
	cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	cfg.CVE.CacheDir = t.TempDir()
	rec := cve.Record{ID: "CVE-2026-99991", Severity: checks.SeverityHigh, CVSS: 8.1, AttackVector: "N",
		Matches: []cve.CPEMatch{{Part: "a", Vendor: "f5", Product: "nginx", StartIncl: "1.26.0", EndExcl: "1.26.4"}}}
	if err := writeTestCVEShard(cfg.CVE.CacheDir, []cve.Record{rec}, &cve.CacheStats{VendorCount: 1}); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(cfg, nil, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}

	a := unifi.Client{MAC: "02:00:00:00:ab:01", IP: "192.0.2.10", Name: "bridge"}
	b := a
	b.IP = "192.0.2.11"
	poll := func(clients ...unifi.Client) {
		e.applySnapshotDelta(t.Context(), &unifi.Snapshot{Clients: clients}, time.Now())
	}
	e.snap = &unifi.Snapshot{Clients: []unifi.Client{a}}
	poll(b)
	hp := probe.HostProfile{Client: b, ProbeIP: b.IP, ScannedAt: time.Now(), OpenPorts: []int{80},
		HTTP:     map[int]probe.HTTPBanner{80: {Server: "nginx/1.26.3"}},
		Services: []probe.Service{{Port: 80, Protocol: "http", Findings: []probe.ServiceFinding{{ID: "http-version", Severity: "low"}}}}}
	f := checks.Finding{Client: b, CheckID: "bridge-service", ObservedIPs: []string{b.IP}}
	if !e.storeHostScan(b.MAC, b, hp, []checks.Finding{f}, time.Now()) {
		t.Fatal("could not seed the probe at the current address")
	}
	e.recomputeAndPublish(t.Context(), true, nil)
	poll(a)
	older := hp
	hp.ScannedAt = time.Now()
	if !e.storeHostScan(a.MAC, a, hp, []checks.Finding{f}, time.Now()) || e.storeHostScan(a.MAC, a, older, nil, time.Now()) {
		t.Fatal("expected only the newer probe of the sibling to be accepted")
	}
	empty := probe.HostProfile{Client: a, ProbeIP: a.IP, ScannedAt: time.Now()}
	if e.storeHostScan(a.MAC, a, empty, nil, time.Now()) {
		t.Fatal("a clean scan at a different address cleared confirmed findings")
	}
	e.recomputeAndPublish(t.Context(), false, nil)
	published := e.Snapshot()
	ent := published.View.Entities[hostEntityID(a)]
	if ent == nil || ent.IP != b.IP || ent.ExactCVECount != 1 || e.snap.Clients[0].IP != a.IP {
		t.Fatalf("sibling publication: host %+v, inventory %+v", ent, e.snap.Clients)
	}
	keys := e.prevRiskState.ExactCVEs
	cveKey := a.MAC + "|nginx|1.26.3|" + rec.ID
	if len(keys) != 1 || keys[cveKey] == "" || e.webhookSeq != 0 {
		t.Fatalf("CVE alert keys %v, queued webhooks %d", keys, e.webhookSeq)
	}
	if !slices.ContainsFunc(published.View.Blast.Actions, func(action blast.Action) bool {
		return action.ID == "act:patch:"+rec.ID+":"+a.MAC
	}) {
		t.Fatalf("missing patch action for the bridge in %+v", published.View.Blast.Actions)
	}
	for _, id := range []string{f.CheckID, "NERVA-HTTP-VERSION"} {
		if !slices.ContainsFunc(published.Report.Findings, func(f checks.Finding) bool {
			return f.CheckID == id && f.Client.IP == b.IP && slices.Equal(f.ObservedIPs, []string{b.IP})
		}) {
			t.Fatalf("missing %s at %s in %+v", id, b.IP, published.Report.Findings)
		}
	}

	other := unifi.Client{MAC: "02:00:00:00:ab:02", IP: b.IP, Name: "new owner"}
	poll(a, other)
	view := e.Snapshot().View
	bridge, owner := view.Entities[hostEntityID(a)], view.Entities[hostEntityID(other)]
	if bridge == nil || bridge.IP != a.IP || owner == nil || owner.IP != b.IP || owner.ExactCVECount != 0 || len(owner.Services) != 0 {
		t.Fatalf("reassigned probe address: bridge %+v, new owner %+v", bridge, owner)
	}
	if len(e.prevRiskState.ExactCVEs) != 1 || e.prevRiskState.ExactCVEs[cveKey] == "" ||
		len(e.findingsByMAC[a.MAC]) != 1 || e.webhookSeq != 0 {
		t.Fatalf("reassignment changed attribution: keys %v, findings %+v, queued webhooks %d", e.prevRiskState.ExactCVEs, e.findingsByMAC, e.webhookSeq)
	}
	if e.storeHostScan(a.MAC, a, hp, []checks.Finding{f}, time.Now()) || !e.storeHostScan(a.MAC, a, empty, nil, time.Now()) {
		t.Fatal("reassignment must reject the old sibling and accept a scan of the current address")
	}
}

// TestClientIPv4FlapDuringProbe changes the live address inside a loopback
// HTTP check so both scan paths finish with a newer poll reporting a sibling.
func TestClientIPv4FlapDuringProbe(t *testing.T) {
	for _, mode := range []string{"single host", "full scan", "duplicate MAC"} {
		t.Run(mode, func(t *testing.T) {
			cl := unifi.Client{MAC: "02:00:00:00:ab:01", Name: "bridge", NetworkName: "Default", IP: "192.0.2.10"}
			sibling := &unifi.Snapshot{Clients: []unifi.Client{cl}}
			cl.IP = "127.0.0.1"
			mux := http.NewServeMux()
			srv := httptest.NewServer(mux)
			defer srv.Close()
			port := srv.Listener.Addr().(*net.TCPAddr).Port
			check := &checks.Check{
				ID: "bridge-service", Title: "Bridge service", Severity: checks.SeverityLow,
				Preconditions: checks.Preconditions{PortsAny: []int{port}},
				Probe: checks.ProbeSpec{Type: "http", Port: port, Scheme: "http", Timeout: 5 * time.Second, HTTPStepSpec: checks.HTTPStepSpec{
					Method: "GET", Path: "/bridge-check", Match: checks.MatchSpec{Status: []int{http.StatusOK}},
				}},
			}
			cfg := config.Default()
			cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
			cfg.UniFi.URL, cfg.UniFi.Username, cfg.UniFi.Password = srv.URL, "test", "test"
			e, err := NewEngine(cfg, []*checks.Check{check}, []int{port}, Options{SkipCVE: true})
			if err != nil {
				t.Fatal(err)
			}
			e.snap = sibling
			tasks := e.applySnapshotDelta(t.Context(), &unifi.Snapshot{Clients: []unifi.Client{cl}}, time.Now())
			if len(tasks) != 1 {
				t.Fatalf("first move queued %+v", tasks)
			}
			mux.HandleFunc("/bridge-check", func(w http.ResponseWriter, r *http.Request) {
				if mode == "duplicate MAC" {
					wrong := cl
					wrong.NetworkID = "other"
					e.applySnapshotDelta(r.Context(), &unifi.Snapshot{Clients: []unifi.Client{wrong, cl}}, time.Now())
				} else {
					e.applySnapshotDelta(r.Context(), sibling, time.Now())
				}
				w.WriteHeader(http.StatusOK)
			})
			var departed atomic.Bool
			mux.HandleFunc("/proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
				if departed.Load() {
					io.WriteString(w, `{"data":[]}`)
					return
				}
				fmt.Fprintf(w, `{"data":[{"mac":%q,"ip":%q,"network":%q}]}`, cl.MAC, cl.IP, cl.NetworkName)
			})
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, `{"data":[]}`)
			})
			if mode != "full scan" {
				e.scanSingleHost(t.Context(), tasks[0])
			} else if err := e.runFullScan(t.Context(), "reconcile"); err != nil {
				t.Fatal(err)
			}
			hp := e.profilesByMAC[cl.MAC]
			fl := e.findingsByMAC[cl.MAC]
			wantIP := sibling.Clients[0].IP
			if mode == "duplicate MAC" {
				wantIP = cl.IP
			}
			if hp.Client.IP != wantIP || hp.Client.NetworkID != cl.NetworkID || hp.ProbeIP != cl.IP || !hp.HasPort(port) ||
				len(fl) != 1 || fl[0].CheckID != check.ID || !slices.Equal(fl[0].ObservedIPs, []string{cl.IP}) {
				t.Fatalf("completed probe of %s: profile %+v, findings %+v", cl.IP, hp, fl)
			}
			cv := e.Snapshot().Clients[0]
			if cv.Client.IP != cl.IP || cv.LastScannedAt == nil || !slices.Contains(cv.OpenPorts, port) || cv.FindingCount == 0 {
				t.Fatalf("published client lost the sibling probe: %+v", cv)
			}
			if mode == "full scan" {
				departed.Store(true)
				if err := e.runFullScan(t.Context(), "reconcile"); err != nil {
					t.Fatal(err)
				}
				if e.ipv4ByMAC[cl.MAC] != nil {
					t.Fatal("adopted full scan retained the departed client's address history")
				}
			}
		})
	}
}

// TestWebhookQueueOverflowPreservesInFlightAndQueuedBatches verifies that
// overflowing the async webhook queue while batch 0 is in flight never drops
// the in-flight batch or silently pops/overwrites the next queued batch on
// completion or retry.
func TestWebhookQueueOverflowPreservesInFlightAndQueuedBatches(t *testing.T) {
	batch0Started := make(chan struct{})
	releaseBatch0 := make(chan struct{})
	var batch0Once sync.Once

	var mu sync.Mutex
	var delivered []string
	allDone := make(chan struct{})
	var allDoneOnce sync.Once

	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Site string `json:"site"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload.Site == "batch-0" {
			batch0Once.Do(func() { close(batch0Started) })
			<-releaseBatch0
		}
		mu.Lock()
		delivered = append(delivered, payload.Site)
		if len(delivered) >= maxPendingWebhooks {
			allDoneOnce.Do(func() { close(allDone) })
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer whSrv.Close()

	cfg := config.Default()
	cfg.UniFi.URL = "https://192.0.2.1"
	cfg.UniFi.APIKey = "test"
	cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	cfg.Notify.WebhookURL = whSrv.URL
	cfg.Notify.Format = "json"

	eng, err := NewEngine(cfg, nil, nil, Options{SkipCVE: true})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.webhookRetryBase = 10 * time.Millisecond

	makeDiff := func(name string) risk.Diff {
		return risk.Diff{
			NewFindings: []checks.Finding{{
				CheckID:           "UB-0001",
				Title:             name,
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{IP: "192.0.2.50", Name: name},
			}},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start batch 0 in flight and wait until the server has received it.
	eng.enqueueWebhook(ctx, pendingWebhook{site: "batch-0", diff: makeDiff("batch-0")})
	select {
	case <-batch0Started:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for batch-0 to start sending")
	}

	// Overflow past maxPendingWebhooks (total 66 batches: 0..65). Index 1 is
	// evicted on overflow so batch-0 stays intact at index 0 and batches 3..65
	// occupy indices 1..63.
	for i := 1; i <= maxPendingWebhooks+1; i++ {
		name := "batch-" + strconv.Itoa(i)
		eng.enqueueWebhook(ctx, pendingWebhook{site: name, diff: makeDiff(name)})
	}
	close(releaseBatch0)

	select {
	case <-allDone:
	case <-time.After(5 * time.Second):
		mu.Lock()
		n := len(delivered)
		mu.Unlock()
		t.Fatalf("timed out waiting for %d webhook deliveries, got %d", maxPendingWebhooks, n)
	}

	// Wait briefly to confirm no stray extra/duplicate deliveries occur.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		eng.webhookMu.Lock()
		empty := len(eng.pendingWebhooks) == 0 && !eng.webhookRunning
		eng.webhookMu.Unlock()
		if empty {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(delivered) != maxPendingWebhooks {
		t.Fatalf("expected exactly %d delivered batches (batch-0 + newest 63), got %d: %v", maxPendingWebhooks, len(delivered), delivered)
	}
	if delivered[0] != "batch-0" {
		t.Fatalf("first delivered batch = %q, want batch-0", delivered[0])
	}
	if delivered[1] != "batch-3" || delivered[len(delivered)-1] != "batch-65" {
		t.Fatalf("expected continuous tail batch-3..batch-65 with no extra silent pop, got [1]=%q last=%q", delivered[1], delivered[len(delivered)-1])
	}
}

// TestPendingWebhooksSurviveRestartWithSameID verifies that unsent webhook
// alerts persist to `<statePath>.pending-webhooks.json`, remain on disk across
// context cancellation, and are automatically delivered on Start by a restarted
// Engine with the exact same Standard Webhooks webhook-id.
func TestPendingWebhooksSurviveRestartWithSameID(t *testing.T) {
	rawKey := []byte("restart-durable-webhook-key-32b!")
	secret := "whsec_" + base64.StdEncoding.EncodeToString(rawKey)
	statePath := filepath.Join(t.TempDir(), "state.json")

	var failWebhook atomic.Bool
	failWebhook.Store(true)
	firstHit := make(chan string, 4)
	deliveredCh := make(chan string, 4)

	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("webhook-id")
		if failWebhook.Load() {
			firstHit <- id
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		deliveredCh <- id
	}))
	defer whSrv.Close()

	// Minimal mock UniFi server so restartedEngine.Start runs its real startup path.
	unifiMux := http.NewServeMux()
	unifiMux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "tok"})
		w.WriteHeader(http.StatusOK)
	})
	unifiMux.HandleFunc("/proxy/network/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	unifiMux.HandleFunc("/proxy/network/api/s/default/stat/device", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	unifiMux.HandleFunc("/proxy/network/api/s/default/rest/networkconf", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"_id":"n1","name":"Main","purpose":"corporate","ip_subnet":"192.0.2.1/24"}]}`))
	})
	unifiMux.HandleFunc("/proxy/network/api/s/default/rest/portforward", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	})
	unifiSrv := httptest.NewTLSServer(unifiMux)
	defer unifiSrv.Close()

	makeCfg := func() *config.Config {
		cfg := config.Default()
		cfg.UniFi.URL = unifiSrv.URL
		cfg.UniFi.Username = "uniblue"
		cfg.UniFi.Password = "secret"
		cfg.UniFi.InsecureSkipVerify = true
		cfg.State.Path = statePath
		cfg.Notify.WebhookURL = whSrv.URL
		cfg.Notify.WebhookSecret = secret
		cfg.Notify.Format = "json"
		return cfg
	}

	eng1, err := NewEngine(makeCfg(), nil, nil, Options{SkipCVE: true})
	if err != nil {
		t.Fatalf("NewEngine 1: %v", err)
	}
	eng1.webhookRetryBase = 5 * time.Second

	ctx1, cancel1 := context.WithCancel(context.Background())
	eng1.enqueueWebhook(ctx1, pendingWebhook{
		site: "default",
		diff: risk.Diff{
			NewFindings: []checks.Finding{{
				CheckID:           "UB-0001",
				Title:             "Telnet open",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{IP: "192.0.2.50", Name: "nas"},
			}},
		},
	})

	var firstID string
	select {
	case firstID = <-firstHit:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for initial failed webhook attempt")
	}
	if !strings.HasPrefix(firstID, "msg_") {
		t.Fatalf("expected msg_* webhook-id, got %q", firstID)
	}

	// Cancel engine 1 while retry is pending; persisted file must remain intact.
	cancel1()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		eng1.webhookMu.Lock()
		stopped := !eng1.webhookRunning
		eng1.webhookMu.Unlock()
		if stopped {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	persistPath := statePath + ".pending-webhooks.json"
	if _, err := os.Stat(persistPath); err != nil {
		t.Fatalf("expected persisted pending webhooks file %q to survive shutdown: %v", persistPath, err)
	}

	// Webhook endpoint recovers and a brand-new Engine starts against the same state path.
	failWebhook.Store(false)
	eng2, err := NewEngine(makeCfg(), nil, nil, Options{SkipCVE: true, PollInterval: time.Hour, ReconcileInterval: time.Hour})
	if err != nil {
		t.Fatalf("NewEngine 2: %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if err := eng2.Start(ctx2); err != nil {
		t.Fatalf("eng2.Start: %v", err)
	}

	select {
	case deliveredID := <-deliveredCh:
		if deliveredID != firstID {
			t.Fatalf("restarted engine delivered webhook-id %q, want %q", deliveredID, firstID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for restarted engine to deliver persisted webhook")
	}

	// Persisted file should be removed once the queue drains cleanly.
	cleanDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(cleanDeadline) {
		if _, err := os.Stat(persistPath); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %q to be removed after queue drained", persistPath)
}

// TestRandomPerLoginSessionCookiesAndLogout verifies that each POST /api/v1/session
// mints a distinct 32-byte random hex session cookie, validates against the
// engine's bounded session store, expires old sessions, and revokes only the
// caller's session on DELETE /api/v1/session.
func TestRandomPerLoginSessionCookiesAndLogout(t *testing.T) {
	eng := NewDemoEngineForTest(t)
	eng.cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	eng.opts.ListenAddr = "127.0.0.1:8080"
	eng.opts.APIToken = "session-secret-token"
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	eng.sessions.nowFn = func() time.Time { return now }
	h := eng.Handler()

	login := func() *http.Cookie {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/session", strings.NewReader(`{"token":"session-secret-token"}`))
		req.Host = "127.0.0.1:8080"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /api/v1/session status = %d, want 200", rec.Code)
		}
		for _, ck := range rec.Result().Cookies() {
			if ck.Name == sessionCookieName {
				return ck
			}
		}
		t.Fatal("POST /api/v1/session did not set session cookie")
		return nil
	}

	ck1 := login()
	ck2 := login()
	if strings.Contains(ck1.Value, eng.opts.APIToken) || strings.Contains(ck2.Value, eng.opts.APIToken) {
		t.Fatalf("session cookie must never contain raw API token")
	}
	for _, ck := range []*http.Cookie{ck1, ck2} {
		if len(ck.Value) != 64 || strings.Trim(ck.Value, "0123456789abcdef") != "" {
			t.Fatal("expected a hex-encoded 256-bit session cookie")
		}
	}
	if ck1.Value == ck2.Value {
		t.Fatalf("expected distinct random session cookies per login, both were %q", ck1.Value)
	}

	// Stored sessions survive a server restart with the same API token.
	engRestarted := NewDemoEngineForTest(t)
	engRestarted.cfg.State.Path = eng.cfg.State.Path
	engRestarted.opts.ListenAddr = "127.0.0.1:8080"
	engRestarted.opts.APIToken = "session-secret-token"
	engRestarted.sessions.nowFn = func() time.Time { return now }
	reqRestart := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/state", nil)
	reqRestart.Host = "127.0.0.1:8080"
	reqRestart.AddCookie(ck2)
	recRestart := httptest.NewRecorder()
	h = engRestarted.Handler()
	h.ServeHTTP(recRestart, reqRestart)
	if recRestart.Code != http.StatusOK {
		t.Fatalf("cookie after restart with same token status = %d, want 200", recRestart.Code)
	}

	checkState := func(ck *http.Cookie, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/state", nil)
		req.Host = "127.0.0.1:8080"
		req.AddCookie(ck)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("GET /api/v1/state status = %d, want %d", rec.Code, want)
		}
	}

	checkState(ck1, http.StatusOK)
	checkState(ck2, http.StatusOK)

	// DELETE /api/v1/session revokes ck1 and clears the cookie without affecting ck2.
	reqLogout := httptest.NewRequest(http.MethodDelete, "http://127.0.0.1:8080/api/v1/session", nil)
	reqLogout.Host = "127.0.0.1:8080"
	reqLogout.AddCookie(ck1)
	recLogout := httptest.NewRecorder()
	h.ServeHTTP(recLogout, reqLogout)
	if recLogout.Code != http.StatusOK {
		t.Fatalf("DELETE /api/v1/session status = %d, want 200", recLogout.Code)
	}
	cleared := false
	for _, ck := range recLogout.Result().Cookies() {
		if ck.Name == sessionCookieName && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("expected DELETE /api/v1/session to expire session cookie, got %+v", recLogout.Result().Cookies())
	}

	checkState(ck1, http.StatusUnauthorized)
	checkState(ck2, http.StatusOK)

	// Expired session cookie is rejected after sessionTTL.
	now = now.Add(sessionTTL + time.Minute)
	checkState(ck2, http.StatusUnauthorized)

	fresh := login()
	// Rotating the API token immediately invalidates prior sessions.
	engRotated := NewDemoEngineForTest(t)
	engRotated.cfg.State.Path = eng.cfg.State.Path
	engRotated.opts.ListenAddr = "127.0.0.1:8080"
	engRotated.opts.APIToken = "rotated-secret-token"
	engRotated.sessions.nowFn = func() time.Time { return now }
	reqRot := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/state", nil)
	reqRot.Host = "127.0.0.1:8080"
	reqRot.AddCookie(fresh)
	recRot := httptest.NewRecorder()
	engRotated.Handler().ServeHTTP(recRot, reqRot)
	if recRot.Code != http.StatusUnauthorized {
		t.Fatalf("cookie after token rotation status = %d, want 401", recRot.Code)
	}
}

// TestWebhookPushesNewCVEsCoalescesHighSignalEventsAndFiltersNoise verifies:
// (1) initial/upgraded CVE baselines seed silently without blasting old CVEs,
//
//	while newly discovered or newly KEV-promoted exact CVEs push immediately;
//
// (2) bursty admin/policy/config events coalesce into a single webhook push;
// (3) edge physical tamper, evil-twin, honeypot, and trusted medium-swap events
//
//	push, whereas WAN IPS blocks, internal link/PoE/STP flaps, dormant wakeups,
//	and untrusted medium swaps stay off the push.
func TestWebhookPushesNewCVEsCoalescesHighSignalEventsAndFiltersNoise(t *testing.T) {
	type receivedWebhook struct {
		Diff risk.Diff `json:"diff"`
	}
	var mu sync.Mutex
	var received []receivedWebhook
	notifyCh := make(chan struct{}, 16)

	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p receivedWebhook
		_ = json.NewDecoder(r.Body).Decode(&p)
		mu.Lock()
		received = append(received, p)
		mu.Unlock()
		select {
		case notifyCh <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer whSrv.Close()

	cacheDir := t.TempDir()
	rec1 := cve.Record{
		ID: "CVE-2026-88001", Severity: checks.SeverityHigh, CVSS: 7.5,
		Matches: []cve.CPEMatch{{Part: "a", Vendor: "f5", Product: "nginx", StartIncl: "1.26.0", EndExcl: "1.26.4"}},
	}
	rec2 := cve.Record{
		ID: "CVE-2026-88002", Severity: checks.SeverityCritical, CVSS: 9.8, KEV: true,
		Matches: []cve.CPEMatch{{Part: "a", Vendor: "f5", Product: "nginx", StartIncl: "1.26.0", EndExcl: "1.26.5"}},
	}
	if err := writeTestCVEShard(cacheDir, []cve.Record{rec1}, &cve.CacheStats{SyncedAt: time.Now().UTC(), TotalCVEs: 1, IndexedCPECVEs: 1, VendorCount: 1}); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.UniFi.URL = "https://192.0.2.1"
	cfg.UniFi.APIKey = "test"
	cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	cfg.CVE.CacheDir = cacheDir
	cfg.Notify.WebhookURL = whSrv.URL
	cfg.Notify.Format = "json"
	cfg.Notify.MinSeverity = "medium"
	cfg.Network.TrustedVLANs = []string{"Main"}
	cfg.Network.IsolatedVLANs = []string{"IoT"}

	eng, err := NewEngine(cfg, nil, nil, Options{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.webhookCoalesceWindow = 250 * time.Millisecond

	trustedCl := unifi.Client{MAC: "02:aa:bb:00:00:10", IP: "10.0.1.10", Name: "workstation", NetworkName: "Main", IsWired: true}
	iotCl := unifi.Client{MAC: "02:aa:bb:00:00:20", IP: "10.0.20.20", Name: "amp", NetworkName: "IoT", IsWired: true}
	snap := &unifi.Snapshot{
		Site: "Home",
		Networks: []unifi.Network{
			{ID: "n1", Name: "Main", Subnet: "10.0.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "n2", Name: "IoT", Subnet: "10.0.20.1/24", Purpose: "corporate", ZoneName: "IoT", IsolationEnabled: true},
		},
		Clients: []unifi.Client{trustedCl, iotCl},
	}

	eng.mu.Lock()
	eng.snap = snap
	eng.baselineComplete = true
	// Simulate upgraded state.json where ExactCVEs was not yet seeded (nil map).
	eng.prevRiskState = &risk.State{
		UpdatedAt:      time.Now().UTC(),
		Findings:       map[string]checks.Severity{},
		TrustedClients: map[string]string{trustedCl.MAC: trustedCl.Name},
		PortForwards:   map[string]string{},
	}
	eng.profilesByMAC[clientKey(iotCl)] = probe.HostProfile{
		Client:    iotCl,
		OpenPorts: []int{80},
		HTTP:      map[int]probe.HTTPBanner{80: {Server: "nginx/1.26.3"}},
		ScannedAt: time.Now().UTC(),
	}
	eng.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. First recompute seeds ExactCVEs silently; noisy events must NOT push.
	eng.recomputeAndPublish(ctx, false, []LiveEvent{
		{Type: "ids_threat", Severity: "high", Summary: "Blocked WAN scan"},
		{Type: "port_stp_blocked", Severity: "high", Summary: "STP blocked Switch Port 3"},
		{Type: "client_dormant_wakeup", Severity: "medium", Summary: "Old tablet woke up"},
		{Type: "port_link_up", Severity: "info", Summary: "Physical link UP on Main Switch Port 2 (zone=internal, VLAN=Main)"},
		{Type: "port_poe_tamper", Severity: "high", Summary: "Possible physical cable swap on Main Switch Port 2 (zone=internal)"},
		{Type: "client_medium_swap", Severity: "high", SubjectID: hostEntityID(iotCl), IP: iotCl.IP, Summary: "IoT device swapped medium"},
	})
	time.Sleep(60 * time.Millisecond)
	mu.Lock()
	if len(received) != 0 {
		t.Fatalf("expected 0 webhooks on silent CVE seed + noisy events, got %+v", received)
	}
	mu.Unlock()

	// 2. Burst of high-signal events (admin + policy + edge tamper + trusted swap)
	// coalesces into a SINGLE webhook delivery.
	eng.recomputeAndPublish(ctx, false, []LiveEvent{
		{Type: "admin_activity", Severity: "medium", Summary: "Alice changed firewall settings"},
		{Type: "policy_changed", Severity: "high", Summary: "UniFi firewall policies changed"},
	})
	eng.recomputeAndPublish(ctx, false, []LiveEvent{
		{Type: "port_link_down", Severity: "high", Summary: "Physical link DOWN on Garage Switch Port 4 (zone=external)"},
		{Type: "port_poe_tamper", Severity: "critical", Summary: "Possible physical cable swap on Garage Switch Port 4 (zone=external)"},
		{Type: "port_mac_surge", Severity: "high", Summary: "MAC table jumped 1 -> 2 on Switch Port 5 (zone=internal)"},
		{Type: "wifi_evil_twin", Severity: "critical", Summary: "Possible Evil-Twin AP broadcasting HomeWiFi"},
		{Type: "honeypot_hit", Severity: "high", Summary: "Internal device probed UniFi Honeypot"},
		{Type: "client_medium_swap", Severity: "high", SubjectID: hostEntityID(trustedCl), IP: trustedCl.IP, Summary: "workstation swapped Wired -> Wi-Fi"},
	})

	select {
	case <-notifyCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for coalesced live-event webhook")
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	if len(received) != 1 {
		t.Fatalf("expected burst of live events to coalesce into 1 webhook, got %d (%+v)", len(received), received)
	}
	if len(received[0].Diff.Events) != 8 {
		t.Fatalf("expected 8 coalesced high-signal events, got %d (%+v)", len(received[0].Diff.Events), received[0].Diff.Events)
	}
	mu.Unlock()

	// 3. New KEV CVE lands in cache -> pushes immediately with CVE + MinFixedVersion.
	if err := writeTestCVEShard(cacheDir, []cve.Record{rec1, rec2}, &cve.CacheStats{SyncedAt: time.Now().UTC().Add(time.Second), TotalCVEs: 2, IndexedCPECVEs: 2, VendorCount: 1, KEVCount: 1}); err != nil {
		t.Fatal(err)
	}
	eng.recomputeAndPublish(ctx, false, nil)

	select {
	case <-notifyCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for new exact CVE webhook")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("expected 2 total webhooks, got %d", len(received))
	}
	cves := received[1].Diff.NewCVEs
	if len(cves) != 1 || cves[0].CVEID != "CVE-2026-88002" || !cves[0].KEV || cves[0].MinFixedVersion != "1.26.5" {
		t.Fatalf("unexpected NewCVEs webhook payload: %+v", cves)
	}
}

func TestMissingCVECachePreservesPatchAction(t *testing.T) {
	cfg := config.Default()
	cfg.UniFi.URL, cfg.UniFi.APIKey = "https://192.0.2.1", "test"
	cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	cfg.CVE.CacheDir = t.TempDir()
	vendors := filepath.Join(cfg.CVE.CacheDir, "vendors")
	if err := os.Mkdir(vendors, 0o755); err != nil {
		t.Fatal(err)
	}
	shard := filepath.Join(vendors, "example.json.gz")
	f, err := os.Create(shard)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if err := json.NewEncoder(gz).Encode([]cve.Record{{ID: "CVE-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.CVE.CacheDir, "stats.json"), []byte(`{"vendor_count":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(cfg, nil, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if e.cveCache == nil {
		t.Fatal("CVE cache did not load at startup")
	}
	const patch = "act:patch:CVE-1:gateway"
	seen := time.Now().UTC().Add(-24 * time.Hour)
	e.prevRiskState = &risk.State{ScoringVersion: risk.CurrentScoringVersion, Actions: map[string]string{patch: "P1"}, ActionLastSeen: map[string]time.Time{patch: seen}}
	e.snap = &unifi.Snapshot{Devices: []unifi.Device{{ID: "gateway"}}}
	for _, removed := range []string{shard, vendors, cfg.CVE.CacheDir} {
		if err := os.RemoveAll(removed); err != nil {
			t.Fatal(err)
		}
		e.recomputeAndPublish(t.Context(), true, nil)
		if e.Snapshot().CVELoaded || e.prevRiskState.Actions[patch] != "P1" || !e.prevRiskState.ActionLastSeen[patch].Equal(seen) {
			t.Fatalf("removed %s: loaded=%t actions=%v seen=%v", removed, e.Snapshot().CVELoaded, e.prevRiskState.Actions, e.prevRiskState.ActionLastSeen)
		}
	}
}

// TestEngineActionBaselineUpgrade follows a saved legacy baseline through the
// real blast evaluator, dashboard publication and outbound JSON webhook.
func TestEngineActionBaselineUpgrade(t *testing.T) {
	delivered := make(chan risk.Diff, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct{ Diff risk.Diff }
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		delivered <- payload.Diff
	}))
	defer srv.Close()
	cfg := config.Default()
	cfg.UniFi.URL, cfg.UniFi.APIKey = "https://192.0.2.1", "test"
	cfg.State.Path = filepath.Join(t.TempDir(), "uniblue-state.json")
	cfg.Notify.WebhookURL, cfg.Notify.Format, cfg.Notify.MinSeverity = srv.URL, "json", "high"
	if err := os.WriteFile(cfg.State.Path, []byte(`{"scoring_version":0,"findings":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(cfg, nil, nil, Options{SkipCVE: true})
	if err != nil {
		t.Fatal(err)
	}
	cl := unifi.Client{MAC: "02:00:00:00:00:0a", IP: "192.0.2.10", NetworkID: "lab", NetworkName: "Sensors"}
	publish := func(port int) {
		e.snap = &unifi.Snapshot{Site: "test", Clients: []unifi.Client{cl},
			Networks: []unifi.Network{{ID: "lab", Name: cl.NetworkName, VLAN: "20", ZoneName: "Internal"}}}
		e.profilesByMAC[cl.MAC] = probe.HostProfile{Client: cl}
		e.findingsByMAC[cl.MAC] = []checks.Finding{{
			CheckID: fmt.Sprintf("service-%d", port), Title: "Review service", Client: cl, Port: port, BaseSeverity: checks.SeverityHigh,
		}}
		e.recomputeAndPublish(t.Context(), true, nil)
	}
	publish(80)
	st, err := risk.LoadState(cfg.State.Path)
	id := "act:check:service-80:" + cl.MAC + ":tcp/80"
	if err != nil || st == nil || st.ScoringVersion != 3 || st.Actions[id] == "" || st.ActionPeakAt[id].IsZero() || e.webhookSeq != 0 {
		t.Fatalf("upgrade state=%+v err=%v queued=%d", st, err, e.webhookSeq)
	}
	publish(443)
	select {
	case d := <-delivered:
		if len(d.NewActions) != 0 || e.prevRiskState.Actions["act:check:service-443:"+cl.MAC+":tcp/443"] != "P3" ||
			len(d.NewFindings) != 1 || d.NewFindings[0].EffectiveSeverity != checks.SeverityHigh || len(d.EscalatedFindings) != 0 {
			t.Fatalf("new service diff = %+v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("no high finding webhook for new service, actions = %+v", e.prevRiskState.Actions)
	}
	var findings int
	for _, ev := range e.Snapshot().Events {
		if ev.Type == "finding_new" {
			findings++
		}
	}
	if findings != 1 {
		t.Fatalf("dashboard reported %d new findings, want only the new service", findings)
	}
	cl.NetworkName = "Building automation"
	publish(443)
	if e.webhookSeq != 1 {
		t.Fatalf("VLAN rename queued another webhook, total = %d", e.webhookSeq)
	}
}

// TestBlastAlertCoverage exercises the exact rule and socket identities used
// to replace findings in both the new and escalated parts of a webhook.
func TestBlastAlertCoverage(t *testing.T) {
	cl := unifi.Client{MAC: "02:00:00:00:00:0a", IP: "192.0.2.10"}
	v6 := unifi.Client{IPv6: []string{"2001:DB8::A"}}
	const expanded = "2001:0db8:0000:0000:0000:0000:0000:000a"
	device := unifi.Device{MAC: "02-00-00-00-00-0B", IP: "192.0.2.11"}
	snap := &unifi.Snapshot{Clients: []unifi.Client{cl}, Devices: []unifi.Device{device, {MAC: "02:00:00:00:00:06", IP: "2001:db8::a"}}, PortForwards: []unifi.PortForward{
		{ID: "https", Enabled: true, FwdIP: cl.IP, Proto: "tcp_udp", FwdPort: "443"},
		{ID: "ssh", Enabled: true, FwdIP: cl.IP, Proto: "tcp", FwdPort: "22"},
		{Name: "Web", Enabled: true, FwdIP: cl.IP, Proto: "tcp", DstPort: "8443", FwdPort: "443"},
		{Name: "web", Enabled: false},
		{Name: "Mail", Enabled: true, FwdIP: cl.IP, Proto: "tcp", DstPort: "25"},
		{Name: "MAIL", Enabled: true, FwdIP: device.IP, Proto: "tcp", DstPort: "25"},
		{Enabled: true, FwdIP: device.IP, Proto: "tcp", DstPort: "2525", FwdPort: "25,465"},
		{Enabled: true, FwdIP: cl.IP, Proto: "tcp", DstPort: "8443", FwdPort: "8000-8002"},
		{Enabled: true, FwdIP: cl.IP, Proto: "tcp", DstPort: "8000-8002"},
		{Enabled: true, FwdIP: expanded, Proto: "tcp", DstPort: "18000-18002", FwdPort: "8000-8002"},
	}}
	forward := func(id string, port int) checks.Finding {
		return checks.Finding{CheckID: "UB-UNIFI-PORTFWD", Property: "portfwd:" + id, Client: cl, Port: port}
	}
	dns := checks.Finding{CheckID: "DNS", Client: v6, Port: 53, Transport: "UDP"}
	tcp := dns
	tcp.Transport = "tcp"
	vnc := checks.Finding{CheckID: "UB-0002", Client: cl, Port: 5900}
	high := vnc
	high.EffectiveSeverity = checks.SeverityHigh
	deviceForward := forward("tcp-25-"+device.IP+"-", 0)
	deviceForward.Client = unifi.Client{IP: device.IP}
	gw := checks.Finding{CheckID: "UB-UNIFI-FW-WAN-GW", Client: unifi.Client{MAC: "fw:Rule"}}
	for _, tc := range []struct {
		name, id string
		tier     blast.Priority
		lane     blast.Lane
		f        checks.Finding
		covered  bool
	}{
		{"verify only", "act:verify:UB-0002:" + cl.MAC + ":tcp/5900", blast.P2, blast.LaneVerify, vnc, false},
		{"verify lane", "act:check:UB-0002:" + cl.MAC + ":5900", blast.P2, blast.LaneVerify, vnc, false},
		{"zero credit", "act:check:UB-0002:" + cl.MAC + ":5900", "", blast.LaneFixNow, vnc, false},
		{"high finding with medium action", "act:check:UB-0002:" + cl.MAC + ":5900", blast.P3, blast.LaneFixNow, high, false},
		{"high finding with low action", "act:check:UB-0002:" + cl.MAC + ":5900", blast.P4, blast.LaneFixNow, high, false},
		{"host check bundle", "act:check-host:UB-0002:" + cl.MAC, blast.P2, blast.LaneFixNow, high, true},
		{"lower priority host check bundle", "act:check-host:UB-0002:" + cl.MAC, blast.P3, blast.LaneReduceExposure, high, false},
		{"IPv6 infra bundle", "act:wan-service:02:00:00:00:00:06:tcp/8000", blast.P2, blast.LaneFixNow, forward("tcp-18000-18002-"+expanded+"-8000-8002", 0), true},
		{"high finding with high action", "act:check:UB-0002:" + cl.MAC + ":5900", blast.P2, blast.LaneFixNow, high, true},
		{"posture", "act:gateway-local:rule", blast.P2, blast.LaneFixNow, checks.Finding{CheckID: "UB-UNIFI-SSH-PASSWORD", Client: gw.Client}, false},
		{"WAN to gateway", "act:gateway-local:RULE", blast.P2, blast.LaneFixNow, gw, true},
		{"gateway routed", "act:gateway-routed:rule", blast.P2, blast.LaneFixNow, checks.Finding{CheckID: "UB-UNIFI-FW-WAN-LAN", Client: gw.Client}, true},
		{"switch routed", "act:switch-routed:rule", blast.P2, blast.LaneFixNow, checks.Finding{CheckID: "UB-UNIFI-FW-ISO-LEAK", Client: gw.Client}, true},
		{"forward ID", "act:wan-pf:HTTPS", blast.P1, blast.LaneFixNow, forward("https", 443), true},
		{"forward name", "act:wan-pf:WEB", blast.P1, blast.LaneFixNow, forward("tcp-8443-"+cl.IP+"-443", 443), true},
		{"duplicate name", "act:wan-pf:mail", blast.P2, blast.LaneFixNow, forward("tcp-25-"+cl.IP+"-", 0), false},
		{"duplicate name on other backend", "act:wan-pf:mail", blast.P2, blast.LaneFixNow, deviceForward, false},
		{"socket fallback", "act:wan-pf:" + device.IP + ":tcp/25", blast.P2, blast.LaneFixNow, forward("tcp-2525-"+device.IP+"-25,465", 0), true},
		{"omitted translated port", "act:wan-service:" + device.IP + ":tcp/25", blast.P2, blast.LaneFixNow, deviceForward, true},
		{"translated range", "act:wan-service:" + cl.IP + ":tcp/8443", blast.P2, blast.LaneFixNow, forward("tcp-8443-"+cl.IP+"-8000-8002", 0), false},
		{"untranslated range", "act:wan-pf:" + cl.IP + ":tcp/8000", blast.P2, blast.LaneFixNow, forward("tcp-8000-8002-"+cl.IP+"-", 0), true},
		{"translated IPv6 range", "act:wan-pf:2001:db8::a:tcp/8000", blast.P2, blast.LaneFixNow, forward("tcp-18000-18002-"+expanded+"-8000-8002", 0), true},
		{"canonical IPv6 bundle", "act:wan-service:2001:db8::a:tcp/8000", blast.P2, blast.LaneFixNow, forward("tcp-18000-18002-"+expanded+"-8000-8002", 0), true},
		{"device bundle", "act:wan-service:02:00:00:00:00:0b:tcp/25", blast.P2, blast.LaneFixNow, deviceForward, true},
		{"bundle by MAC", "act:wan-service:" + cl.MAC + ":tcp/443", blast.P1, blast.LaneFixNow, forward("https", 443), true},
		{"bundle by IP and translated port", "act:wan-service:" + cl.IP + ":udp/443", blast.P1, blast.LaneFixNow, forward("https", 0), true},
		{"different forward", "act:wan-service:" + cl.MAC + ":tcp/443", blast.P1, blast.LaneFixNow, forward("ssh", 22), false},
		{"different forward transport", "act:wan-service:" + cl.IP + ":udp/22", blast.P1, blast.LaneFixNow, forward("ssh", 22), false},
		{"TCP grant", "act:check:dns:2001:db8::a:53", blast.P2, blast.LaneFixNow, tcp, true},
		{"TCP socket", "act:check:dns:2001:db8::a:tcp/53", blast.P2, blast.LaneFixNow, tcp, true},
		{"UDP grant", "act:check:dns:2001:db8::a:53:udp", blast.P2, blast.LaneFixNow, dns, true},
		{"UDP socket", "act:check:dns:2001:db8::a:udp/53", blast.P2, blast.LaneFixNow, dns, true},
		{"different socket transport", "act:check:dns:2001:db8::a:53:udp", blast.P2, blast.LaneFixNow, tcp, false},
		{"different socket port", "act:check:dns:2001:db8::a:tcp/853", blast.P2, blast.LaneFixNow, tcp, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := risk.Diff{NewFindings: []checks.Finding{tc.f}, EscalatedFindings: []checks.Finding{tc.f}}
			rep := blast.Report{Actions: []blast.Action{{ID: tc.id, HighestTierReduced: tc.tier, Lane: tc.lane}}}
			unseeded := risk.State{ScoringVersion: risk.CurrentScoringVersion}
			ApplyBlastActionsToDiff(&d, &unseeded, snap, rep, nil, nil, true)
			if len(d.NewActions) != 0 || len(d.NewFindings) != 1 || len(d.EscalatedFindings) != 1 {
				t.Fatalf("initial seed changed alerts: %+v", d)
			}
			ApplyBlastActionsToDiff(&d, nil, snap, rep, nil, nil, true)
			if (len(d.NewFindings) == 0) != tc.covered || (len(d.EscalatedFindings) == 0) != tc.covered {
				t.Fatalf("covered = %t, diff = %+v", tc.covered, d)
			}
			if tc.f.EffectiveSeverity == checks.SeverityHigh && (!d.HasAlerts(checks.SeverityHigh) || !d.HasAlerts(checks.SeverityMedium)) {
				t.Fatalf("high finding lost webhook delivery: %+v", d)
			}
		})
	}
}

func TestPatchActionCoverageAtWebhookThreshold(t *testing.T) {
	cl := unifi.Client{MAC: "02:00:00:00:00:0A", IPv6: []string{"2001:db8::A"}}
	snap := &unifi.Snapshot{Clients: []unifi.Client{cl}}
	patch := blast.Action{ID: "act:patch:CVE-1:" + strings.ToLower(cl.MAC), HighestTierReduced: blast.P1, Lane: blast.LaneFixNow}
	other := patch
	other.ID = "act:patch:CVE-1:192.0.2.2"
	rep := blast.Report{Actions: []blast.Action{patch, other}}
	high := risk.CVEAlert{CVEID: "cve-1", HostIP: "2001:DB8::a", Severity: checks.SeverityHigh}
	kev := high
	kev.KEV = true
	for _, tc := range []struct {
		name string
		tier blast.Priority
		cves []risk.CVEAlert
		keep bool
	}{
		{"higher priority than CVE", blast.P1, []risk.CVEAlert{high}, true},
		{"equal threshold", blast.P2, []risk.CVEAlert{high}, false},
		{"KEV promotion", blast.P1, []risk.CVEAlert{kev, high}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep.Actions[0].HighestTierReduced = tc.tier
			d := risk.Diff{NewCVEs: tc.cves}
			actions, seen, _, _, _, _ := ApplyBlastActionsToDiff(&d, nil, snap, rep, nil, tc.cves, true)
			has := func(id string) bool {
				return slices.ContainsFunc(d.NewActions, func(a risk.ActionAlert) bool { return a.ID == id })
			}
			if has(patch.ID) != tc.keep || !has(other.ID) || actions[patch.ID] != string(tc.tier) {
				t.Fatalf("diff = %+v, actions = %v", d, actions)
			}
			if tc.tier == blast.P2 {
				prev := risk.State{ScoringVersion: risk.CurrentScoringVersion, Actions: actions, ActionLastSeen: seen}
				rep.Actions[0].HighestTierReduced = blast.P1
				ApplyBlastActionsToDiff(&d, &prev, snap, rep, nil, tc.cves, true)
				if len(d.EscalatedActions) != 1 || d.EscalatedActions[0].ID != patch.ID || d.EscalatedActions[0].Previous != "P2" {
					t.Fatalf("patch exposure escalation = %+v", d)
				}
			}
		})
	}
	high.Product = "Web Server"
	bundle := "act:patch-product:web-server:" + strings.ToLower(cl.MAC)
	rep.Actions[0] = blast.Action{ID: bundle, HighestTierReduced: blast.P2, Lane: blast.LaneFixNow}
	d := risk.Diff{NewCVEs: []risk.CVEAlert{high}}
	ApplyBlastActionsToDiff(&d, nil, snap, rep, nil, d.NewCVEs, true)
	if len(d.NewActions) != 1 || d.NewActions[0].ID != other.ID || len(d.NewCVEs) != 1 {
		t.Fatal(d)
	}

}

func TestActionsPreventWebhookCoalescing(t *testing.T) {
	for _, d := range []risk.Diff{{NewActions: []risk.ActionAlert{{ID: "new"}}}, {EscalatedActions: []risk.ActionAlert{{ID: "escalated"}}}} {
		d.Events = []risk.AlertEvent{{Type: "event"}}
		if isLiveEventOnlyDiff(d) {
			t.Fatalf("action classified as event only: %+v", d)
		}
		d.Events, d.NewCVEs = nil, []risk.CVEAlert{{CVEID: "CVE-1"}}
		if isCVEOnlyDiff(d) {
			t.Fatalf("action classified as CVE only: %+v", d)
		}
	}
}
