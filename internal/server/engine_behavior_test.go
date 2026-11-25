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
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestHTTPProtectionHostOriginTokenAndRescanResponses verifies DNS-rebinding
// Host protection on both loopback and non-loopback listeners, reverse-proxy
// AllowedHosts support, cross-origin POST CSRF blocking, Bearer token and
// HttpOnly session cookie authentication via POST /api/auth, and 503 queue-full
// responses.
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
		{http.MethodGet, "/api/state", "rebind.evil.example:8080", http.StatusForbidden},
		{http.MethodPost, "/api/rescan", "rebind.evil.example:8080", http.StatusForbidden},
		{http.MethodGet, "/api/state", "192.168.1.50:8080", http.StatusOK},
		{http.MethodGet, "/api/state", "[fd00::50]:8080", http.StatusOK},
		{http.MethodGet, "/api/state", "uniblue.local:8080", http.StatusOK},
		{http.MethodGet, "/api/state", "uniblue.lan", http.StatusOK},
		{http.MethodGet, "/api/state", "uniblue", http.StatusOK},
	} {
		r := httptest.NewRequest(tc.method, "http://127.0.0.1"+tc.path, nil)
		r.Host = tc.host
		w := httptest.NewRecorder()
		hLAN.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("non-loopback %s %s Host=%q: got %d, want %d", tc.method, tc.path, tc.host, w.Code, tc.want)
		}
	}

	// 3. Cross-origin POST /api/rescan must be rejected (403).
	reqCSRF := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/rescan", nil)
	reqCSRF.Host = "127.0.0.1:8080"
	reqCSRF.Header.Set("Origin", "https://evil.example")
	recCSRF := httptest.NewRecorder()
	h.ServeHTTP(recCSRF, reqCSRF)
	if recCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin POST /api/rescan, got %d", recCSRF.Code)
	}

	// 4. Same-origin POST /api/rescan succeeds.
	reqOK := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/rescan", nil)
	reqOK.Host = "127.0.0.1:8080"
	reqOK.Header.Set("Origin", "http://127.0.0.1:8080")
	recOK := httptest.NewRecorder()
	h.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for same-origin POST /api/rescan, got %d", recOK.Code)
	}

	// 5. Reverse-proxy AllowedHosts supports both Host-preserving (Caddy) and
	// Host-rewriting (nginx) proxies on loopback listeners while still rejecting
	// unlisted origins.
	engProxy := NewDemoEngineForTest(t)
	engProxy.opts.ListenAddr = "127.0.0.1:8080"
	engProxy.opts.AllowedHosts = []string{"uniblue.example.com"}
	hProxy := engProxy.Handler()

	reqCaddy := httptest.NewRequest(http.MethodGet, "http://uniblue.example.com/api/state", nil)
	reqCaddy.Host = "uniblue.example.com"
	reqCaddy.Header.Set("Origin", "https://uniblue.example.com")
	recCaddy := httptest.NewRecorder()
	hProxy.ServeHTTP(recCaddy, reqCaddy)
	if recCaddy.Code != http.StatusOK {
		t.Fatalf("expected 200 for Host-preserving reverse proxy, got %d", recCaddy.Code)
	}

	reqNginx := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/rescan", nil)
	reqNginx.Host = "127.0.0.1:8080"
	reqNginx.Header.Set("Origin", "https://uniblue.example.com")
	recNginx := httptest.NewRecorder()
	hProxy.ServeHTTP(recNginx, reqNginx)
	if recNginx.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for Host-rewriting reverse proxy rescan, got %d", recNginx.Code)
	}

	reqEvilOrigin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/rescan", nil)
	reqEvilOrigin.Host = "127.0.0.1:8080"
	reqEvilOrigin.Header.Set("Origin", "https://attacker.example")
	recEvilOrigin := httptest.NewRecorder()
	hProxy.ServeHTTP(recEvilOrigin, reqEvilOrigin)
	if recEvilOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unlisted Origin even with AllowedHosts, got %d", recEvilOrigin.Code)
	}

	// 6. Optional Bearer token and POST /api/auth HttpOnly session cookie protect /api/*.
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

	// Bad token to POST /api/auth returns 401.
	reqBadLogin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/auth", strings.NewReader(`{"token":"wrong"}`))
	reqBadLogin.Host = "127.0.0.1:8080"
	recBadLogin := httptest.NewRecorder()
	hTok.ServeHTTP(recBadLogin, reqBadLogin)
	if recBadLogin.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad /api/auth token, got %d", recBadLogin.Code)
	}

	// Valid token to POST /api/auth issues HttpOnly; SameSite=Strict session cookie.
	reqLogin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/auth", strings.NewReader(`{"token":"secret-token"}`))
	reqLogin.Host = "127.0.0.1:8080"
	recLogin := httptest.NewRecorder()
	hTok.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid /api/auth token, got %d", recLogin.Code)
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
	reqCookieState := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/state", nil)
	reqCookieState.Host = "127.0.0.1:8080"
	reqCookieState.AddCookie(sessCookie)
	recCookieState := httptest.NewRecorder()
	hTok.ServeHTTP(recCookieState, reqCookieState)
	if recCookieState.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET /api/state with session cookie, got %d", recCookieState.Code)
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
	liveEng.handleRescan(recFull, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/rescan?ip=192.0.2.10", nil))
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
// that startup recompute before baseline does not wipe persisted host findings,
// adding the first port forward on an empty site fires policy_changed,
// concurrent recomputeAndPublish calls stay serialized without corrupting
// state.json, and policy signatures are order-independent and complete.
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
	eng.prevRiskState = &risk.State{UpdatedAt: time.Now().UTC(), Findings: map[string]checks.Severity{}}
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
					{PortIdx: 1, Enabled: true, Up: true, NativeNetworkName: "IoT", TaggedVLANMgmt: "block_all", PortSecurityEnabled: true},
				},
			},
		},
		Visibility: &unifi.SiteVisibility{SettingsAvailable: true, WLANsAvailable: true, PortProfilesAvailable: true},
	}

	// Simulate transient failure of settings, WLANs, and rest/portconf.
	failSnap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{
				MAC: "aa:00:00:00:00:02", Name: "Switch", Type: "usw",
				Ports: []unifi.SwitchPort{
					{PortIdx: 1, Enabled: true, Up: true, NativeNetworkName: "Default", TaggedVLANMgmt: "auto", PortSecurityEnabled: false},
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

	// Verify runFullScan adoption evicts a Wi-Fi client that was in leave-grace.
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
	phone := unifi.Client{MAC: "02:cc:dd:ee:ff:01", IP: "192.0.2.77", Name: "sleepy-phone", NetworkName: "Main", IsWired: false}
	eng2.mu.Lock()
	eng2.snap = &unifi.Snapshot{
		Site:             "default",
		SecuritySettings: &unifi.SiteSecuritySettings{UPnPEnabled: true},
		Visibility:       &unifi.SiteVisibility{SettingsAvailable: true},
	}
	eng2.missingClients[clientKey(phone)] = missingClient{client: phone, since: time.Now().UTC()}
	eng2.profilesByMAC[clientKey(phone)] = probe.HostProfile{Client: phone, ScannedAt: time.Now().UTC()}
	eng2.findingsByMAC[clientKey(phone)] = []checks.Finding{
		{CheckID: "UB-0001", Title: "Ghost finding", EffectiveSeverity: checks.SeverityHigh, Client: phone, Port: 23},
	}
	eng2.mu.Unlock()

	if err := eng2.runFullScan(context.Background(), "reconcile"); err != nil {
		t.Fatalf("runFullScan: %v", err)
	}
	snapOut := eng2.Snapshot()
	for _, f := range snapOut.Report.Findings {
		if f.CheckID == "UB-0001" {
			t.Fatalf("ghost finding lingered after full-scan snapshot adoption: %+v", f)
		}
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
	foundLeft := false
	for _, ev := range snapOut.Events {
		if ev.Type == "client_left" && ev.Host == "sleepy-phone" {
			foundLeft = true
		}
	}
	if !foundLeft {
		t.Fatalf("expected client_left event for evicted leave-grace client, got %+v", snapOut.Events)
	}
}

// TestClientSkipReasonAndIPv6ClassLookup verifies canonical exclude_ips matching,
// public/out-of-subnet skip reasons matching the probe IP guard, and IPv6-only
// client classification lookup by MAC fallback.
func TestClientSkipReasonAndIPv6ClassLookup(t *testing.T) {
	siteSubnets := []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}
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
