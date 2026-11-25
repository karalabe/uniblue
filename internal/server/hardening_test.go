// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/notify"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

func TestAPIDevicesAndHostFallbackIncludesGatewayWANIPAndSleepingClientGrace(t *testing.T) {
	eng := NewDemoEngineForTest(t)
	eng.mu.Lock()
	if eng.current.Report.UniFiPosture == nil {
		eng.current.Report.UniFiPosture = &risk.UniFiPostureSummary{}
	}
	eng.current.Report.UniFiPosture.Health.WANIP = "203.0.113.10"
	var gwMAC, swIP string
	for _, ent := range eng.current.View.Entities {
		if ent.Kind == "device" {
			if ent.Model != "" && strings.Contains(strings.ToLower(ent.Role), "gateway") {
				gwMAC = ent.MAC
			} else if swIP == "" && ent.IP != "" {
				swIP = ent.IP
			}
		}
	}
	eng.mu.Unlock()
	if swIP == "" {
		t.Fatal("expected at least one UniFi device in demo view")
	}

	h := eng.Handler()

	// 1. GET /api/v1/devices lists UniFi devices.
	reqDevs := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/devices", nil)
	recDevs := httptest.NewRecorder()
	h.ServeHTTP(recDevs, reqDevs)
	if recDevs.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/devices status = %d, want 200", recDevs.Code)
	}
	var devsResp struct {
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(recDevs.Body.Bytes(), &devsResp); err != nil || len(devsResp.Devices) == 0 {
		t.Fatalf("expected non-empty /api/v1/devices response, got %s", recDevs.Body.String())
	}

	// 2. GET /api/v1/hosts/{switchIP} resolves UniFi switch instead of 404.
	reqSw := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/hosts/"+swIP, nil)
	recSw := httptest.NewRecorder()
	h.ServeHTTP(recSw, reqSw)
	if recSw.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/hosts/%s status = %d, want 200 (%s)", swIP, recSw.Code, recSw.Body.String())
	}

	// 3. GET /api/v1/hosts/{gatewayWANIP} and /api/v1/devices/{gatewayWANIP} resolve gateway.
	for _, path := range []string{"/api/v1/hosts/203.0.113.10", "/api/v1/devices/203.0.113.10"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080"+path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200 (%s)", path, rec.Code, rec.Body.String())
		}
		if gwMAC != "" && !strings.Contains(strings.ToLower(rec.Body.String()), strings.ToLower(gwMAC)) {
			t.Fatalf("GET %s did not return gateway MAC %s: %s", path, gwMAC, rec.Body.String())
		}
	}

	// 4. Sleeping Wi-Fi client within leave grace stays in View.Entities on recompute
	// so mid-scan /api/v1/hosts/{ip} lookups never flap to transient 404.
	sleeping := unifi.Client{MAC: "aa:bb:cc:dd:ee:99", Name: "SleepingPhone", IP: "10.0.10.99", NetworkName: "Main"}
	eng.mu.Lock()
	eng.snap = &unifi.Snapshot{Site: "default", Clients: nil}
	if eng.missingClients == nil {
		eng.missingClients = make(map[string]missingClient)
	}
	eng.missingClients[clientKey(sleeping)] = missingClient{client: sleeping, since: time.Now().UTC()}
	eng.mu.Unlock()
	eng.recomputeAndPublish(context.Background(), false, nil)

	reqSleep := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/hosts/10.0.10.99", nil)
	recSleep := httptest.NewRecorder()
	h.ServeHTTP(recSleep, reqSleep)
	if recSleep.Code != http.StatusOK {
		t.Fatalf("sleeping client within leave grace returned %d, want 200", recSleep.Code)
	}
}

func TestWebhookPermanent4xxDropsWithoutBlockingAndShutdownSuccessDoesNotResend(t *testing.T) {
	var callNum atomic.Int32
	var mu sync.Mutex
	var gotIDs []string
	doneSecond := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callNum.Add(1)
		var payload struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		gotIDs = append(gotIDs, payload.ID)
		mu.Unlock()
		if n == 1 {
			// Permanent 400 rejection for batch 1.
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		select {
		case doneSecond <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	eng := NewDemoEngineForTest(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	eng.cfg.State.Path = statePath
	eng.webhookRetryBase = 10 * time.Millisecond
	notifier, err := notify.New(config.NotifyConfig{
		WebhookURL:  srv.URL,
		Format:      "json",
		MinSeverity: "medium",
	})
	if err != nil {
		t.Fatal(err)
	}
	eng.notifier = notifier

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d1 := risk.Diff{NewTrustedClients: []unifi.Client{{MAC: "aa:bb:cc:dd:00:01", Name: "BadBatch"}}}
	d2 := risk.Diff{NewTrustedClients: []unifi.Client{{MAC: "aa:bb:cc:dd:00:02", Name: "GoodBatch"}}}
	eng.enqueueWebhooks(ctx, []pendingWebhook{
		{id: "msg_bad_400", site: "default", diff: d1},
		{id: "msg_good_200", site: "default", diff: d2},
	}, true)

	select {
	case <-doneSecond:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for batch 2 after permanent 400 on batch 1")
	}
	// Give drainer a moment to persist empty queue.
	time.Sleep(30 * time.Millisecond)

	mu.Lock()
	if len(gotIDs) != 2 || gotIDs[0] != "msg_bad_400" || gotIDs[1] != "msg_good_200" {
		t.Fatalf("expected permanent 400 batch dropped immediately and batch 2 delivered, got %+v", gotIDs)
	}
	mu.Unlock()

	if _, err := os.Stat(eng.pendingWebhooksPath()); !os.IsNotExist(err) {
		t.Fatalf("expected pending webhooks file removed after drain, stat err=%v", err)
	}

	// Verify shutdown race: if ctx cancels right as SendWithID succeeds (returns nil),
	// the delivered batch MUST still be removed from disk so restart does not resend.
	ctx2, cancel2 := context.WithCancel(context.Background())
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Cancel right after flushing the 200 response so the client finishes
		// reading HTTP 200 (SendWithID returns nil) while ctx2 is already done.
		time.Sleep(15 * time.Millisecond)
		cancel2()
	}))
	defer srv2.Close()
	n2, _ := notify.New(config.NotifyConfig{WebhookURL: srv2.URL, Format: "json", MinSeverity: "medium"})
	eng.notifier = n2
	eng.enqueueWebhook(ctx2, pendingWebhook{id: "msg_cancel_race", site: "default", diff: d2})

	// Wait until the queue drains (SendWithID returned nil and removed batch).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		eng.webhookMu.Lock()
		running := eng.webhookRunning
		remaining := len(eng.pendingWebhooks)
		eng.webhookMu.Unlock()
		if !running && remaining == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	eng.webhookMu.Lock()
	remaining := len(eng.pendingWebhooks)
	eng.webhookMu.Unlock()
	if remaining != 0 {
		t.Fatalf("delivered batch during shutdown cancel remained in queue (%d)", remaining)
	}
	if _, err := os.Stat(eng.pendingWebhooksPath()); !os.IsNotExist(err) {
		t.Fatalf("expected delivered shutdown batch removed from disk, stat err=%v", err)
	}
}

func TestWebhookCVEBurstChunkingAndQueuePriorityAndEventBurstCounts(t *testing.T) {
	// 1. Oversized NewCVEs bursts split into bounded <=50 CVE batches.
	var bigCVEs []risk.CVEAlert
	for i := 0; i < 120; i++ {
		bigCVEs = append(bigCVEs, risk.CVEAlert{
			CVEID:    fmt.Sprintf("CVE-2026-%05d", i),
			HostIP:   "192.168.1.10",
			Product:  "nginx",
			Severity: checks.SeverityHigh,
		})
	}
	chunks := splitWebhookByCVEs("default", risk.Diff{NewCVEs: bigCVEs}, 50)
	if len(chunks) != 3 || len(chunks[0].diff.NewCVEs) != 50 || len(chunks[1].diff.NewCVEs) != 50 || len(chunks[2].diff.NewCVEs) != 20 {
		t.Fatalf("unexpected CVE chunking: len=%d", len(chunks))
	}

	// 2. Live-event-only bursts never evict queued diff-bearing finding batches.
	eng := NewDemoEngineForTest(t)
	eng.cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	eng.webhookMu.Lock()
	for i := 0; i < maxPendingWebhooks; i++ {
		eng.enqueueWebhookLocked(context.Background(), pendingWebhook{
			id:   fmt.Sprintf("finding-%d", i),
			site: "default",
			diff: risk.Diff{NewTrustedClients: []unifi.Client{{MAC: fmt.Sprintf("aa:bb:cc:dd:00:%02x", i)}}},
		}, false)
	}
	eng.enqueueWebhookLocked(context.Background(), pendingWebhook{
		id:   "live-noise",
		site: "default",
		diff: risk.Diff{Events: []risk.AlertEvent{{Type: "admin_activity", Severity: checks.SeverityMedium, Summary: "Admin login"}}},
	}, false)
	for _, pw := range eng.pendingWebhooks {
		if isLiveEventOnlyDiff(pw.diff) {
			eng.webhookMu.Unlock()
			t.Fatal("live-event-only batch must not evict queued diff-bearing finding batches")
		}
	}
	eng.webhookMu.Unlock()

	// 3. Duplicate live events in a coalescing window preserve repeat count (xN).
	ev := risk.AlertEvent{Type: "honeypot_hit", Severity: checks.SeverityHigh, Host: "iot-1", IP: "10.0.30.5", Summary: "Probed honeypot"}
	merged := appendUniqueAlertEvents([]risk.AlertEvent{ev, ev}, []risk.AlertEvent{ev})
	if len(merged) != 1 || merged[0].Summary != "Probed honeypot (x3)" {
		t.Fatalf("expected coalesced burst count (x3), got %+v", merged)
	}
}

func TestDiffExactCVEsMACIdentityLegacyMigrationAndTransientGrace(t *testing.T) {
	cl := unifi.Client{MAC: "aa:bb:cc:dd:ee:44", Name: "WebSrv", IP: "192.168.1.44", NetworkName: "Main"}
	snap := &unifi.Snapshot{Clients: []unifi.Client{cl}}
	match := cve.Match{
		Product: cve.Product{HostName: "WebSrv", HostIP: "192.168.1.44", Label: "nginx", Version: "1.26.3"},
		Record:  cve.Record{ID: "CVE-2026-10001", Severity: checks.SeverityHigh, CVSS: 7.5},
	}

	// Legacy IP-keyed baseline migrates silently to MAC-keyed without re-alerting.
	prevLegacy := &risk.State{
		UpdatedAt: time.Now().UTC(),
		ExactCVEs: map[string]string{
			"192.168.1.44|nginx|1.26.3|CVE-2026-10001": "high",
		},
	}
	alerts, nextCVEs, nextSeen := diffExactCVEs(prevLegacy, snap, map[string]struct{}{cl.MAC: {}}, []cve.Match{match}, nil)
	if len(alerts) != 0 {
		t.Fatalf("legacy IP key should migrate silently without alerting, got %+v", alerts)
	}
	macKey := "aa:bb:cc:dd:ee:44|nginx|1.26.3|CVE-2026-10001"
	if _, ok := nextCVEs[macKey]; !ok {
		t.Fatalf("expected MAC-anchored key %q in next ExactCVEs, got %+v", macKey, nextCVEs)
	}

	// Host gets a new DHCP IP (192.168.1.99) with the same MAC -> zero false re-alert.
	clMoved := cl
	clMoved.IP = "192.168.1.99"
	matchMoved := match
	matchMoved.Product.HostIP = "192.168.1.99"
	prevMAC := &risk.State{UpdatedAt: time.Now().UTC(), ExactCVEs: nextCVEs, ExactCVELastSeen: nextSeen}
	alerts, nextCVEs, nextSeen = diffExactCVEs(prevMAC, &unifi.Snapshot{Clients: []unifi.Client{clMoved}}, map[string]struct{}{clMoved.MAC: {}}, []cve.Match{matchMoved}, nil)
	if len(alerts) != 0 {
		t.Fatalf("DHCP IP change with same MAC must not re-alert existing CVE, got %+v", alerts)
	}

	// Transient 1-scan banner drop within grace keeps the key so next scan does not flap.
	prevRecent := &risk.State{UpdatedAt: time.Now().UTC(), ExactCVEs: nextCVEs, ExactCVELastSeen: nextSeen}
	_, carriedCVEs, _ := diffExactCVEs(prevRecent, &unifi.Snapshot{Clients: []unifi.Client{clMoved}}, map[string]struct{}{clMoved.MAC: {}}, nil, nil)
	if _, ok := carriedCVEs[macKey]; !ok {
		t.Fatalf("expected transient banner miss within grace to retain CVE key %q", macKey)
	}
}

func TestPreserveUnavailableTelemetryProfileManagedVsManualPort(t *testing.T) {
	prevSnap := &unifi.Snapshot{
		Devices: []unifi.Device{{
			MAC: "11:22:33:44:55:66",
			Ports: []unifi.SwitchPort{
				{
					PortIdx:             1,
					Enabled:             true,
					OpMode:              "switch",
					Forward:             "native",
					TaggedVLANMgmt:      "block_all",
					NativeNetworkID:     "net-cam",
					NativeNetworkName:   "Cameras",
					PortConfID:          "prof-ext-cam",
					ProfileManaged:      true,
					PortSecurityEnabled: true,
					PortSecurityMACs:    []string{"aa:bb:cc:dd:ee:01"},
				},
				{
					PortIdx:           2,
					Enabled:           true,
					OpMode:            "switch",
					Forward:           "native",
					TaggedVLANMgmt:    "block_all",
					NativeNetworkName: "IoT",
					ProfileManaged:    false,
				},
			},
		}},
	}
	nextSnap := &unifi.Snapshot{
		Visibility: &unifi.SiteVisibility{PortProfilesAvailable: false},
		Devices: []unifi.Device{{
			MAC: "11:22:33:44:55:66",
			Ports: []unifi.SwitchPort{
				{
					PortIdx:             1,
					Enabled:             true,
					OpMode:              "switch",
					Forward:             "all",
					TaggedVLANMgmt:      "auto",
					NativeNetworkName:   "Default",
					PortConfID:          "prof-ext-cam",
					ProfileManaged:      true,
					PortSecurityEnabled: false,
				},
				{
					PortIdx:           2,
					Enabled:           true,
					OpMode:            "switch",
					Forward:           "all",
					TaggedVLANMgmt:    "auto",
					NativeNetworkName: "Main",
					ProfileManaged:    false,
				},
			},
		}},
	}

	preserveUnavailableTelemetry(prevSnap, nextSnap)
	p1 := nextSnap.Devices[0].Ports[0]
	if p1.NativeNetworkName != "Cameras" || p1.TaggedVLANMgmt != "block_all" || !p1.PortSecurityEnabled {
		t.Fatalf("profile-managed port must carry forward all profile fields when portconf unavailable, got %+v", p1)
	}
	p2 := nextSnap.Devices[0].Ports[1]
	if p2.NativeNetworkName != "Main" || p2.TaggedVLANMgmt != "auto" {
		t.Fatalf("manual port direct edits must remain visible even when portconf unavailable, got %+v", p2)
	}
}

func TestWebhookTransient4xxRetriesAndSameClientStableIPv6Only(t *testing.T) {
	// 1. Transient 404/401 on attempt 1 retries and delivers on attempt 2.
	var attempts atomic.Int32
	delivered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		select {
		case delivered <- struct{}{}:
		default:
		}
	}))
	defer srv.Close()

	eng := NewDemoEngineForTest(t)
	eng.cfg.State.Path = filepath.Join(t.TempDir(), "state.json")
	eng.webhookRetryBase = 10 * time.Millisecond
	n, err := notify.New(config.NotifyConfig{WebhookURL: srv.URL, Format: "json", MinSeverity: "medium"})
	if err != nil {
		t.Fatal(err)
	}
	eng.notifier = n
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eng.enqueueWebhook(ctx, pendingWebhook{
		id:   "msg_transient_404",
		site: "default",
		diff: risk.Diff{NewTrustedClients: []unifi.Client{{MAC: "aa:bb:cc:dd:00:09", Name: "Box"}}},
	})
	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("expected transient 404 webhook to retry and deliver")
	}
	if attempts.Load() < 2 {
		t.Fatalf("expected at least 2 attempts for transient 404, got %d", attempts.Load())
	}

	// 2. IPv6-only client rotating a temporary privacy address listed first
	// still shares its stable ULA/GUA and must NOT count as a client move.
	oldV6 := unifi.Client{MAC: "aa:bb:cc:dd:ee:61", IPv6: []string{"2001:db8::temp1", "fd00::61"}}
	newV6 := unifi.Client{MAC: "aa:bb:cc:dd:ee:61", IPv6: []string{"2001:db8::temp2", "fd00::61"}}
	if !sameClientStableIP(oldV6, newV6) {
		t.Fatal("IPv6-only privacy rotation with unchanged stable address must not trigger client_moved")
	}
	movedV6 := unifi.Client{MAC: "aa:bb:cc:dd:ee:61", IPv6: []string{"2001:db8:99::1"}}
	if sameClientStableIP(oldV6, movedV6) {
		t.Fatal("IPv6-only host with completely disjoint routable IPv6 addresses should be detected as moved")
	}
}

// TestOutboxCommitsOneBatchAfterStorageRecovers verifies that a failed webhook
// outbox write rolls back pendingWebhooks cleanly so retrying the same batch
// after storage recovers produces exactly one queued entry.
func TestOutboxCommitsOneBatchAfterStorageRecovers(t *testing.T) {
	dir := t.TempDir()
	badDir := filepath.Join(dir, "unavailable")
	if err := os.WriteFile(badDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewDemoEngineForTest(t)
	e.cfg.State.Path = filepath.Join(badDir, "state.json")
	item := pendingWebhook{
		site: "default",
		diff: risk.Diff{
			NewFindings: []checks.Finding{{
				CheckID:           "same-finding",
				BaseSeverity:      checks.SeverityHigh,
				EffectiveSeverity: checks.SeverityHigh,
			}},
		},
	}
	if err := e.enqueueWebhooks(context.Background(), []pendingWebhook{item}, false); err == nil {
		t.Fatal("expected persistence error when outbox directory is not writable")
	}
	e.cfg.State.Path = filepath.Join(dir, "state.json")
	if err := e.enqueueWebhooks(context.Background(), []pendingWebhook{item}, false); err != nil {
		t.Fatal(err)
	}
	if len(e.pendingWebhooks) != 1 {
		t.Fatalf("expected exactly 1 queued batch after storage recovery, got %d (%+v)", len(e.pendingWebhooks), e.pendingWebhooks)
	}
}
