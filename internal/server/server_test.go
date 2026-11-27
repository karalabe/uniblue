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
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/blast"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
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
		hostScanCh:     make(chan hostScanTask, 4),
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

// TestHTTPHandlers verifies the dashboard HTML, static logo assets, JSON state
// endpoint, offline HTML export, and full/single-host rescan endpoints.
func TestHTTPHandlers(t *testing.T) {
	eng := newTestEngine()
	h := eng.Handler()

	// GET / serves the self-contained dashboard HTML.
	t.Run("index", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET / status = %d, want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Fatalf("GET / content-type = %q, want text/html", ct)
		}
		if !strings.Contains(rec.Body.String(), "UniBlue") || !strings.Contains(rec.Body.String(), "/api/v1/events/stream") {
			t.Fatalf("GET / missing expected dashboard markup")
		}
	})

	// Unknown root subpaths return 404; unknown /api/ paths return JSON 404.
	t.Run("not_found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/does-not-exist", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET /does-not-exist status = %d, want 404", rec.Code)
		}

		recAPI := httptest.NewRecorder()
		h.ServeHTTP(recAPI, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/nope", nil))
		if recAPI.Code != http.StatusNotFound {
			t.Fatalf("GET /api/v1/nope status = %d, want 404", recAPI.Code)
		}
		var apiErr apiError
		if err := json.Unmarshal(recAPI.Body.Bytes(), &apiErr); err != nil || apiErr.Error != "not_found" {
			t.Fatalf("expected JSON not_found error, got %q (%v)", recAPI.Body.String(), err)
		}
	})

	// Embedded theme-specific SVG logos are served with image/svg+xml.
	for _, path := range []string{"/assets/logo-light.svg", "/assets/logo-dark.svg"} {
		t.Run("asset_"+path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080"+path, nil))
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

	// GET /api/v1/state returns the live StateSnapshot JSON.
	t.Run("state", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/state", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/state status = %d, want 200", rec.Code)
		}
		var got StateSnapshot
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode /api/v1/state: %v", err)
		}
		if got.Site != "default" || got.EventMode != "poll-5s" {
			t.Fatalf("unexpected state: %+v", got)
		}
	})

	// GET /api/v1/health returns lightweight liveness and watchdog status.
	t.Run("health", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/health", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/health status = %d, want 200", rec.Code)
		}
		var got HealthResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode /api/v1/health: %v", err)
		}
		if got.Status != "ok" || got.Site != "default" || got.EventMode != "poll-5s" {
			t.Fatalf("unexpected health: %+v", got)
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

	// POST /api/v1/scans and POST /api/v1/hosts/{id}/scan queue full or single-host
	// scans and reject unknown hosts with JSON 404.
	t.Run("scans", func(t *testing.T) {
		// Full rescan
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/scans", nil))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("POST /api/v1/scans status = %d, want 202", rec.Code)
		}
		select {
		case <-eng.fullRescanCh:
		default:
			t.Fatalf("expected full rescan signal to be queued")
		}

		// Known host rescan via /api/v1/hosts/{id}/scan (by IP)
		recHost := httptest.NewRecorder()
		h.ServeHTTP(recHost, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/hosts/192.0.2.10/scan", nil))
		if recHost.Code != http.StatusAccepted {
			t.Fatalf("POST /api/v1/hosts/192.0.2.10/scan status = %d, want 202", recHost.Code)
		}
		select {
		case task := <-eng.hostScanCh:
			if task.client.IP != "192.0.2.10" {
				t.Fatalf("queued host IP = %q, want 192.0.2.10", task.client.IP)
			}
		default:
			t.Fatalf("expected host rescan to be queued")
		}

		// Known host rescan via POST /api/v1/scans body (by MAC)
		recHostBody := httptest.NewRecorder()
		h.ServeHTTP(recHostBody, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/scans", strings.NewReader(`{"host":"aa:bb:cc:dd:ee:01"}`)))
		if recHostBody.Code != http.StatusAccepted {
			t.Fatalf("POST /api/v1/scans {host:MAC} status = %d, want 202", recHostBody.Code)
		}
		select {
		case task := <-eng.hostScanCh:
			if task.client.MAC != "aa:bb:cc:dd:ee:01" {
				t.Fatalf("queued host MAC = %q, want aa:bb:cc:dd:ee:01", task.client.MAC)
			}
		default:
			t.Fatalf("expected host rescan via JSON body to be queued")
		}

		// Unknown host rescan returns JSON 404
		recUnknown := httptest.NewRecorder()
		h.ServeHTTP(recUnknown, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/v1/hosts/192.0.2.99/scan", nil))
		if recUnknown.Code != http.StatusNotFound {
			t.Fatalf("POST /api/v1/hosts/192.0.2.99/scan status = %d, want 404", recUnknown.Code)
		}
		var apiErr apiError
		if err := json.Unmarshal(recUnknown.Body.Bytes(), &apiErr); err != nil || apiErr.Error != "not_found" {
			t.Fatalf("expected JSON not_found error, got %q", recUnknown.Body.String())
		}
	})
}

// TestEventsSSE verifies that /api/v1/events/stream sends an initial keepalive
// frame and streams live Engine events to subscribed clients.
func TestEventsSSE(t *testing.T) {
	eng := newTestEngine()
	srv := httptest.NewServer(eng.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /api/v1/events/stream: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/events/stream status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("GET /api/v1/events/stream content-type = %q, want text/event-stream", ct)
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

// TestWiredUnplugEvictsFindingsImmediatelyAndReplugRescans verifies that when a
// wired client's switch access port drops link, UniBlue immediately removes the
// client and its cached vulnerabilities even while UniFi still caches the client,
// publishes the clean snapshot before notifying SSE subscribers, and queues a
// fresh security scan when the cable is plugged back in.
func TestWiredUnplugEvictsFindingsImmediatelyAndReplugRescans(t *testing.T) {
	const (
		swMAC  = "11:22:33:44:55:66"
		clMAC  = "aa:bb:cc:dd:ee:42"
		clIP   = "192.0.2.42"
		portNo = 7
	)
	makeSnap := func(portUp bool, includeClient bool) *unifi.Snapshot {
		s := &unifi.Snapshot{
			Site:           "default",
			ControllerType: "unifi-os",
			Networks: []unifi.Network{
				{ID: "net-iot", Name: "IoT", VLAN: "20", Subnet: "192.0.2.0/24", ZoneName: "IoT", IsolationEnabled: true},
			},
			Devices: []unifi.Device{
				{
					MAC:   swMAC,
					Name:  "USW-Main",
					Model: "USW-Pro-24",
					Type:  "usw",
					IP:    "192.0.2.2",
					Ports: []unifi.SwitchPort{
						{
							PortIdx:           portNo,
							Name:              "Ventilation",
							Up:                portUp,
							Enabled:           true,
							NativeNetworkName: "IoT",
							TaggedVLANMgmt:    "block_all",
						},
					},
				},
			},
		}
		if includeClient {
			s.Clients = []unifi.Client{
				{
					MAC:         clMAC,
					Name:        "ventilation-unit",
					IP:          clIP,
					NetworkID:   "net-iot",
					NetworkName: "IoT",
					VLAN:        "20",
					IsWired:     true,
					SwitchMAC:   swMAC,
					SwitchPort:  portNo,
				},
			}
		}
		return s
	}

	initSnap := makeSnap(true, true)
	hvacClient := initSnap.Clients[0]
	eng := &Engine{
		cfg:            &config.Config{},
		eventMode:      "poll-5s",
		snap:           initSnap,
		profilesByMAC:  map[string]probe.HostProfile{},
		findingsByMAC:  map[string][]checks.Finding{},
		missingClients: map[string]missingClient{},
		lastPorts:      snapshotPortStates(initSnap, config.NetworkConfig{}),
		anomalies:      newAnomalyTracker(),
		lastClasses:    map[string]classify.Result{},
		fullRescanCh:   make(chan string, 1),
		hostScanCh:     make(chan hostScanTask, 8),
		subscribers:    map[chan LiveEvent]struct{}{},
	}
	now := time.Now().UTC()
	eng.profilesByMAC[clMAC] = probe.HostProfile{
		Client:    hvacClient,
		OpenPorts: []int{56747},
		ScannedAt: now,
	}
	eng.findingsByMAC[clMAC] = []checks.Finding{
		{
			CheckID:           "UB-2026-0039",
			Title:             "Ventilation API exposed",
			BaseSeverity:      checks.SeverityHigh,
			EffectiveSeverity: checks.SeverityHigh,
			Client:            hvacClient,
			Port:              56747,
		},
	}
	eng.recomputeAndPublish(context.Background(), true, nil)

	before := eng.Snapshot()
	if len(before.Clients) != 1 {
		t.Fatalf("initial clients = %d, want 1", len(before.Clients))
	}
	hasCheckBefore := false
	for _, f := range before.Report.Findings {
		if f.CheckID == "UB-2026-0039" {
			hasCheckBefore = true
		}
	}
	if !hasCheckBefore {
		t.Fatalf("expected initial report to contain UB-2026-0039")
	}

	// Subscribe to SSE before unplugging so we verify snapshot freshness on event receipt.
	subCh, unsub := eng.Subscribe()
	defer unsub()

	// Step 1: Unplug Ethernet cable (port goes DOWN, but UniFi still caches the client).
	unplugSnap := makeSnap(false, true)
	toScan := eng.applySnapshotDelta(context.Background(), unplugSnap, now.Add(5*time.Second))
	if len(toScan) != 0 {
		t.Fatalf("unplug queued %d scans, want 0", len(toScan))
	}

	// Drain SSE events and verify e.Snapshot() already reflects zero vulnerabilities.
	var sawLeft, sawPortDown bool
	for {
		select {
		case ev := <-subCh:
			snapAtEvent := eng.Snapshot()
			for _, f := range snapAtEvent.Report.Findings {
				if f.CheckID == "UB-2026-0039" {
					t.Fatalf("SSE event %q arrived while stale UB-2026-0039 was still in Snapshot()", ev.Type)
				}
			}
			if ev.Type == "client_left" {
				sawLeft = true
			}
			if ev.Type == "port_link_down" {
				sawPortDown = true
			}
		default:
			goto drainedUnplug
		}
	}
drainedUnplug:
	if !sawLeft || !sawPortDown {
		t.Fatalf("expected client_left (%v) and port_link_down (%v) on unplug", sawLeft, sawPortDown)
	}
	afterUnplug := eng.Snapshot()
	if len(afterUnplug.Clients) != 0 {
		t.Fatalf("clients after unplug = %d, want 0", len(afterUnplug.Clients))
	}
	if len(eng.profilesByMAC) != 0 || len(eng.findingsByMAC) != 0 {
		t.Fatalf("expected profilesByMAC (%d) and findingsByMAC (%d) to be evicted immediately", len(eng.profilesByMAC), len(eng.findingsByMAC))
	}

	// Step 2: Plug Ethernet cable back in (port comes UP, client still cached by UniFi).
	replugSnap := makeSnap(true, true)
	toScan = eng.applySnapshotDelta(context.Background(), replugSnap, now.Add(15*time.Second))
	if len(toScan) != 1 || toScan[0].client.IP != clIP || !toScan[0].retryOnEmpty {
		t.Fatalf("replug toScan = %+v, want 1 task for %s with retryOnEmpty=true", toScan, clIP)
	}

	var sawJoined, sawPortUp bool
	for {
		select {
		case ev := <-subCh:
			if ev.Type == "client_joined" && strings.Contains(ev.Summary, "queuing security scan") {
				sawJoined = true
			}
			if ev.Type == "port_link_up" {
				sawPortUp = true
			}
		default:
			goto drainedReplug
		}
	}
drainedReplug:
	if !sawJoined || !sawPortUp {
		t.Fatalf("expected client_joined (%v) and port_link_up (%v) on replug", sawJoined, sawPortUp)
	}
	afterReplug := eng.Snapshot()
	if len(afterReplug.Clients) != 1 || afterReplug.Clients[0].LastScannedAt != nil {
		t.Fatalf("expected reconnected client to appear as unassessed pending scan, got %+v", afterReplug.Clients)
	}

	// Step 3: Simulate scan completion after replug: the unchanged UB-2026-0039
	// finding returns to the live dashboard WITHOUT re-firing a false finding_new
	// alert (carried forward across transient offline unplug), while a genuinely
	// new exposure (UB-0001) DOES fire finding_new.
	eng.mu.Lock()
	eng.profilesByMAC[clMAC] = probe.HostProfile{Client: hvacClient, OpenPorts: []int{23, 56747}, ScannedAt: now.Add(20 * time.Second)}
	eng.findingsByMAC[clMAC] = []checks.Finding{
		{
			CheckID:           "UB-2026-0039",
			Title:             "Ventilation API exposed",
			BaseSeverity:      checks.SeverityHigh,
			EffectiveSeverity: checks.SeverityHigh,
			Client:            hvacClient,
			Port:              56747,
		},
		{
			CheckID:           "UB-0001",
			Title:             "Cleartext Telnet Service",
			BaseSeverity:      checks.SeverityHigh,
			EffectiveSeverity: checks.SeverityHigh,
			Client:            hvacClient,
			Port:              23,
		},
	}
	eng.mu.Unlock()
	eng.recomputeAndPublish(context.Background(), false, nil)

	var sawDuplicateOld, sawGenuineNew bool
	for {
		select {
		case ev := <-subCh:
			if ev.Type == "finding_new" && strings.Contains(ev.Summary, "UB-2026-0039") {
				sawDuplicateOld = true
			}
			if ev.Type == "finding_new" && strings.Contains(ev.Summary, "UB-0001") {
				sawGenuineNew = true
			}
		default:
			goto drainedFinding
		}
	}
drainedFinding:
	if sawDuplicateOld {
		t.Fatalf("did not expect duplicate finding_new for unchanged UB-2026-0039 after brief unplug/replug")
	}
	if !sawGenuineNew {
		t.Fatalf("expected finding_new event for genuinely new UB-0001 after replug scan")
	}

	// Step 4: Verify rapid link-up while client was still in prevClients also queues rescan.
	eng.mu.Lock()
	p := eng.lastPorts[portKey(swMAC, portNo)]
	p.Up = false
	eng.lastPorts[portKey(swMAC, portNo)] = p
	eng.mu.Unlock()
	toScan = eng.applySnapshotDelta(context.Background(), makeSnap(true, true), now.Add(30*time.Second))
	if len(toScan) != 1 || toScan[0].client.IP != clIP {
		t.Fatalf("rapid link-up toScan = %+v, want rescan for %s", toScan, clIP)
	}
}

// TestWirelessLeaveGraceEvictsProfileAndFindings verifies that wireless clients
// still honor defaultLeaveGrace to prevent sleep/roam flapping, and evict both
// cached profiles and cached findings once the grace period expires.
func TestWirelessLeaveGraceEvictsProfileAndFindings(t *testing.T) {
	const (
		clMAC = "aa:bb:cc:dd:ee:99"
		clIP  = "192.0.2.99"
	)
	wifiClient := unifi.Client{
		MAC:         clMAC,
		Name:        "phone-1",
		IP:          clIP,
		NetworkName: "Default",
		IsWired:     false,
	}
	initSnap := &unifi.Snapshot{
		Site:    "default",
		Clients: []unifi.Client{wifiClient},
	}
	eng := &Engine{
		cfg:            &config.Config{},
		eventMode:      "poll-5s",
		snap:           initSnap,
		profilesByMAC:  map[string]probe.HostProfile{clMAC: {Client: wifiClient, OpenPorts: []int{80}}},
		findingsByMAC:  map[string][]checks.Finding{clMAC: {{CheckID: "UB-0001", Client: wifiClient, EffectiveSeverity: checks.SeverityMedium}}},
		missingClients: map[string]missingClient{},
		lastPorts:      map[string]portLiveState{},
		anomalies:      newAnomalyTracker(),
		lastClasses:    map[string]classify.Result{},
		prevRiskState:  &risk.State{ScoringVersion: risk.CurrentScoringVersion, Findings: map[string]checks.Severity{}},
		fullRescanCh:   make(chan string, 1),
		hostScanCh:     make(chan hostScanTask, 4),
		subscribers:    map[chan LiveEvent]struct{}{},
	}

	t0 := time.Now().UTC()
	// Absent at t0: should enter missingClients grace window without eviction.
	eng.applySnapshotDelta(context.Background(), &unifi.Snapshot{Site: "default"}, t0)
	if _, ok := eng.missingClients[clMAC]; !ok {
		t.Fatalf("expected wireless client to enter missingClients grace window")
	}
	if _, ok := eng.findingsByMAC[clMAC]; !ok {
		t.Fatalf("expected wireless findings to remain cached during grace window")
	}

	// Still absent after defaultLeaveGrace: both profile and findings must be evicted.
	eng.applySnapshotDelta(context.Background(), &unifi.Snapshot{Site: "default"}, t0.Add(defaultLeaveGrace+time.Second))
	if len(eng.profilesByMAC) != 0 || len(eng.findingsByMAC) != 0 || len(eng.missingClients) != 0 {
		t.Fatalf("expected wireless client eviction after grace: profiles=%d findings=%d missing=%d",
			len(eng.profilesByMAC), len(eng.findingsByMAC), len(eng.missingClients))
	}
}

// TestServeExitsImmediatelyWithActiveSSE verifies that cancelling the server
// context (as on Ctrl-C) immediately terminates open SSE streams and shuts down
// Serve without blocking on the graceful shutdown timeout.
func TestServeExitsImmediatelyWithActiveSSE(t *testing.T) {
	// Reserve an ephemeral localhost port then release it for Engine.Serve.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ephemeral port: %v", err)
	}
	addr := probeLn.Addr().String()
	_ = probeLn.Close()

	eng := newTestEngine()
	eng.opts.ListenAddr = addr
	eng.logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- eng.Serve(ctx)
	}()

	// Wait until /api/v1/events/stream accepts connections and emits the initial SSE comment.
	var resp *http.Response
	for range 40 {
		resp, err = http.Get("http://" + addr + "/api/v1/events/stream")
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect /api/v1/events/stream: %v", err)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	if line, err := br.ReadString('\n'); err != nil || !strings.HasPrefix(line, ": connected") {
		t.Fatalf("unexpected initial SSE line %q (err=%v)", line, err)
	}

	// Simulate Ctrl-C while the browser SSE connection is still open.
	start := time.Now()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("Serve took %s to exit with open SSE stream, want <500ms", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Serve hung on shutdown while SSE stream was open")
	}
}

// TestScanProgressBroadcastWithoutActivitySpam verifies that live scan progress
// updates are exposed in Snapshot().ScanProgress and pushed over SSE to wake UI
// clients without cluttering the persisted Activity event history.
func TestScanProgressBroadcastWithoutActivitySpam(t *testing.T) {
	eng := newTestEngine()
	subCh, unsub := eng.Subscribe()
	defer unsub()

	eng.setScanProgress(&ScanProgress{
		Phase:       "probing",
		Label:       "Probing devices for open ports (3 of 10)…",
		Completed:   3,
		Total:       10,
		CurrentHost: "workstation-1",
		Percent:     28,
		Initial:     true,
	})

	snap := eng.Snapshot()
	if !snap.Scanning || snap.ScanProgress == nil {
		t.Fatalf("expected Scanning=true and non-nil ScanProgress, got %+v", snap)
	}
	if snap.ScanProgress.Phase != "probing" || snap.ScanProgress.Completed != 3 || snap.ScanProgress.Percent != 28 {
		t.Fatalf("unexpected ScanProgress: %+v", snap.ScanProgress)
	}
	if len(snap.Events) != 0 {
		t.Fatalf("expected transient scan_progress not to pollute Activity events, got %d events", len(snap.Events))
	}

	select {
	case ev := <-subCh:
		if ev.Type != "scan_progress" {
			t.Fatalf("SSE event type = %q, want scan_progress", ev.Type)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected transient scan_progress SSE notification")
	}

	eng.setScanProgress(nil)
	if after := eng.Snapshot(); after.ScanProgress != nil {
		t.Fatalf("expected ScanProgress to clear after setScanProgress(nil), got %+v", after.ScanProgress)
	}
}

// TestAPIV1EndpointsAndSSEReplay verifies the focused /api/v1/* read endpoints
// (health, findings, cves, hosts, hosts/{id}, isolation, events JSON filters)
// and Last-Event-ID replay on /api/v1/events/stream.
func TestAPIV1EndpointsAndSSEReplay(t *testing.T) {
	eng := NewDemoEngineForTest(t)
	eng.mu.Lock()
	eng.lastScanError = "unifi unreachable"
	eng.current.LastScanError = "unifi unreachable"
	eng.mu.Unlock()

	h := eng.Handler()

	// 1. GET /api/v1/health reflects degraded status on scan error.
	recHealth := httptest.NewRecorder()
	h.ServeHTTP(recHealth, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/health", nil))
	if recHealth.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/health = %d, want 200", recHealth.Code)
	}
	var health HealthResponse
	if err := json.Unmarshal(recHealth.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health.Status != "degraded" || health.LastScanError != "unifi unreachable" || health.ClientCount == 0 {
		t.Fatalf("unexpected health response: %+v", health)
	}

	// 2. GET /api/v1/findings supports severity filtering and rejects invalid severity with JSON 400.
	recFind := httptest.NewRecorder()
	h.ServeHTTP(recFind, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/findings?severity=high", nil))
	if recFind.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/findings?severity=high = %d, want 200", recFind.Code)
	}
	var findBody struct {
		Findings []checks.Finding `json:"findings"`
	}
	if err := json.Unmarshal(recFind.Body.Bytes(), &findBody); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if len(findBody.Findings) == 0 {
		t.Fatal("expected demo high+ findings")
	}
	for _, f := range findBody.Findings {
		if f.EffectiveSeverity < checks.SeverityHigh {
			t.Fatalf("finding %s has severity %s < high", f.CheckID, f.EffectiveSeverity)
		}
	}
	if strings.Contains(recFind.Body.String(), `"UniFiActions"`) || strings.Contains(recFind.Body.String(), `"Summary"`) {
		t.Fatalf("expected snake_case remediation JSON tags, got PascalCase in: %s", recFind.Body.String()[:min(300, recFind.Body.Len())])
	}

	recBadSev := httptest.NewRecorder()
	h.ServeHTTP(recBadSev, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/findings?severity=bogus", nil))
	if recBadSev.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid severity, got %d", recBadSev.Code)
	}

	// 3. GET /api/v1/hosts and GET /api/v1/hosts/{id} resolve by ID, MAC, and IP.
	recHosts := httptest.NewRecorder()
	h.ServeHTTP(recHosts, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/hosts?state=exposed", nil))
	if recHosts.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/hosts?state=exposed = %d, want 200", recHosts.Code)
	}
	var hostsBody struct {
		Hosts []Entity `json:"hosts"`
	}
	if err := json.Unmarshal(recHosts.Body.Bytes(), &hostsBody); err != nil {
		t.Fatalf("decode hosts: %v", err)
	}
	if len(hostsBody.Hosts) == 0 {
		t.Fatal("expected exposed demo hosts")
	}
	sample := hostsBody.Hosts[0]
	for _, lookup := range []string{sample.ID, sample.MAC, sample.IP} {
		if lookup == "" {
			continue
		}
		recOne := httptest.NewRecorder()
		h.ServeHTTP(recOne, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/hosts/"+lookup, nil))
		if recOne.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/hosts/%s = %d, want 200 (%s)", lookup, recOne.Code, recOne.Body.String())
		}
		var got Entity
		if err := json.Unmarshal(recOne.Body.Bytes(), &got); err != nil || got.ID != sample.ID {
			t.Fatalf("lookup %q returned %+v (err=%v), want ID %q", lookup, got, err, sample.ID)
		}
	}

	// 4. GET /api/v1/cves and GET /api/v1/isolation return valid non-null arrays.
	recCVE := httptest.NewRecorder()
	h.ServeHTTP(recCVE, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/cves?kev=true", nil))
	if recCVE.Code != http.StatusOK || !strings.Contains(recCVE.Body.String(), `"exact":`) {
		t.Fatalf("GET /api/v1/cves?kev=true = %d %s", recCVE.Code, recCVE.Body.String())
	}

	recIso := httptest.NewRecorder()
	h.ServeHTTP(recIso, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/isolation?verdict=violation", nil))
	if recIso.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/isolation?verdict=violation = %d, want 200", recIso.Code)
	}
	var iso risk.IsolationMatrix
	if err := json.Unmarshal(recIso.Body.Bytes(), &iso); err != nil {
		t.Fatalf("decode isolation: %v", err)
	}
	for _, cell := range iso.Cells {
		if cell.Verdict != risk.IsolationViolation {
			t.Fatalf("unexpected non-violation cell %+v", cell)
		}
	}

	// 5. GET /api/v1/events returns JSON with since_id/type/limit filters, and
	// GET /api/v1/events/stream replays missed events via Last-Event-ID.
	eng.emit(LiveEvent{Type: "admin_activity", Severity: "medium", Summary: "ev1"})
	eng.emit(LiveEvent{Type: "policy_changed", Severity: "high", Summary: "ev2"})
	eng.emit(LiveEvent{Type: "honeypot_hit", Severity: "high", Summary: "ev3"})

	recAllEv := httptest.NewRecorder()
	h.ServeHTTP(recAllEv, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/events?type=admin_activity,policy_changed,honeypot_hit&limit=10", nil))
	if recAllEv.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/events = %d, want 200", recAllEv.Code)
	}
	var evResp struct {
		Events []LiveEvent `json:"events"`
	}
	if err := json.Unmarshal(recAllEv.Body.Bytes(), &evResp); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	if len(evResp.Events) != 3 {
		t.Fatalf("expected 3 filtered events, got %d", len(evResp.Events))
	}
	// Newest-first: evResp.Events[2] is ev1, evResp.Events[1] is ev2, evResp.Events[0] is ev3.
	firstID := evResp.Events[2].ID

	srv := httptest.NewServer(h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reqSSE, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events/stream", nil)
	if err != nil {
		t.Fatalf("new SSE request: %v", err)
	}
	reqSSE.Header.Set("Last-Event-ID", strings.TrimSpace(strconv.FormatInt(firstID, 10)))
	respSSE, err := srv.Client().Do(reqSSE)
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	defer respSSE.Body.Close()

	br := bufio.NewReader(respSSE.Body)
	var replayed []LiveEvent
	for len(replayed) < 2 {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read replayed SSE line: %v", err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data: ") {
			var ev LiveEvent
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); err != nil {
				t.Fatalf("unmarshal replayed event: %v", err)
			}
			replayed = append(replayed, ev)
		}
	}
	if replayed[0].Summary != "ev2" || replayed[1].Summary != "ev3" {
		t.Fatalf("expected chronological replay [ev2, ev3], got [%s, %s]", replayed[0].Summary, replayed[1].Summary)
	}
}

// apiInfraTarget reads the device identity independently of transport verdict details.
type apiInfraTarget struct {
	// Target is the device name shown in the dashboard.
	Target string `json:"target"`
	// TargetID distinguishes equipment that shares a name.
	TargetID string `json:"target_id"`
	// Scope distinguishes the controller from its physical host.
	Scope string `json:"scope"`
}

// getBlastJSON exercises the authenticated HTTP router and checks its JSON envelope.
func getBlastJSON(t *testing.T, h http.Handler, path, token string, status int, dest any) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/"+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != status {
		t.Fatalf("GET %s = %d, want %d: %.200s", path, rec.Code, status, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), dest); err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return rec.Body.String()
}

// TestBlastAPI checks queue filters, payload size controls, and device aliases
// against the same published inventory that powers the dashboard.
func TestBlastAPI(t *testing.T) {
	const token = "test-blast-token"
	eng, err := NewDemoEngine(Options{APIToken: token})
	if err != nil {
		t.Fatal(err)
	}
	h := eng.Handler()
	snap := eng.Snapshot()
	type response struct {
		siteBlastResponse
		// InfraBlast selects the identity fields of each infrastructure report.
		InfraBlast []apiInfraTarget `json:"infra_blast"`
	}
	for _, opt := range []string{"", "?include_simulation=false", "?include_simulation=0", "?include_simulation=1", "?include_simulation=true", "?include_simulation=+TRUE+"} {
		var got response
		body := getBlastJSON(t, h, "blast"+opt, token, http.StatusOK, &got)
		include := opt == "?include_simulation=1" || opt == "?include_simulation=true" || opt == "?include_simulation=+TRUE+"
		if strings.Contains(body, `"simulation":`) != include || include && !reflect.DeepEqual(got.Simulation, snap.View.Blast.Simulation) ||
			got.Site != snap.Site || !got.UpdatedAt.Equal(snap.UpdatedAt) ||
			len(got.Actions) != len(snap.View.Blast.Actions) || len(got.InfraBlast) != len(snap.View.InfraBlast) ||
			len(got.Cloud) != len(snap.View.Blast.Cloud) || len(got.Exposures) != len(snap.View.Blast.Exposures) {
			t.Fatalf("incorrect snapshot or graph for %q", opt)
		}
	}
	for _, filter := range []string{"lane=fix-now", "lane=reduce-exposure", "lane=verify", "priority=+p2+", "lane=reduce-exposure&priority=p3"} {
		q, _ := url.ParseQuery(filter)
		var got response
		getBlastJSON(t, h, "blast?"+filter, token, http.StatusOK, &got)
		if len(got.Actions) == 0 {
			t.Fatalf("no matching demo action for %s", filter)
		}
		check := func(l blast.Lane, p blast.Priority) {
			t.Helper()
			if q.Has("lane") && string(l) != q.Get("lane") || q.Has("priority") && !strings.EqualFold(string(p), strings.TrimSpace(q.Get("priority"))) {
				t.Errorf("%s returned lane %q priority %q", filter, l, p)
			}
		}
		for _, a := range got.Actions {
			check(a.Lane, a.HighestTierReduced)
		}
		for _, x := range got.Exposures {
			check(x.Lane, x.Priority)
		}
	}

	const bmc = "02:11:22:00:10:05"
	var bmcActions []blast.Action
	for _, id := range []string{bmc, "host:" + bmc, "192.168.10.5", "fd00:10::5"} {
		var got response
		getBlastJSON(t, h, "blast?host="+id, token, http.StatusOK, &got)
		if len(got.Actions) == 0 || len(got.Exposures) == 0 || len(got.Cloud) != 1 || got.Cloud[0].Asset != bmc || len(got.InfraBlast) != 0 {
			t.Fatalf("incomplete or unrelated rows for %s", id)
		}
		if bmcActions == nil {
			bmcActions = got.Actions
		} else if !reflect.DeepEqual(got.Actions, bmcActions) {
			t.Errorf("alias %s selected different actions", id)
		}
		for _, x := range got.Exposures {
			if x.Asset != bmc {
				t.Errorf("%s returned unrelated exposure for %q", id, x.Asset)
			}
		}
	}
	const nas = "02:11:22:00:10:12"
	for _, tc := range []struct {
		query string
		want  []string
		other string
	}{
		{"host=192.168.10.12", []string{"act:check:NERVA-SMB-V1-ENABLED:" + nas + ":tcp/445", "act:check:NERVA-TLS-CERTIFICATE-EXPIRED:" + nas + ":tcp/443"}, bmc},
		{"host=192.168.10.5&lane=+VERIFY+", []string{"act:verify:UB-0019:" + bmc + ":udp/623", "act:verify:UB-0020:" + bmc + ":tcp/443"}, nas},
	} {
		var got response
		getBlastJSON(t, h, "blast?"+tc.query, token, http.StatusOK, &got)
		var ids []string
		for _, a := range got.Actions {
			ids = append(ids, a.ID)
			if strings.Contains(a.ID, tc.other) || strings.Contains(tc.query, "lane=") && a.Lane != blast.LaneVerify {
				t.Errorf("%s returned unrelated action %s", tc.query, a.ID)
			}
		}
		for _, want := range tc.want {
			if !slices.Contains(ids, want) {
				t.Errorf("%s missing %s in %v", tc.query, want, ids)
			}
		}
	}
	var gateway response
	getBlastJSON(t, h, "blast?host=198.51.100.42", token, http.StatusOK, &gateway)
	if len(gateway.InfraBlast) != 2 || gateway.InfraBlast[0].Scope != "Controller" || gateway.InfraBlast[1].Target != "Dream Machine SE" {
		t.Fatalf("WAN address returned scopes %+v", gateway.InfraBlast)
	}
	var unknown response
	getBlastJSON(t, h, "blast?host=missing&include_simulation=true", token, http.StatusOK, &unknown)
	if unknown.Simulation == nil || unknown.Actions == nil || unknown.Exposures == nil || unknown.Cloud == nil || unknown.InfraBlast == nil ||
		len(unknown.Actions)+len(unknown.Exposures)+len(unknown.Cloud)+len(unknown.InfraBlast) != 0 {
		t.Fatal("unknown host must return empty arrays and the requested full graph")
	}
	for _, filter := range []string{"lane=unknown", "priority=P6", "include_simulation=yes", "include_simulation=t", "include_simulation="} {
		var body apiError
		getBlastJSON(t, h, "blast?"+filter, token, http.StatusBadRequest, &body)
		if body.Error != "invalid_parameter" || body.Message == "" {
			t.Errorf("invalid %s: %+v", filter, body)
		}
	}
	for _, path := range []string{"blast", "hosts/192.168.10.5/blast"} {
		var body apiError
		getBlastJSON(t, h, path, "", http.StatusUnauthorized, &body)
		if body.Error != "unauthorized" {
			t.Errorf("unauthenticated GET %s: %+v", path, body)
		}
	}
}

// TestHostBlastAPI follows the demo's management cascade and verifies hypothetical
// fixes are local to one request, including valid actions outside the host's baseline.
func TestHostBlastAPI(t *testing.T) {
	eng, err := NewDemoEngine(Options{})
	if err != nil {
		t.Fatal(err)
	}
	h := eng.Handler()
	type response struct {
		// Site identifies the inventory that supplied these paths.
		Site string `json:"site"`
		// UpdatedAt is the publication time of the scan.
		UpdatedAt time.Time `json:"updated_at"`
		// Simulation holds reach and predecessor paths from Patient Zero.
		Simulation blast.HostSimulation `json:"simulation"`
		// RelevantActions lists the selected remediations in queue order.
		RelevantActions []blast.Action `json:"relevant_actions"`
		// InfraBlast contains infrastructure scopes for this host.
		InfraBlast []apiInfraTarget `json:"infra_blast"`
	}
	get := func(path string) response {
		t.Helper()
		var got response
		getBlastJSON(t, h, "hosts/"+path, "", http.StatusOK, &got)
		return got
	}
	const proxy = "192.168.10.20/blast"
	base := get(proxy)
	sim := base.Simulation
	if base.Site != eng.current.Site || !base.UpdatedAt.Equal(eng.current.UpdatedAt) || base.InfraBlast == nil || len(base.InfraBlast) != 0 || sim.AppliedFixes == nil || len(sim.AppliedFixes) != 0 ||
		sim.Mode != blast.ModeRealistic || sim.Host.Name != "Caddy Reverse Proxy" || sim.Host.EntryExposure != "WAN TCP/443" ||
		sim.DirectReach != 5 || sim.CascadedReach != 1 || !slices.ContainsFunc(sim.Paths, func(p blast.HostBlastPath) bool {
		return p.Hop == 2 && p.FromName == "Rack Server iDRAC" && p.Target.Name == "Rack Virtualization Server"
	}) {
		t.Fatal("missing demo proxy management cascade or snapshot metadata")
	}
	if p, w := get(proxy+"?mode=proven").Simulation, get(proxy+"?mode=worst").Simulation; p.Mode != blast.ModeProven ||
		w.Mode != blast.ModeWorstCase || p.TotalReach >= sim.TotalReach || w.TotalReach <= sim.TotalReach {
		t.Fatalf("unexpected reach across modes: proven %d, realistic %d, worst %d", p.TotalReach, sim.TotalReach, w.TotalReach)
	}
	cuts := []string{"act:vlan-ingress:net-home", "act:check:NERVA-SMB-V1-ENABLED:02:11:22:00:10:12:tcp/445"}
	const other = "act:vlan-egress:net-home->net-iot"
	q := url.Values{"fix": {cuts[0], cuts[1], other}}
	fixed := get(proxy + "?" + q.Encode())
	if fixed.Simulation.TotalReach != sim.TotalReach-3 || !slices.Equal(fixed.Simulation.RelevantFixes, sim.RelevantFixes) ||
		slices.Contains(sim.RelevantFixes, other) || !reflect.DeepEqual(get(proxy), base) {
		t.Fatalf("reach after both cuts = %d, baseline = %d", fixed.Simulation.TotalReach, sim.TotalReach)
	}
	var wantIDs, gotIDs []string
	for _, a := range eng.current.View.Blast.Actions {
		if slices.Contains(sim.RelevantFixes, a.ID) || a.ID == other {
			wantIDs = append(wantIDs, a.ID)
		}
	}
	for _, a := range fixed.RelevantActions {
		gotIDs = append(gotIDs, a.ID)
	}
	if !slices.Equal(gotIDs, wantIDs) || !slices.Contains(gotIDs, other) {
		t.Fatalf("relevant actions %v, want %v", gotIDs, wantIDs)
	}
	if got := get(proxy + "?fix=act:wan-pf:pf-https").Simulation.Host.EntryExposure; got != "Local LAN" {
		t.Errorf("entry after closing proxy forward = %q", got)
	}
	for _, id := range []string{"dev:02:aa:bb:00:00:01", "02:aa:bb:00:00:01", "192.168.1.1", "198.51.100.42"} {
		gw := get(id + "/blast")
		if gw.Simulation.Host.Name != "Dream Machine SE" || gw.Simulation.DirectReach == 0 || gw.Simulation.CascadedReach == 0 ||
			len(gw.InfraBlast) != 2 || gw.InfraBlast[0].Scope != "Controller" || gw.InfraBlast[1].Scope != "Gateway" || gw.InfraBlast[1].TargetID != gw.Simulation.Host.ID {
			t.Errorf("gateway lookup %s did not return device paths and scope", id)
		}
	}
	for _, tc := range []struct {
		path, code string
		status     int
	}{
		{proxy + "?mode=typo", "invalid_parameter", http.StatusBadRequest},
		{proxy + "?fix=", "invalid_parameter", http.StatusBadRequest},
		{proxy + "?fix=%zz", "invalid_parameter", http.StatusBadRequest},
		{proxy + "?fix=act:wan-pf:pf-https&fix=%zz", "invalid_parameter", http.StatusBadRequest},
		{proxy + "?fix=act:typo", "invalid_parameter", http.StatusBadRequest},
		{proxy + "?fix=a,b", "invalid_parameter", http.StatusBadRequest},
		{proxy + "?fix=act:wan-pf:pf-https&fix=", "invalid_parameter", http.StatusBadRequest},
		{proxy + "?fix=act:port-tags:02:aa:bb:00:00:02:1", "invalid_parameter", http.StatusBadRequest},
		{"missing/blast", "not_found", http.StatusNotFound},
	} {
		var body apiError
		getBlastJSON(t, h, "hosts/"+tc.path, "", tc.status, &body)
		if body.Error != tc.code || body.Message == "" {
			t.Error(body)
		}
	}
	eng.current.View.Blast.Simulation = nil
	var missing apiError
	getBlastJSON(t, h, "hosts/"+proxy, "", http.StatusNotFound, &missing)
	if missing.Error != "not_found" || !strings.Contains(missing.Message, "simulation unavailable") {
		t.Errorf("known host without graph: %+v", missing)
	}
}

// TestHostBlastWithoutMAC checks both stable controller IDs and IPv6-only inventory
// when a client has no hardware address to link its drawer to the simulation.
func TestHostBlastWithoutMAC(t *testing.T) {
	clients := []unifi.Client{
		{ID: "client-A", IPv6: []string{"2001:DB8::A", "2001:DB8::1A"}},
		{IPv6: []string{"2001:DB8::B"}},
	}
	eng := newTestEngine()
	report := blast.Evaluate(blast.Input{Snapshot: &unifi.Snapshot{Clients: clients}})
	eng.current.View = &PresentationModel{Blast: &report}
	for _, cl := range clients {
		eng.current.Clients = append(eng.current.Clients, ClientView{Client: cl})
	}
	h := eng.Handler()
	const drawerA, drawerB = "host:ip/2001:DB8::A", "host:ip/2001:DB8::B"
	for _, tc := range []struct{ id, key, entity string }{
		{"2001:db8::a", "client-A", drawerA}, {"2001:db8::1a", "client-A", drawerA},
		{"client-A", "client-A", drawerA}, {drawerA, "client-A", drawerA},
		{"2001:db8::b", "2001:DB8::B", drawerB}, {drawerB, "2001:DB8::B", drawerB},
	} {
		var site blast.Report
		getBlastJSON(t, h, "blast?host="+tc.id, "", http.StatusOK, &site)
		if len(site.Cloud) != 1 || site.Cloud[0].Asset != tc.key {
			t.Errorf("cloud rows for %q = %+v", tc.id, site.Cloud)
		}
		var host struct {
			// Simulation identifies the selected asset independently of its drawer ID.
			Simulation blast.HostSimulation `json:"simulation"`
		}
		getBlastJSON(t, h, "hosts/"+url.PathEscape(tc.id)+"/blast", "", http.StatusOK, &host)
		if n := host.Simulation.Host; n.ID != tc.key || n.EntityID != tc.entity {
			t.Errorf("simulation for %q selected %q with drawer %q", tc.id, n.ID, n.EntityID)
		}
	}
}

// TestBlastOfflineForward checks that an offline backend can be found through either report list.
func TestBlastOfflineForward(t *testing.T) {
	const backend = "192.0.2.42"
	eng := newTestEngine()
	in := blast.Input{Snapshot: &unifi.Snapshot{
		PortForwards:     []unifi.PortForward{{ID: "offline", Enabled: true, Proto: "tcp", DstPort: "8443", FwdIP: backend, FwdPort: "8443"}},
		SecuritySettings: &unifi.SiteSecuritySettings{UPnPEnabled: true},
	}}
	report := blast.Evaluate(in)
	eng.current.View = &PresentationModel{Blast: &blast.Report{Exposures: report.Exposures}}
	h := eng.Handler()
	get := func() blast.Report {
		var got blast.Report
		getBlastJSON(t, h, "blast?host=::ffff:192.0.2.42", "", http.StatusOK, &got)
		return got
	}
	if got := get(); !slices.ContainsFunc(got.Exposures, func(x blast.Exposure) bool { return x.Asset == backend && x.Entry == blast.Internet }) {
		t.Fatalf("missing forwarded backend in exposures: %+v", got.Exposures)
	}
	eng.current.View.Blast = &blast.Report{Actions: report.Actions}
	got := get()
	for _, want := range []string{"act:wan-pf:offline", "act:verify:upnp-leases:site"} {
		if !slices.ContainsFunc(got.Actions, func(a blast.Action) bool { return a.ID == want }) {
			t.Errorf("missing %s for offline backend", want)
		}
	}
}

// TestBlastAPIEgressTargets checks that the seventh sensor is still covered
// after the ranking display has filled its six asset chips.
func TestBlastAPIEgressTargets(t *testing.T) {
	const network = "sensors"
	snap := &unifi.Snapshot{
		Networks: []unifi.Network{{ID: network, Name: network, ZoneName: network}},
		FirewallPolicies: []unifi.FirewallPolicy{{Enabled: true, Action: "ALLOW", Protocol: "all", IPVersion: "both",
			Source:      unifi.PolicyEndpoint{ZoneName: network, AnyTarget: true, AnyPort: true},
			Destination: unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true}}},
	}
	eng := newTestEngine()
	for i := 1; i <= 7; i++ {
		cl := unifi.Client{ID: "sensor-" + strconv.Itoa(i), IP: "192.0.2." + strconv.Itoa(i), NetworkID: network}
		snap.Clients = append(snap.Clients, cl)
		eng.current.Clients = append(eng.current.Clients, ClientView{Client: cl})
	}
	report := blast.Evaluate(blast.Input{Snapshot: snap, NetCfg: config.NetworkConfig{
		IsolationPolicy: config.IsolationIntent{IoTVLANs: []string{network}},
	}})
	eng.current.View = &PresentationModel{Blast: &report}
	h := eng.Handler()
	var got blast.Report
	getBlastJSON(t, h, "blast?host=192.0.2.7&lane=reduce-exposure", "", http.StatusOK, &got)
	const cut = "act:vlan-egress:sensors->internet"
	if !slices.ContainsFunc(got.Actions, func(a blast.Action) bool {
		return a.ID == cut && len(a.AffectedAssets) == 6 && !slices.Contains(a.AffectedAssets, "sensor-7")
	}) {
		t.Fatalf("seventh sensor's actions = %+v", got.Actions)
	}
	var host struct {
		// Simulation reports the effect of applying the VLAN egress control.
		Simulation blast.HostSimulation `json:"simulation"`
	}
	getBlastJSON(t, h, "hosts/sensor-7/blast?fix="+url.QueryEscape(cut), "", http.StatusOK, &host)
	if host.Simulation.Host.InternetState != "local-only (policy)" || !slices.Equal(host.Simulation.AppliedFixes, []string{cut}) {
		t.Fatalf("egress cut on seventh sensor = %+v", host.Simulation)
	}
}

// TestBlastAPIEdgeless checks the graph produced for a lone host and the API
// representation of snapshots whose empty edge list was never initialized.
func TestBlastAPIEdgeless(t *testing.T) {
	eng := newTestEngine()
	report := blast.Evaluate(blast.Input{Snapshot: eng.snap})
	if report.Simulation == nil || report.Simulation.Edges == nil || len(report.Simulation.Edges) != 0 {
		t.Fatalf("single-host graph = %+v", report.Simulation)
	}
	report.Simulation.Edges = nil
	eng.current.View = &PresentationModel{Blast: &report}
	var got blast.Report
	getBlastJSON(t, eng.Handler(), "blast?include_simulation=TRUE", "", http.StatusOK, &got)
	if got.Simulation == nil || got.Simulation.Edges == nil || len(got.Simulation.Edges) != 0 || report.Simulation.Edges != nil {
		t.Fatalf("edgeless graph = %+v, stored edges = %#v", got.Simulation, report.Simulation.Edges)
	}
}

// TestHostBlastCloudKey distinguishes a dedicated controller from identically named equipment.
func TestHostBlastCloudKey(t *testing.T) {
	d := unifi.Device{ID: "console-id", MAC: "02:00:00:00:00:01", Name: "Cloud Key", IP: "192.0.2.1", Type: "uck"}
	sw := unifi.Device{ID: "switch-id", MAC: "02:00:00:00:00:02", Name: d.Name, IP: "192.0.2.2", Type: "usw"}
	in := blast.Input{Snapshot: &unifi.Snapshot{Devices: []unifi.Device{d, sw}}}
	eng := newTestEngine()
	eng.current.View = BuildPresentationModel(in.Snapshot, risk.Report{}, nil, nil, nil, nil, nil)
	AttachBlast(eng.current.View, blast.Evaluate(in), blast.EvaluateAllInfra(in))
	h := eng.Handler()
	for _, id := range []string{d.ID, d.IP, d.MAC, devEntityID(d.MAC)} {
		var got struct {
			// InfraBlast includes the Network application hosted on this console.
			InfraBlast []apiInfraTarget `json:"infra_blast"`
		}
		getBlastJSON(t, h, "hosts/"+id+"/blast", "", http.StatusOK, &got)
		if len(got.InfraBlast) != 1 || got.InfraBlast[0].Scope != "Controller" || got.InfraBlast[0].Target != "Network controller" {
			t.Errorf("Cloud Key alias %s returned %+v", id, got.InfraBlast)
		}
	}
	var got siteBlastResponse
	getBlastJSON(t, h, "blast?host="+sw.ID, "", http.StatusOK, &got)
	if len(got.InfraBlast) != 1 || got.InfraBlast[0].Scope != "Switch" {
		t.Errorf("switch sharing the controller name returned %+v", got.InfraBlast)
	}

	vm := unifi.Client{ID: "vm-id", IP: "192.0.2.3", Name: d.Name}
	in.ControllerHost = vm.IP
	in.Snapshot.Clients = []unifi.Client{vm}
	eng.current.Clients = []ClientView{{Client: vm}}
	AttachBlast(eng.current.View, blast.Evaluate(in), blast.EvaluateAllInfra(in))
	getBlastJSON(t, h, "hosts/"+vm.ID+"/blast", "", http.StatusOK, &got)
	if len(got.InfraBlast) != 1 || got.InfraBlast[0].Scope != "Controller" || got.InfraBlast[0].HostedOnID != vm.ID {
		t.Errorf("controller VM returned %+v", got.InfraBlast)
	}
}

// TestDashboardSimulationControls checks the controls shared by the live and offline dashboards.
func TestDashboardSimulationControls(t *testing.T) {
	html := string(dashboardHTML)
	for _, s := range []string{
		`data-action="checkup-page"`, `data-action="checkup-lane"`, "const checkupPageSize = 5",
		`let blastMode = "realistic"`, `<select id="blast-device"`, `blastControl("mode", "proven", "Proven"`,
		`blastControl("mode", "realistic", "Realistic"`, `blastControl("mode", "worst", "Worst-Case"`,
		"For this device", "All simulatable", "WAN Gateway",
	} {
		if !strings.Contains(html, s) {
			t.Errorf("missing %s", s)
		}
	}
	if strings.Contains(html, "nb-br") {
		t.Error("obsolete simulator badge is still referenced")
	}
	legend, canvas := strings.Index(html, `<div class="br-legend"`), strings.Index(html, `<div class="br-map"`)
	if legend < 0 || canvas < legend {
		t.Fatal("map legend must precede the canvas")
	}
}

// TestDashboardHeaderAndServiceChips protects the space reserved for signed-in
// controls and the readable label shared by service tags and the device drawer.
func TestDashboardHeaderAndServiceChips(t *testing.T) {
	html := string(dashboardHTML)
	for _, rule := range []string{
		"@media (max-width: 1240px)", ".nav-pills { order: 3; width: 100%;",
		".hdr-r .status-pill { min-width: 0; max-width: 100%; }",
		"#status-lbl { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }",
		"flex: 0 1 420px;", `if (lbl.includes("ssh-key-accepted")) return "SSH key invited" + suffix;`,
	} {
		if !strings.Contains(html, rule) {
			t.Errorf("dashboard missing %q", rule)
		}
	}
}
