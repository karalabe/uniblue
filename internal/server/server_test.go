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
	"strings"
	"testing"
	"time"

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
		case task := <-eng.hostScanCh:
			if task.client.IP != "192.0.2.10" {
				t.Fatalf("queued host IP = %q, want 192.0.2.10", task.client.IP)
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

// TestEventsSSE verifies that /api/events sends an initial keepalive frame and
// streams live Engine events to subscribed clients.
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

	// Step 3: Simulate scan completion restoring the finding; verify finding_new fires.
	eng.mu.Lock()
	eng.profilesByMAC[clMAC] = probe.HostProfile{Client: hvacClient, OpenPorts: []int{56747}, ScannedAt: now.Add(20 * time.Second)}
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
	eng.mu.Unlock()
	eng.recomputeAndPublish(context.Background(), false, nil)

	var sawFindingNew bool
	for {
		select {
		case ev := <-subCh:
			if ev.Type == "finding_new" && strings.Contains(ev.Summary, "UB-2026-0039") {
				sawFindingNew = true
			}
		default:
			goto drainedFinding
		}
	}
drainedFinding:
	if !sawFindingNew {
		t.Fatalf("expected finding_new event when vulnerability reappeared after replug scan")
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
		prevRiskState:  &risk.State{Findings: map[string]checks.Severity{}},
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

	// Wait until /api/events accepts connections and emits the initial SSE comment.
	var resp *http.Response
	for range 40 {
		resp, err = http.Get("http://" + addr + "/api/events")
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect /api/events: %v", err)
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
