// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package server runs UniBlue as a live, event-driven security daemon with a
// lightweight built-in web UI, Server-Sent Events (SSE) stream, and targeted
// per-host live scanning whenever clients join, move, or policies change.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/fingerprints"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/notify"
	"github.com/karalabe/uniblue/internal/oui"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/topology"
	"github.com/karalabe/uniblue/internal/unifi"
)

const (
	// maxEventHistory caps the in-memory ring buffer of live events shown in the UI.
	maxEventHistory = 200

	// defaultJoinDebounce gives newly connected clients a few seconds to finish
	// DHCP and bring up listening services before UniBlue probes them.
	defaultJoinDebounce = 3 * time.Second

	// defaultLeaveGrace avoids flapping offline/online alerts when Wi-Fi clients
	// briefly sleep or roam between APs.
	defaultLeaveGrace = 60 * time.Second
)

// Options tunes the live server daemon's polling, reconciliation, and HTTP settings.
type Options struct {
	// ListenAddr is the TCP address for the built-in web UI and API (e.g., "127.0.0.1:8080").
	ListenAddr string

	// PollInterval sets how often UniFi topology deltas are polled when WebSocket
	// push is unavailable (e.g., Integration API v1). Defaults to 5 seconds.
	PollInterval time.Duration

	// ReconcileInterval sets how often a full LAN re-probe runs to catch newly
	// opened ports on already-connected hosts. Defaults to 30 minutes.
	ReconcileInterval time.Duration

	// SkipCVE disables local NVD+KEV correlation even when a cache exists.
	SkipCVE bool

	// Logger receives structured daemon logs.
	Logger *slog.Logger
}

// LiveEvent represents one real-time network or security event streamed to the
// web UI over SSE and kept in the recent event history.
type LiveEvent struct {
	// ID is a monotonically increasing event sequence number.
	ID int64 `json:"id"`

	// Time is the UTC timestamp when the event occurred.
	Time time.Time `json:"time"`

	// Type categorizes the event ("startup", "client_joined", "client_moved",
	// "client_left", "host_scanned", "finding_new", "policy_changed", "scan_complete").
	Type string `json:"type"`

	// Severity ranks visual emphasis ("info", "low", "medium", "high", "critical").
	Severity string `json:"severity"`

	// Host identifies the involved client or gateway, if applicable.
	Host string `json:"host,omitempty"`

	// IP is the host IP address, if applicable.
	IP string `json:"ip,omitempty"`

	// SubjectID links this event directly to a typed PresentationModel entity
	// (e.g., "host:<mac>", "port:<mac>/<idx>", "dev:<mac>") for one-click drilldown.
	SubjectID string `json:"subject_id,omitempty"`

	// Summary is a concise human-readable description of the event.
	Summary string `json:"summary"`
}

// ClientView merges UniFi client metadata, deterministic classification, open
// ports, and finding count for fast rendering in the web UI.
type ClientView struct {
	// Client is the live UniFi client record.
	Client unifi.Client `json:"client"`

	// Class is the deterministic hardware/protocol classification.
	Class classify.Result `json:"class"`

	// OpenPorts lists TCP ports confirmed open during the latest probe.
	OpenPorts []int `json:"open_ports,omitempty"`

	// FindingCount is the number of active findings on this host.
	FindingCount int `json:"finding_count"`

	// MaxSeverity is the highest active finding severity on this host, or "clean".
	MaxSeverity string `json:"max_severity"`

	// LastScannedAt records when this host was last actively probed.
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
}

// StateSnapshot is the complete, immutable read model served by GET /api/state
// and rendered by the live web dashboard.
type StateSnapshot struct {
	// StartedAt records when `uniblue serve` booted.
	StartedAt time.Time `json:"started_at"`

	// UpdatedAt records when state last changed.
	UpdatedAt time.Time `json:"updated_at"`

	// LastFullScanAt records when the latest full LAN reconciliation finished.
	LastFullScanAt time.Time `json:"last_full_scan_at"`

	// EventMode describes the active UniFi ingestion mode ("websocket" or "poll-5s").
	EventMode string `json:"event_mode"`

	// Scanning reports whether a full or targeted probe is currently running.
	Scanning bool `json:"scanning"`

	// Site is the UniFi site name.
	Site string `json:"site"`

	// ControllerType is the detected UniFi API flavor.
	ControllerType string `json:"controller_type"`

	// CVELoaded reports whether local NVD+KEV correlation is active.
	CVELoaded bool `json:"cve_loaded"`

	// Report holds the latest risk-scored findings, WAN surface, and posture notes.
	Report risk.Report `json:"report"`

	// ExactCVEs holds rolled-up exact-version CVE matches.
	ExactCVEs []cve.ProductSummary `json:"exact_cves,omitempty"`

	// PotentialCVEs holds rolled-up version-unknown patch verification reminders.
	PotentialCVEs []cve.ProductSummary `json:"potential_cves,omitempty"`

	// Topology holds the pure structural topology & placement model.
	Topology *topology.Model `json:"topology,omitempty"`

	// Clients holds the enriched per-client table for the web UI.
	Clients []ClientView `json:"clients,omitempty"`

	// Events holds the most recent live events (newest first).
	Events []LiveEvent `json:"events,omitempty"`

	// View holds the pre-evaluated single-source-of-truth UI presentation model
	// (entities, verdicts, fix-next queue, physical blueprint, logical lanes).
	View *PresentationModel `json:"view,omitempty"`
}

// missingClient records a client that disappeared from UniFi's active list
// while waiting out the leave grace window to avoid Wi-Fi sleep flapping.
type missingClient struct {
	client unifi.Client
	since  time.Time
}

// portLiveState captures the previous link and security configuration of a
// single physical switch port so pollDelta can emit real-time link/config events.
type portLiveState struct {
	DeviceName    string
	DeviceIP      string
	PortIdx       int
	PortName      string
	Zone          string
	Up            bool
	Enabled       bool
	NativeVLAN    string
	TaggedPolicy  string
	PortSecurity  bool
	PoEPowerWatts float64
	MACTableCount int
	STPState      string
}

// Engine coordinates UniFi event ingestion, targeted single-host live checks,
// periodic full reconciliation, webhook alerting, and SSE broadcasting.
type Engine struct {
	cfg        *config.Config
	opts       Options
	ctrl       *unifi.Controller
	checkList  []*checks.Check
	scanPorts  []int
	classifier *classify.Classifier
	cveCache   *cve.Cache
	cveIdent   *cve.Fingerprinter
	notifier   *notify.Notifier
	minNotify  checks.Severity
	logger     *slog.Logger

	startedAt time.Time
	eventMode string
	eventSeq  atomic.Int64

	// mu protects the live state maps and the published StateSnapshot.
	mu             sync.RWMutex
	snap           *unifi.Snapshot
	profilesByMAC  map[string]probe.HostProfile
	findingsByMAC  map[string][]checks.Finding
	missingClients map[string]missingClient
	lastPorts      map[string]portLiveState
	anomalies      *anomalyTracker
	lastClasses    map[string]classify.Result
	lastPolicySig  string
	lastFwdSig     string
	prevRiskState  *risk.State
	events         []LiveEvent
	current        StateSnapshot
	activeScans    atomic.Int32
	fullRescanCh   chan string
	hostScanCh     chan unifi.Client
	subMu          sync.Mutex
	subscribers    map[chan LiveEvent]struct{}
}

// NewEngine initializes all UniBlue components (UniFi client, checks, IEEE OUI
// classifier, optional CVE cache, and webhook notifier) for live server mode.
func NewEngine(cfg *config.Config, checkList []*checks.Check, scanPorts []int, opts Options) (*Engine, error) {
	if opts.PollInterval <= 0 {
		opts.PollInterval = 5 * time.Second
	}
	if opts.ReconcileInterval <= 0 {
		opts.ReconcileInterval = 30 * time.Minute
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	ctrl, err := unifi.New(cfg.UniFi)
	if err != nil {
		return nil, err
	}
	notifier, err := notify.New(cfg.Notify)
	if err != nil {
		return nil, err
	}
	minSev, err := checks.ParseSeverity(cfg.Notify.MinSeverity)
	if err != nil {
		return nil, err
	}

	ouiDB := oui.New("")
	_ = ouiDB.Load()
	classifier, err := classify.Load(classifydata.BuiltinFS, ouiDB)
	if err != nil {
		return nil, err
	}

	var cveCache *cve.Cache
	var cveIdent *cve.Fingerprinter
	if !opts.SkipCVE {
		cache := cve.NewCache(cfg.CVE.CacheDir)
		if _, err := cache.Stats(); err == nil {
			if ident, err := cve.LoadFingerprinter(fingerprints.BuiltinFS); err == nil {
				cveCache = cache
				cveIdent = ident
			}
		}
	}

	prevState, _ := risk.LoadState(cfg.State.Path)

	return &Engine{
		cfg:            cfg,
		opts:           opts,
		ctrl:           ctrl,
		checkList:      checkList,
		scanPorts:      scanPorts,
		classifier:     classifier,
		cveCache:       cveCache,
		cveIdent:       cveIdent,
		notifier:       notifier,
		minNotify:      minSev,
		logger:         opts.Logger,
		startedAt:      time.Now().UTC(),
		profilesByMAC:  make(map[string]probe.HostProfile),
		findingsByMAC:  make(map[string][]checks.Finding),
		missingClients: make(map[string]missingClient),
		lastPorts:      make(map[string]portLiveState),
		anomalies:      newAnomalyTracker(),
		lastClasses:    make(map[string]classify.Result),
		prevRiskState:  prevState,
		fullRescanCh:   make(chan string, 1),
		hostScanCh:     make(chan unifi.Client, 64),
		subscribers:    make(map[chan LiveEvent]struct{}),
	}, nil
}

// Start authenticates with UniFi, fetches an immediate UniFi topology snapshot
// so the web UI can render clients, VLANs, and firewall findings right away,
// and spawns background goroutines for the initial LAN probe baseline, event
// ingestion (WebSocket + 5s delta polling), targeted per-host scanning, and
// periodic full reconciliation.
func (e *Engine) Start(ctx context.Context) error {
	if err := e.ctrl.Login(ctx); err != nil {
		return err
	}
	if e.ctrl.SupportsWebSocket() {
		e.eventMode = "websocket"
	} else {
		e.eventMode = fmt.Sprintf("poll-%s", e.opts.PollInterval)
	}

	e.emit(LiveEvent{
		Type:     "startup",
		Severity: "info",
		Summary:  fmt.Sprintf("UniBlue live monitor started (mode=%s, poll=%s)", e.eventMode, e.opts.PollInterval),
	})

	// Fetch UniFi topology synchronously (~15ms on LAN) so the web UI renders
	// clients, VLANs, and firewall posture immediately before LAN probing ends.
	snap, err := e.ctrl.FetchSnapshot(ctx)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.snap = snap
	e.lastFwdSig = portForwardSignature(snap.PortForwards)
	e.lastPolicySig = firewallPolicySignature(snap.FirewallPolicies)
	e.lastPorts = snapshotPortStates(snap, e.cfg.Network)
	e.anomalies.Seed(snap, e.lastPorts, time.Now().UTC())
	e.mu.Unlock()
	e.recomputeAndPublish(ctx, false)

	// Start single-host live scan worker pool (bounded by 2 workers to stay gentle).
	for range 2 {
		go e.hostScanWorker(ctx)
	}

	// Start event ingestion (WebSocket push when supported, plus 5s delta polling).
	if e.ctrl.SupportsWebSocket() {
		go e.websocketLoop(ctx)
	}
	// Queue the full LAN baseline probe asynchronously so Serve binds immediately.
	e.queueFullRescan("initial baseline")
	go e.pollAndReconcileLoop(ctx)
	return nil
}

// Snapshot returns a thread-safe copy of the latest StateSnapshot for HTTP handlers.
func (e *Engine) Snapshot() StateSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cp := e.current
	cp.Scanning = e.activeScans.Load() > 0
	return cp
}

// TriggerFullRescan queues an asynchronous full scan if one is not already queued.
func (e *Engine) TriggerFullRescan() {
	e.queueFullRescan("manual rescan")
}

func (e *Engine) queueFullRescan(reason string) {
	select {
	case e.fullRescanCh <- reason:
	default:
	}
}

// TriggerHostRescan queues a targeted live probe against a single client IP.
func (e *Engine) TriggerHostRescan(ip string) bool {
	ip = strings.TrimSpace(ip)
	e.mu.RLock()
	var target *unifi.Client
	if e.snap != nil {
		for _, cl := range e.snap.Clients {
			if cl.IP == ip {
				cp := cl
				target = &cp
				break
			}
		}
	}
	e.mu.RUnlock()
	if target == nil {
		return false
	}
	select {
	case e.hostScanCh <- *target:
		return true
	default:
		return false
	}
}

// Subscribe registers an SSE subscriber channel receiving live events.
func (e *Engine) Subscribe() (chan LiveEvent, func()) {
	ch := make(chan LiveEvent, 32)
	e.subMu.Lock()
	e.subscribers[ch] = struct{}{}
	e.subMu.Unlock()
	return ch, func() {
		e.subMu.Lock()
		delete(e.subscribers, ch)
		e.subMu.Unlock()
	}
}

// pollAndReconcileLoop runs the 5-second lightweight UniFi delta check and the
// slower periodic full reconciliation loop until ctx is cancelled.
func (e *Engine) pollAndReconcileLoop(ctx context.Context) {
	pollTicker := time.NewTicker(e.opts.PollInterval)
	defer pollTicker.Stop()
	reconcileTicker := time.NewTicker(e.opts.ReconcileInterval)
	defer reconcileTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case reason := <-e.fullRescanCh:
			if err := e.runFullScan(ctx, reason); err != nil && ctx.Err() == nil {
				e.logger.Error("full scan failed", "reason", reason, "err", err)
			}
		case <-reconcileTicker.C:
			if err := e.runFullScan(ctx, "periodic reconciliation"); err != nil && ctx.Err() == nil {
				e.logger.Error("periodic reconciliation failed", "err", err)
			}
		case <-pollTicker.C:
			e.pollDelta(ctx)
		}
	}
}

// websocketLoop maintains a reconnecting UniFi WebSocket subscription for
// cookie-authenticated controllers, triggering immediate delta checks on events.
func (e *Engine) websocketLoop(ctx context.Context) {
	evCh := make(chan unifi.Event, 64)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-evCh:
				// Any client sync, connection event, or firewall/setting event
				// triggers an immediate lightweight topology diff.
				msg := strings.ToLower(ev.Message)
				if strings.Contains(msg, "sta") || strings.Contains(msg, "event") ||
					strings.Contains(msg, "device") || strings.Contains(msg, "port") ||
					strings.Contains(msg, "firewall") {
					e.pollDelta(ctx)
				}
			}
		}
	}()

	backoff := 2 * time.Second
	for ctx.Err() == nil {
		err := e.ctrl.SubscribeEvents(ctx, evCh)
		if ctx.Err() != nil {
			return
		}
		e.logger.Warn("unifi websocket disconnected, reconnecting", "err", err, "backoff", backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// pollDelta fetches a fresh UniFi topology snapshot (no LAN probing) and reacts
// immediately to newly appearing clients, IP/VLAN changes, departures, or
// firewall/port-forward changes.
func (e *Engine) pollDelta(ctx context.Context) {
	pollCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	snap, err := e.ctrl.FetchSnapshot(pollCtx)
	if err != nil {
		if ctx.Err() == nil {
			e.logger.Warn("unifi delta poll failed", "err", err)
		}
		return
	}

	now := time.Now().UTC()
	var toScan []unifi.Client
	changed := false

	e.mu.Lock()
	prevSnap := e.snap
	prevClients := make(map[string]unifi.Client)
	if prevSnap != nil {
		for _, cl := range prevSnap.Clients {
			prevClients[clientKey(cl)] = cl
		}
	}

	seenNow := make(map[string]struct{}, len(snap.Clients))
	for _, cl := range snap.Clients {
		k := clientKey(cl)
		seenNow[k] = struct{}{}

		// Check whether the client was merely sleeping within the leave grace window.
		prev, existed := prevClients[k]
		if !existed {
			if mc, wasMissing := e.missingClients[k]; wasMissing {
				prev = mc.client
				existed = true
			}
		}
		delete(e.missingClients, k)

		switch {
		case !existed:
			changed = true
			e.emitLocked(LiveEvent{
				Type:     "client_joined",
				Severity: "info",
				Host:     cl.DisplayName(),
				IP:       cl.IP,
				Summary:  fmt.Sprintf("%s joined %s (%s)", cl.DisplayName(), fallbackVLAN(cl.NetworkName), cl.IP),
			})
			for _, aev := range e.anomalies.EvaluateClientJoinAnomalies(cl, now) {
				e.emitLocked(aev)
			}
			if cl.IP != "" {
				toScan = append(toScan, cl)
			}
		case prev.IP != cl.IP || prev.NetworkName != cl.NetworkName:
			changed = true
			e.emitLocked(LiveEvent{
				Type:     "client_moved",
				Severity: "medium",
				Host:     cl.DisplayName(),
				IP:       cl.IP,
				Summary:  fmt.Sprintf("%s changed (%s/%s -> %s/%s)", cl.DisplayName(), prev.IP, fallbackVLAN(prev.NetworkName), cl.IP, fallbackVLAN(cl.NetworkName)),
			})
			if cl.IP != "" {
				toScan = append(toScan, cl)
			}
		default:
			// Update stored profile client metadata in case alias changed.
			if hp, ok := e.profilesByMAC[k]; ok {
				hp.Client = cl
				e.profilesByMAC[k] = hp
			}
		}
	}

	// Track newly disappeared clients with a grace window so Wi-Fi sleep doesn't flap alerts.
	for k, prev := range prevClients {
		if _, active := seenNow[k]; active {
			continue
		}
		if _, tracked := e.missingClients[k]; !tracked {
			e.missingClients[k] = missingClient{client: prev, since: now}
		}
	}

	// Evict any client that has stayed absent past defaultLeaveGrace.
	for k, mc := range e.missingClients {
		if now.Sub(mc.since) >= defaultLeaveGrace {
			delete(e.missingClients, k)
			delete(e.profilesByMAC, k)
			changed = true
			e.emitLocked(LiveEvent{
				Type:     "client_left",
				Severity: "info",
				Host:     mc.client.DisplayName(),
				IP:       mc.client.IP,
				Summary:  fmt.Sprintf("%s left %s (%s)", mc.client.DisplayName(), fallbackVLAN(mc.client.NetworkName), mc.client.IP),
			})
		}
	}

	// Detect WAN port-forward or user firewall policy changes.
	fwdSig := portForwardSignature(snap.PortForwards)
	polSig := firewallPolicySignature(snap.FirewallPolicies)
	if e.lastFwdSig != "" && fwdSig != e.lastFwdSig {
		changed = true
		e.emitLocked(LiveEvent{
			Type:     "policy_changed",
			Severity: "high",
			Summary:  "WAN port-forwarding rules changed — re-evaluating exposure surface",
		})
		// Probe any active host referenced by an enabled port forward.
		for _, pf := range snap.PortForwards {
			if !pf.Enabled || pf.FwdIP == "" {
				continue
			}
			for _, cl := range snap.Clients {
				if cl.IP == pf.FwdIP {
					toScan = append(toScan, cl)
					break
				}
			}
		}
	}
	if e.lastPolicySig != "" && polSig != e.lastPolicySig {
		changed = true
		e.emitLocked(LiveEvent{
			Type:     "policy_changed",
			Severity: "high",
			Summary:  "UniFi firewall policies changed — re-auditing zone rules",
		})
	}

	// Detect live physical switch port link & security configuration changes.
	currPorts := snapshotPortStates(snap, e.cfg.Network)
	if len(e.lastPorts) > 0 {
		for pk, curr := range currPorts {
			prev, existed := e.lastPorts[pk]
			if !existed {
				continue
			}
			isSensitive := curr.Zone == "external" || curr.Zone == "external_uplink" || curr.Zone == "unused"
			if !prev.Up && curr.Up {
				changed = true
				sev := "info"
				if isSensitive {
					sev = "critical"
				}
				e.emitLocked(LiveEvent{
					Type:     "port_link_up",
					Severity: sev,
					Host:     fmt.Sprintf("%s Port %d", curr.DeviceName, curr.PortIdx),
					IP:       curr.DeviceIP,
					Summary:  fmt.Sprintf("Physical link UP on %s Port %d (%s, zone=%s, VLAN=%s)", curr.DeviceName, curr.PortIdx, curr.PortName, curr.Zone, fallbackVLAN(curr.NativeVLAN)),
				})
			} else if prev.Up && !curr.Up {
				changed = true
				sev := "info"
				if curr.Zone == "external" || curr.Zone == "external_uplink" {
					sev = "high"
				}
				e.emitLocked(LiveEvent{
					Type:     "port_link_down",
					Severity: sev,
					Host:     fmt.Sprintf("%s Port %d", curr.DeviceName, curr.PortIdx),
					IP:       curr.DeviceIP,
					Summary:  fmt.Sprintf("Physical link DOWN on %s Port %d (%s, zone=%s)", curr.DeviceName, curr.PortIdx, curr.PortName, curr.Zone),
				})
			}
			if prev.Enabled != curr.Enabled || prev.NativeVLAN != curr.NativeVLAN || prev.TaggedPolicy != curr.TaggedPolicy || prev.PortSecurity != curr.PortSecurity {
				changed = true
				sev := "medium"
				if isSensitive {
					sev = "high"
				}
				e.emitLocked(LiveEvent{
					Type:     "port_config_changed",
					Severity: sev,
					Host:     fmt.Sprintf("%s Port %d", curr.DeviceName, curr.PortIdx),
					IP:       curr.DeviceIP,
					Summary: fmt.Sprintf("Port config changed on %s Port %d (zone=%s): enabled=%v->%v, VLAN=%s->%s, tagged=%s->%s, mac_lock=%v->%v",
						curr.DeviceName, curr.PortIdx, curr.Zone,
						prev.Enabled, curr.Enabled,
						fallbackVLAN(prev.NativeVLAN), fallbackVLAN(curr.NativeVLAN),
						prev.TaggedPolicy, curr.TaggedPolicy,
						prev.PortSecurity, curr.PortSecurity),
				})
			}
		}
	}

	// Evaluate physical-layer tamper anomalies (PoE drop cable swap, inline hub
	// MAC surge, STP blocking), IoT upload spikes, and site security telemetry
	// (IDS/IPS/Honeypot/Admin logs, Evil-Twin APs, VPN/WAN transitions, config drift).
	for _, aev := range e.anomalies.EvaluatePortAnomalies(e.lastPorts, currPorts) {
		changed = true
		e.emitLocked(aev)
	}
	for _, aev := range e.anomalies.EvaluateIoTUploadSpikes(snap.Clients, e.lastClasses, now) {
		changed = true
		e.emitLocked(aev)
	}
	for _, aev := range e.anomalies.EvaluateSiteTelemetry(snap, snap.RecentLogs) {
		changed = true
		e.emitLocked(aev)
	}

	e.snap = snap
	e.lastFwdSig = fwdSig
	e.lastPolicySig = polSig
	e.lastPorts = currPorts
	e.mu.Unlock()

	if changed {
		e.recomputeAndPublish(ctx, false)
	}

	// Debounce newly joined hosts briefly so DHCP & daemons finish starting before probing.
	if len(toScan) > 0 {
		go func(targets []unifi.Client) {
			timer := time.NewTimer(defaultJoinDebounce)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			for _, cl := range targets {
				select {
				case e.hostScanCh <- cl:
				case <-ctx.Done():
					return
				}
			}
		}(toScan)
	}
}

// hostScanWorker processes targeted single-host live probes queued when a
// client joins, changes IP/VLAN, or is rescanned manually from the UI.
func (e *Engine) hostScanWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case cl := <-e.hostScanCh:
			e.scanSingleHost(ctx, cl)
		}
	}
}

// scanSingleHost runs gentle port probing + Nerva + YAML checks against a single
// host and updates the live state snapshot immediately.
func (e *Engine) scanSingleHost(ctx context.Context, cl unifi.Client) {
	if cl.IP == "" {
		return
	}
	if _, skip := e.cfg.Network.ExcludedSet()[cl.IP]; skip {
		return
	}

	e.activeScans.Add(1)
	defer e.activeScans.Add(-1)

	e.mu.RLock()
	hints := e.snap.PortHintsByIP()
	e.mu.RUnlock()

	fp := probe.NewFingerprinter(e.scanPorts, 1, e.cfg.Scan.Timeout, e.cfg.Network.ExcludedSet())
	fp.SetHostPortHints(checks.PlanHostPorts([]unifi.Client{cl}, e.checkList, hints))
	profiles := fp.FingerprintAll(ctx, []unifi.Client{cl})
	if len(profiles) == 0 {
		return
	}
	hp := profiles[0]
	enrichedSingle := []probe.HostProfile{hp.Clone()}
	attachConfiguredEnrichments(nil, enrichedSingle, e.cfg.Network)
	runner := checks.NewRunner(e.checkList, 1)
	hostCheckFindings := runner.RunHost(ctx, enrichedSingle[0])

	e.mu.Lock()
	e.profilesByMAC[clientKey(cl)] = hp
	e.findingsByMAC[clientKey(cl)] = hostCheckFindings
	e.mu.Unlock()

	e.recomputeAndPublish(ctx, false)

	// Emit a crisp scan-result event using the freshly evaluated findings
	// (avoids issuing duplicate check probes against the host).
	published := e.Snapshot()
	var hostFindings int
	maxSev := checks.SeverityInfo
	for _, f := range published.Report.Findings {
		if f.Client.IP == cl.IP && f.CheckID != "UB-UNIFI-PORTFWD" && f.CheckID != "UB-UNIFI-FIRMWARE" && !f.IsInventoryOnly() {
			hostFindings++
			if f.EffectiveSeverity > maxSev {
				maxSev = f.EffectiveSeverity
			}
		}
	}
	sev := "info"
	summary := fmt.Sprintf("Scanned %s (%s): %d open port(s), clean", cl.DisplayName(), cl.IP, len(hp.OpenPorts))
	if hostFindings > 0 {
		sev = maxSev.String()
		summary = fmt.Sprintf("Scanned %s (%s): %d open port(s), %d exposure(s) detected!",
			cl.DisplayName(), cl.IP, len(hp.OpenPorts), hostFindings)
	}
	e.emit(LiveEvent{
		Type:     "host_scanned",
		Severity: sev,
		Host:     cl.DisplayName(),
		IP:       cl.IP,
		Summary:  summary,
	})
}

// runFullScan executes a complete UniFi snapshot + uniform LAN probe sweep and
// publishes the refreshed StateSnapshot.
func (e *Engine) runFullScan(ctx context.Context, reason string) error {
	e.activeScans.Add(1)
	defer e.activeScans.Add(-1)

	e.logger.Info("starting full scan", "reason", reason)
	snap, err := e.ctrl.FetchSnapshot(ctx)
	if err != nil {
		return err
	}

	fp := probe.NewFingerprinter(e.scanPorts, e.cfg.Scan.Concurrency, e.cfg.Scan.Timeout, e.cfg.Network.ExcludedSet())
	fp.SetHostPortHints(checks.PlanHostPorts(snap.Clients, e.checkList, snap.PortHintsByIP()))
	profiles := fp.FingerprintAll(ctx, snap.Clients)

	// Run Stage 2 active/passive checks once per full scan on deep-cloned enriched
	// profiles and cache per-host results so subsequent topology/policy-only
	// recomputations require ZERO device network I/O.
	enriched := make([]probe.HostProfile, len(profiles))
	for i, hp := range profiles {
		enriched[i] = hp.Clone()
	}
	attachConfiguredEnrichments(snap, enriched, e.cfg.Network)
	runner := checks.NewRunner(e.checkList, e.cfg.Scan.Concurrency)
	freshFindings := runner.RunAll(ctx, enriched)
	byMAC := make(map[string][]checks.Finding, len(profiles))
	for _, f := range freshFindings {
		k := clientKey(f.Client)
		byMAC[k] = append(byMAC[k], f)
	}

	e.mu.Lock()
	e.snap = snap
	e.lastFwdSig = portForwardSignature(snap.PortForwards)
	e.lastPolicySig = firewallPolicySignature(snap.FirewallPolicies)
	e.lastPorts = snapshotPortStates(snap, e.cfg.Network)
	e.profilesByMAC = make(map[string]probe.HostProfile, len(profiles))
	for _, hp := range profiles {
		e.profilesByMAC[clientKey(hp.Client)] = hp
	}
	e.findingsByMAC = byMAC
	e.missingClients = make(map[string]missingClient)
	e.mu.Unlock()

	e.recomputeAndPublish(ctx, true)

	snapView := e.Snapshot()
	e.emit(LiveEvent{
		Type:     "scan_complete",
		Severity: "info",
		Summary: fmt.Sprintf("Full scan complete (%s): %d clients, %d findings, %d exact CVEs",
			reason, snapView.Report.ClientCount, len(snapView.Report.Findings), len(snapView.ExactCVEs)),
	})
	return nil
}

// recomputeAndPublish runs checks, blast-radius risk evaluation, CVE rollup,
// topology construction, and webhook diffing against the current in-memory
// snapshot and host profiles.
func (e *Engine) recomputeAndPublish(ctx context.Context, isFullScan bool) {
	e.mu.RLock()
	snapPtr := e.snap
	if snapPtr == nil {
		e.mu.RUnlock()
		return
	}
	// Shallow-copy Snapshot header so site-supplement enrichment never mutates shared pointers.
	snapCopy := *snapPtr
	if snapPtr.Visibility != nil {
		visCopy := *snapPtr.Visibility
		visCopy.MissingFeeds = append([]string(nil), snapPtr.Visibility.MissingFeeds...)
		snapCopy.Visibility = &visCopy
	}
	snap := &snapCopy

	profiles := make([]probe.HostProfile, 0, len(e.profilesByMAC))
	var cachedFindings []checks.Finding
	for k, hp := range e.profilesByMAC {
		profiles = append(profiles, hp.Clone())
		if fl := e.findingsByMAC[k]; len(fl) > 0 {
			cachedFindings = append(cachedFindings, fl...)
		}
	}
	prevRisk := e.prevRiskState
	e.mu.RUnlock()

	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Client.IP < profiles[j].Client.IP
	})
	attachConfiguredEnrichments(snap, profiles, e.cfg.Network)

	rawFindings := append([]checks.Finding(nil), cachedFindings...)
	rawFindings = append(rawFindings, checks.FindingsFromProfiles(profiles, rawFindings)...)
	report := risk.Evaluate(snap, rawFindings, e.cfg.Network)

	var exactCVEs, potentialCVEs []cve.ProductSummary
	cveLoaded := false
	if e.cveCache != nil && e.cveIdent != nil {
		cveLoaded = true
		products := e.cveIdent.Identify(snap, profiles)
		if matches, err := e.cveCache.MatchProducts(products, cve.MatchOptions{
			MinSeverity:          checks.SeverityHigh,
			PotentialMaxAgeYears: 2,
		}); err == nil {
			for _, s := range cve.RollupMatches(matches) {
				if s.Confidence == cve.ConfidenceExact {
					exactCVEs = append(exactCVEs, s)
				} else {
					potentialCVEs = append(potentialCVEs, s)
				}
			}
		}
	}

	classes := e.classifier.ClassifyAll(snap, profiles)
	topoModel := topology.Build(snap, classes, e.cfg.Network)

	// Build enriched per-client views for the dashboard.
	profileByKey := make(map[string]probe.HostProfile, len(profiles))
	for _, hp := range profiles {
		profileByKey[clientKey(hp.Client)] = hp
	}
	findingsByIP := make(map[string][]checks.Finding)
	for _, f := range report.Findings {
		if f.Client.IP != "" && f.CheckID != "UB-UNIFI-PORTFWD" && f.CheckID != "UB-UNIFI-FIRMWARE" && !f.IsInventoryOnly() {
			findingsByIP[f.Client.IP] = append(findingsByIP[f.Client.IP], f)
		}
	}

	clientViews := make([]ClientView, 0, len(snap.Clients))
	for _, cl := range snap.Clients {
		k := clientKey(cl)
		clsKey := cl.IP
		if clsKey == "" {
			clsKey = cl.MAC
		}
		cv := ClientView{
			Client:      cl,
			Class:       classes[clsKey],
			MaxSeverity: "clean",
		}
		if hp, ok := profileByKey[k]; ok {
			cv.OpenPorts = hp.OpenPorts
			ts := hp.ScannedAt
			cv.LastScannedAt = &ts
		}
		if fl := findingsByIP[cl.IP]; len(fl) > 0 {
			cv.FindingCount = len(fl)
			maxSev := checks.SeverityInfo
			for _, f := range fl {
				if f.EffectiveSeverity > maxSev {
					maxSev = f.EffectiveSeverity
				}
			}
			cv.MaxSeverity = maxSev.String()
		}
		clientViews = append(clientViews, cv)
	}
	sort.Slice(clientViews, func(i, j int) bool {
		if clientViews[i].Client.NetworkName != clientViews[j].Client.NetworkName {
			return clientViews[i].Client.NetworkName < clientViews[j].Client.NetworkName
		}
		return clientViews[i].Client.IP < clientViews[j].Client.IP
	})

	// Diff against previous baseline for webhook alerting and live finding events.
	diff := risk.ComputeDiff(prevRisk, snap, report, e.cfg.Network)
	if prevRisk != nil {
		for _, nf := range diff.NewFindings {
			e.emit(LiveEvent{
				Type:     "finding_new",
				Severity: nf.EffectiveSeverity.String(),
				Host:     nf.Client.DisplayName(),
				IP:       nf.Client.IP,
				Summary:  fmt.Sprintf("New [%s] %s: %s", strings.ToUpper(nf.EffectiveSeverity.String()), nf.CheckID, nf.Title),
			})
		}
		if diff.HasAlerts(e.minNotify) {
			if err := e.notifier.Send(ctx, snap.Site, diff); err != nil {
				e.logger.Error("webhook notification failed", "err", err)
			}
		}
	}

	nextState := risk.BuildState(snap, report, e.cfg.Network)
	_ = risk.SaveState(e.cfg.State.Path, nextState)
	viewModel := BuildPresentationModel(snap, report, topoModel, clientViews, exactCVEs, potentialCVEs, profiles)

	now := time.Now().UTC()
	e.mu.Lock()
	e.prevRiskState = nextState
	e.lastClasses = classes
	lastFull := e.current.LastFullScanAt
	if isFullScan {
		lastFull = now
	}
	eventsCopy := make([]LiveEvent, len(e.events))
	copy(eventsCopy, e.events)
	e.current = StateSnapshot{
		StartedAt:      e.startedAt,
		UpdatedAt:      now,
		LastFullScanAt: lastFull,
		EventMode:      e.eventMode,
		Site:           snap.Site,
		ControllerType: snap.ControllerType,
		CVELoaded:      cveLoaded,
		Report:         report,
		ExactCVEs:      exactCVEs,
		PotentialCVEs:  potentialCVEs,
		Topology:       topoModel,
		Clients:        clientViews,
		Events:         eventsCopy,
		View:           viewModel,
	}
	e.mu.Unlock()
}

// emit records ev in the recent history buffer and fans it out to all SSE clients.
func (e *Engine) emit(ev LiveEvent) {
	e.mu.Lock()
	e.emitLocked(ev)
	e.mu.Unlock()
}

// emitLocked appends ev (caller must hold e.mu) and broadcasts non-blockingly.
func (e *Engine) emitLocked(ev LiveEvent) {
	ev.ID = e.eventSeq.Add(1)
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	e.events = append([]LiveEvent{ev}, e.events...)
	if len(e.events) > maxEventHistory {
		e.events = e.events[:maxEventHistory]
	}
	e.current.Events = append([]LiveEvent(nil), e.events...)

	e.subMu.Lock()
	for ch := range e.subscribers {
		select {
		case ch <- ev:
		default:
		}
	}
	e.subMu.Unlock()
}

func clientKey(cl unifi.Client) string {
	if cl.MAC != "" {
		return strings.ToLower(cl.MAC)
	}
	return cl.IP
}

// attachConfiguredEnrichments merges any owner-provided read-only bridge/NVR
// inventories, passive flow records, and site supplement telemetry without
// network I/O, recording any load errors into snap.Visibility.MissingFeeds.
func attachConfiguredEnrichments(snap *unifi.Snapshot, profiles []probe.HostProfile, netCfg config.NetworkConfig) {
	if snap != nil && strings.TrimSpace(netCfg.SiteSupplementPath) != "" {
		_ = unifi.ApplySiteSupplement(snap, netCfg.SiteSupplementPath)
	}
	for _, bi := range netCfg.BridgeInventories {
		if strings.TrimSpace(bi.Path) == "" {
			continue
		}
		children, err := probe.LoadBridgeInventory(probe.BridgeInventorySpec{
			Format:       bi.Format,
			Path:         bi.Path,
			ParentIP:     bi.ParentIP,
			ParentMAC:    bi.ParentMAC,
			ParentRole:   bi.ParentRole,
			ObservedFrom: bi.ObservedFrom,
		})
		if err != nil {
			unifi.RecordMissingFeed(snap, fmt.Sprintf("bridge-inventory (%s: %v)", bi.Path, err))
			continue
		}
		if len(children) > 0 {
			probe.AttachBridgeChildren(profiles, children)
		}
	}
	if strings.TrimSpace(netCfg.PassiveFlowsPath) != "" {
		flows, err := probe.LoadPassiveFlows(netCfg.PassiveFlowsPath)
		if err != nil {
			unifi.RecordMissingFeed(snap, fmt.Sprintf("passive-flows (%s: %v)", netCfg.PassiveFlowsPath, err))
		} else if len(flows) > 0 {
			probe.ApplyPassiveFlows(profiles, flows)
		}
	}
}

func fallbackVLAN(name string) string {
	if name == "" {
		return "unknown VLAN"
	}
	return name
}

func portForwardSignature(pfs []unifi.PortForward) string {
	parts := make([]string, 0, len(pfs))
	for _, pf := range pfs {
		parts = append(parts, fmt.Sprintf("%s|%v|%s|%s|%s|%s|%s", pf.Name, pf.Enabled, pf.Proto, pf.DstPort, pf.FwdIP, pf.FwdPort, pf.Src))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func firewallPolicySignature(pols []unifi.FirewallPolicy) string {
	parts := make([]string, 0, len(pols))
	for _, p := range pols {
		parts = append(parts, fmt.Sprintf(
			"%d|%s|%s|%s|%v|%s|%s|%s|%v|%v|%s|%s(%v,%v,%v,%v)->%s(%v,%v,%v,%v)",
			p.Index, p.Origin, p.ID, p.Name, p.Enabled, p.Action, p.IPVersion, p.Protocol,
			p.ConnectionStates, p.MatchReturnTraffic, p.Schedule,
			p.Source.ZoneName, p.Source.IPs, p.Source.NetworkIDs, p.Source.Ports, p.Source.NegateTarget,
			p.Destination.ZoneName, p.Destination.IPs, p.Destination.NetworkIDs, p.Destination.Ports, p.Destination.NegateTarget,
		))
	}
	return strings.Join(parts, ";")
}

func snapshotPortStates(snap *unifi.Snapshot, netCfg config.NetworkConfig) map[string]portLiveState {
	views, _, _ := risk.AnalyzeSwitchPorts(snap, netCfg, nil, nil)
	out := make(map[string]portLiveState)
	for _, sw := range views {
		for _, p := range sw.Ports {
			key := fmt.Sprintf("%s|%d", sw.MAC, p.PortIdx)
			out[key] = portLiveState{
				DeviceName:    sw.Name,
				DeviceIP:      sw.IP,
				PortIdx:       p.PortIdx,
				PortName:      p.Name,
				Zone:          p.Zone,
				Up:            p.Up,
				Enabled:       p.Enabled,
				NativeVLAN:    p.NativeVLAN,
				TaggedPolicy:  p.TaggedPolicy,
				PortSecurity:  p.PortSecurity,
				PoEPowerWatts: p.PoEPowerWatts,
				MACTableCount: p.MACTableCount,
				STPState:      p.STPState,
			}
		}
	}
	return out
}
