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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/fingerprints"
	"github.com/karalabe/uniblue/internal/blast"
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

	// defaultBootRetryDelay schedules one quiet follow-up probe for newly joined
	// or replugged hosts that initially show zero open ports while still booting.
	defaultBootRetryDelay = 15 * time.Second

	// defaultLeaveGrace avoids flapping offline/online alerts when Wi-Fi clients
	// briefly sleep or roam between APs. Wired clients evict immediately on leave
	// or physical switch port link-down.
	defaultLeaveGrace = 60 * time.Second

	// maxWebhookCVEsPerBatch caps how many CVEAlert entries are packed into a
	// single webhook delivery (~40 KB JSON, well below typical 1 MB proxy body
	// limits while keeping large fleet CVE bursts within the pending queue cap).
	maxWebhookCVEsPerBatch = 150

	// maxCoalescedEventsPerBatch caps how many live events can be merged into
	// a single queued live-event batch during extended webhook outages.
	maxCoalescedEventsPerBatch = 200

	// exactCVETransientGrace retains exact CVE baseline keys across brief banner
	// misses or single hourly CVE sync hiccups (exceeding both the default 30m
	// full-scan interval and 1h CVE refresh interval) so known CVEs do not flap.
	exactCVETransientGrace = 2 * time.Hour

	// exactCVEOfflineTTL bounds how long exact CVE baseline keys are carried
	// forward for offline or unprobed hosts before aging out.
	exactCVEOfflineTTL = 7 * 24 * time.Hour

	// maxTransient4xxRetries bounds retries for non-permanent 4xx webhook
	// rejections (such as 401/403/404 during proxy restarts, clock skew, or
	// secret rotation) so brief receiver glitches recover without stalling the
	// queue for 24 hours.
	maxTransient4xxRetries = 5

	// webhookShutdownGrace gives an already-started in-flight webhook POST a
	// brief grace window to finish cleanly when the engine context cancels so
	// completed deliveries are removed from disk and not duplicated on restart.
	webhookShutdownGrace = 2 * time.Second
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

	// CVERefreshInterval sets how often Start automatically downloads/refreshes
	// the local NVD+KEV cache in the background (when > 0 and SkipCVE is false).
	// When 0, only an already-present local cache is loaded without network sync.
	CVERefreshInterval time.Duration

	// APIToken optionally requires Authorization: Bearer <token> or session cookie on /api/v1/* endpoints.
	APIToken string

	// AllowedHosts optionally whitelists additional reverse-proxy Host / Origin
	// values (merged with UNIBLUE_ALLOWED_HOSTS).
	AllowedHosts []string

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

	// Skipped is true when this host is intentionally excluded or unprobeable
	// (e.g., in network.exclude_ips, no IP, or public non-local IP) so the UI
	// never treats it as permanently pending assessment.
	Skipped bool `json:"skipped,omitempty"`

	// SkipReason explains why active probing was skipped for this host.
	SkipReason string `json:"skip_reason,omitempty"`
}

// StateSnapshot is the complete, immutable read model served by GET /api/v1/state
// and rendered by the live web dashboard.
type StateSnapshot struct {
	// StartedAt records when `uniblue serve` booted.
	StartedAt time.Time `json:"started_at"`

	// UpdatedAt records when state last changed.
	UpdatedAt time.Time `json:"updated_at"`

	// LastFullScanAt records when the latest full LAN reconciliation finished.
	LastFullScanAt time.Time `json:"last_full_scan_at"`

	// LastScanError records the most recent full-scan error (cleared once a
	// scan succeeds) so the UI can surface errors instead of hanging at 4%.
	LastScanError string `json:"last_scan_error,omitempty"`

	// EventMode describes the active UniFi ingestion mode ("websocket" or "poll-5s").
	EventMode string `json:"event_mode"`

	// Scanning reports whether a full or targeted probe is currently running.
	Scanning bool `json:"scanning"`

	// ScanProgress reports live per-stage progress while a full baseline or
	// manual rescan is executing, or nil when idle.
	ScanProgress *ScanProgress `json:"scan_progress,omitempty"`

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

// ScanProgress reports live step-by-step progress while a full LAN baseline or
// manual rescan is executing so the UI can display an accurate progress bar.
type ScanProgress struct {
	// Phase identifies the active stage ("topology", "discovery", "probing",
	// "fingerprinting", "fingerprinting-fallback", "checks", "evaluating").
	Phase string `json:"phase"`

	// Label is a plain-English description of the active stage.
	Label string `json:"label"`

	// Completed is the number of items (hosts or open ports) finished in the current stage.
	Completed int `json:"completed"`

	// Total is the total number of items (hosts or open ports) in the current stage.
	Total int `json:"total"`

	// CurrentHost is the most recently completed host or host:port label, if any.
	CurrentHost string `json:"current_host,omitempty"`

	// Percent is the overall 0..100 completion estimate across all stages.
	Percent int `json:"percent"`

	// Initial is true during the first baseline scan before LastFullScanAt is set.
	Initial bool `json:"initial"`

	// StageTotals retains the total item count for each completed or active scan
	// stage (keyed by Phase) so the UI can keep displaying finished counters.
	StageTotals map[string]int `json:"stage_totals,omitempty"`
}

// missingClient records a client that disappeared from UniFi's active list
// while waiting out the leave grace window to avoid Wi-Fi sleep flapping.
type missingClient struct {
	client unifi.Client
	since  time.Time
}

// hostScanTask describes a targeted single-host probe queued on client join,
// physical port link-up, policy change, or manual UI rescan.
type hostScanTask struct {
	client       unifi.Client
	retryOnEmpty bool
	quietOnEmpty bool
}

// portLiveState captures the previous link and security configuration of a
// single physical switch port so pollDelta can emit real-time link/config events.
type portLiveState struct {
	DeviceMAC    string
	DeviceName   string
	DeviceIP     string
	PortIdx      int
	PortName     string
	Zone         string
	Up           bool
	Enabled      bool
	NativeVLAN   string
	TaggedPolicy string
	PortSecurity bool
	// PortSecurityUnknown suppresses change alerts until both scans have a confirmed setting.
	PortSecurityUnknown bool
	PoEPowerWatts       float64
	MACTableCount       int
	STPState            string
	HasUniFiPeer        bool
}

type hostRescanStatus int

const (
	hostRescanQueued hostRescanStatus = iota
	hostRescanNotFound
	hostRescanQueueFull
)

type pendingWebhook struct {
	seq         uint64
	id          string
	site        string
	diff        risk.Diff
	attempts    int
	nextAttempt time.Time
	queuedAt    time.Time
}

type persistedWebhook struct {
	ID          string    `json:"id"`
	Site        string    `json:"site"`
	Diff        risk.Diff `json:"diff"`
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"next_attempt"`
	QueuedAt    time.Time `json:"queued_at,omitempty"`
}

const (
	maxPendingWebhooks           = 64
	maxWebhookRetries            = 288
	maxWebhookAge                = 24 * time.Hour
	defaultWebhookCoalesceWindow = 15 * time.Second
)

// Engine coordinates UniFi event ingestion, targeted single-host live checks,
// periodic full reconciliation, webhook alerting, and SSE broadcasting.
type Engine struct {
	cfg            *config.Config
	opts           Options
	demoMode       bool
	ctrl           *unifi.Controller
	checkList      []*checks.Check
	scanPorts      []int
	classifier     *classify.Classifier
	cveCache       *cve.Cache
	cveIdent       *cve.Fingerprinter
	velocityMemo   map[string]cve.TargetVelocity
	velocityMemoAt time.Time
	velocityGen    uint64
	notifier       *notify.Notifier
	minNotify      checks.Severity
	logger         *slog.Logger

	startedAt time.Time
	eventMode string
	eventSeq  atomic.Int64

	// pollMu serializes UniFi delta polls so concurrent websocket + ticker polls
	// never apply an older snapshot on top of a newer one.
	pollMu sync.Mutex

	// recomputeMu serializes read-diff-save-publish so concurrent scans
	// never double-alert, roll back dashboard state, or race on state.json.
	recomputeMu sync.Mutex

	// fullScanMu serializes full scans executed on their own goroutine.
	fullScanMu sync.Mutex

	// webhookMu guards the asynchronous webhook delivery, coalescing & retry queue
	// so slow or failing webhook endpoints never stall recomputeMu or pollDelta.
	webhookMu             sync.Mutex
	pendingWebhooks       []pendingWebhook
	webhookSeq            uint64
	webhookRunning        bool
	webhookRetryBase      time.Duration
	webhookCoalesceWindow time.Duration
	coalesceGen           uint64
	coalesceCancel        context.CancelFunc
	coalescedSite         string
	coalescedEvents       []risk.AlertEvent

	// authLimiter throttles repeated failed API/dashboard auth attempts per IP.
	authLimiter authFailureLimiter

	// sessions tracks active per-login random HttpOnly session cookies.
	sessions sessionStore

	// cveSyncFn optionally overrides cve.Cache.Sync in tests.
	cveSyncFn func(ctx context.Context, cache *cve.Cache) (*cve.CacheStats, error)

	// mu protects the live state maps and the published StateSnapshot.
	mu               sync.RWMutex
	snap             *unifi.Snapshot
	deltaGen         uint64
	profilesByMAC    map[string]probe.HostProfile
	findingsByMAC    map[string][]checks.Finding
	missingClients   map[string]missingClient
	lastPorts        map[string]portLiveState
	anomalies        *anomalyTracker
	lastClasses      map[string]classify.Result
	lastPolicySig    string
	lastFwdSig       string
	fwdSigInit       bool
	policySigInit    bool
	baselineComplete bool
	lastScanError    string
	lastDiscovery    *probe.LANDiscovery
	lastDiscoveryAt  time.Time
	prevRiskState    *risk.State
	auditedSSHHosts  map[string]probe.SSHKeyAuditCacheEntry
	events           []LiveEvent
	current          StateSnapshot
	scanProgress     *ScanProgress
	lastProgressEmit time.Time
	activeScans      atomic.Int32
	fullRescanCh     chan string
	hostScanCh       chan hostScanTask
	subMu            sync.Mutex
	subscribers      map[chan LiveEvent]struct{}
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
		cfg:                   cfg,
		opts:                  opts,
		ctrl:                  ctrl,
		checkList:             checkList,
		scanPorts:             scanPorts,
		classifier:            classifier,
		cveCache:              cveCache,
		cveIdent:              cveIdent,
		notifier:              notifier,
		minNotify:             minSev,
		logger:                opts.Logger,
		startedAt:             time.Now().UTC(),
		profilesByMAC:         make(map[string]probe.HostProfile),
		findingsByMAC:         make(map[string][]checks.Finding),
		missingClients:        make(map[string]missingClient),
		lastPorts:             make(map[string]portLiveState),
		anomalies:             newAnomalyTracker(),
		lastClasses:           make(map[string]classify.Result),
		prevRiskState:         prevState,
		auditedSSHHosts:       make(map[string]probe.SSHKeyAuditCacheEntry),
		webhookCoalesceWindow: defaultWebhookCoalesceWindow,
		fullRescanCh:          make(chan string, 1),
		hostScanCh:            make(chan hostScanTask, 64),
		subscribers:           make(map[chan LiveEvent]struct{}),
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
	initPorts := snapshotPortStates(snap, e.cfg.Network)
	snap.Clients = filterOfflineWiredClients(snap.Clients, initPorts)
	e.mu.Lock()
	e.snap = snap
	if snap.Visibility == nil || snap.Visibility.PortForwardsAvailable {
		e.lastFwdSig = portForwardSignature(snap.PortForwards)
		e.fwdSigInit = true
	}
	if snap.Visibility == nil || snap.Visibility.GatewayPoliciesAvailable {
		e.lastPolicySig = firewallPolicySignature(snap.FirewallPolicies)
		e.policySigInit = true
	}
	e.lastPorts = initPorts
	e.anomalies.Seed(snap, e.lastPorts, time.Now().UTC())
	e.mu.Unlock()
	// Publish initial UniFi topology immediately WITHOUT diffing/notifying/saving
	// state, so existing host findings in uniblue-state.json are preserved until
	// the initial baseline probe finishes.
	e.recomputeAndPublish(ctx, false, nil)

	// Start single-host live scan worker pool (bounded by 2 workers to stay gentle).
	for range 2 {
		go e.hostScanWorker(ctx)
	}

	// Start single-flight full-scan worker so live delta polling continues
	// uninterrupted even while a multi-minute full LAN scan is running.
	go e.fullScanLoop(ctx)

	// Start event ingestion (WebSocket push when supported, plus 5s delta polling).
	if e.ctrl.SupportsWebSocket() {
		go e.websocketLoop(ctx)
	}
	// Queue the full LAN baseline probe asynchronously so Serve binds immediately.
	e.setScanProgress(&ScanProgress{
		Phase:   "topology",
		Label:   "Preparing initial network checkup...",
		Total:   len(snap.Clients),
		Percent: 4,
		Initial: true,
	})
	e.queueFullRescan("initial baseline")
	go e.pollAndReconcileLoop(ctx)
	e.resumePendingWebhooks(ctx)
	if !e.opts.SkipCVE && e.opts.CVERefreshInterval > 0 {
		go e.cveSyncLoop(ctx)
	}
	return nil
}

// cveSyncLoop keeps the local offline NVD+KEV cache populated and fresh in the
// background so long-running deployments (including Docker/Unraid) get CVE
// matching automatically without manual `uniblue cve sync` runs or restarts.
func (e *Engine) cveSyncLoop(ctx context.Context) {
	interval := e.opts.CVERefreshInterval
	if interval <= 0 {
		return
	}
	cache := cve.NewCache(e.cfg.CVE.CacheDir)

	initialDelay := time.Duration(0)
	if st, err := cache.Stats(); err == nil && st.VendorCount > 0 && !st.SyncedAt.IsZero() {
		age := time.Since(st.SyncedAt)
		if age < 0 {
			initialDelay = 0
		} else if age < interval {
			initialDelay = interval - age
		}
	}

	retryBackoff := 2 * time.Minute
	const maxRetryBackoff = 30 * time.Minute

	timer := time.NewTimer(initialDelay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		syncFn := e.cveSyncFn
		if syncFn == nil {
			syncFn = func(sctx context.Context, c *cve.Cache) (*cve.CacheStats, error) {
				return c.Sync(sctx, cve.SyncOptions{})
			}
		}

		prevStats, _ := cache.Stats()
		e.mu.RLock()
		alreadyLoaded := e.cveCache != nil && e.cveIdent != nil
		e.mu.RUnlock()

		if !alreadyLoaded {
			e.logger.Info("syncing local NVD + CISA KEV CVE cache", "dir", e.cfg.CVE.CacheDir)
		} else {
			e.logger.Debug("checking local NVD + CISA KEV CVE cache for updates", "dir", e.cfg.CVE.CacheDir)
		}
		stats, err := syncFn(ctx, cache)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.logger.Warn("background CVE cache sync failed; will retry", "err", err, "retry_in", retryBackoff)
			timer.Reset(retryBackoff)
			retryBackoff *= 2
			if retryBackoff > maxRetryBackoff {
				retryBackoff = maxRetryBackoff
			}
			continue
		}

		retryBackoff = 2 * time.Minute
		if alreadyLoaded && !cveStatsChanged(prevStats, stats) {
			e.logger.Debug("local CVE cache already up to date")
			timer.Reset(interval)
			continue
		}

		ident, err := cve.LoadFingerprinter(fingerprints.BuiltinFS)
		if err != nil {
			e.logger.Warn("failed to load CVE fingerprinter after sync", "err", err)
			timer.Reset(interval)
			continue
		}

		e.mu.Lock()
		e.cveCache = cache
		e.cveIdent = ident
		e.velocityMemo = nil
		e.velocityMemoAt = time.Time{}
		e.velocityGen++
		e.mu.Unlock()

		var totalCVEs, vendors, kevs int
		if stats != nil {
			totalCVEs = stats.TotalCVEs
			vendors = stats.VendorCount
			kevs = stats.KEVCount
		}
		e.logger.Info("local CVE cache ready", "cves", totalCVEs, "vendors", vendors, "kev", kevs)
		e.recomputeAndPublish(ctx, false, []LiveEvent{{
			Type:     "cve_synced",
			Severity: "info",
			Summary:  fmt.Sprintf("CVE cache updated (%d CVEs across %d vendors, %d KEV)", totalCVEs, vendors, kevs),
		}})
		timer.Reset(interval)
	}
}

func cveStatsChanged(prev, cur *cve.CacheStats) bool {
	if prev == nil || cur == nil {
		return prev != cur
	}
	if prev.TotalCVEs != cur.TotalCVEs ||
		prev.IndexedCPECVEs != cur.IndexedCPECVEs ||
		prev.VendorCount != cur.VendorCount ||
		prev.KEVCount != cur.KEVCount ||
		prev.KEVSHA != cur.KEVSHA ||
		!prev.SyncedAt.Equal(cur.SyncedAt) {
		return true
	}
	if len(prev.YearSHAs) != len(cur.YearSHAs) {
		return true
	}
	for k, v := range prev.YearSHAs {
		if cur.YearSHAs[k] != v {
			return true
		}
	}
	return false
}

// Snapshot returns a thread-safe copy of the latest StateSnapshot for HTTP handlers.
func (e *Engine) Snapshot() StateSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cp := e.current
	cp.Scanning = e.activeScans.Load() > 0 || (e.scanProgress != nil && e.scanProgress.Initial)
	cp.LastScanError = e.lastScanError
	if e.scanProgress != nil {
		sp := *e.scanProgress
		cp.ScanProgress = &sp
	}
	return cp
}

// setScanProgress updates the live scan progress snapshot and broadcasts a
// throttled, non-persisted SSE refresh signal so open dashboards update smoothly
// without cluttering the Activity event history.
func (e *Engine) setScanProgress(p *ScanProgress) {
	now := time.Now().UTC()
	e.mu.Lock()
	prevPhase := ""
	if e.scanProgress != nil {
		prevPhase = e.scanProgress.Phase
	}
	if p == nil {
		e.scanProgress = nil
		e.lastProgressEmit = now
		e.mu.Unlock()
		return
	}
	cp := *p
	// Discard stale out-of-order updates from concurrent workers within the same phase.
	if e.scanProgress != nil && e.scanProgress.Phase == cp.Phase &&
		e.scanProgress.Total == cp.Total && cp.Completed < e.scanProgress.Completed {
		e.mu.Unlock()
		return
	}
	// Clone prior stage totals so each emitted ScanProgress owns an immutable map
	// and retains completed counts across phase transitions and page reloads.
	var totals map[string]int
	if e.scanProgress != nil && len(e.scanProgress.StageTotals) > 0 {
		totals = maps.Clone(e.scanProgress.StageTotals)
	}
	if len(p.StageTotals) > 0 {
		if totals == nil {
			totals = make(map[string]int, len(p.StageTotals)+1)
		}
		maps.Copy(totals, p.StageTotals)
	}
	if cp.Phase != "" && cp.Total >= 0 {
		if totals == nil {
			totals = make(map[string]int, 1)
		}
		totals[cp.Phase] = cp.Total
	}
	cp.StageTotals = totals
	e.scanProgress = &cp
	shouldBroadcast := cp.Phase != prevPhase ||
		(cp.Total > 0 && cp.Completed >= cp.Total) ||
		now.Sub(e.lastProgressEmit) >= 250*time.Millisecond
	if shouldBroadcast {
		e.lastProgressEmit = now
		e.emitTransientLocked(LiveEvent{
			Type:     "scan_progress",
			Severity: "info",
			Time:     now,
			Summary:  cp.Label,
		})
	}
	e.mu.Unlock()
}

// emitTransientLocked fans out a live SSE hint without recording it in e.events.
func (e *Engine) emitTransientLocked(ev LiveEvent) {
	ev.ID = e.eventSeq.Add(1)
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	e.subMu.Lock()
	for ch := range e.subscribers {
		select {
		case ch <- ev:
		default:
		}
	}
	e.subMu.Unlock()
}

// TriggerFullRescan queues an asynchronous full scan if one is not already queued.
func (e *Engine) TriggerFullRescan() {
	if e.demoMode {
		e.emit(LiveEvent{
			Type:     "scan_complete",
			Severity: "info",
			Summary:  "Demo network refreshed (simulated scan, zero packets sent)",
		})
		return
	}
	e.queueFullRescan("manual rescan")
}

func (e *Engine) queueFullRescan(reason string) {
	select {
	case e.fullRescanCh <- reason:
	default:
	}
}

// TriggerHostRescan queues a targeted live probe against a single client
// identified by entity ID ("host:<mac>"), MAC address, or IPv4/IPv6 address.
func (e *Engine) TriggerHostRescan(target string) bool {
	_, st := e.triggerHostRescanStatus(target)
	return st == hostRescanQueued
}

func clientMatchesIdentifier(cl unifi.Client, query string) bool {
	q := strings.TrimSpace(query)
	if q == "" {
		return false
	}
	if strings.EqualFold(hostEntityID(cl), q) {
		return true
	}
	if cl.MAC != "" && strings.EqualFold(cl.MAC, q) {
		return true
	}
	if cl.IP != "" && strings.EqualFold(cl.IP, q) {
		return true
	}
	for _, ip := range cl.AllIPs() {
		if strings.EqualFold(ip, q) {
			return true
		}
	}
	return false
}

func (e *Engine) triggerHostRescanStatus(query string) (unifi.Client, hostRescanStatus) {
	q := strings.TrimSpace(query)
	e.mu.RLock()
	var target *unifi.Client
	if e.snap != nil && q != "" {
		for _, cl := range e.snap.Clients {
			if clientMatchesIdentifier(cl, q) {
				cp := cl
				target = &cp
				break
			}
		}
	}
	e.mu.RUnlock()
	if target == nil {
		return unifi.Client{}, hostRescanNotFound
	}
	if e.demoMode {
		e.emit(LiveEvent{
			Type:      "host_scanned",
			Severity:  "info",
			Host:      target.DisplayName(),
			IP:        target.PrimaryIP(),
			SubjectID: hostEntityID(*target),
			Summary:   fmt.Sprintf("Demo host %s (%s) rechecked (simulated, zero packets sent)", target.DisplayName(), target.PrimaryIP()),
		})
		return *target, hostRescanQueued
	}
	select {
	case e.hostScanCh <- hostScanTask{client: *target}:
		e.emit(LiveEvent{
			Type:      "host_scanning",
			Severity:  "info",
			Host:      target.DisplayName(),
			IP:        target.PrimaryIP(),
			SubjectID: hostEntityID(*target),
			Summary:   fmt.Sprintf("Rescanning %s (%s)...", target.DisplayName(), target.PrimaryIP()),
		})
		return *target, hostRescanQueued
	default:
		return *target, hostRescanQueueFull
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

// SubscribeWithReplay atomically registers an SSE subscriber and collects any
// buffered events with ID > lastEventID in chronological (ascending ID) order
// so reconnecting clients never miss events across reconnect boundaries.
func (e *Engine) SubscribeWithReplay(lastEventID int64) ([]LiveEvent, chan LiveEvent, func()) {
	ch := make(chan LiveEvent, 32)
	e.mu.RLock()
	var replay []LiveEvent
	if lastEventID > 0 && len(e.events) > 0 {
		// e.events is stored newest-first; collect matching items then reverse.
		for i := len(e.events) - 1; i >= 0; i-- {
			if e.events[i].ID > lastEventID {
				replay = append(replay, e.events[i])
			}
		}
	}
	e.subMu.Lock()
	e.subscribers[ch] = struct{}{}
	e.subMu.Unlock()
	e.mu.RUnlock()

	return replay, ch, func() {
		e.subMu.Lock()
		delete(e.subscribers, ch)
		e.subMu.Unlock()
	}
}

// fullScanLoop executes queued full scans sequentially in a dedicated goroutine
// so delta polling stays responsive during multi-minute scans, and retries a
// failed initial baseline scan with bounded exponential backoff so the UI never
// hangs indefinitely at 4%.
func (e *Engine) fullScanLoop(ctx context.Context) {
	backoff := 5 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case reason := <-e.fullRescanCh:
			err := e.runFullScan(ctx, reason)
			if err != nil && ctx.Err() == nil {
				e.logger.Error("full scan failed", "reason", reason, "err", err)
				e.mu.Lock()
				e.lastScanError = err.Error()
				e.current.LastScanError = err.Error()
				e.scanProgress = nil
				needInitialRetry := !e.baselineComplete
				e.emitTransientLocked(LiveEvent{
					Type:     "scan_error",
					Severity: "high",
					Summary:  fmt.Sprintf("Full scan failed (%s): %v", reason, err),
				})
				e.mu.Unlock()

				if needInitialRetry {
					delay := backoff
					if backoff < 60*time.Second {
						backoff *= 2
					}
					go func(d time.Duration) {
						t := time.NewTimer(d)
						select {
						case <-ctx.Done():
							t.Stop()
						case <-t.C:
							e.queueFullRescan("initial baseline retry")
						}
					}(delay)
				}
			} else if err == nil {
				backoff = 5 * time.Second
			}
		}
	}
}

// pollAndReconcileLoop runs the 5-second lightweight UniFi delta check and
// triggers periodic full reconciliation without blocking delta polls on scans.
func (e *Engine) pollAndReconcileLoop(ctx context.Context) {
	pollTicker := time.NewTicker(e.opts.PollInterval)
	defer pollTicker.Stop()
	reconcileTicker := time.NewTicker(e.opts.ReconcileInterval)
	defer reconcileTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-reconcileTicker.C:
			e.queueFullRescan("periodic reconciliation")
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
// immediately to newly appearing clients, IP/VLAN changes, departures, physical
// switch port link transitions, or firewall/port-forward changes. Serialized by
// pollMu so concurrent websocket and ticker polls never apply snapshots out of order.
func (e *Engine) pollDelta(ctx context.Context) {
	e.pollMu.Lock()
	defer e.pollMu.Unlock()

	pollCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	snap, err := e.ctrl.FetchSnapshot(pollCtx)
	if err != nil {
		if ctx.Err() == nil {
			e.logger.Warn("unifi delta poll failed", "err", err)
		}
		return
	}

	toScan := e.applySnapshotDelta(ctx, snap, time.Now().UTC())
	// Debounce newly joined or replugged hosts briefly so DHCP & daemons finish starting before probing.
	if len(toScan) > 0 {
		go func(targets []hostScanTask) {
			timer := time.NewTimer(defaultJoinDebounce)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			for _, task := range targets {
				select {
				case e.hostScanCh <- task:
				case <-ctx.Done():
					return
				}
			}
		}(toScan)
	}
}

// applySnapshotDelta diffs a newly fetched UniFi snapshot against the engine's
// live state, evicting disconnected wired clients immediately on switch link-down
// (even while UniFi still caches them), publishing the refreshed StateSnapshot
// before broadcasting SSE events, and returning any hosts queued for rescanning.
func (e *Engine) applySnapshotDelta(ctx context.Context, snap *unifi.Snapshot, now time.Time) []hostScanTask {
	e.mu.RLock()
	prevSnapHint := e.snap
	e.mu.RUnlock()
	preserveUnavailableTelemetry(prevSnapHint, snap)

	currPorts := snapshotPortStates(snap, e.cfg.Network)
	snap.Clients = filterOfflineWiredClients(snap.Clients, currPorts)

	var toScan []hostScanTask
	queuedScan := make(map[string]struct{})
	queueScan := func(cl unifi.Client, retryOnEmpty bool) {
		if cl.PrimaryIP() == "" {
			return
		}
		k := clientKey(cl)
		if _, dup := queuedScan[k]; dup {
			return
		}
		queuedScan[k] = struct{}{}
		toScan = append(toScan, hostScanTask{client: cl, retryOnEmpty: retryOnEmpty})
	}

	var pendingEvents []LiveEvent
	changed := false

	e.mu.Lock()
	prevSnap := e.snap
	preserveUnavailableTelemetry(prevSnap, snap)
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

		// Check whether a Wi-Fi client was merely sleeping within the leave grace window.
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
			clIP := cl.PrimaryIP()
			summary := fmt.Sprintf("%s joined %s (waiting for IP)", cl.DisplayName(), fallbackVLAN(cl.NetworkName))
			if clIP != "" {
				summary = fmt.Sprintf("%s joined %s (%s); queuing security scan", cl.DisplayName(), fallbackVLAN(cl.NetworkName), clIP)
			}
			pendingEvents = append(pendingEvents, LiveEvent{
				Type:      "client_joined",
				Severity:  "info",
				Host:      cl.DisplayName(),
				IP:        clIP,
				SubjectID: hostEntityID(cl),
				Summary:   summary,
			})
			if e.anomalies != nil {
				pendingEvents = append(pendingEvents, e.anomalies.EvaluateClientJoinAnomalies(cl, now)...)
			}
			queueScan(cl, true)
		case !sameClientStableIP(prev, cl) || prev.NetworkName != cl.NetworkName:
			changed = true
			delete(e.profilesByMAC, k)
			delete(e.findingsByMAC, k)
			prevIP := prev.PrimaryIP()
			clIP := cl.PrimaryIP()
			summary := fmt.Sprintf("%s changed (%s/%s -> %s/%s)", cl.DisplayName(), prevIP, fallbackVLAN(prev.NetworkName), clIP, fallbackVLAN(cl.NetworkName))
			if clIP != "" {
				summary += "; queuing security scan"
			}
			pendingEvents = append(pendingEvents, LiveEvent{
				Type:      "client_moved",
				Severity:  "medium",
				Host:      cl.DisplayName(),
				IP:        clIP,
				SubjectID: hostEntityID(cl),
				Summary:   summary,
			})
			queueScan(cl, true)
		default:
			// Update stored profile client metadata in case alias changed.
			if hp, ok := e.profilesByMAC[k]; ok {
				hp.Client = cl
				e.profilesByMAC[k] = hp
			}
		}
	}

	// Evict wired clients immediately on disconnect (they do not Wi-Fi sleep);
	// hold wireless clients briefly in missingClients to avoid sleep/roam flapping.
	for k, prev := range prevClients {
		if _, active := seenNow[k]; active {
			continue
		}
		if prev.IsWired {
			delete(e.missingClients, k)
			delete(e.profilesByMAC, k)
			delete(e.findingsByMAC, k)
			changed = true
			prevIP := prev.PrimaryIP()
			pendingEvents = append(pendingEvents, LiveEvent{
				Type:      "client_left",
				Severity:  "info",
				Host:      prev.DisplayName(),
				IP:        prevIP,
				SubjectID: hostEntityID(prev),
				Summary:   fmt.Sprintf("%s left %s (%s)", prev.DisplayName(), fallbackVLAN(prev.NetworkName), prevIP),
			})
			continue
		}
		if _, tracked := e.missingClients[k]; !tracked {
			e.missingClients[k] = missingClient{client: prev, since: now}
		}
	}

	// Evict any wireless client that has stayed absent past defaultLeaveGrace.
	for k, mc := range e.missingClients {
		if now.Sub(mc.since) >= defaultLeaveGrace {
			delete(e.missingClients, k)
			delete(e.profilesByMAC, k)
			delete(e.findingsByMAC, k)
			changed = true
			mcIP := mc.client.PrimaryIP()
			pendingEvents = append(pendingEvents, LiveEvent{
				Type:      "client_left",
				Severity:  "info",
				Host:      mc.client.DisplayName(),
				IP:        mcIP,
				SubjectID: hostEntityID(mc.client),
				Summary:   fmt.Sprintf("%s left %s (%s)", mc.client.DisplayName(), fallbackVLAN(mc.client.NetworkName), mcIP),
			})
		}
	}

	// Detect WAN port-forward or user firewall policy changes only when the
	// respective feed was actually retrieved (so temporary feed denials never
	// emit false policy_changed alerts when the feed disappears and returns).
	fwdOK := snap.Visibility == nil || snap.Visibility.PortForwardsAvailable
	polOK := snap.Visibility == nil || snap.Visibility.GatewayPoliciesAvailable
	fwdSig := portForwardSignature(snap.PortForwards)
	polSig := firewallPolicySignature(snap.FirewallPolicies)
	if fwdOK && e.fwdSigInit && fwdSig != e.lastFwdSig {
		changed = true
		pendingEvents = append(pendingEvents, LiveEvent{
			Type:     "policy_changed",
			Severity: "high",
			Summary:  "WAN port-forwarding rules changed; re-evaluating exposure surface",
		})
		// Probe any active host referenced by an enabled port forward.
		for _, pf := range snap.PortForwards {
			if !pf.Enabled || pf.FwdIP == "" {
				continue
			}
			for _, cl := range snap.Clients {
				if clientHasIP(cl, pf.FwdIP) {
					queueScan(cl, false)
					break
				}
			}
		}
	}
	if polOK && e.policySigInit && polSig != e.lastPolicySig {
		changed = true
		pendingEvents = append(pendingEvents, LiveEvent{
			Type:     "policy_changed",
			Severity: "high",
			Summary:  "UniFi firewall policies changed; re-auditing zone rules",
		})
	}

	// Detect live physical switch port link & security configuration changes.
	if len(e.lastPorts) > 0 {
		for pk, curr := range currPorts {
			prev, existed := e.lastPorts[pk]
			if !existed {
				continue
			}
			isSensitive := curr.Zone == "external" || curr.Zone == "external_uplink" || curr.Zone == "unused"
			pid := portEntityID(curr.DeviceMAC, curr.PortIdx)
			if !prev.Up && curr.Up {
				changed = true
				sev := "info"
				if isSensitive {
					sev = "critical"
				}
				pendingEvents = append(pendingEvents, LiveEvent{
					Type:      "port_link_up",
					Severity:  sev,
					Host:      fmt.Sprintf("%s Port %d", curr.DeviceName, curr.PortIdx),
					IP:        curr.DeviceIP,
					SubjectID: pid,
					Summary:   fmt.Sprintf("Physical link UP on %s Port %d (%s, zone=%s, VLAN=%s)", curr.DeviceName, curr.PortIdx, curr.PortName, curr.Zone, fallbackVLAN(curr.NativeVLAN)),
				})
				// If a wired client on this access port was never evicted (e.g. a quick
				// unplug/replug between polls), clear its stale profile/findings and
				// queue a fresh scan so patched or swapped hardware is re-verified.
				if isAccessPortZone(curr.Zone) {
					for _, cl := range snap.Clients {
						clIP := cl.PrimaryIP()
						if !cl.IsWired || cl.SwitchMAC == "" || cl.SwitchPort <= 0 || clIP == "" {
							continue
						}
						if portKey(cl.SwitchMAC, cl.SwitchPort) != pk {
							continue
						}
						k := clientKey(cl)
						if _, already := queuedScan[k]; already {
							continue
						}
						delete(e.profilesByMAC, k)
						delete(e.findingsByMAC, k)
						pendingEvents = append(pendingEvents, LiveEvent{
							Type:      "host_scanning",
							Severity:  "info",
							Host:      cl.DisplayName(),
							IP:        clIP,
							SubjectID: hostEntityID(cl),
							Summary:   fmt.Sprintf("Cable reconnected on %s Port %d; queuing security scan for %s (%s)", curr.DeviceName, curr.PortIdx, cl.DisplayName(), clIP),
						})
						queueScan(cl, true)
					}
				}
			} else if prev.Up && !curr.Up {
				changed = true
				sev := "info"
				if curr.Zone == "external" || curr.Zone == "external_uplink" {
					sev = "high"
				}
				pendingEvents = append(pendingEvents, LiveEvent{
					Type:      "port_link_down",
					Severity:  sev,
					Host:      fmt.Sprintf("%s Port %d", curr.DeviceName, curr.PortIdx),
					IP:        curr.DeviceIP,
					SubjectID: pid,
					Summary:   fmt.Sprintf("Physical link DOWN on %s Port %d (%s, zone=%s)", curr.DeviceName, curr.PortIdx, curr.PortName, curr.Zone),
				})
			}
			portProfilesOK := snap.Visibility == nil || snap.Visibility.PortProfilesAvailable
			directChanged := prev.Enabled != curr.Enabled ||
				(!prev.PortSecurityUnknown && !curr.PortSecurityUnknown && prev.PortSecurity != curr.PortSecurity) ||
				(curr.NativeVLAN != "" && prev.NativeVLAN != curr.NativeVLAN)
			profileChanged := portProfilesOK && ((prev.TaggedPolicy != "unknown" && curr.TaggedPolicy != "unknown" && prev.TaggedPolicy != curr.TaggedPolicy) || (curr.NativeVLAN == "" && prev.NativeVLAN != curr.NativeVLAN))
			if directChanged || profileChanged {
				changed = true
				sev := "medium"
				if isSensitive {
					sev = "high"
				}
				pendingEvents = append(pendingEvents, LiveEvent{
					Type:      "port_config_changed",
					Severity:  sev,
					Host:      fmt.Sprintf("%s Port %d", curr.DeviceName, curr.PortIdx),
					IP:        curr.DeviceIP,
					SubjectID: pid,
					Summary: fmt.Sprintf("Port config changed on %s Port %d (zone=%s): enabled=%v->%v, VLAN=%s->%s, tagged=%s->%s, mac_lock=%v->%v",
						curr.DeviceName, curr.PortIdx, curr.Zone,
						prev.Enabled, curr.Enabled,
						fallbackVLAN(prev.NativeVLAN), fallbackVLAN(curr.NativeVLAN),
						prev.TaggedPolicy, curr.TaggedPolicy,
						portSecurityLabel(prev.PortSecurity, prev.PortSecurityUnknown), portSecurityLabel(curr.PortSecurity, curr.PortSecurityUnknown)),
				})
			}
		}
	}

	// Evaluate physical-layer tamper anomalies (PoE drop cable swap, inline hub
	// MAC surge, STP blocking), IoT upload spikes, and site security telemetry
	// (IDS/IPS/Honeypot/Admin logs, Evil-Twin APs, VPN/WAN transitions, config drift).
	if e.anomalies != nil {
		for _, aev := range e.anomalies.EvaluatePortAnomalies(e.lastPorts, currPorts) {
			changed = true
			pendingEvents = append(pendingEvents, aev)
		}
		for _, aev := range e.anomalies.EvaluateIoTUploadSpikes(snap.Clients, e.lastClasses, now) {
			changed = true
			pendingEvents = append(pendingEvents, aev)
		}
		for _, aev := range e.anomalies.EvaluateSiteTelemetry(snap, snap.RecentLogs) {
			changed = true
			pendingEvents = append(pendingEvents, aev)
		}
	}

	e.snap = snap
	e.deltaGen++
	if fwdOK {
		e.lastFwdSig = fwdSig
		e.fwdSigInit = true
	}
	if polOK {
		e.lastPolicySig = polSig
		e.policySigInit = true
	}
	e.lastPorts = currPorts
	e.mu.Unlock()

	if changed {
		e.recomputeAndPublish(ctx, false, pendingEvents)
	} else if len(pendingEvents) > 0 {
		e.mu.Lock()
		for _, ev := range pendingEvents {
			e.emitLocked(ev)
		}
		e.mu.Unlock()
	}

	return toScan
}

// hostScanWorker processes targeted single-host live probes queued when a
// client joins, reconnects on a switch port, changes IP/VLAN, or is rescanned manually.
func (e *Engine) hostScanWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-e.hostScanCh:
			e.scanSingleHost(ctx, task)
		}
	}
}

// scanSingleHost runs gentle port probing + Nerva + YAML checks against a single
// host and updates the live state snapshot immediately.
func (e *Engine) scanSingleHost(ctx context.Context, task hostScanTask) {
	cl := task.client
	if cl.PrimaryIP() == "" {
		return
	}
	if isClientExcluded(cl, e.cfg.Network.ExcludedSet()) {
		return
	}

	e.activeScans.Add(1)
	defer e.activeScans.Add(-1)

	e.mu.RLock()
	hints := e.snap.PortHintsByIP()
	sitePrefixes := snapshotSubnets(e.snap)
	var devices []unifi.Device
	if e.snap != nil {
		devices = e.snap.Devices
	}
	reflectorIPs := snapshotReflectorIPs(e.snap)
	cacheTTL := e.opts.ReconcileInterval
	if cacheTTL <= 0 {
		cacheTTL = 30 * time.Minute
	}
	var cachedDisc *probe.LANDiscovery
	if e.lastDiscovery != nil && time.Since(e.lastDiscoveryAt) < cacheTTL {
		cachedDisc = e.lastDiscovery
	}
	e.mu.RUnlock()

	fp := probe.NewFingerprinter(e.scanPorts, 1, e.cfg.Scan.Timeout, e.cfg.Network.ExcludedSet())
	fp.SetInfrastructure(devices)
	fp.SetAllowedSubnets(sitePrefixes)
	fp.SetTrustedReflectors(reflectorIPs)
	if cachedDisc != nil {
		fp.SetCachedDiscovery(cachedDisc)
	}
	fp.SetHostPortHints(checks.PlanHostPorts([]unifi.Client{cl}, e.checkList, hints))
	profiles := fp.FingerprintAll(ctx, []unifi.Client{cl})
	if cachedDisc == nil {
		if disc := fp.Discovery(); disc != nil {
			e.mu.Lock()
			e.lastDiscovery = disc
			e.lastDiscoveryAt = time.Now().UTC()
			e.mu.Unlock()
		}
	}
	if len(profiles) == 0 {
		return
	}
	hp := profiles[0]
	enrichedSingle := []probe.HostProfile{hp.Clone()}
	attachConfiguredEnrichments(nil, enrichedSingle, e.cfg.Network)
	runner := checks.NewRunner(e.checkList, 1)
	hostCheckFindings := runner.RunHost(ctx, enrichedSingle[0])

	if ctx.Err() != nil {
		return
	}
	k := clientKey(cl)
	e.mu.Lock()
	stillMatches := false
	if e.snap != nil {
		for _, cur := range e.snap.Clients {
			if clientKey(cur) == k && cur.PrimaryIP() == cl.PrimaryIP() && cur.NetworkName == cl.NetworkName {
				stillMatches = true
				break
			}
		}
	}
	if !stillMatches {
		e.mu.Unlock()
		return
	}
	if prev, ok := e.profilesByMAC[k]; ok && prev.SSH != nil && hp.SSH != nil &&
		prev.SSH.Port == hp.SSH.Port && prev.SSH.HostKeyFingerprint != "" &&
		prev.SSH.HostKeyFingerprint == hp.SSH.HostKeyFingerprint {
		// Preserve opt-in SSH audit outcomes across single-host rescans so
		// confirmed findings are never dropped and re-alerted on the next full scan.
		hp.SSH.NoneAuthAccepted = prev.SSH.NoneAuthAccepted
		hp.SSH.BruteForceProtected = prev.SSH.BruteForceProtected
		hp.SSH.CanaryFalsePositive = prev.SSH.CanaryFalsePositive
		hp.SSH.AcceptedKeys = append([]probe.SSHAcceptedKey(nil), prev.SSH.AcceptedKeys...)
	}
	e.profilesByMAC[k] = hp
	e.findingsByMAC[k] = hostCheckFindings
	e.mu.Unlock()

	e.recomputeAndPublish(ctx, false, nil)

	// Emit a crisp scan-result event using the freshly evaluated findings
	// (avoids issuing duplicate check probes against the host).
	published := e.Snapshot()
	clIP := cl.PrimaryIP()
	var hostFindings int
	maxSev := checks.SeverityInfo
	for _, f := range published.Report.Findings {
		sameHost := (k != "" && clientKey(f.Client) == k) || (clIP != "" && strings.EqualFold(f.Client.PrimaryIP(), clIP))
		if sameHost && f.CheckID != "UB-UNIFI-PORTFWD" && f.CheckID != "UB-UNIFI-FIRMWARE" && !f.IsInventoryOnly() {
			hostFindings++
			if f.EffectiveSeverity > maxSev {
				maxSev = f.EffectiveSeverity
			}
		}
	}
	if !task.quietOnEmpty || len(hp.OpenPorts) > 0 || hostFindings > 0 {
		sev := "info"
		summary := fmt.Sprintf("Scanned %s (%s): %d open port(s), clean", cl.DisplayName(), clIP, len(hp.OpenPorts))
		if hostFindings > 0 {
			sev = maxSev.String()
			summary = fmt.Sprintf("Scanned %s (%s): %d open port(s), %d exposure(s) detected!",
				cl.DisplayName(), clIP, len(hp.OpenPorts), hostFindings)
		}
		e.emit(LiveEvent{
			Type:      "host_scanned",
			Severity:  sev,
			Host:      cl.DisplayName(),
			IP:        clIP,
			SubjectID: hostEntityID(cl),
			Summary:   summary,
		})
	}

	// Slow-booting embedded or PoE devices often bring up Ethernet link seconds
	// before their application daemons listen. Schedule one quiet follow-up probe
	// when a newly joined or replugged host initially reports zero open ports.
	if task.retryOnEmpty && len(hp.OpenPorts) == 0 && hostFindings == 0 {
		go func(target unifi.Client) {
			timer := time.NewTimer(defaultBootRetryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			e.mu.RLock()
			active := false
			if e.snap != nil {
				for _, cur := range e.snap.Clients {
					if clientKey(cur) == clientKey(target) && cur.PrimaryIP() == target.PrimaryIP() {
						active = true
						target = cur
						break
					}
				}
			}
			e.mu.RUnlock()
			if !active {
				return
			}
			select {
			case e.hostScanCh <- hostScanTask{client: target, quietOnEmpty: true}:
			case <-ctx.Done():
			}
		}(cl)
	}
}

// sameClientStableIP reports whether a and b have the same primary routing
// identity without treating IPv6 temporary privacy-address rotations on a
// dual-stack or IPv6-only host (where a stable IPv4 or non-link-local IPv6
// address remains present) as a client move.
func sameClientStableIP(a, b unifi.Client) bool {
	ipA := strings.ToLower(strings.TrimSpace(a.IP))
	ipB := strings.ToLower(strings.TrimSpace(b.IP))
	if ipA != ipB {
		return false
	}
	if ipA != "" {
		// Both carry the same IPv4 address; rotating temporary IPv6 privacy
		// addresses on the same VLAN is normal and not a client move.
		return true
	}
	// IPv6-only client: if both snapshots carry non-link-local IPv6 addresses
	// and share at least one stable address, a rotating temporary privacy
	// address (even when listed first by UniFi) is not a client move.
	routableV6 := func(cl unifi.Client) map[netip.Addr]struct{} {
		set := make(map[netip.Addr]struct{}, len(cl.IPv6))
		for _, raw := range cl.IPv6 {
			addr, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil {
				continue
			}
			addr = addr.Unmap()
			if !addr.Is6() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
				continue
			}
			set[addr] = struct{}{}
		}
		return set
	}
	setA := routableV6(a)
	setB := routableV6(b)
	if len(setA) > 0 && len(setB) > 0 {
		for addr := range setA {
			if _, ok := setB[addr]; ok {
				return true
			}
		}
		return false
	}
	return strings.EqualFold(strings.TrimSpace(a.PrimaryIP()), strings.TrimSpace(b.PrimaryIP()))
}

func clientHasIP(cl unifi.Client, target string) bool {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return false
	}
	for _, ip := range cl.AllIPs() {
		if strings.ToLower(strings.TrimSpace(ip)) == t {
			return true
		}
	}
	return false
}

// runFullScan executes a complete UniFi snapshot + uniform LAN probe sweep and
// publishes the refreshed StateSnapshot without clobbering live delta updates
// that occurred while the scan ran.
func (e *Engine) runFullScan(ctx context.Context, reason string) error {
	e.fullScanMu.Lock()
	defer e.fullScanMu.Unlock()

	e.activeScans.Add(1)
	defer e.activeScans.Add(-1)

	isInitial := e.Snapshot().LastFullScanAt.IsZero()
	e.setScanProgress(&ScanProgress{
		Phase:   "topology",
		Label:   "Reading UniFi router, switches, cables & firewall rules...",
		Percent: 5,
		Initial: isInitial,
	})

	e.mu.RLock()
	startGen := e.deltaGen
	prevSnapHint := e.snap
	var prevSSHKeys map[string]string
	if e.prevRiskState != nil {
		prevSSHKeys = e.prevRiskState.SSHHostKeys
	}
	e.mu.RUnlock()

	e.logger.Info("starting full scan", "reason", reason)
	snap, err := e.ctrl.FetchSnapshot(ctx)
	if err != nil {
		e.setScanProgress(nil)
		return err
	}
	preserveUnavailableTelemetry(prevSnapHint, snap)
	currPorts := snapshotPortStates(snap, e.cfg.Network)
	snap.Clients = filterOfflineWiredClients(snap.Clients, currPorts)
	totalClients := len(snap.Clients)

	fp := probe.NewFingerprinter(e.scanPorts, e.cfg.Scan.Concurrency, e.cfg.Scan.Timeout, e.cfg.Network.ExcludedSet())
	if err := fp.SetSSHKeyAudit(e.cfg.Scan.SSHKeyAudit); err != nil {
		e.logger.Warn("ssh key audit disabled due to key load error", "err", err)
	}
	fp.SetPreviousSSHHostKeys(prevSSHKeys)
	fp.SetAuditedSSHHostKeys(e.auditedSSHHosts)
	fp.SetInfrastructure(snap.Devices)
	fp.SetAllowedSubnets(snapshotSubnets(snap))
	fp.SetTrustedReflectors(snapshotReflectorIPs(snap))
	fp.SetHostPortHints(checks.PlanHostPorts(snap.Clients, e.checkList, snap.PortHintsByIP()))
	fp.SetProgressFunc(func(phase string, done, total int, host string) {
		switch phase {
		case "discovery":
			e.setScanProgress(&ScanProgress{
				Phase:   "discovery",
				Label:   "Listening for local service announcements (mDNS & UPnP)…",
				Total:   total,
				Percent: 10,
				Initial: isInitial,
			})
		case "probing":
			pct := 14
			if total > 0 {
				pct = 14 + (done*32)/total
			}
			e.setScanProgress(&ScanProgress{
				Phase:       "probing",
				Label:       fmt.Sprintf("Probing devices for open ports (%d of %d)…", done, total),
				Completed:   done,
				Total:       total,
				CurrentHost: host,
				Percent:     pct,
				Initial:     isInitial,
			})
		case "fingerprinting":
			pct := 46
			label := "Identifying services across discovered ports…"
			if total > 0 {
				pct = 46 + (done*18)/total
				label = fmt.Sprintf("Identifying services across discovered ports (%d of %d)…", done, total)
			}
			e.setScanProgress(&ScanProgress{
				Phase:       "fingerprinting",
				Label:       label,
				Completed:   done,
				Total:       total,
				CurrentHost: host,
				Percent:     pct,
				Initial:     isInitial,
			})
		case "fingerprinting-fallback":
			pct := 64
			label := "Checking unclassified open ports…"
			if total > 0 {
				pct = 64 + (done*4)/total
				label = fmt.Sprintf("Checking unclassified open ports (%d of %d)…", done, total)
			}
			e.setScanProgress(&ScanProgress{
				Phase:       "fingerprinting-fallback",
				Label:       label,
				Completed:   done,
				Total:       total,
				CurrentHost: host,
				Percent:     pct,
				Initial:     isInitial,
			})
		}
	})
	profiles := fp.FingerprintAll(ctx, snap.Clients)

	// Run active and passive checks once per full scan on deep-cloned enriched
	// profiles and cache per-host results so subsequent topology/policy-only
	// recomputations require ZERO device network I/O.
	enriched := make([]probe.HostProfile, len(profiles))
	for i, hp := range profiles {
		enriched[i] = hp.Clone()
	}
	attachConfiguredEnrichments(snap, enriched, e.cfg.Network)
	runner := checks.NewRunner(e.checkList, e.cfg.Scan.Concurrency)
	runner.SetProgressFunc(func(done, total int, host string) {
		pct := 68
		if total > 0 {
			pct = 68 + (done*26)/total
		}
		e.setScanProgress(&ScanProgress{
			Phase:       "checks",
			Label:       fmt.Sprintf("Running read-only security checks (%d of %d)…", done, total),
			Completed:   done,
			Total:       total,
			CurrentHost: host,
			Percent:     pct,
			Initial:     isInitial,
		})
	})
	e.setScanProgress(&ScanProgress{
		Phase:   "checks",
		Label:   fmt.Sprintf("Running read-only security checks (0 of %d)…", len(enriched)),
		Total:   len(enriched),
		Percent: 68,
		Initial: isInitial,
	})
	freshFindings := runner.RunAll(ctx, enriched)
	if ctx.Err() != nil {
		e.setScanProgress(nil)
		return ctx.Err()
	}
	byMAC := make(map[string][]checks.Finding, len(profiles))
	for _, f := range freshFindings {
		k := clientKey(f.Client)
		byMAC[k] = append(byMAC[k], f)
	}

	e.setScanProgress(&ScanProgress{
		Phase:     "evaluating",
		Label:     "Evaluating firewall isolation, risk & security bugs (CVEs)...",
		Completed: totalClients,
		Total:     totalClients,
		Percent:   96,
		Initial:   isInitial,
	})

	var scanExtraEvents []LiveEvent
	e.mu.Lock()
	adopted := e.deltaGen == startGen || e.snap == nil
	if adopted {
		// No live delta arrived while the full scan ran; preserve any telemetry
		// feeds that transiently failed and adopt the full snapshot cleanly.
		preserveUnavailableTelemetry(e.snap, snap)
		e.snap = snap
		if snap.Visibility == nil || snap.Visibility.PortForwardsAvailable {
			e.lastFwdSig = portForwardSignature(snap.PortForwards)
			e.fwdSigInit = true
		}
		if snap.Visibility == nil || snap.Visibility.GatewayPoliciesAvailable {
			e.lastPolicySig = firewallPolicySignature(snap.FirewallPolicies)
			e.policySigInit = true
		}
		e.lastPorts = currPorts
	}
	// Merge scanned host profiles/findings carefully: keep only hosts still active
	// at the same IP/network, and never overwrite a fresher per-host rescan that
	// completed while this full scan was running.
	activeByKey := make(map[string]unifi.Client, len(e.snap.Clients))
	for _, cl := range e.snap.Clients {
		activeByKey[clientKey(cl)] = cl
	}
	if adopted {
		// Evict absent wired clients immediately and wireless clients whose
		// leave-grace window has elapsed, while keeping briefly dozing/roaming
		// Wi-Fi clients intact across full-scan adoption.
		adoptNow := time.Now().UTC()
		for k, mc := range e.missingClients {
			if _, stillActive := activeByKey[k]; stillActive {
				delete(e.missingClients, k)
				continue
			}
			if !mc.client.IsWired && adoptNow.Sub(mc.since) < defaultLeaveGrace {
				continue
			}
			delete(e.missingClients, k)
			delete(e.profilesByMAC, k)
			delete(e.findingsByMAC, k)
			mcIP := mc.client.PrimaryIP()
			scanExtraEvents = append(scanExtraEvents, LiveEvent{
				Type:      "client_left",
				Severity:  "info",
				Host:      mc.client.DisplayName(),
				IP:        mcIP,
				SubjectID: hostEntityID(mc.client),
				Summary:   fmt.Sprintf("%s left %s (%s)", mc.client.DisplayName(), fallbackVLAN(mc.client.NetworkName), mcIP),
			})
		}
		for k := range e.profilesByMAC {
			if _, stillActive := activeByKey[k]; !stillActive {
				if _, inGrace := e.missingClients[k]; inGrace {
					continue
				}
				delete(e.profilesByMAC, k)
				delete(e.findingsByMAC, k)
			}
		}
		for k := range e.findingsByMAC {
			if _, stillActive := activeByKey[k]; !stillActive {
				if _, inGrace := e.missingClients[k]; inGrace {
					continue
				}
				delete(e.findingsByMAC, k)
			}
		}
	}
	for _, hp := range profiles {
		k := clientKey(hp.Client)
		cur, ok := activeByKey[k]
		if !ok || cur.PrimaryIP() != hp.Client.PrimaryIP() || cur.NetworkName != hp.Client.NetworkName {
			continue
		}
		if existing, has := e.profilesByMAC[k]; has && existing.ScannedAt.After(hp.ScannedAt) {
			continue
		}
		hp.Client = cur
		e.profilesByMAC[k] = hp
		e.findingsByMAC[k] = byMAC[k]
	}
	e.baselineComplete = true
	e.lastScanError = ""
	if disc := fp.Discovery(); disc != nil {
		e.lastDiscovery = disc
		e.lastDiscoveryAt = time.Now().UTC()
	}
	e.mu.Unlock()

	// Keep scanProgress in the "evaluating" state until recomputeAndPublish
	// atomically publishes LastFullScanAt and clears scanProgress together.
	e.recomputeAndPublish(ctx, true, scanExtraEvents)

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
// snapshot and host profiles. Any extraEvents (and newly detected findings) are
// broadcast over SSE only after e.current is atomically updated so UI clients
// immediately fetch the fresh snapshot.
func (e *Engine) recomputeAndPublish(ctx context.Context, isFullScan bool, extraEvents []LiveEvent) {
	// Serialize the entire read -> diff -> notify -> save -> publish sequence so
	// concurrent host scans, delta polls, and full scans never double-alert,
	// publish stale snapshots out of order, or race on state.json.
	e.recomputeMu.Lock()
	defer e.recomputeMu.Unlock()

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
	// Retain briefly sleeping/roaming wireless clients still within their
	// defaultLeaveGrace window so /api/v1/hosts/{id} and the dashboard do not
	// flap them out of existence with transient 404s mid-scan.
	if len(e.missingClients) > 0 {
		clients := make([]unifi.Client, 0, len(snapPtr.Clients)+len(e.missingClients))
		seenCl := make(map[string]struct{}, len(snapPtr.Clients))
		for _, cl := range snapPtr.Clients {
			clients = append(clients, cl)
			seenCl[clientKey(cl)] = struct{}{}
		}
		for k, mc := range e.missingClients {
			if _, ok := seenCl[k]; !ok {
				clients = append(clients, mc.client)
			}
		}
		snapCopy.Clients = clients
	}
	snap := &snapCopy

	profiles := make([]probe.HostProfile, 0, len(e.profilesByMAC))
	probedHostKeys := make(map[string]struct{}, len(e.profilesByMAC)*2)
	var cachedFindings []checks.Finding
	for k, hp := range e.profilesByMAC {
		profiles = append(profiles, hp.Clone())
		probedHostKeys[k] = struct{}{}
		for _, ip := range hp.Client.AllIPs() {
			probedHostKeys[strings.ToLower(strings.TrimSpace(ip))] = struct{}{}
		}
		if fl := e.findingsByMAC[k]; len(fl) > 0 {
			cachedFindings = append(cachedFindings, fl...)
		}
	}
	prevRisk := e.prevRiskState
	baselineReady := e.baselineComplete || isFullScan
	cveCache := e.cveCache
	cveIdent := e.cveIdent
	velGen := e.velocityGen
	velMemo := make(map[string]cve.TargetVelocity)
	if !e.velocityMemoAt.IsZero() && time.Since(e.velocityMemoAt) <= time.Hour {
		for k, v := range e.velocityMemo {
			velMemo[k] = v
		}
	}
	e.mu.RUnlock()

	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Client.PrimaryIP() < profiles[j].Client.PrimaryIP()
	})
	devChildren := attachConfiguredEnrichments(snap, profiles, e.cfg.Network)

	keys := prevRisk.CompareSSHHostKeys(profiles)
	rawFindings := append([]checks.Finding(nil), cachedFindings...)
	rawFindings = append(rawFindings, checks.FindingsFromProfiles(profiles, rawFindings)...)
	report := risk.Evaluate(snap, rawFindings, e.cfg.Network)
	report.SSHHostKeys = keys

	var exactCVEs, potentialCVEs []cve.ProductSummary
	var rawExactMatches []cve.Match
	var allCVEMatches []cve.Match
	var targetSignals []blast.TargetSignal
	cveLoaded := false
	cveMatched := false
	if cveCache != nil && cveIdent != nil {
		cveLoaded = true
		nowVel := time.Now().UTC()
		products := cveIdent.Identify(snap, profiles)
		targetSignals = CollectTargetSignalsCached(cveCache, products, nowVel, velMemo)
		e.mu.Lock()
		if e.velocityGen == velGen && e.cveCache == cveCache {
			e.velocityMemo = velMemo
			if e.velocityMemoAt.IsZero() || nowVel.Sub(e.velocityMemoAt) > time.Hour {
				e.velocityMemoAt = nowVel
			}
		}
		e.mu.Unlock()
		matches, err := cveCache.MatchProducts(products, cve.MatchOptions{
			MinSeverity:          checks.SeverityHigh,
			PotentialMaxAgeYears: 2,
		})
		if err != nil {
			e.logger.Warn("failed to match products against local CVE cache; preserving CVE baseline", "err", err)
		} else {
			cveMatched = true
			allCVEMatches = matches
			for _, m := range matches {
				if m.Confidence == cve.ConfidenceExact {
					rawExactMatches = append(rawExactMatches, m)
				}
			}
			for _, s := range cve.RollupMatches(matches) {
				if s.Confidence == cve.ConfidenceExact {
					exactCVEs = append(exactCVEs, s)
				} else {
					potentialCVEs = append(potentialCVEs, s)
				}
			}
		}
	}

	var classes map[string]classify.Result
	if e.classifier != nil {
		classes = e.classifier.ClassifyAll(snap, profiles)
	} else {
		classes = make(map[string]classify.Result)
	}
	topoModel := topology.Build(snap, classes, e.cfg.Network)

	// Build enriched per-client views for the dashboard.
	profileByKey := make(map[string]probe.HostProfile, len(profiles))
	for _, hp := range profiles {
		profileByKey[clientKey(hp.Client)] = hp
	}
	findingsByKey := make(map[string][]checks.Finding)
	for _, f := range report.Findings {
		if k := clientKey(f.Client); k != "" && f.CheckID != "UB-UNIFI-PORTFWD" && f.CheckID != "UB-UNIFI-FIRMWARE" && !f.IsInventoryOnly() {
			findingsByKey[k] = append(findingsByKey[k], f)
		}
	}

	excludedSet := e.cfg.Network.ExcludedSet()
	sitePrefixes := snapshotSubnets(snap)
	clientViews := make([]ClientView, 0, len(snap.Clients))
	for _, cl := range snap.Clients {
		k := clientKey(cl)
		cv := ClientView{
			Client:      cl,
			Class:       lookupClientClass(classes, cl),
			MaxSeverity: "clean",
		}
		if hp, ok := profileByKey[k]; ok {
			cv.OpenPorts = hp.OpenPorts
			if !hp.ScannedAt.IsZero() {
				ts := hp.ScannedAt
				cv.LastScannedAt = &ts
			}
		} else if reason := clientSkipReason(cl, excludedSet, sitePrefixes); reason != "" {
			cv.Skipped = true
			cv.SkipReason = reason
		}
		if fl := findingsByKey[k]; len(fl) > 0 {
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
		return clientViews[i].Client.PrimaryIP() < clientViews[j].Client.PrimaryIP()
	})

	// Diff against previous baseline for webhook alerting and live finding events
	// ONLY after the initial baseline probe has completed, so restarting `serve`
	// never wipes existing host findings from uniblue-state.json or fires a storm
	// of false "new" alerts. Advance the in-memory and on-disk baseline immediately
	// and dispatch external webhooks asynchronously so a slow or failing webhook
	// never stalls recomputeMu/pollDelta or re-emits finding_new infinitely.
	postEvents := append([]LiveEvent(nil), extraEvents...)
	nextState := prevRisk
	var webhooksToSend []pendingWebhook
	var liveEventsToPush []risk.AlertEvent
	if baselineReady {
		diff := risk.ComputeDiffWithProbed(prevRisk, snap, report, e.cfg.Network, probedHostKeys)
		var nextExactCVEs map[string]string
		var nextExactCVELastSeen map[string]time.Time
		if cveMatched {
			var newCVEs []risk.CVEAlert
			newCVEs, nextExactCVEs, nextExactCVELastSeen = diffExactCVEs(prevRisk, snap, probedHostKeys, rawExactMatches, exactCVEs)
			diff.NewCVEs = newCVEs
		}
		if prevRisk != nil {
			for _, nf := range diff.NewFindings {
				postEvents = append(postEvents, LiveEvent{
					Type:      "finding_new",
					Severity:  nf.EffectiveSeverity.String(),
					Host:      nf.Client.DisplayName(),
					IP:        nf.Client.PrimaryIP(),
					SubjectID: findingSubjectEntityID(nf, snap),
					Summary:   fmt.Sprintf("New [%s] %s: %s", strings.ToUpper(nf.EffectiveSeverity.String()), nf.CheckID, nf.Title),
				})
			}
			pushEvents := selectPushWorthyEvents(extraEvents, snap, e.cfg.Network, e.minNotify)
			if e.notifier != nil {
				if diff.HasAlerts(e.minNotify) {
					diff.Events = append(diff.Events, pushEvents...)
					webhooksToSend = splitWebhookByCVEs(snap.Site, diff, maxWebhookCVEsPerBatch)
				} else if len(pushEvents) > 0 {
					liveEventsToPush = pushEvents
				}
			}
		}
		nextState = risk.BuildStateWithPrev(prevRisk, snap, report, e.cfg.Network, probedHostKeys)
		if cveMatched {
			nextState.ExactCVEs = nextExactCVEs
			nextState.ExactCVELastSeen = nextExactCVELastSeen
		}
		// Persist any outbound alert batches to disk BEFORE advancing the
		// saved state baseline so a crash or disk write failure never loses
		// an alert. The async drainer starts right after publishing state below.
		webhookPersistOK := true
		if len(webhooksToSend) > 0 {
			if err := e.enqueueWebhooks(ctx, webhooksToSend, false); err != nil {
				webhookPersistOK = false
				nextState = prevRisk
				e.logger.Error("failed to persist pending webhooks; retaining previous baseline to prevent alert loss", "err", err)
			}
		}
		if webhookPersistOK && e.cfg != nil && e.cfg.State.Path != "" {
			if err := risk.SaveState(e.cfg.State.Path, nextState); err != nil {
				e.logger.Error("failed to persist state baseline", "path", e.cfg.State.Path, "err", err)
			}
		}
	}
	viewModel := BuildPresentationModel(snap, report, topoModel, clientViews, exactCVEs, potentialCVEs, profiles)
	AttachDeviceChildren(viewModel, devChildren)
	ctrlHost := ""
	if e.cfg != nil && e.cfg.UniFi.URL != "" {
		if u, err := url.Parse(e.cfg.UniFi.URL); err == nil {
			ctrlHost = u.Hostname()
		}
	}
	blastProfiles := AppendDeviceChildProfiles(snap, profiles, devChildren)
	blastRep, infraReps := EvaluateSiteBlast(snap, blastProfiles, rawFindings, report, e.cfg.Network, e.checkList, allCVEMatches, targetSignals, ctrlHost)
	AttachBlast(viewModel, blastRep, infraReps)

	now := time.Now().UTC()
	e.mu.Lock()
	if nextState != nil {
		e.prevRiskState = nextState
	}
	e.lastClasses = classes
	lastFull := e.current.LastFullScanAt
	if isFullScan {
		lastFull = now
		e.baselineComplete = true
		e.scanProgress = nil
		e.lastScanError = ""
	}
	eventsCopy := make([]LiveEvent, len(e.events))
	copy(eventsCopy, e.events)
	e.current = StateSnapshot{
		StartedAt:      e.startedAt,
		UpdatedAt:      now,
		LastFullScanAt: lastFull,
		LastScanError:  e.lastScanError,
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
	for _, ev := range postEvents {
		e.emitLocked(ev)
	}
	e.mu.Unlock()

	if len(webhooksToSend) > 0 {
		e.startWebhookDrainer(ctx)
	} else if len(liveEventsToPush) > 0 {
		e.enqueueLiveEvents(ctx, snap.Site, liveEventsToPush)
	}
}

func (e *Engine) pendingWebhooksPath() string {
	if e.cfg == nil {
		return ""
	}
	p := strings.TrimSpace(e.cfg.State.Path)
	if p == "" {
		return ""
	}
	return p + ".pending-webhooks.json"
}

func (e *Engine) persistPendingWebhooksLocked() error {
	path := e.pendingWebhooksPath()
	if path == "" {
		return nil
	}
	if len(e.pendingWebhooks) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			e.logger.Warn("failed to remove empty pending webhooks file", "path", path, "err", err)
			return err
		}
		return nil
	}
	out := make([]persistedWebhook, 0, len(e.pendingWebhooks))
	for _, item := range e.pendingWebhooks {
		out = append(out, persistedWebhook{
			ID:          item.id,
			Site:        item.site,
			Diff:        item.diff,
			Attempts:    item.attempts,
			NextAttempt: item.nextAttempt,
			QueuedAt:    item.queuedAt,
		})
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		e.logger.Error("failed to marshal pending webhooks", "err", err)
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			e.logger.Error("failed to create pending webhooks directory", "dir", dir, "err", err)
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".pending-webhooks-*.tmp")
	if err != nil {
		e.logger.Error("failed to create pending webhooks temp file", "path", path, "err", err)
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		e.logger.Error("failed to chmod pending webhooks temp file", "path", path, "err", err)
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		cleanup()
		e.logger.Error("failed to write pending webhooks temp file", "path", path, "err", err)
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		e.logger.Error("failed to sync pending webhooks temp file", "path", path, "err", err)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		e.logger.Error("failed to close pending webhooks temp file", "path", path, "err", err)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		e.logger.Error("failed to persist pending webhooks", "path", path, "err", err)
		return err
	}
	return nil
}

func (e *Engine) resumePendingWebhooks(ctx context.Context) {
	path := e.pendingWebhooksPath()
	var loaded []persistedWebhook
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				e.logger.Warn("failed to read persisted pending webhooks", "path", path, "err", err)
			}
		} else if len(strings.TrimSpace(string(raw))) > 0 {
			if err := json.Unmarshal(raw, &loaded); err != nil {
				e.logger.Warn("failed to parse persisted pending webhooks", "path", path, "err", err)
			}
		}
	}

	e.webhookMu.Lock()
	defer e.webhookMu.Unlock()
	if len(loaded) > 0 {
		existingIDs := make(map[string]struct{}, len(e.pendingWebhooks))
		for _, item := range e.pendingWebhooks {
			if item.id != "" {
				existingIDs[item.id] = struct{}{}
			}
		}
		now := time.Now().UTC()
		for _, pw := range loaded {
			id := strings.TrimSpace(pw.ID)
			if id == "" {
				id = notify.NewWebhookID()
			}
			if _, dup := existingIDs[id]; dup {
				continue
			}
			queuedAt := pw.QueuedAt
			if queuedAt.IsZero() {
				queuedAt = now
			}
			e.webhookSeq++
			e.pendingWebhooks = append(e.pendingWebhooks, pendingWebhook{
				seq:      e.webhookSeq,
				id:       id,
				site:     pw.Site,
				diff:     pw.Diff,
				attempts: pw.Attempts,
				queuedAt: queuedAt,
			})
			existingIDs[id] = struct{}{}
		}
		if len(e.pendingWebhooks) > maxPendingWebhooks {
			e.pendingWebhooks = e.pendingWebhooks[len(e.pendingWebhooks)-maxPendingWebhooks:]
		}
	}
	if len(e.pendingWebhooks) > 0 && !e.webhookRunning && e.notifier != nil {
		e.webhookRunning = true
		go e.drainWebhooks(ctx)
	}
}

func splitWebhookByCVEs(site string, diff risk.Diff, maxCVEs int) []pendingWebhook {
	if maxCVEs <= 0 || len(diff.NewCVEs) <= maxCVEs {
		return []pendingWebhook{{id: notify.NewWebhookID(), site: site, diff: diff}}
	}
	var out []pendingWebhook
	first := diff
	first.NewCVEs = append([]risk.CVEAlert(nil), diff.NewCVEs[:maxCVEs]...)
	out = append(out, pendingWebhook{id: notify.NewWebhookID(), site: site, diff: first})
	for off := maxCVEs; off < len(diff.NewCVEs); off += maxCVEs {
		end := off + maxCVEs
		if end > len(diff.NewCVEs) {
			end = len(diff.NewCVEs)
		}
		chunk := make([]risk.CVEAlert, end-off)
		copy(chunk, diff.NewCVEs[off:end])
		out = append(out, pendingWebhook{
			id:   notify.NewWebhookID(),
			site: site,
			diff: risk.Diff{NewCVEs: chunk},
		})
	}
	return out
}

func isLiveEventOnlyDiff(d risk.Diff) bool {
	return len(d.NewFindings) == 0 &&
		len(d.EscalatedFindings) == 0 &&
		len(d.NewTrustedClients) == 0 &&
		len(d.NewPortForwards) == 0 &&
		len(d.NewCVEs) == 0 &&
		len(d.Events) > 0
}

func isCVEOnlyDiff(d risk.Diff) bool {
	return len(d.NewFindings) == 0 &&
		len(d.EscalatedFindings) == 0 &&
		len(d.NewTrustedClients) == 0 &&
		len(d.NewPortForwards) == 0 &&
		len(d.Events) == 0 &&
		len(d.NewCVEs) > 0
}

func (e *Engine) enqueueWebhook(ctx context.Context, item pendingWebhook) {
	_ = e.enqueueWebhooks(ctx, []pendingWebhook{item}, true)
}

func (e *Engine) enqueueWebhooks(ctx context.Context, items []pendingWebhook, startDrainer bool) error {
	if len(items) == 0 {
		return nil
	}
	e.webhookMu.Lock()
	defer e.webhookMu.Unlock()
	return e.commitWebhooksLocked(ctx, items, startDrainer)
}

// commitWebhooksLocked stages items (merging any buffered coalesced live events
// into the first batch) and persists the resulting outbox in a single durable
// write. On storage failure, both pendingWebhooks and coalescedEvents remain
// untouched so the caller can retry without losing or duplicating alerts.
func (e *Engine) commitWebhooksLocked(ctx context.Context, items []pendingWebhook, startDrainer bool) error {
	previous, seq := e.pendingWebhooks, e.webhookSeq
	e.pendingWebhooks = append([]pendingWebhook(nil), previous...)
	for i, item := range items {
		if i == 0 && len(e.coalescedEvents) > 0 {
			item.diff.Events = appendUniqueAlertEvents(e.coalescedEvents, item.diff.Events)
		}
		e.stageWebhookLocked(item)
	}
	if err := e.persistPendingWebhooksLocked(); err != nil {
		e.pendingWebhooks, e.webhookSeq = previous, seq
		return err
	}
	if e.coalesceCancel != nil {
		e.coalesceCancel()
		e.coalesceCancel = nil
	}
	e.coalesceGen++
	e.coalescedEvents = nil
	e.coalescedSite = ""
	if startDrainer && !e.webhookRunning && e.notifier != nil {
		e.webhookRunning = true
		go e.drainWebhooks(ctx)
	}
	return nil
}

func (e *Engine) startWebhookDrainer(ctx context.Context) {
	e.webhookMu.Lock()
	if len(e.pendingWebhooks) > 0 && !e.webhookRunning && e.notifier != nil {
		e.webhookRunning = true
		go e.drainWebhooks(ctx)
	}
	e.webhookMu.Unlock()
}

// enqueueWebhookLocked persists a single webhook batch via commitWebhooksLocked.
func (e *Engine) enqueueWebhookLocked(ctx context.Context, item pendingWebhook, startDrainer bool) error {
	return e.commitWebhooksLocked(ctx, []pendingWebhook{item}, startDrainer)
}

// stageWebhookLocked inserts item into the in-memory pendingWebhooks slice
// while enforcing maxPendingWebhooks priority eviction rules and preserving any
// currently in-flight webhook ID at index 0.
func (e *Engine) stageWebhookLocked(item pendingWebhook) {
	if item.id == "" {
		item.id = notify.NewWebhookID()
	}
	if item.queuedAt.IsZero() {
		item.queuedAt = time.Now().UTC()
	}
	if len(e.pendingWebhooks) >= maxPendingWebhooks {
		// Never drop index 0 while drainWebhooks may be actively sending it.
		startIdx := 0
		if e.webhookRunning && len(e.pendingWebhooks) > 1 {
			startIdx = 1
		}
		if isLiveEventOnlyDiff(item.diff) {
			// Prefer merging into an unattempted non-in-flight live-event batch
			// so steady live-event bursts never evict queued diffs and never
			// mutate a batch whose webhook-id was already sent.
			merged := false
			for i := len(e.pendingWebhooks) - 1; i >= startIdx; i-- {
				if e.pendingWebhooks[i].attempts == 0 && isLiveEventOnlyDiff(e.pendingWebhooks[i].diff) && e.pendingWebhooks[i].site == item.site {
					combined := appendUniqueAlertEvents(e.pendingWebhooks[i].diff.Events, item.diff.Events)
					if len(combined) > maxCoalescedEventsPerBatch {
						combined = combined[len(combined)-maxCoalescedEventsPerBatch:]
					}
					e.pendingWebhooks[i].diff.Events = combined
					merged = true
					break
				}
			}
			if merged {
				return
			}
			// Otherwise evict the oldest non-in-flight live-event batch if one exists;
			// never evict a queued diff/finding batch for a live-event-only batch.
			evictIdx := -1
			for i := startIdx; i < len(e.pendingWebhooks); i++ {
				if isLiveEventOnlyDiff(e.pendingWebhooks[i].diff) {
					evictIdx = i
					break
				}
			}
			if evictIdx < 0 {
				e.logger.Warn("webhook queue full of state-diff alerts; dropping live-event-only batch to preserve queued findings")
				return
			}
			e.pendingWebhooks = append(e.pendingWebhooks[:evictIdx], e.pendingWebhooks[evictIdx+1:]...)
		} else if isCVEOnlyDiff(item.diff) {
			// Incoming split CVE-only batch: evict a live-event batch first,
			// then an older CVE-only batch, never evicting finding/forward/trusted
			// client batches during a mass CVE update.
			evictIdx := -1
			for i := startIdx; i < len(e.pendingWebhooks); i++ {
				if isLiveEventOnlyDiff(e.pendingWebhooks[i].diff) {
					evictIdx = i
					break
				}
			}
			if evictIdx < 0 {
				for i := startIdx; i < len(e.pendingWebhooks); i++ {
					if isCVEOnlyDiff(e.pendingWebhooks[i].diff) {
						evictIdx = i
						break
					}
				}
			}
			if evictIdx < 0 {
				e.logger.Warn("webhook queue full of higher-priority finding alerts; dropping overflow CVE-only batch")
				return
			}
			e.pendingWebhooks = append(e.pendingWebhooks[:evictIdx], e.pendingWebhooks[evictIdx+1:]...)
		} else {
			// Incoming finding/forward/trusted-client batch: evict the oldest
			// non-in-flight live-event-only batch first, then CVE-only, else startIdx.
			evictIdx := startIdx
			foundLower := false
			for i := startIdx; i < len(e.pendingWebhooks); i++ {
				if isLiveEventOnlyDiff(e.pendingWebhooks[i].diff) {
					evictIdx = i
					foundLower = true
					break
				}
			}
			if !foundLower {
				for i := startIdx; i < len(e.pendingWebhooks); i++ {
					if isCVEOnlyDiff(e.pendingWebhooks[i].diff) {
						evictIdx = i
						break
					}
				}
			}
			e.pendingWebhooks = append(e.pendingWebhooks[:evictIdx], e.pendingWebhooks[evictIdx+1:]...)
		}
	}
	e.webhookSeq++
	item.seq = e.webhookSeq
	e.pendingWebhooks = append(e.pendingWebhooks, item)
}

// enqueueLiveEvents buffers high-signal live security events for
// webhookCoalesceWindow so rapid admin/policy edits coalesce into one clean
// webhook delivery, flushing immediately if the window is zero or on shutdown.
func (e *Engine) enqueueLiveEvents(ctx context.Context, site string, events []risk.AlertEvent) {
	if len(events) == 0 || e.notifier == nil {
		return
	}
	e.webhookMu.Lock()
	window := e.webhookCoalesceWindow
	e.coalescedSite = site
	e.coalescedEvents = appendUniqueAlertEvents(e.coalescedEvents, events)
	if window <= 0 {
		if err := e.enqueueWebhookLocked(ctx, pendingWebhook{site: site}, true); err == nil {
			e.webhookMu.Unlock()
			return
		}
		window = time.Second
	}
	if e.coalesceCancel != nil {
		e.webhookMu.Unlock()
		return
	}
	e.coalesceGen++
	gen := e.coalesceGen
	waitCtx, cancel := context.WithCancel(ctx)
	e.coalesceCancel = cancel
	e.webhookMu.Unlock()

	go func() {
		timer := time.NewTimer(window)
		defer timer.Stop()
		defer cancel()
		select {
		case <-timer.C:
			e.flushCoalescedEvents(ctx, gen, true)
		case <-waitCtx.Done():
			// If parent ctx was cancelled (shutdown), persist buffered events to
			// disk without starting a new drainer so restart delivers them.
			if ctx.Err() != nil {
				e.flushCoalescedEvents(ctx, gen, false)
			}
		}
	}()
}

func (e *Engine) flushCoalescedEvents(ctx context.Context, gen uint64, startDrainer bool) {
	e.webhookMu.Lock()
	defer e.webhookMu.Unlock()
	if e.coalesceGen != gen || len(e.coalescedEvents) == 0 {
		return
	}
	e.coalesceCancel = nil
	if err := e.enqueueWebhookLocked(ctx, pendingWebhook{site: e.coalescedSite}, startDrainer); err != nil {
		e.logger.Error("failed to persist buffered webhook events", "err", err)
		if startDrainer && ctx.Err() == nil {
			timer := time.AfterFunc(time.Second, func() { e.flushCoalescedEvents(ctx, gen, ctx.Err() == nil) })
			e.coalesceCancel = func() { timer.Stop() }
		}
	}
}

func splitEventCount(summary string) (string, int) {
	s := strings.TrimSpace(summary)
	if idx := strings.LastIndex(s, " (x"); idx > 0 && strings.HasSuffix(s, ")") {
		numStr := s[idx+3 : len(s)-1]
		if n, err := strconv.Atoi(numStr); err == nil && n > 1 {
			return s[:idx], n
		}
	}
	return s, 1
}

func appendUniqueAlertEvents(dst, src []risk.AlertEvent) []risk.AlertEvent {
	idxByKey := make(map[string]int, len(dst)+len(src))
	counts := make([]int, 0, len(dst)+len(src))
	bases := make([]string, 0, len(dst)+len(src))
	out := make([]risk.AlertEvent, 0, len(dst)+len(src))
	add := func(ev risk.AlertEvent) {
		base, n := splitEventCount(ev.Summary)
		key := ev.Type + "|" + ev.Host + "|" + ev.IP + "|" + base
		if idx, dup := idxByKey[key]; dup {
			counts[idx] += n
			if ev.Severity > out[idx].Severity {
				out[idx].Severity = ev.Severity
			}
			if ev.Time.After(out[idx].Time) {
				out[idx].Time = ev.Time
			}
			out[idx].Summary = fmt.Sprintf("%s (x%d)", bases[idx], counts[idx])
			return
		}
		idxByKey[key] = len(out)
		bases = append(bases, base)
		counts = append(counts, n)
		if n > 1 {
			ev.Summary = fmt.Sprintf("%s (x%d)", base, n)
		} else {
			ev.Summary = base
		}
		out = append(out, ev)
	}
	for _, ev := range dst {
		add(ev)
	}
	for _, ev := range src {
		add(ev)
	}
	return out
}

// diffExactCVEs compares freshly matched exact-version CVEs against the
// previous baseline state, returning newly matched (or newly KEV-promoted)
// CVE alerts, the next persisted ExactCVEs map, and last-seen timestamps.
// Keys are anchored to device MAC addresses when known (falling back to IP
// only when MAC is unavailable) so DHCP renumbering does not cause re-alerts
// while a new host reusing an old IP is alerted cleanly.
func diffExactCVEs(
	prev *risk.State,
	snap *unifi.Snapshot,
	probedHostKeys map[string]struct{},
	exactMatches []cve.Match,
	exactRollups []cve.ProductSummary,
) ([]risk.CVEAlert, map[string]string, map[string]time.Time) {
	now := time.Now().UTC()
	ipToDevKey := make(map[string]string)
	activeKeys := make(map[string]struct{})
	infraKeys := make(map[string]struct{})
	if snap != nil {
		for _, d := range snap.Devices {
			dmac := strings.ToLower(strings.TrimSpace(d.MAC))
			dip := strings.ToLower(strings.TrimSpace(d.IP))
			if dmac != "" {
				activeKeys[dmac] = struct{}{}
				infraKeys[dmac] = struct{}{}
			}
			if dip != "" {
				activeKeys[dip] = struct{}{}
				infraKeys[dip] = struct{}{}
				if dmac != "" {
					ipToDevKey[dip] = dmac
				}
			}
		}
		for _, cl := range snap.Clients {
			cmac := strings.ToLower(strings.TrimSpace(cl.MAC))
			if cmac != "" {
				activeKeys[cmac] = struct{}{}
			}
			for _, ip := range cl.AllIPs() {
				if low := strings.ToLower(strings.TrimSpace(ip)); low != "" {
					activeKeys[low] = struct{}{}
					if cmac != "" {
						ipToDevKey[low] = cmac
					}
				}
			}
		}
	}

	fixedByProd := make(map[string]string, len(exactRollups))
	for _, s := range exactRollups {
		pk := fmt.Sprintf("%s|%s|%s",
			strings.ToLower(strings.TrimSpace(s.Product.HostIP)),
			strings.ToLower(strings.TrimSpace(s.Product.Label)),
			strings.ToLower(strings.TrimSpace(s.Product.Version)),
		)
		if s.MinFixedVersion != "" {
			fixedByProd[pk] = s.MinFixedVersion
		}
	}

	next := make(map[string]string, len(exactMatches))
	nextLastSeen := make(map[string]time.Time, len(exactMatches))
	migratedLegacy := make(map[string]struct{})
	var alerts []risk.CVEAlert
	seeded := prev != nil && prev.ExactCVEs != nil

	for _, m := range exactMatches {
		hostIP := strings.ToLower(strings.TrimSpace(m.Product.HostIP))
		devKey := ipToDevKey[hostIP]
		if devKey == "" {
			devKey = hostIP
		}
		label := strings.ToLower(strings.TrimSpace(m.Product.Label))
		ver := strings.ToLower(strings.TrimSpace(m.Product.Version))
		key := fmt.Sprintf("%s|%s|%s|%s", devKey, label, ver, m.Record.ID)
		legacyKey := fmt.Sprintf("%s|%s|%s|%s", hostIP, label, ver, m.Record.ID)
		status := m.Record.Severity.String()
		if m.Record.KEV {
			status += "|kev"
		}
		next[key] = status
		nextLastSeen[key] = now

		if !seeded {
			continue
		}
		prevStatus, existed := prev.ExactCVEs[key]
		if !existed && legacyKey != key {
			if legStatus, legOK := prev.ExactCVEs[legacyKey]; legOK {
				prevStatus = legStatus
				existed = true
				migratedLegacy[legacyKey] = struct{}{}
			}
		}
		kevPromoted := m.Record.KEV && !strings.HasSuffix(prevStatus, "|kev")
		if existed && !kevPromoted {
			continue
		}
		pk := fmt.Sprintf("%s|%s|%s", hostIP, label, ver)
		alerts = append(alerts, risk.CVEAlert{
			CVEID:           m.Record.ID,
			HostName:        m.Product.HostName,
			HostIP:          m.Product.HostIP,
			VLAN:            m.Product.VLAN,
			Product:         m.Product.Label,
			Version:         m.Product.Version,
			Severity:        m.Record.Severity,
			CVSS:            m.Record.CVSS,
			KEV:             m.Record.KEV,
			WANExposed:      m.Product.WANExposed,
			MinFixedVersion: fixedByProd[pk],
		})
	}

	// Carry forward exact CVE keys for offline/unprobed hosts (up to 7 days)
	// and across brief transient banner misses (up to 15 minutes) so sleeping
	// laptops or single flaky probes do not drop and re-alert existing CVEs.
	if seeded {
		for k, v := range prev.ExactCVEs {
			if _, exists := next[k]; exists {
				continue
			}
			if _, migrated := migratedLegacy[k]; migrated {
				continue
			}
			lastSeen := prev.UpdatedAt
			if prev.ExactCVELastSeen != nil {
				if ts, ok := prev.ExactCVELastSeen[k]; ok && !ts.IsZero() {
					lastSeen = ts
				}
			}
			if lastSeen.IsZero() {
				lastSeen = now
			}
			age := now.Sub(lastSeen)
			hostKey, _, _ := strings.Cut(k, "|")
			_, isActive := activeKeys[hostKey]
			_, wasProbed := probedHostKeys[hostKey]
			_, isInfra := infraKeys[hostKey]
			offlineOrUnprobed := !isActive || (probedHostKeys != nil && !wasProbed && !isInfra)
			if (offlineOrUnprobed && age <= exactCVEOfflineTTL) || age <= exactCVETransientGrace {
				next[k] = v
				nextLastSeen[k] = lastSeen
			}
		}
	}

	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].KEV != alerts[j].KEV {
			return alerts[i].KEV
		}
		if alerts[i].Severity != alerts[j].Severity {
			return alerts[i].Severity > alerts[j].Severity
		}
		if alerts[i].CVSS != alerts[j].CVSS {
			return alerts[i].CVSS > alerts[j].CVSS
		}
		if alerts[i].HostIP != alerts[j].HostIP {
			return alerts[i].HostIP < alerts[j].HostIP
		}
		return alerts[i].CVEID < alerts[j].CVEID
	})
	return alerts, next, nextLastSeen
}

// selectPushWorthyEvents filters live engine events down to high-signal
// security and edge-tamper events worthy of waking an operator or AI agent:
// admin activity, firewall/config drift, internal honeypot hits, physical edge
// tampering (external/unused port link/PoE/config changes and MAC surges),
// evil-twin Wi-Fi SSIDs, and trusted-VLAN wired/Wi-Fi medium swaps.
func selectPushWorthyEvents(events []LiveEvent, snap *unifi.Snapshot, netCfg config.NetworkConfig, minNotify checks.Severity) []risk.AlertEvent {
	if len(events) == 0 {
		return nil
	}
	isSensitivePortSummary := func(summary string) bool {
		low := strings.ToLower(summary)
		return strings.Contains(low, "zone=external") || strings.Contains(low, "zone=unused")
	}
	isTrustedSwap := func(ev LiveEvent) bool {
		if snap == nil {
			return false
		}
		for _, cl := range snap.Clients {
			if (ev.SubjectID != "" && hostEntityID(cl) == ev.SubjectID) ||
				(ev.IP != "" && clientHasIP(cl, ev.IP)) {
				return risk.IsClientOnTrustedVLAN(snap, cl, netCfg)
			}
		}
		return false
	}

	var out []risk.AlertEvent
	for _, ev := range events {
		push := false
		switch ev.Type {
		case "admin_activity", "policy_changed", "config_drift", "honeypot_hit", "wifi_evil_twin", "port_mac_surge":
			push = true
		case "port_poe_tamper":
			push = strings.EqualFold(ev.Severity, "critical") || isSensitivePortSummary(ev.Summary)
		case "port_link_up", "port_link_down", "port_config_changed":
			push = isSensitivePortSummary(ev.Summary)
		case "client_medium_swap":
			push = isTrustedSwap(ev)
		}
		if !push {
			continue
		}
		sev, err := checks.ParseSeverity(ev.Severity)
		if err != nil {
			sev = checks.SeverityMedium
		}
		if sev < minNotify {
			continue
		}
		ts := ev.Time
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		out = append(out, risk.AlertEvent{
			Type:     ev.Type,
			Severity: sev,
			Time:     ts,
			Host:     ev.Host,
			IP:       ev.IP,
			Summary:  ev.Summary,
		})
	}
	return out
}

func (e *Engine) drainWebhooks(ctx context.Context) {
	baseDelay := e.webhookRetryBase
	if baseDelay <= 0 {
		baseDelay = 5 * time.Second
	}
	for {
		e.webhookMu.Lock()
		if len(e.pendingWebhooks) == 0 {
			e.webhookRunning = false
			e.webhookMu.Unlock()
			return
		}
		item := e.pendingWebhooks[0]
		e.webhookMu.Unlock()

		if wait := time.Until(item.nextAttempt); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				e.webhookMu.Lock()
				e.webhookRunning = false
				e.webhookMu.Unlock()
				return
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			e.webhookMu.Lock()
			e.webhookRunning = false
			e.webhookMu.Unlock()
			return
		}

		// Give an already-started HTTP delivery a brief shutdown grace window so
		// a response completing concurrently with ctx cancellation finishes and
		// removes the batch from disk instead of aborting and resending on restart.
		sendCtx, cancelSend := context.WithCancel(context.Background())
		var graceTimer *time.Timer
		var graceMu sync.Mutex
		stopWatch := context.AfterFunc(ctx, func() {
			graceMu.Lock()
			graceTimer = time.AfterFunc(webhookShutdownGrace, cancelSend)
			graceMu.Unlock()
		})
		err := e.notifier.SendWithID(sendCtx, item.id, item.site, item.diff)
		stopWatch()
		graceMu.Lock()
		if graceTimer != nil {
			graceTimer.Stop()
		}
		graceMu.Unlock()
		cancelSend()

		if err == nil {
			// Always remove a successfully delivered batch even if ctx was
			// cancelled concurrently during shutdown so restart never resends it.
			e.webhookMu.Lock()
			for i := range e.pendingWebhooks {
				if e.pendingWebhooks[i].seq == item.seq {
					e.pendingWebhooks = append(e.pendingWebhooks[:i], e.pendingWebhooks[i+1:]...)
					_ = e.persistPendingWebhooksLocked()
					break
				}
			}
			if ctx.Err() != nil {
				e.webhookRunning = false
				e.webhookMu.Unlock()
				return
			}
			e.webhookMu.Unlock()
			continue
		}
		if ctx.Err() != nil {
			// Leave unsent batches persisted on disk for delivery after restart.
			e.webhookMu.Lock()
			e.webhookRunning = false
			e.webhookMu.Unlock()
			return
		}
		e.webhookMu.Lock()
		idx := -1
		for i := range e.pendingWebhooks {
			if e.pendingWebhooks[i].seq == item.seq {
				idx = i
				break
			}
		}
		var statusErr *notify.HTTPStatusError
		isPermanent := errors.As(err, &statusErr) && statusErr.Permanent()
		isTransient4xx := errors.As(err, &statusErr) && statusErr.TransientClientError()
		if isPermanent {
			e.logger.Error("webhook rejected permanently by receiver; dropping alert batch to prevent queue stall", "status", statusErr.StatusCode, "err", err)
			if idx >= 0 {
				e.pendingWebhooks = append(e.pendingWebhooks[:idx], e.pendingWebhooks[idx+1:]...)
				_ = e.persistPendingWebhooksLocked()
			}
			e.webhookMu.Unlock()
			continue
		}
		item.attempts++
		maxAttempts := maxWebhookRetries
		if isTransient4xx {
			maxAttempts = maxTransient4xxRetries
		}
		expired := item.attempts >= maxAttempts || (!item.queuedAt.IsZero() && time.Since(item.queuedAt) >= maxWebhookAge)
		if expired {
			e.logger.Error("webhook notification failed after retries; dropping alert batch", "attempts", item.attempts, "err", err)
			if idx >= 0 {
				e.pendingWebhooks = append(e.pendingWebhooks[:idx], e.pendingWebhooks[idx+1:]...)
				_ = e.persistPendingWebhooksLocked()
			}
			e.webhookMu.Unlock()
			continue
		}
		shift := item.attempts - 1
		if shift > 10 {
			shift = 10
		}
		delay := baseDelay << shift
		if delay > 5*time.Minute {
			delay = 5 * time.Minute
		}
		item.nextAttempt = time.Now().Add(delay)
		if idx >= 0 {
			e.pendingWebhooks[idx] = item
			_ = e.persistPendingWebhooksLocked()
		}
		e.logger.Error("webhook notification failed; scheduling async retry", "attempt", item.attempts, "retry_in", delay, "err", err)
		e.webhookMu.Unlock()
	}
}

// preserveUnavailableTelemetry carries forward last-known SecuritySettings,
// WLANs, and profile-governed switch port fields across transient controller
// telemetry fetch failures so temporary errors do not drop findings or fire
// false drift / port_config_changed alerts, while keeping direct per-port live
// changes (Enabled, PortSecurity, non-empty NativeNetworkName) visible.
func preserveUnavailableTelemetry(prevSnap, nextSnap *unifi.Snapshot) {
	if prevSnap == nil || nextSnap == nil || nextSnap.Visibility == nil {
		return
	}
	if !nextSnap.Visibility.SettingsAvailable && nextSnap.SecuritySettings == nil && prevSnap.SecuritySettings != nil {
		cp := *prevSnap.SecuritySettings
		nextSnap.SecuritySettings = &cp
	}
	if !nextSnap.Visibility.WLANsAvailable && len(nextSnap.WLANs) == 0 && len(prevSnap.WLANs) > 0 {
		nextSnap.WLANs = append([]unifi.WLANConfig(nil), prevSnap.WLANs...)
	}
	if !nextSnap.Visibility.PortProfilesAvailable && len(prevSnap.Devices) > 0 && len(nextSnap.Devices) > 0 {
		prevPorts := make(map[string]unifi.SwitchPort)
		for _, d := range prevSnap.Devices {
			dmac := strings.ToLower(strings.TrimSpace(d.MAC))
			for _, p := range d.Ports {
				prevPorts[portKey(dmac, p.PortIdx)] = p
			}
		}
		for di := range nextSnap.Devices {
			dmac := strings.ToLower(strings.TrimSpace(nextSnap.Devices[di].MAC))
			for pi := range nextSnap.Devices[di].Ports {
				p := &nextSnap.Devices[di].Ports[pi]
				if old, ok := prevPorts[portKey(dmac, p.PortIdx)]; ok {
					if p.ProfileManaged {
						p.Enabled = old.Enabled
						p.OpMode = old.OpMode
						p.Forward = old.Forward
						p.TaggedVLANMgmt = old.TaggedVLANMgmt
						p.NativeNetworkName = old.NativeNetworkName
						p.NativeNetworkID = old.NativeNetworkID
						p.PoEMode = old.PoEMode
						p.PortSecurityEnabled = old.PortSecurityEnabled
						if len(p.PortSecurityMACs) == 0 && len(old.PortSecurityMACs) > 0 {
							p.PortSecurityMACs = append([]string(nil), old.PortSecurityMACs...)
						}
						if p.PortConfID == "" && old.PortConfID != "" {
							p.PortConfID = old.PortConfID
						}
						continue
					}
					if p.OpMode == "" && old.OpMode != "" {
						p.OpMode = old.OpMode
					}
					if p.Forward == "" && old.Forward != "" {
						p.Forward = old.Forward
					}
					if p.TaggedVLANMgmt == "" && old.TaggedVLANMgmt != "" {
						p.TaggedVLANMgmt = old.TaggedVLANMgmt
					}
					if p.NativeNetworkName == "" && old.NativeNetworkName != "" {
						p.NativeNetworkName = old.NativeNetworkName
						if p.NativeNetworkID == "" {
							p.NativeNetworkID = old.NativeNetworkID
						}
					}
				}
			}
		}
	}
}

func lookupClientClass(classes map[string]classify.Result, cl unifi.Client) classify.Result {
	if len(classes) == 0 {
		return classify.Result{}
	}
	if cl.IP != "" {
		if r, ok := classes[cl.IP]; ok && r.Category != "" {
			return r
		}
	}
	if pip := cl.PrimaryIP(); pip != "" {
		if r, ok := classes[pip]; ok && r.Category != "" {
			return r
		}
	}
	for _, ip := range cl.AllIPs() {
		if r, ok := classes[ip]; ok && r.Category != "" {
			return r
		}
	}
	if cl.MAC != "" {
		if r, ok := classes[cl.MAC]; ok && r.Category != "" {
			return r
		}
		if r, ok := classes[strings.ToLower(cl.MAC)]; ok && r.Category != "" {
			return r
		}
	}
	return classify.Result{}
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
// Children owned by UniFi infrastructure devices (e.g., UDM Pro / UNVR Protect)
// are returned keyed by lowercase UniFi device MAC.
func attachConfiguredEnrichments(snap *unifi.Snapshot, profiles []probe.HostProfile, netCfg config.NetworkConfig) map[string][]probe.ChildDevice {
	if snap != nil && strings.TrimSpace(netCfg.SiteSupplementPath) != "" {
		_ = unifi.ApplySiteSupplement(snap, netCfg.SiteSupplementPath)
	}
	var devChildren map[string][]probe.ChildDevice
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
			if snap != nil && len(snap.Devices) > 0 {
				for mac, list := range probe.MatchDeviceBridgeChildren(snap.Devices, children) {
					if devChildren == nil {
						devChildren = make(map[string][]probe.ChildDevice)
					}
					devChildren[mac] = append(devChildren[mac], list...)
				}
			}
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
	return devChildren
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

func snapshotSubnets(snap *unifi.Snapshot) []netip.Prefix {
	if snap == nil {
		return nil
	}
	var out []netip.Prefix
	for _, n := range snap.Networks {
		if p, err := netip.ParsePrefix(strings.TrimSpace(n.Subnet)); err == nil {
			out = append(out, p.Masked())
		}
		if p, err := netip.ParsePrefix(strings.TrimSpace(n.IPv6Subnet)); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func snapshotReflectorIPs(snap *unifi.Snapshot) []string {
	if snap == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return
		}
		norm := addr.Unmap().String()
		if _, dup := seen[norm]; dup {
			return
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	for _, d := range snap.Devices {
		t := strings.ToLower(strings.TrimSpace(d.Type))
		if t == "ugw" || t == "udm" || t == "uxg" || t == "ucg" {
			add(d.IP)
		}
	}
	for _, n := range snap.Networks {
		p := strings.ToLower(strings.TrimSpace(n.Purpose))
		if p == "wan" || p == "wan2" {
			continue
		}
		if pfx, err := netip.ParsePrefix(strings.TrimSpace(n.Subnet)); err == nil {
			if pfx.Addr().IsValid() && pfx.Addr() != pfx.Masked().Addr() {
				add(pfx.Addr().String())
			}
		}
	}
	return out
}

var cgnatProbePrefix = netip.MustParsePrefix("100.64.0.0/10")

func canonicalIPSet(raw map[string]struct{}) map[string]struct{} {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(raw)*2)
	for k := range raw {
		trimmed := strings.TrimSpace(k)
		if trimmed == "" {
			continue
		}
		out[trimmed] = struct{}{}
		if addr, err := netip.ParseAddr(trimmed); err == nil {
			out[addr.Unmap().String()] = struct{}{}
		}
	}
	return out
}

func isClientExcluded(cl unifi.Client, excluded map[string]struct{}) bool {
	if len(excluded) == 0 {
		return false
	}
	canon := canonicalIPSet(excluded)
	for _, rawIP := range cl.AllIPs() {
		ip := strings.TrimSpace(rawIP)
		if ip == "" {
			continue
		}
		if _, skip := canon[ip]; skip {
			return true
		}
		if addr, err := netip.ParseAddr(ip); err == nil {
			if _, skip := canon[addr.Unmap().String()]; skip {
				return true
			}
		}
	}
	return false
}

func isAllowedClientProbeIP(rawIP string, allowedSubnets []netip.Prefix) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLoopback() || cgnatProbePrefix.Contains(addr) {
		return true
	}
	for _, pfx := range allowedSubnets {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

func clientSkipReason(cl unifi.Client, excluded map[string]struct{}, allowedSubnets []netip.Prefix) string {
	if isClientExcluded(cl, excluded) {
		return "Excluded via network.exclude_ips"
	}
	ips := cl.AllIPs()
	if len(ips) == 0 {
		return "No IP address reported by UniFi"
	}
	for _, rawIP := range ips {
		if isAllowedClientProbeIP(rawIP, allowedSubnets) {
			return ""
		}
	}
	return "Public or out-of-subnet IP address (active probing skipped)"
}

func firewallPolicySignature(pols []unifi.FirewallPolicy) string {
	parts := make([]string, 0, len(pols))
	for _, p := range pols {
		if strings.EqualFold(strings.TrimSpace(p.Origin), "SYSTEM_DEFINED") {
			continue
		}
		parts = append(parts, fmt.Sprintf(
			"%d|%s|%s|%s|%v|%s|%s|%s|%v|%v|%v|%s|%s|%s(%v,%v,%v,%v,%v,%v,%v,%v,%v,%s)->%s(%v,%v,%v,%v,%v,%v,%v,%v,%v,%s)",
			p.Index, p.Origin, p.ID, p.Name, p.Enabled, p.Action, p.IPVersion, p.Protocol, p.ProtocolNegated,
			p.ConnectionStates, p.MatchReturnTraffic, p.Schedule, p.UnsupportedReason,
			p.Source.ZoneName, p.Source.IPs, p.Source.NetworkIDs, p.Source.MACs, p.Source.Ports, p.Source.PortRanges,
			p.Source.AnyTarget, p.Source.AnyPort, p.Source.NegateTarget, p.Source.NegatePort, p.Source.UnsupportedSelector,
			p.Destination.ZoneName, p.Destination.IPs, p.Destination.NetworkIDs, p.Destination.MACs, p.Destination.Ports, p.Destination.PortRanges,
			p.Destination.AnyTarget, p.Destination.AnyPort, p.Destination.NegateTarget, p.Destination.NegatePort, p.Destination.UnsupportedSelector,
		))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}

func portKey(mac string, portIdx int) string {
	return fmt.Sprintf("%s|%d", strings.ToLower(strings.TrimSpace(mac)), portIdx)
}

func isAccessPortZone(zone string) bool {
	switch strings.ToLower(strings.TrimSpace(zone)) {
	case "wan", "uplink", "external_uplink":
		return false
	default:
		return true
	}
}

// filterOfflineWiredClients removes wired clients whose physical switch access
// port currently reports link DOWN. UniFi often keeps unplugged wired clients in
// its active client list for several minutes after the Ethernet cable is pulled.
func filterOfflineWiredClients(clients []unifi.Client, ports map[string]portLiveState) []unifi.Client {
	if len(clients) == 0 || len(ports) == 0 {
		return clients
	}
	out := make([]unifi.Client, 0, len(clients))
	for _, cl := range clients {
		if cl.IsWired && cl.SwitchMAC != "" && cl.SwitchPort > 0 {
			if p, known := ports[portKey(cl.SwitchMAC, cl.SwitchPort)]; known && !p.Up && isAccessPortZone(p.Zone) {
				continue
			}
		}
		out = append(out, cl)
	}
	return out
}

func snapshotPortStates(snap *unifi.Snapshot, netCfg config.NetworkConfig) map[string]portLiveState {
	views, _, _ := risk.AnalyzeSwitchPorts(snap, netCfg, nil, nil)
	out := make(map[string]portLiveState)
	for _, sw := range views {
		swMAC := strings.ToLower(strings.TrimSpace(sw.MAC))
		for _, p := range sw.Ports {
			key := portKey(swMAC, p.PortIdx)
			hasUniFiPeer := false
			for _, peer := range p.Peers {
				if peer.Kind == "device" {
					hasUniFiPeer = true
					break
				}
			}
			out[key] = portLiveState{
				DeviceMAC:           swMAC,
				DeviceName:          sw.Name,
				DeviceIP:            sw.IP,
				PortIdx:             p.PortIdx,
				PortName:            p.Name,
				Zone:                p.Zone,
				Up:                  p.Up,
				Enabled:             p.Enabled,
				NativeVLAN:          p.NativeVLAN,
				TaggedPolicy:        p.TaggedPolicy,
				PortSecurity:        p.PortSecurity,
				PortSecurityUnknown: p.PortSecurityUnknown,
				PoEPowerWatts:       p.PoEPowerWatts,
				MACTableCount:       p.MACTableCount,
				STPState:            p.STPState,
				HasUniFiPeer:        hasUniFiPeer,
			}
		}
	}
	return out
}
