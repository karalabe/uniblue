// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karalabe/uniblue/internal/config"
)

const (
	// controllerIntegrationV1 identifies consoles accessed via the official
	// UniFi Network Integration API v1 using an X-API-Key token.
	controllerIntegrationV1 = "integration-v1"

	// controllerUniFiOS identifies modern UniFi OS consoles (UDM Pro, Cloud
	// Gateways, newer Cloud Keys) using local cookie auth under /proxy/network.
	controllerUniFiOS = "unifi-os"

	// controllerClassic identifies legacy standalone Network controllers and
	// older Cloud Key firmware serving API calls directly at /api/s/<site>.
	controllerClassic = "classic"

	// integrationV1Prefix is the local console mount path for UniFi's official
	// Network Integration API v1.
	integrationV1Prefix = "/proxy/network/integration/v1"

	// integrationPageLimit requests up to 200 items per page to minimize round
	// trips on medium-to-large home and SMB networks.
	integrationPageLimit = 200

	// maxIntegrationPages caps pagination so a malfunctioning or hostile
	// controller reporting a huge totalCount cannot cause an endless loop.
	maxIntegrationPages = 250

	// maxControllerBodyBytes caps JSON payloads read from the controller so a
	// misconfigured URL cannot exhaust memory.
	maxControllerBodyBytes = 16 << 20

	// Bound HTTP 429 retries so one throttled feed cannot hold a poll indefinitely.
	defaultRateLimitBase = time.Second
	defaultRateLimitMax  = time.Minute
	maxRateLimitAttempts = 5

	// maxControllerConns bounds concurrent in-flight controller requests to
	// match the HTTP transport's per-host connection limit so extra callers wait
	// before pacing instead of queueing past a shared 429 cooldown.
	maxControllerConns = 4

	// defaultAuthFailCooldown prevents concurrent or repeated 401 responses from
	// hammering the controller login endpoint when credentials were revoked or
	// changed while running.
	defaultAuthFailCooldown = 30 * time.Second

	// defaultTransientReloginCooldown coalesces bursts of concurrent 401s inside
	// a single poll cycle when the controller returns transient 5xx or transport
	// errors during a restart, without engaging the full credential lockout.
	defaultTransientReloginCooldown = 3 * time.Second

	// defaultReloginSuppressTTL bounds how long a path-level or WebSocket
	// re-login suppression lasts so a transient console restart window never
	// permanently prevents re-authentication.
	defaultReloginSuppressTTL = 5 * time.Minute
)

// Controller is a read-only client for a single UniFi controller or gateway.
type Controller struct {
	// baseURL is the trimmed controller URL without a trailing slash.
	baseURL string

	// site is the UniFi site reference used for legacy/v2 API path routing (typically "default").
	site string

	// displaySite is the human-readable site name reported in Snapshot.Site,
	// preserving the user-configured site name over an opaque internalReference.
	displaySite string

	// siteID stores the resolved site UUID when speaking the Integration v1 API.
	siteID string

	// username and password are used when cookie-based login is active.
	username string
	password string

	// apiKey is sent via X-API-Key when token-based authentication is configured.
	apiKey string

	// insecureSkipVerify mirrors unifi.insecure_skip_verify for both REST and WebSocket TLS.
	insecureSkipVerify bool

	// httpClient carries TLS configuration, timeouts, and the session cookie jar.
	httpClient *http.Client

	// paceMu protects both deadlines so a new 429 also delays queued requests.
	paceMu         sync.Mutex
	nextRequestAt  time.Time
	rateLimitUntil time.Time
	requestDelay   time.Duration
	rateLimitBase  time.Duration
	rateLimitMax   time.Duration
	// paceSlot gives one paced caller at a time the next slot. Cancelled polls
	// can leave the queue without reserving slots that nobody will use.
	paceSlot chan struct{}
	// inFlight caps concurrent requests before waitTurn so no caller queues
	// inside http.Transport and slips past a shared 429 cooldown.
	inFlight chan struct{}

	// authMu guards apiPrefix, controllerType, site, displaySite, siteID, csrfToken,
	// authEpoch, wsReloginSuppressedUntil, unauthPaths, and unsupportedPaths.
	authMu sync.RWMutex

	// loginMu serializes Login/relogin calls so concurrent 401s re-authenticate once
	// and failed re-logins share a cooldown window.
	loginMu sync.Mutex
	// authFailCooldown, transientReloginCooldown, and reloginSuppressTTL are
	// optional duration overrides (used in tests) that default to the package
	// default constants when zero.
	authFailCooldown         time.Duration
	transientReloginCooldown time.Duration
	reloginSuppressTTL       time.Duration
	// authFailCooldownUntil and lastLoginErr cache the active relogin backoff
	// deadline and error under loginMu.
	authFailCooldownUntil time.Time
	lastLoginErr          error

	// authEpoch increments on every completed Login so single-flight relogin callers
	// know whether another goroutine already refreshed the session.
	authEpoch uint64

	// wsReloginSuppressedUntil bounds how long WebSocket upgrade rejections skip
	// re-login after a fresh re-authentication did not yet yield a successful
	// handshake, preventing login loops without permanently freezing recovery.
	wsReloginSuppressedUntil time.Time

	// unauthPaths records REST paths that still returned 401 immediately after a
	// fresh re-login along with their suppression expiry time, avoiding repeated
	// re-logins on every poll while automatically recovering after a restart.
	unauthPaths map[string]time.Time

	// unsupportedPaths caches denials of optional legacy feeds for this API-key
	// session until their TTL expires so snapshots keep reporting the original
	// status without hammering unsupported endpoints on every poll.
	unsupportedPaths map[string]cachedDenial

	// apiPrefix is "/proxy/network" for UniFi OS consoles or "" for classic
	// controllers, discovered automatically during Login.
	apiPrefix string

	// controllerType records which API flavor was detected during Login.
	controllerType string

	// csrfToken stores the X-CSRF-Token returned by UniFi OS during login.
	csrfToken string
}

// New constructs a Controller from the user's UniFi configuration. Call Login
// before FetchSnapshot (or let FetchSnapshot call it automatically).
func New(cfg config.UniFiConfig) (*Controller, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("init cookie jar: %w", err)
	}

	baseURL := strings.TrimRight(cfg.URL, "/")
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse controller url: %w", err)
	}

	transport := &http.Transport{
		MaxIdleConnsPerHost: maxControllerConns,
		MaxConnsPerHost:     maxControllerConns,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // local gateways typically serve self-signed certs
		},
	}

	return &Controller{
		baseURL:            baseURL,
		site:               cfg.Site,
		displaySite:        strings.TrimSpace(cfg.Site),
		username:           cfg.Username,
		password:           cfg.Password,
		apiKey:             cfg.APIKey,
		requestDelay:       cfg.RequestDelay,
		paceSlot:           make(chan struct{}, 1),
		inFlight:           make(chan struct{}, maxControllerConns),
		rateLimitBase:      defaultRateLimitBase,
		rateLimitMax:       defaultRateLimitMax,
		insecureSkipVerify: cfg.InsecureSkipVerify,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Jar:       jar,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("stopped after 5 redirects")
				}
				if !sameOrigin(req.URL, parsedBase) {
					return fmt.Errorf("refusing cross-host redirect to %s://%s", req.URL.Scheme, req.URL.Host)
				}
				return nil
			},
		},
	}, nil
}

func (c *Controller) currentControllerType() string {
	c.authMu.RLock()
	defer c.authMu.RUnlock()
	return c.controllerType
}

func (c *Controller) sessionPrefixAndSite() (string, string) {
	c.authMu.RLock()
	defer c.authMu.RUnlock()
	return c.apiPrefix, c.site
}

func (c *Controller) snapshotSiteName() string {
	c.authMu.RLock()
	defer c.authMu.RUnlock()
	if c.displaySite != "" {
		return c.displaySite
	}
	return c.site
}

func (c *Controller) currentSiteID() string {
	c.authMu.RLock()
	defer c.authMu.RUnlock()
	return c.siteID
}

func (c *Controller) currentCSRFToken() string {
	c.authMu.RLock()
	defer c.authMu.RUnlock()
	return c.csrfToken
}

func (c *Controller) currentCSRFTokenAndEpoch() (string, uint64) {
	c.authMu.RLock()
	defer c.authMu.RUnlock()
	return c.csrfToken, c.authEpoch
}

func (c *Controller) setCSRFToken(tok string) {
	c.authMu.Lock()
	c.csrfToken = tok
	c.authMu.Unlock()
}

func (c *Controller) setCSRFTokenIfEpoch(epoch uint64, tok string) {
	c.authMu.Lock()
	if c.authEpoch == epoch {
		c.csrfToken = tok
	}
	c.authMu.Unlock()
}

func (c *Controller) currentAuthEpoch() uint64 {
	c.authMu.RLock()
	defer c.authMu.RUnlock()
	return c.authEpoch
}

func (c *Controller) canRelogin() bool {
	return c.apiKey == "" && c.username != "" && c.password != ""
}

func (c *Controller) authFailCooldownDuration() time.Duration {
	if c.authFailCooldown > 0 {
		return c.authFailCooldown
	}
	return defaultAuthFailCooldown
}

func (c *Controller) transientReloginCooldownDuration() time.Duration {
	if c.transientReloginCooldown > 0 {
		return c.transientReloginCooldown
	}
	return defaultTransientReloginCooldown
}

func (c *Controller) reloginSuppressTTLDuration() time.Duration {
	if c.reloginSuppressTTL > 0 {
		return c.reloginSuppressTTL
	}
	return defaultReloginSuppressTTL
}

func (c *Controller) shouldReloginWS() bool {
	c.authMu.RLock()
	defer c.authMu.RUnlock()
	return c.wsReloginSuppressedUntil.IsZero() || !time.Now().Before(c.wsReloginSuppressedUntil)
}

func (c *Controller) markWSReloginSuppressed() {
	ttl := c.reloginSuppressTTLDuration()
	c.authMu.Lock()
	c.wsReloginSuppressedUntil = time.Now().Add(ttl)
	c.authMu.Unlock()
}

func (c *Controller) clearWSReloginSuppressed() {
	c.authMu.Lock()
	c.wsReloginSuppressedUntil = time.Time{}
	c.authMu.Unlock()
}

func (c *Controller) isPathUnauthorized(path string) bool {
	c.authMu.RLock()
	defer c.authMu.RUnlock()
	if len(c.unauthPaths) == 0 {
		return false
	}
	until, ok := c.unauthPaths[path]
	return ok && time.Now().Before(until)
}

func (c *Controller) markPathUnauthorized(path string) {
	ttl := c.reloginSuppressTTLDuration()
	c.authMu.Lock()
	if c.unauthPaths == nil {
		c.unauthPaths = make(map[string]time.Time)
	}
	c.unauthPaths[path] = time.Now().Add(ttl)
	c.authMu.Unlock()
}

func (c *Controller) clearPathUnauthorized(path string) {
	c.authMu.Lock()
	delete(c.unauthPaths, path)
	c.authMu.Unlock()
}

func (c *Controller) resetReloginSuppressions() {
	c.authMu.Lock()
	c.wsReloginSuppressedUntil = time.Time{}
	c.unauthPaths = nil
	c.authMu.Unlock()
}

// shouldActivateAuthCooldown reports whether a failed login error represents an
// actual controller authentication or rate-limit rejection (HTTP 401/403/429 or
// invalid credentials) rather than a caller timeout, cancellation, or transient
// transport/server failure.
func shouldActivateAuthCooldown(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return hasAuthRejectionError(err)
}

// hasAuthRejectionError recursively inspects err (including joined/wrapped
// errors) for HTTP 401/403/429 responses, credential-rejection HTTP 400
// messages, or UniFi API envelope authentication/permission errors.
func hasAuthRejectionError(err error) bool {
	if err == nil {
		return false
	}
	if httpErr, ok := err.(*httpStatusError); ok {
		switch httpErr.status {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
			return true
		case http.StatusBadRequest:
			msg := strings.ToLower(strings.TrimSpace(httpErr.apiMsg))
			if strings.Contains(msg, "invalid") || strings.Contains(msg, "credential") ||
				strings.Contains(msg, "password") || strings.Contains(msg, "unauth") {
				return true
			}
		}
	}
	if apiErr, ok := err.(*apiEnvelopeError); ok {
		msg := strings.ToLower(strings.TrimSpace(apiErr.msg))
		if strings.Contains(msg, "invalid") || strings.Contains(msg, "credential") ||
			strings.Contains(msg, "password") || strings.Contains(msg, "unauth") ||
			strings.Contains(msg, "nopermission") {
			return true
		}
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		for _, sub := range multi.Unwrap() {
			if hasAuthRejectionError(sub) {
				return true
			}
		}
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		return hasAuthRejectionError(single.Unwrap())
	}
	return false
}

// relogin performs single-flight session re-authentication under loginMu.
// Callers whose seenEpoch is already stale return nil immediately because
// another goroutine refreshed the session; failures enter either the full
// credential-rejection cooldown or a short burst cooldown for transient 5xx
// and transport errors while leaving caller-cancelled contexts unpenalized.
func (c *Controller) relogin(ctx context.Context, seenEpoch uint64) error {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	if c.currentAuthEpoch() != seenEpoch {
		return nil
	}
	now := time.Now()
	if !c.authFailCooldownUntil.IsZero() && now.Before(c.authFailCooldownUntil) && c.lastLoginErr != nil {
		return c.lastLoginErr
	}
	if err := c.loginLocked(ctx); err != nil {
		if shouldActivateAuthCooldown(ctx, err) {
			c.lastLoginErr = err
			c.authFailCooldownUntil = time.Now().Add(c.authFailCooldownDuration())
		} else if (ctx == nil || ctx.Err() == nil) &&
			!errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) {
			// Apply a brief burst cooldown for transient controller/server 5xx
			// failures so concurrent 401s in one poll cycle coalesce to a single
			// login attempt while keeping caller-canceled contexts unpenalized.
			c.lastLoginErr = err
			c.authFailCooldownUntil = time.Now().Add(c.transientReloginCooldownDuration())
		}
		return err
	}
	c.lastLoginErr = nil
	c.authFailCooldownUntil = time.Time{}
	return nil
}

// Login authenticates against the controller and auto-detects the appropriate
// API flavor:
//   - If an API key is configured, it prefers the official Integration v1 API
//     (/proxy/network/integration/v1) and resolves the site UUID.
//   - Otherwise it authenticates with local credentials against UniFi OS
//     (/api/auth/login) and falls back to classic controllers (/api/login).
func (c *Controller) Login(ctx context.Context) error {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	if err := c.loginLocked(ctx); err != nil {
		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			err = fmt.Errorf("%w (set unifi.insecure_skip_verify: true if this console uses a self-signed certificate)", err)
		}
		return err
	}
	c.lastLoginErr = nil
	c.authFailCooldownUntil = time.Time{}
	c.resetReloginSuppressions()
	return nil
}

// loginLocked executes authentication while the caller holds loginMu,
// dispatching to API-key resolution or local cookie login with UniFi OS
// (/api/auth/login) and classic (/api/login) auto-detection.
func (c *Controller) loginLocked(ctx context.Context) error {
	if c.apiKey != "" {
		return c.loginWithAPIKey(ctx)
	}

	knownType := c.currentControllerType()
	if knownType == controllerClassic {
		if _, classicErr := c.postLogin(ctx, "/api/login"); classicErr != nil {
			return fmt.Errorf("classic unifi login failed: %w", classicErr)
		}
		return c.finishSessionLogin(ctx, "", controllerClassic)
	}

	// Attempt UniFi OS authentication first (UDM Pro / Cloud Gateway / modern
	// Cloud Key). On initial detection, a 404 (or 400/401/405 on self-hosted
	// Network apps that do not serve /api/auth/login) falls back to /api/login.
	// Once UniFi OS has already been detected, avoid hammering /api/login on a
	// 401 credential failure.
	status, uosErr := c.postLogin(ctx, "/api/auth/login")
	if uosErr == nil {
		return c.finishSessionLogin(ctx, "/proxy/network", controllerUniFiOS)
	}
	if (status >= 200 && status < 300) || status == http.StatusTooManyRequests || status >= 500 || status == 0 {
		return fmt.Errorf("unifi-os login failed: %w", uosErr)
	}
	if knownType == controllerUniFiOS && status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
		return fmt.Errorf("unifi-os login failed: %w", uosErr)
	}

	if _, classicErr := c.postLogin(ctx, "/api/login"); classicErr != nil {
		if status == http.StatusNotFound {
			return fmt.Errorf("classic unifi login failed: %w", classicErr)
		}
		return fmt.Errorf("unifi-os login failed: %w (classic fallback: %w)", uosErr, classicErr)
	}
	return c.finishSessionLogin(ctx, "", controllerClassic)
}

// loginWithAPIKey resolves the configured site against UniFi's official Network
// Integration API v1 (/proxy/network/integration/v1/sites). If that endpoint is
// unavailable (e.g., an older controller behind an API key proxy), it falls
// back to probing legacy REST prefixes.
func (c *Controller) loginWithAPIKey(ctx context.Context) error {
	sites, err := fetchAllPages[integrationSite](ctx, c, integrationV1Prefix+"/sites")
	if err == nil {
		_, currentSite := c.sessionPrefixAndSite()
		site, resolveErr := resolveIntegrationSite(sites, currentSite)
		if resolveErr != nil {
			return resolveErr
		}
		c.authMu.Lock()
		c.siteID = site.ID
		if ref := strings.TrimSpace(site.InternalReference); ref != "" {
			c.site = ref
		}
		if c.displaySite == "" {
			c.displaySite = firstNonEmpty(site.Name, site.InternalReference, site.ID)
		} else if strings.EqualFold(c.displaySite, site.ID) && strings.TrimSpace(site.Name) != "" {
			c.displaySite = strings.TrimSpace(site.Name)
		}
		c.controllerType = controllerIntegrationV1
		c.apiPrefix = "/proxy/network"
		c.unsupportedPaths = make(map[string]cachedDenial)
		c.authEpoch++
		c.authMu.Unlock()
		return nil
	}

	// Fall back to legacy site REST endpoints only if the official integration
	// endpoint is absent (404); surface auth errors directly so bad keys are obvious.
	var httpErr *httpStatusError
	if !errors.As(err, &httpErr) || httpErr.status != http.StatusNotFound {
		return fmt.Errorf("unifi integration api login failed: %w", err)
	}

	// These probes select the primary API for the new session. A denial from
	// an earlier Integration v1 enrichment attempt must not skip discovery.
	c.authMu.Lock()
	c.unsupportedPaths = nil
	c.authMu.Unlock()
	probes := []struct {
		prefix string
		kind   string
	}{
		{prefix: "/proxy/network", kind: controllerUniFiOS},
		{prefix: "", kind: controllerClassic},
	}
	var lastErr error
	_, currentSite := c.sessionPrefixAndSite()
	for _, p := range probes {
		var out apiEnvelope[rawNetwork]
		if probeErr := c.getJSON(ctx, p.prefix+fmt.Sprintf("/api/s/%s/rest/networkconf", url.PathEscape(currentSite)), &out); probeErr == nil {
			c.authMu.Lock()
			c.apiPrefix, c.controllerType = p.prefix, p.kind
			c.authEpoch++
			c.authMu.Unlock()
			return nil
		} else {
			lastErr = probeErr
		}
	}
	return fmt.Errorf("unifi api key probe failed: %w", errors.Join(err, lastErr))
}

// resolveIntegrationSite matches the user's configured site string against a
// site's UUID, internalReference (typically "default"), or display name.
func resolveIntegrationSite(sites []integrationSite, wanted string) (integrationSite, error) {
	if len(sites) == 0 {
		return integrationSite{}, errors.New("unifi integration api returned no sites")
	}
	want := strings.ToLower(strings.TrimSpace(wanted))
	if want != "" {
		for _, site := range sites {
			if strings.EqualFold(site.ID, want) || strings.EqualFold(site.InternalReference, want) {
				return site, nil
			}
		}
		var match *integrationSite
		for i := range sites {
			if strings.EqualFold(sites[i].Name, want) {
				if match != nil {
					return integrationSite{}, errors.New("ambiguous site display name")
				}
				match = &sites[i]
			}
		}
		if match != nil {
			return *match, nil
		}
	}
	// Single-site consoles often name their sole site something custom while
	// users leave config.yaml at the default "default".
	if len(sites) == 1 && (want == "" || want == "default") {
		return sites[0], nil
	}
	names := make([]string, 0, len(sites))
	for _, s := range sites {
		names = append(names, fmt.Sprintf("%s (ref=%s, id=%s)", s.Name, s.InternalReference, s.ID))
	}
	return integrationSite{}, fmt.Errorf("site %q not found; available sites: %s", wanted, strings.Join(names, ", "))
}

// postLogin submits local credentials to path and stores any CSRF token
// returned by the controller. It returns the HTTP status code so callers can
// distinguish 404 (wrong controller flavor) from credential errors.
func (c *Controller) postLogin(ctx context.Context, path string) (int, error) {
	payload, err := json.Marshal(map[string]string{
		"username": c.username,
		"password": c.password,
	})
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, body, err := c.readResponse(req, path, false)
	if resp == nil {
		return 0, err
	}
	if err != nil {
		return resp.StatusCode, err
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 {
		if !json.Valid(trimmed) || trimmed[0] != '{' {
			return resp.StatusCode, errors.New("invalid login JSON object")
		}
		if err := checkAPIEnvelopeError(path, trimmed); err != nil {
			return resp.StatusCode, err
		}
	}
	if token := resp.Header.Get("X-CSRF-Token"); token != "" {
		c.setCSRFToken(token)
	}
	return resp.StatusCode, nil
}

// FetchSnapshot collects a point-in-time inventory and security posture
// snapshot from the controller, logging in automatically if no session is
// active yet. Depending on the detected API flavor, it dispatches to either
// Integration API v1 or legacy/v2 endpoints (cookie-authenticated, or using
// API-key fallback after an Integration API 404), concurrently
// fetching clients, infrastructure devices, networks, port forwards, firewall
// zones and policies, switch ACLs, and best-effort site telemetry (WLANs,
// rogue APs, security settings, WAN/VPN health, historical clients, and recent
// logs) while recording any unavailable feeds in Snapshot.Visibility.
func (c *Controller) FetchSnapshot(ctx context.Context) (*Snapshot, error) {
	if c.currentControllerType() == "" {
		if err := c.Login(ctx); err != nil {
			return nil, err
		}
	}
	var snap *Snapshot
	var err error
	if c.currentControllerType() == controllerIntegrationV1 {
		snap, err = c.fetchIntegrationSnapshot(ctx)
	} else {
		snap, err = c.fetchLegacySnapshot(ctx)
	}
	if err == nil && ctx.Err() != nil {
		// Feeds read after the deadline degrade to empty, so the snapshot is incomplete.
		return nil, ctx.Err()
	}
	if err == nil {
		// Refresh local addresses alongside inventory so DHCP changes reach every report consumer.
		addrs, _ := net.InterfaceAddrs()
		snap.ScannerIPs = localScannerIPs(addrs)
	}
	return snap, err
}

// localScannerIPs keeps addresses that could identify the scanner in routed IPS logs.
// An incomplete interface inventory leaves unmatched sources at their controller severity.
func localScannerIPs(addrs []net.Addr) []string {
	var ips []string
	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if ip.IsGlobalUnicast() {
			ips = append(ips, ip.String())
		}
	}
	slices.Sort(ips)
	return slices.Compact(ips)
}

// fetchIntegrationSnapshot queries UniFi's official Network Integration API v1
// endpoints concurrently with full pagination and resolves client VLANs via
// subnet CIDR matching when the client record omits network metadata.
func (c *Controller) fetchIntegrationSnapshot(ctx context.Context) (*Snapshot, error) {
	type clientsRes struct {
		items []integrationClient
		err   error
	}
	type devicesRes struct {
		items []integrationDevice
		err   error
	}
	type networksRes struct {
		items []integrationNetwork
		err   error
	}
	type forwardsRes struct {
		items []rawPortForward
		err   error
	}
	type zonesRes struct {
		items []integrationFirewallZone
		err   error
	}
	type policiesRes struct {
		items []integrationFirewallPolicy
		err   error
	}
	type aclsRes struct {
		items []integrationACLRule
		err   error
	}
	type tmlRes struct {
		items []integrationTrafficMatchingList
		err   error
	}
	type legacyClientsRes struct {
		items []rawClient
		err   error
	}
	type legacyDevicesRes struct {
		items []rawDevice
		err   error
	}

	clientsCh := make(chan clientsRes, 1)
	devicesCh := make(chan devicesRes, 1)
	networksCh := make(chan networksRes, 1)
	forwardsCh := make(chan forwardsRes, 1)
	zonesCh := make(chan zonesRes, 1)
	policiesCh := make(chan policiesRes, 1)
	aclsCh := make(chan aclsRes, 1)
	tmlCh := make(chan tmlRes, 1)
	legacyClientsCh := make(chan legacyClientsRes, 1)
	legacyDevicesCh := make(chan legacyDevicesRes, 1)
	telemetryCh := make(chan siteTelemetry, 1)

	apiPrefix, site := c.sessionPrefixAndSite()
	site = url.PathEscape(site)
	legacyBase := apiPrefix + "/api/s/" + site + "/"
	legacyNetworks := asyncFeed(func() ([]rawNetwork, error) { return getLegacyRows[rawNetwork](ctx, c, legacyBase+"rest/networkconf") })
	groupCh := asyncFeed(func() ([]firewallGroup, error) {
		return getLegacyRows[firewallGroup](ctx, c, legacyBase+"rest/firewallgroup")
	})
	siteBase := fmt.Sprintf("%s/sites/%s", integrationV1Prefix, url.PathEscape(c.currentSiteID()))

	go func() {
		telemetryCh <- c.fetchSiteTelemetry(ctx)
	}()

	go func() {
		items, err := fetchAllPages[integrationClient](ctx, c, siteBase+"/clients")
		clientsCh <- clientsRes{items: items, err: err}
	}()
	go func() {
		items, err := fetchAllPages[integrationDevice](ctx, c, siteBase+"/devices")
		devicesCh <- devicesRes{items: items, err: err}
	}()
	go func() {
		items, err := fetchAllPages[integrationNetwork](ctx, c, siteBase+"/networks")
		networksCh <- networksRes{items: items, err: err}
	}()
	go func() {
		// Port forwards are not yet exposed under /integration/v1 on all versions;
		// opportunistically attempt the legacy endpoint and record failures in Visibility.
		var env apiEnvelope[rawPortForward]
		if err := c.getJSON(ctx, apiPrefix+fmt.Sprintf("/api/s/%s/rest/portforward", site), &env); err == nil {
			forwardsCh <- forwardsRes{items: env.Data}
			return
		} else {
			forwardsCh <- forwardsRes{err: err}
		}
	}()
	go func() {
		// Zone-Based Firewall endpoints exist on UniFi Network 9+; preserve errors
		// so downstream isolation evaluation distinguishes unavailable telemetry
		// from an empty policy table.
		items, err := fetchAllPages[integrationFirewallZone](ctx, c, siteBase+"/firewall/zones")
		zonesCh <- zonesRes{items: items, err: err}
	}()
	go func() {
		items, err := fetchAllPages[integrationFirewallPolicy](ctx, c, siteBase+"/firewall/policies")
		policiesCh <- policiesRes{items: items, err: err}
	}()
	go func() {
		// Switch ACL rules are exposed under Integration API v1 on UniFi Network 9+.
		// Preserve errors (e.g., 404 on older controllers) so SwitchACLCoverage
		// distinguishes an empty ACL table from unavailable telemetry.
		items, err := fetchAllPages[integrationACLRule](ctx, c, siteBase+"/acl-rules")
		aclsCh <- aclsRes{items: items, err: err}
	}()
	go func() {
		// Traffic Matching Lists (Network Lists / Port Lists / IP Lists) resolve
		// TRAFFIC_MATCHING_LIST references inside Zone-Based Firewall policies.
		items, err := fetchAllPages[integrationTrafficMatchingList](ctx, c, siteBase+"/traffic-matching-lists")
		tmlCh <- tmlRes{items: items, err: err}
	}()
	go func() {
		// Opportunistically fetch legacy stat/sta to enrich Integration v1 clients
		// with true DHCP hostnames, OUI strings, Wi-Fi SSIDs, and switch port links.
		var env apiEnvelope[rawClient]
		err := c.getJSON(ctx, apiPrefix+fmt.Sprintf("/api/s/%s/stat/sta", site), &env)
		legacyClientsCh <- legacyClientsRes{items: env.Data, err: err}
	}()
	go func() {
		// Opportunistically fetch legacy stat/device to attach physical LLDP uplinks and switch ports.
		var env apiEnvelope[rawDevice]
		err := c.getJSON(ctx, apiPrefix+fmt.Sprintf("/api/s/%s/stat/device", site), &env)
		legacyDevicesCh <- legacyDevicesRes{items: env.Data, err: err}
	}()

	cr := <-clientsCh
	dr := <-devicesCh
	nr := <-networksCh
	fr := <-forwardsCh
	zr := <-zonesCh
	pr := <-policiesCh
	ar := <-aclsCh
	tr := <-tmlCh
	lcr := <-legacyClientsCh
	ldr := <-legacyDevicesCh

	ln, gr := <-legacyNetworks, <-groupCh
	// Older Network versions with Integration v1 do not serve /networks (404);
	// fall back to legacy rest/networkconf rows when available, or record the
	// missing networks feed without aborting the rest of the snapshot.
	var netHTTP *httpStatusError
	legacyFallback := errors.As(nr.err, &netHTTP) && netHTTP.status == http.StatusNotFound
	var networksMissingErr error
	if legacyFallback {
		if ln.err == nil {
			for _, r := range ln.items {
				nr.items = append(nr.items, integrationNetwork{ID: firstNonEmpty(r.ExternalID, r.ID), Name: r.Name, VLANID: r.VLAN, Purpose: r.Purpose})
			}
		} else {
			networksMissingErr = nr.err
		}
		nr.err = nil
	}
	if err := errors.Join(cr.err, dr.err, nr.err); err != nil {
		return nil, fmt.Errorf("fetch unifi integration snapshot: %w", err)
	}

	// Build firewall zone lookup maps (zoneID -> name and networkID -> zone)
	// so every network and firewall policy carries resolved human-readable zone names.
	zones := make([]FirewallZone, 0, len(zr.items))
	zoneNameByID := make(map[string]string, len(zr.items))
	zoneByNetID := make(map[string]FirewallZone)
	for _, rz := range zr.items {
		origin := ""
		if rz.Metadata != nil {
			origin = rz.Metadata.Origin
		}
		z := FirewallZone{
			ID:         rz.ID,
			Name:       rz.Name,
			Origin:     origin,
			NetworkIDs: rz.NetworkIDs,
		}
		zones = append(zones, z)
		zoneNameByID[z.ID] = z.Name
		for _, nid := range z.NetworkIDs {
			zoneByNetID[nid] = z
		}
	}

	// Enrich each network with its IPv4 subnet, isolation flag, zone ID, and
	// legacy purpose (since the Integration v1 list omits ipv4Configuration and purpose),
	// and retain legacy rest/networkconf records so switch port_table native_networkconf_id
	// values resolve to human-readable VLAN names.
	legacyNets := ln.items
	detailErr := c.enrichIntegrationNetworks(ctx, siteBase, nr.items, legacyNets, legacyFallback)
	devMACByID := deviceAliases(dr.items, ldr.items)
	networks := make([]Network, 0, len(nr.items))
	for _, rn := range nr.items {
		subnet := extractIntegrationSubnet(rn)
		purpose := strings.ToLower(strings.TrimSpace(rn.Purpose))
		if purpose == "" {
			purpose = strings.ToLower(rn.Management)
		}
		zoneID := rn.ZoneID
		zoneName := zoneNameByID[zoneID]
		if zoneName == "" {
			if z, ok := zoneByNetID[rn.ID]; ok {
				zoneID = z.ID
				zoneName = z.Name
			}
		}
		n := Network{
			ID:                    rn.ID,
			Name:                  rn.Name,
			Purpose:               purpose,
			VLAN:                  string(rn.VLANID),
			Subnet:                subnet,
			IPv6Subnets:           rn.collectedIPv6,
			IsolationEnabled:      rn.IsolationEnabled,
			InternetAccessEnabled: rn.InternetAccessEnabled,
			DomainName:            extractIntegrationDomainName(rn),
			ZoneID:                zoneID,
			ZoneName:              zoneName,
			RouterDeviceMAC:       strings.ToLower(strings.TrimSpace(firstNonEmpty(rn.RouterDeviceMAC, rn.GatewayDevice))),
			DHCPGuardEnabled:      rn.DHCPGuardEnabled,
			MDNSReflectorEnabled:  rn.MDNSEnabled,
			IGMPSnooping:          rn.IGMPSnooping,
			DNSServers:            extractIntegrationDNS(rn),
			DHCPStart:             extractIntegrationDHCPStart(rn),
			DHCPEnd:               extractIntegrationDHCPEnd(rn),
		}
		if rn.DeviceID != "" || strings.EqualFold(rn.Management, "SWITCH") || rn.RouterDeviceMAC != "" {
			n.RouterDeviceMAC = firstNonEmpty(devMACByID[rn.DeviceID], devMACByID[rn.RouterDeviceMAC], canonicalMAC(n.RouterDeviceMAC))
			n.RouterUnresolved = n.RouterDeviceMAC == ""
		}
		networks = append(networks, n)
	}
	netIDs := networkAliases(networks, legacyNets)
	enrichGatewayIPv6Subnets(networks, netIDs, ldr.items)

	tmlByID := make(map[string]integrationTrafficMatchingList, len(tr.items))
	for _, list := range tr.items {
		if id := strings.TrimSpace(list.ID); id != "" {
			tmlByID[id] = list
		}
	}
	policies := convertIntegrationPolicies(pr.items, zoneNameByID, tmlByID)

	legacyClientByMAC := make(map[string]rawClient, len(lcr.items))
	for _, lc := range lcr.items {
		if m := strings.ToLower(strings.TrimSpace(lc.MAC)); m != "" {
			// Without networkconf, legacy IDs cannot identify Integration networks.
			if ln.err != nil {
				lc.NetworkID = ""
			}
			legacyClientByMAC[m] = lc
		}
	}
	legacyDevByMAC := make(map[string]rawDevice, len(ldr.items))
	for _, ld := range ldr.items {
		if m := strings.ToLower(strings.TrimSpace(ld.MAC)); m != "" {
			legacyDevByMAC[m] = ld
		}
	}

	telem := <-telemetryCh

	// Index rest/user friendly names by fixed_ip so active hosts with ephemeral
	// MACs (e.g. Docker macvlan containers) or static BMCs retain UniFi aliases.
	userNameByFixedIP := fixedAliases(telem.knownUsers)
	applyGuestRestrictions(policies, telem.guest)
	for i := range policies {
		normalizeNetworkRefs(&policies[i].Source, netIDs)
		normalizeNetworkRefs(&policies[i].Destination, netIDs)
	}

	seenMAC := make(map[string]struct{}, len(cr.items))
	clients := make([]Client, 0, len(cr.items))
	for _, rc := range cr.items {
		mac := strings.ToLower(strings.TrimSpace(rc.MACAddress))
		if mac != "" {
			seenMAC[mac] = struct{}{}
		}
		cl := Client{
			ID:       strings.TrimSpace(rc.ID),
			MAC:      mac,
			IP:       strings.TrimSpace(rc.IPAddress),
			IPv6:     dedupeIPs(rc.IPv6Addresses),
			Hostname: strings.TrimSpace(rc.Name),
			Name:     strings.TrimSpace(rc.Name),
			IsWired:  strings.EqualFold(rc.Type, "WIRED"),
		}
		if lc, ok := legacyClientByMAC[mac]; ok {
			// Prefer the legacy user_id/_id when available so client IDs stay
			// stable across API-key and session auth modes.
			cl.ID = firstNonEmpty(lc.UserID, lc.ID, cl.ID)
			if h := strings.TrimSpace(lc.Hostname); h != "" {
				cl.Hostname = h
			}
			if n := strings.TrimSpace(lc.Name); n != "" && cl.Name == "" {
				cl.Name = n
			}
			if o := strings.TrimSpace(lc.OUI); o != "" {
				cl.OUI = o
			}
			if len(lc.IPv6Addresses) > 0 {
				cl.IPv6 = dedupeIPs(append(cl.IPv6, lc.IPv6Addresses...))
			}
			cl.IsWired = cl.IsWired || lc.IsWired
			cl.ESSID = strings.TrimSpace(lc.ESSID)
			cl.SwitchMAC = strings.ToLower(strings.TrimSpace(lc.SwMAC))
			cl.SwitchPort = lc.SwPort
			cl.APMAC = strings.ToLower(strings.TrimSpace(lc.APMAC))
			cl.TxBytes, cl.RxBytes = clientByteCounters(cl.IsWired || lc.IsWired, lc.TxBytes, lc.RxBytes, lc.WiredTxBytes, lc.WiredRxBytes)
			cl.FirstSeen = lc.FirstSeen
			cl.LastSeen = lc.LastSeen
		}
		if (cl.Name == "" || strings.EqualFold(cl.Name, cl.MAC)) && cl.IP != "" {
			if alias := userNameByFixedIP[cl.IP]; alias != "" {
				cl.Name = alias
			}
		}
		if m := devMACByID[rc.UplinkDeviceID]; m != "" {
			switch strings.ToUpper(rc.Type) {
			case "WIRED":
				if cl.SwitchMAC == "" {
					cl.SwitchMAC = m
				}
			case "WIRELESS":
				if cl.APMAC == "" {
					cl.APMAC = m
				}
			}
		}
		lc := legacyClientByMAC[mac]
		assignClientNetwork(&cl, lc.NetworkID, lc.Network, netIDs, networks)
		clients = append(clients, cl)
	}
	// Merge any active clients visible in legacy stat/sta that Integration v1
	// omitted (commonly static-IP BMCs or shared-NIC management interfaces).
	for mac, lc := range legacyClientByMAC {
		if _, dup := seenMAC[mac]; dup {
			continue
		}
		ip := strings.TrimSpace(lc.IP)
		name := strings.TrimSpace(lc.Name)
		if name == "" && ip != "" {
			name = userNameByFixedIP[ip]
		}
		txBytes, rxBytes := clientByteCounters(lc.IsWired, lc.TxBytes, lc.RxBytes, lc.WiredTxBytes, lc.WiredRxBytes)
		cl := Client{
			ID:         firstNonEmpty(lc.UserID, lc.ID),
			MAC:        mac,
			IP:         ip,
			IPv6:       dedupeIPs(lc.IPv6Addresses),
			Hostname:   strings.TrimSpace(lc.Hostname),
			Name:       name,
			OUI:        strings.TrimSpace(lc.OUI),
			IsWired:    lc.IsWired,
			ESSID:      strings.TrimSpace(lc.ESSID),
			SwitchMAC:  strings.ToLower(strings.TrimSpace(lc.SwMAC)),
			SwitchPort: lc.SwPort,
			APMAC:      strings.ToLower(strings.TrimSpace(lc.APMAC)),
			TxBytes:    txBytes,
			RxBytes:    rxBytes,
			FirstSeen:  lc.FirstSeen,
			LastSeen:   lc.LastSeen,
		}
		assignClientNetwork(&cl, lc.NetworkID, lc.Network, netIDs, networks)
		clients = append(clients, cl)
	}

	netByID := make(map[string]Network, len(networks)+len(legacyNets))
	defaultNetName := defaultLANName(networks)
	for _, n := range networks {
		if n.ID != "" {
			netByID[n.ID] = n
		}
	}
	for alias, id := range netIDs {
		if n, ok := netByID[id]; ok {
			netByID[alias] = n
		}
	}

	portConfByID := indexPortConfs(telem.portConfs)
	devices := make([]Device, 0, len(dr.items))
	for _, rd := range dr.items {
		mac := strings.ToLower(strings.TrimSpace(rd.MACAddress))
		dev := Device{
			ID:         strings.TrimSpace(rd.ID),
			MAC:        mac,
			IP:         strings.TrimSpace(rd.IPAddress),
			Name:       strings.TrimSpace(rd.Name),
			Model:      rd.Model,
			Type:       inferDeviceTypeFromModel(rd.Model),
			Version:    rd.FirmwareVersion,
			Upgradable: rd.FirmwareUpdatable,
		}
		if ld, ok := legacyDevByMAC[mac]; ok {
			dev.ID = firstNonEmpty(dev.ID, ld.ExternalID, ld.ID, ld.DeviceID)
			if ld.Type != "" {
				dev.Type = strings.ToLower(ld.Type)
			}
			if ld.Uplink != nil {
				dev.UplinkMAC = strings.ToLower(strings.TrimSpace(ld.Uplink.UplinkMAC))
				dev.UplinkName = strings.TrimSpace(ld.Uplink.UplinkDeviceName)
				dev.UplinkPort = ld.Uplink.UplinkRemotePort
			}
			dev.Ports = convertSwitchPorts(ld, netByID, portConfByID, defaultNetName)
			dev.BSSIDs = extractDeviceBSSIDs(ld)
		}
		devices = append(devices, dev)
	}

	forwards := convertPortForwards(fr.items, indexGroups(gr.items))

	// Populate active client lease counts strictly for clients inside each DHCP pool.
	hasDHCP, hasMDNS := populateNetworkDHCPAndMDNS(networks, clients)

	gwPoliciesAvailable := zr.err == nil && pr.err == nil
	var missingFeeds []string
	missingFeeds = appendFeedError(missingFeeds, "networks", networksMissingErr)
	missingFeeds = appendFeedError(missingFeeds, "traffic-matching-lists", tr.err)
	missingFeeds = appendFeedError(missingFeeds, "firewall-groups", gr.err)
	missingFeeds = appendFeedError(missingFeeds, "network-enrichment", ln.err)
	missingFeeds = appendFeedError(missingFeeds, "network-details", detailErr)
	missingFeeds = append(missingFeeds, telem.missing...)
	if zr.err != nil {
		missingFeeds = append(missingFeeds, fmt.Sprintf("firewall-zones (%s)", shortFetchErr(zr.err)))
	}
	if pr.err != nil {
		missingFeeds = append(missingFeeds, fmt.Sprintf("firewall-policies (%s)", shortFetchErr(pr.err)))
	}
	if fr.err != nil {
		missingFeeds = append(missingFeeds, fmt.Sprintf("port-forwards (%s)", shortFetchErr(fr.err)))
	}
	if ldr.err != nil {
		missingFeeds = append(missingFeeds, fmt.Sprintf("switch-ports (%s)", shortFetchErr(ldr.err)))
	}
	if lcr.err != nil {
		missingFeeds = append(missingFeeds, fmt.Sprintf("client-enrichment (%s)", shortFetchErr(lcr.err)))
	}
	if !telem.wlansOK {
		missingFeeds = append(missingFeeds, "wlan-config (unavailable)")
	}
	if !telem.settingsOK {
		missingFeeds = append(missingFeeds, "security-settings (unavailable)")
	}
	if !telem.portConfsOK {
		reason := "unavailable"
		if telem.portConfsErr != nil {
			reason = shortFetchErr(telem.portConfsErr)
		}
		missingFeeds = append(missingFeeds, fmt.Sprintf("port-profiles (%s)", reason))
	}
	switchACLs := convertIntegrationACLs(ar.items, devMACByID)
	for i := range switchACLs {
		a := &switchACLs[i]
		normalizeNetworkRefs(&a.Source, netIDs)
		normalizeNetworkRefs(&a.Destination, netIDs)
		ids, reason := normalizedScope(a.NetworkIDs, netIDs)
		a.NetworkIDs = ids
		if reason != "" {
			a.Source.UnsupportedSelector = reason
		}
	}
	switchACLCov := aclCoverage(switchACLs, ar.err)
	if switchACLCov.Status != "complete" {
		missingFeeds = append(missingFeeds, "switch-acls ("+switchACLCov.Reason+")")
	}
	return &Snapshot{
		CollectedAt:       time.Now().UTC(),
		Site:              c.snapshotSiteName(),
		ControllerType:    c.currentControllerType(),
		Clients:           clients,
		Devices:           devices,
		Networks:          networks,
		PortForwards:      forwards,
		Zones:             zones,
		FirewallPolicies:  policies,
		SwitchACLs:        switchACLs,
		SwitchACLCoverage: switchACLCov,
		WLANs:             convertWLANs(telem.wlans, netByID),
		RogueAPs:          convertRogueAPs(telem.rogueAPs),
		SecuritySettings:  telem.settings,
		Health:            telem.health,
		KnownClients:      convertHistoricalClients(telem.knownUsers, netByID),
		RecentLogs:        telem.recentLogs,
		Visibility: &SiteVisibility{
			APIMode:                  c.currentControllerType(),
			GatewayPoliciesAvailable: gwPoliciesAvailable,
			SwitchACLsAvailable:      ar.err == nil,
			WLANsAvailable:           telem.wlansOK,
			SettingsAvailable:        telem.settingsOK,
			VPNAvailable:             telem.vpnOK,
			PortForwardsAvailable:    fr.err == nil,
			PortProfilesAvailable:    telem.portConfsOK,
			DHCPAvailable:            hasDHCP,
			MDNSReflectorKnown:       hasMDNS,
			MissingFeeds:             missingFeeds,
		},
	}, nil
}

// fetchLegacySnapshot queries the classic /api/s/<site>/... endpoints (proxied
// under /proxy/network on UniFi OS consoles) concurrently over typed channels.
func (c *Controller) fetchLegacySnapshot(ctx context.Context) (*Snapshot, error) {
	type clientsRes struct {
		items []rawClient
		err   error
	}
	type devicesRes struct {
		items []rawDevice
		err   error
	}
	type networksRes struct {
		items []rawNetwork
		err   error
	}
	type forwardsRes struct {
		items []rawPortForward
		err   error
	}

	clientsCh := make(chan clientsRes, 1)
	devicesCh := make(chan devicesRes, 1)
	networksCh := make(chan networksRes, 1)
	forwardsCh := make(chan forwardsRes, 1)
	telemetryCh := make(chan siteTelemetry, 1)

	apiPrefix, site := c.sessionPrefixAndSite()
	site = url.PathEscape(site)
	feeds := startSessionPolicies(ctx, c, apiPrefix+"/v2/api/site/"+site+"/", apiPrefix+"/api/s/"+site+"/")

	go func() {
		telemetryCh <- c.fetchSiteTelemetry(ctx)
	}()

	go func() {
		var env apiEnvelope[rawClient]
		err := c.getJSON(ctx, apiPrefix+fmt.Sprintf("/api/s/%s/stat/sta", site), &env)
		clientsCh <- clientsRes{items: env.Data, err: err}
	}()
	go func() {
		var env apiEnvelope[rawDevice]
		err := c.getJSON(ctx, apiPrefix+fmt.Sprintf("/api/s/%s/stat/device", site), &env)
		devicesCh <- devicesRes{items: env.Data, err: err}
	}()
	go func() {
		var env apiEnvelope[rawNetwork]
		err := c.getJSON(ctx, apiPrefix+fmt.Sprintf("/api/s/%s/rest/networkconf", site), &env)
		networksCh <- networksRes{items: env.Data, err: err}
	}()
	go func() {
		var env apiEnvelope[rawPortForward]
		err := c.getJSON(ctx, apiPrefix+fmt.Sprintf("/api/s/%s/rest/portforward", site), &env)
		forwardsCh <- forwardsRes{items: env.Data, err: err}
	}()

	cr := <-clientsCh
	dr := <-devicesCh
	nr := <-networksCh
	fr := <-forwardsCh

	if err := errors.Join(cr.err, dr.err, nr.err); err != nil {
		return nil, fmt.Errorf("fetch unifi snapshot: %w", err)
	}

	// Build lookup maps from networkconf so each active client carries both its
	// friendly VLAN name and numeric VLAN tag even when stat/sta omits one.
	networks := make([]Network, 0, len(nr.items))
	netByID := make(map[string]Network, len(nr.items))
	devIDs := deviceAliases(nil, dr.items)
	for _, rn := range nr.items {
		var dnsServers []string
		if s := strings.TrimSpace(rn.DHCPDDNS1); s != "" {
			dnsServers = append(dnsServers, s)
		}
		if s := strings.TrimSpace(rn.DHCPDDNS2); s != "" {
			dnsServers = append(dnsServers, s)
		}
		routerMAC := ""
		if strings.EqualFold(strings.TrimSpace(rn.GatewayType), "switch") && rn.GatewayDevice != "" {
			routerMAC = firstNonEmpty(devIDs[rn.GatewayDevice], canonicalMAC(rn.GatewayDevice))
		}
		dhcpStart, dhcpEnd := "", ""
		if rn.DHCPDEnabled == nil || *rn.DHCPDEnabled {
			dhcpStart = strings.TrimSpace(rn.DHCPDStart)
			dhcpEnd = strings.TrimSpace(rn.DHCPDStop)
		}
		n := Network{
			ID:                    rn.ID,
			Name:                  rn.Name,
			Purpose:               strings.ToLower(strings.TrimSpace(rn.Purpose)),
			VLAN:                  string(rn.VLAN),
			Subnet:                rn.IPSubnet,
			IPv6Subnets:           rn.ipv6Prefixes(),
			IsolationEnabled:      rn.NetworkIsolationEnabled,
			InternetAccessEnabled: rn.InternetAccessEnabled,
			DomainName:            strings.TrimSpace(rn.DomainName),
			RouterDeviceMAC:       routerMAC,
			RouterUnresolved:      strings.EqualFold(rn.GatewayType, "switch") && routerMAC == "",
			DHCPGuardEnabled:      rn.DHCPGuardEnabled,
			MDNSReflectorEnabled:  rn.MDNSEnabled,
			IGMPSnooping:          rn.IGMPSnooping,
			DNSServers:            dnsServers,
			DHCPStart:             dhcpStart,
			DHCPEnd:               dhcpEnd,
		}
		networks = append(networks, n)
	}
	netIDs := networkAliases(networks, nr.items)
	enrichGatewayIPv6Subnets(networks, netIDs, dr.items)
	for _, n := range networks {
		if n.ID != "" {
			netByID[n.ID] = n
		}
	}
	for alias, id := range netIDs {
		if n, ok := netByID[id]; ok {
			netByID[alias] = n
		}
	}
	telem := <-telemetryCh
	fixed := fixedAliases(telem.knownUsers)
	clients := make([]Client, 0, len(cr.items))
	for _, rc := range cr.items {
		txBytes, rxBytes := clientByteCounters(rc.IsWired, rc.TxBytes, rc.RxBytes, rc.WiredTxBytes, rc.WiredRxBytes)
		cl := Client{
			ID:          firstNonEmpty(rc.UserID, rc.ID),
			MAC:         strings.ToLower(strings.TrimSpace(rc.MAC)),
			IP:          strings.TrimSpace(rc.IP),
			IPv6:        dedupeIPs(rc.IPv6Addresses),
			Hostname:    strings.TrimSpace(rc.Hostname),
			Name:        strings.TrimSpace(rc.Name),
			OUI:         strings.TrimSpace(rc.OUI),
			NetworkID:   rc.NetworkID,
			NetworkName: rc.Network,
			VLAN:        string(rc.VLAN),
			IsWired:     rc.IsWired,
			ESSID:       strings.TrimSpace(rc.ESSID),
			SwitchMAC:   strings.ToLower(strings.TrimSpace(rc.SwMAC)),
			SwitchPort:  rc.SwPort,
			APMAC:       strings.ToLower(strings.TrimSpace(rc.APMAC)),
			TxBytes:     txBytes,
			RxBytes:     rxBytes,
			FirstSeen:   rc.FirstSeen,
			LastSeen:    rc.LastSeen,
		}

		assignClientNetwork(&cl, rc.NetworkID, rc.Network, netIDs, networks)
		if cl.Name == "" || strings.EqualFold(cl.Name, cl.MAC) {
			if name := fixed[cl.IP]; name != "" {
				cl.Name = name
			}
		}
		clients = append(clients, cl)
	}

	portConfByID := indexPortConfs(telem.portConfs)

	defaultNetName := defaultLANName(networks)
	devices := make([]Device, 0, len(dr.items))
	for _, rd := range dr.items {
		devType := strings.ToLower(strings.TrimSpace(rd.Type))
		if devType == "" {
			devType = inferDeviceTypeFromModel(rd.Model)
		}
		dev := Device{
			ID:         firstNonEmpty(rd.ExternalID, rd.ID, rd.DeviceID),
			MAC:        strings.ToLower(strings.TrimSpace(rd.MAC)),
			IP:         strings.TrimSpace(rd.IP),
			Name:       strings.TrimSpace(rd.Name),
			Model:      rd.Model,
			Type:       devType,
			Version:    rd.Version,
			Upgradable: rd.Upgradable,
			Ports:      convertSwitchPorts(rd, netByID, portConfByID, defaultNetName),
			BSSIDs:     extractDeviceBSSIDs(rd),
		}
		if rd.Uplink != nil {
			dev.UplinkMAC = strings.ToLower(strings.TrimSpace(rd.Uplink.UplinkMAC))
			dev.UplinkName = strings.TrimSpace(rd.Uplink.UplinkDeviceName)
			dev.UplinkPort = rd.Uplink.UplinkRemotePort
		}
		devices = append(devices, dev)
	}

	hasDHCP, hasMDNS := populateNetworkDHCPAndMDNS(networks, clients)

	missingFeeds := appendFeedError(telem.missing, "port-forwards", fr.err)
	if !telem.wlansOK {
		missingFeeds = append(missingFeeds, "wlan-config (unavailable)")
	}
	if !telem.settingsOK {
		missingFeeds = append(missingFeeds, "security-settings (unavailable)")
	}
	if !telem.portConfsOK {
		reason := "unavailable"
		if telem.portConfsErr != nil {
			reason = shortFetchErr(telem.portConfsErr)
		}
		missingFeeds = append(missingFeeds, fmt.Sprintf("port-profiles (%s)", reason))
	}
	snap := &Snapshot{
		CollectedAt:    time.Now().UTC(),
		Site:           c.snapshotSiteName(),
		ControllerType: c.currentControllerType(),
		Clients:        clients,
		Devices:        devices,
		Networks:       networks,

		WLANs:            convertWLANs(telem.wlans, netByID),
		RogueAPs:         convertRogueAPs(telem.rogueAPs),
		SecuritySettings: telem.settings,
		Health:           telem.health,
		KnownClients:     convertHistoricalClients(telem.knownUsers, netByID),
		RecentLogs:       telem.recentLogs,
		Visibility: &SiteVisibility{
			APIMode:                  c.currentControllerType(),
			GatewayPoliciesAvailable: false,
			SwitchACLsAvailable:      false,
			WLANsAvailable:           telem.wlansOK,
			SettingsAvailable:        telem.settingsOK,
			VPNAvailable:             telem.vpnOK,
			PortForwardsAvailable:    fr.err == nil,
			PortProfilesAvailable:    telem.portConfsOK,
			DHCPAvailable:            hasDHCP,
			MDNSReflectorKnown:       hasMDNS,
			MissingFeeds:             missingFeeds,
		},
	}
	groups := feeds.apply(snap, nr.items, devIDs, telem.guest)
	snap.PortForwards = convertPortForwards(fr.items, groups)
	return snap, nil
}

// sameOrigin compares scheme, hostname, and effective port (treating default
// http:80 and https:443 ports as equivalent to omitted ports).
func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	if !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	effPort := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "http") {
			return "80"
		}
		if strings.EqualFold(u.Scheme, "https") {
			return "443"
		}
		return ""
	}
	return effPort(a) == effPort(b)
}

// fetchAllPages walks a paginated Integration v1 list endpoint using offset and
// limit query parameters until all items reported by totalCount are collected,
// retrying briefly if the live collection shifts mid-traversal.
func fetchAllPages[T any](ctx context.Context, c *Controller, path string) ([]T, error) {
	const maxDriftRetries = 2
	var lastErr error
	for attempt := 0; attempt <= maxDriftRetries; attempt++ {
		items, drifted, err := fetchAllPagesOnce[T](ctx, c, path)
		if err == nil {
			return items, nil
		}
		lastErr = err
		if !drifted || attempt == maxDriftRetries {
			return nil, err
		}
	}
	return nil, lastErr
}

// fetchAllPagesOnce performs one full paginated pass over path, validating
// offset/count/totalCount invariants and duplicate item IDs. It returns
// drifted=true when totalCount shifts or a duplicate row appears mid-walk so
// fetchAllPages can retry the snapshot cleanly.
func fetchAllPagesOnce[T any](ctx context.Context, c *Controller, path string) ([]T, bool, error) {
	var all []T
	seen := make(map[string]bool)
	total := -1
	offset := 0
	for pageNum := 0; pageNum < maxIntegrationPages; pageNum++ {
		pagePath := fmt.Sprintf("%s?offset=%d&limit=%d", path, offset, integrationPageLimit)
		var page integrationPage[json.RawMessage]
		if err := c.getJSON(ctx, pagePath, &page); err != nil {
			return nil, false, err
		}
		if page.Data == nil || page.TotalCount == nil || page.Offset != offset || page.Count != len(page.Data) || *page.TotalCount < 0 {
			return nil, false, fmt.Errorf("invalid integration pagination for %s at offset %d", path, offset)
		}
		if total >= 0 && total != *page.TotalCount {
			return nil, true, fmt.Errorf("integration collection changed while paging %s", path)
		}
		if *page.TotalCount < offset+len(page.Data) {
			return nil, false, fmt.Errorf("invalid integration pagination for %s at offset %d", path, offset)
		}
		total = *page.TotalCount
		for _, raw := range page.Data {
			var identity struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(raw, &identity); err != nil {
				return nil, false, fmt.Errorf("invalid integration row in %s: %w", path, err)
			}
			if identity.ID != "" && seen[identity.ID] {
				return nil, true, fmt.Errorf("duplicate integration row in %s", path)
			}
			if identity.ID != "" {
				seen[identity.ID] = true
			}
			var item T
			if err := json.Unmarshal(raw, &item); err != nil {
				return nil, false, fmt.Errorf("decode row in %s: %w", path, err)
			}
			all = append(all, item)
		}
		offset += len(page.Data)
		if offset == *page.TotalCount {
			return all, false, nil
		}
		if len(page.Data) == 0 {
			return nil, false, fmt.Errorf("incomplete integration page for %s", path)
		}
	}
	return nil, false, fmt.Errorf("integration page limit exceeded for %s", path)
}

// clientByteCounters picks the single appropriate TX/RX byte counter pair for a
// client so wired hosts do not double-count tx_bytes + wired-tx_bytes.
func clientByteCounters(isWired bool, tx, rx, wiredTx, wiredRx int64) (int64, int64) {
	if isWired && (wiredTx > 0 || wiredRx > 0) {
		return wiredTx, wiredRx
	}
	if tx > 0 || rx > 0 {
		return tx, rx
	}
	return wiredTx, wiredRx
}

// extractDeviceBSSIDs returns sorted, deduplicated lowercase radio BSSIDs from
// a legacy stat/device record's vap_table.
func extractDeviceBSSIDs(rd rawDevice) []string {
	if len(rd.VAPTable) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(rd.VAPTable))
	out := make([]string, 0, len(rd.VAPTable))
	for _, vap := range rd.VAPTable {
		b := strings.ToLower(strings.TrimSpace(vap.BSSID))
		if b == "" {
			continue
		}
		if _, dup := seen[b]; dup {
			continue
		}
		seen[b] = struct{}{}
		out = append(out, b)
	}
	sort.Strings(out)
	return out
}

// inferDeviceTypeFromModel maps a UniFi device model code to a normalized
// controller device type ("udm", "uxg", "ugw", "usw", "uap", "uck") when legacy
// stat/device telemetry is absent, instead of misusing device state ("online").
func inferDeviceTypeFromModel(model string) string {
	m := strings.ToUpper(strings.TrimSpace(model))
	compact := strings.NewReplacer("-", "", "_", "", " ", "").Replace(m)
	switch {
	case m == "":
		return ""
	case strings.HasPrefix(compact, "UXG"):
		return "uxg"
	case strings.HasPrefix(compact, "UDM"), strings.HasPrefix(compact, "UDR"), strings.HasPrefix(compact, "UDW"),
		strings.HasPrefix(compact, "UCG"), strings.HasPrefix(compact, "EFG"),
		compact == "UX" || strings.HasPrefix(compact, "UX7") || strings.HasPrefix(m, "UX-"),
		strings.Contains(compact, "DREAMMACHINE"), strings.Contains(compact, "DREAMROUTER"),
		strings.Contains(compact, "DREAMWALL"), strings.Contains(compact, "CLOUDGATEWAY"),
		strings.Contains(compact, "UNIFIEXPRESS"):
		return "udm"
	case strings.HasPrefix(compact, "USG"), strings.HasPrefix(compact, "UGW"):
		return "ugw"
	case strings.HasPrefix(compact, "USW"), strings.HasPrefix(compact, "USL"), strings.HasPrefix(compact, "USC"),
		strings.HasPrefix(compact, "US8"), strings.HasPrefix(compact, "US16"), strings.HasPrefix(compact, "US24"),
		strings.HasPrefix(compact, "US48"), strings.HasPrefix(m, "US-"), strings.Contains(compact, "SWITCH"):
		return "usw"
	case strings.HasPrefix(compact, "UAP"), strings.HasPrefix(compact, "UAL"), strings.HasPrefix(compact, "U6"),
		strings.HasPrefix(compact, "U7"), strings.HasPrefix(compact, "UWB"), strings.HasPrefix(compact, "UDB"),
		strings.HasPrefix(compact, "UK"), strings.HasPrefix(compact, "AC"):
		return "uap"
	case strings.HasPrefix(compact, "UCK"), strings.HasPrefix(compact, "UNVR"), strings.Contains(compact, "CLOUDKEY"):
		return "uck"
	default:
		return ""
	}
}

// populateNetworkDHCPAndMDNS computes active DHCP lease counts strictly from
// clients whose IPv4 address falls within each network's [DHCPStart, DHCPEnd]
// pool (excluding static IPs outside the pool), and reports whether DHCP and
// mDNS reflector telemetry were observed.
func populateNetworkDHCPAndMDNS(networks []Network, clients []Client) (hasDHCP, hasMDNS bool) {
	for i := range networks {
		if networks[i].DHCPStart != "" && networks[i].DHCPEnd != "" {
			hasDHCP = true
			if networks[i].ActiveLeases == 0 {
				startAddr, err1 := netip.ParseAddr(strings.TrimSpace(networks[i].DHCPStart))
				endAddr, err2 := netip.ParseAddr(strings.TrimSpace(networks[i].DHCPEnd))
				if err1 == nil && err2 == nil && startAddr.Is4() && endAddr.Is4() {
					start4 := startAddr.As4()
					end4 := endAddr.As4()
					startNum := uint32(start4[0])<<24 | uint32(start4[1])<<16 | uint32(start4[2])<<8 | uint32(start4[3])
					endNum := uint32(end4[0])<<24 | uint32(end4[1])<<16 | uint32(end4[2])<<8 | uint32(end4[3])
					count := 0
					for _, cl := range clients {
						if cl.NetworkID != "" && networks[i].ID != "" && cl.NetworkID != networks[i].ID {
							continue
						}
						addr, err := netip.ParseAddr(strings.TrimSpace(cl.IP))
						if err != nil || !addr.Is4() {
							continue
						}
						b := addr.As4()
						v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
						if v >= startNum && v <= endNum {
							count++
						}
					}
					networks[i].ActiveLeases = count
				}
			}
		}
		if networks[i].MDNSReflectorEnabled != nil {
			hasMDNS = true
		}
	}
	return hasDHCP, hasMDNS
}

func indexPortConfs(confs []rawPortConf) map[string]rawPortConf {
	if len(confs) == 0 {
		return nil
	}
	out := make(map[string]rawPortConf, len(confs))
	for _, pc := range confs {
		if pc.ID != "" {
			out[pc.ID] = pc
		}
	}
	return out
}

// defaultLANName returns the site's primary untagged management/LAN network
// name (VLAN empty or "1", corporate/default) used as the fallback native VLAN
// when a UniFi switch port has no explicit native_networkconf_id override.
func defaultLANName(networks []Network) string {
	for _, n := range networks {
		if strings.EqualFold(n.Purpose, "wan") || strings.EqualFold(n.Purpose, "wan2") {
			continue
		}
		if n.VLAN == "" || n.VLAN == "0" || n.VLAN == "1" {
			return n.Name
		}
	}
	if len(networks) > 0 {
		return networks[0].Name
	}
	return "Default"
}

// portNetworkIDs resolves legacy profile references against this site's network
// aliases. A missing list stays distinguishable from an explicitly empty list.
func portNetworkIDs(ids []string, networks map[string]Network) []string {
	result := slices.Clone(ids)
	for i, id := range result {
		if n, ok := networks[id]; ok {
			result[i] = n.ID
		}
	}
	return result
}

// convertSwitchPorts normalizes a UniFi device's port_table merged with
// port_overrides and optional port profiles (rest/portconf) into sorted
// SwitchPort entries with resolved native VLAN names.
func convertSwitchPorts(rd rawDevice, netByID map[string]Network, portConfByID map[string]rawPortConf, defaultNetName string) []SwitchPort {
	if len(rd.PortTable) == 0 {
		return nil
	}
	ovByIdx := make(map[int]rawPort, len(rd.PortOverrides))
	for _, ov := range rd.PortOverrides {
		if ov.PortIdx > 0 {
			ovByIdx[ov.PortIdx] = ov
		}
	}

	ports := make([]SwitchPort, 0, len(rd.PortTable))
	for _, rp := range rd.PortTable {
		if rp.PortIdx <= 0 {
			continue
		}
		// Merge any explicit port_override fields onto the live port_table record.
		if rp.TaggedNetworkIDs == nil {
			rp.TaggedNetworkIDs = rp.IncludedNetworkIDs
		}
		if ov, ok := ovByIdx[rp.PortIdx]; ok {
			if ov.TaggedNetworkIDs == nil {
				ov.TaggedNetworkIDs = ov.IncludedNetworkIDs
			}
			if ov.Name != "" {
				rp.Name = ov.Name
			}
			if ov.PortConfID != "" {
				rp.PortConfID = ov.PortConfID
			}
			if ov.SettingPreference != "" {
				rp.SettingPreference = ov.SettingPreference
			}
			if ov.OpMode != "" {
				rp.OpMode = ov.OpMode
			}
			if ov.Forward != "" {
				rp.Forward = ov.Forward
			}
			if ov.TaggedVLANMgmt != "" {
				rp.TaggedVLANMgmt = ov.TaggedVLANMgmt
			}
			if ov.TaggedNetworkIDs != nil || ov.ExcludedNetworkIDs != nil {
				rp.TaggedNetworkIDs, rp.ExcludedNetworkIDs = ov.TaggedNetworkIDs, ov.ExcludedNetworkIDs
			}
			if ov.NativeNetworkConfID != "" {
				rp.NativeNetworkConfID = ov.NativeNetworkConfID
			}
			if ov.PoEMode != "" {
				rp.PoEMode = ov.PoEMode
			}
			if ov.PortSecurityEnabled != nil {
				rp.PortSecurityEnabled = ov.PortSecurityEnabled
			}
			if len(ov.PortSecurityMACs) > 0 {
				rp.PortSecurityMACs = ov.PortSecurityMACs
			}
			if ov.Isolation != nil {
				rp.Isolation = ov.Isolation
			}
		}
		// Apply referenced switch port profile settings when setting_preference is
		// not "manual". When setting_preference is explicitly "auto", the assigned
		// profile takes precedence over any stale per-port fields.
		pref := strings.ToLower(strings.TrimSpace(rp.SettingPreference))
		profileManaged := rp.PortConfID != "" && pref != "manual"
		pc, profileFound := portConfByID[rp.PortConfID]
		if profileManaged {
			if profileFound {
				if pc.TaggedNetworkIDs == nil {
					pc.TaggedNetworkIDs = pc.IncludedNetworkIDs
				}
				profileWins := pref == "auto"
				if (profileWins || rp.OpMode == "") && pc.OpMode != "" {
					rp.OpMode = pc.OpMode
				}
				if profileWins || rp.Forward == "" {
					rp.Forward = pc.Forward
				}
				if pc.TaggedVLANMgmt != "" && (profileWins || rp.TaggedVLANMgmt == "") {
					rp.TaggedVLANMgmt = pc.TaggedVLANMgmt
				} else if profileWins {
					// Clear any stale per-port tagged_vlan_mgmt so the profile's
					// forward setting ("native", "customize", "disabled") governs.
					rp.TaggedVLANMgmt = ""
				}
				if profileWins || (rp.TaggedNetworkIDs == nil && rp.ExcludedNetworkIDs == nil) {
					rp.TaggedNetworkIDs, rp.ExcludedNetworkIDs = pc.TaggedNetworkIDs, pc.ExcludedNetworkIDs
				}
				if (profileWins || rp.NativeNetworkConfID == "") && pc.NativeNetworkConfID != "" {
					rp.NativeNetworkConfID = pc.NativeNetworkConfID
				}
				if (profileWins || rp.PoEMode == "") && pc.PoEMode != "" {
					rp.PoEMode = pc.PoEMode
				}
				if profileWins || rp.PortSecurityEnabled == nil {
					rp.PortSecurityEnabled = pc.PortSecurityEnabled
				}
				if (profileWins || len(rp.PortSecurityMACs) == 0) && len(pc.PortSecurityMACs) > 0 {
					rp.PortSecurityMACs = pc.PortSecurityMACs
				}
				if profileWins || rp.Isolation == nil {
					rp.Isolation = pc.Isolation
				}
			}
		}

		enabled := true
		if rp.Enable != nil {
			enabled = *rp.Enable
		}
		opMode := strings.ToLower(strings.TrimSpace(rp.OpMode))
		fwd := strings.ToLower(strings.TrimSpace(rp.Forward))
		if opMode == "off" || fwd == "disabled" {
			enabled = false
		}

		isWAN := strings.HasPrefix(strings.ToLower(strings.TrimSpace(rp.NetworkName)), "wan")
		nativeName := ""
		if isWAN {
			nativeName = strings.ToUpper(strings.TrimSpace(rp.NetworkName))
		} else if rp.NativeNetworkConfID != "" {
			if n, ok := netByID[rp.NativeNetworkConfID]; ok {
				nativeName = n.Name
			} else {
				nativeName = rp.NativeNetworkConfID
			}
		} else if enabled {
			nativeName = defaultNetName
		}

		tagged := strings.ToLower(strings.TrimSpace(rp.TaggedVLANMgmt))
		if tagged == "" {
			switch fwd {
			case "native":
				tagged = "block_all"
			case "customize", "custom":
				tagged = "custom"
			case "disabled":
				tagged = "disabled"
			case "all":
				tagged = "auto"
			default:
				tagged = "unknown"
			}
		}

		// Treat tagged VLAN membership as unknown whenever a profile-managed
		// port's profile is missing, the forwarding mode could not be decoded,
		// or custom mode omits both inclusion and exclusion lists.
		missingProfile := profileManaged && !profileFound
		taggedUnknown := missingProfile || tagged == "unknown" || (tagged == "custom" && rp.TaggedNetworkIDs == nil && rp.ExcludedNetworkIDs == nil)
		nativeID := rp.NativeNetworkConfID
		if n, ok := netByID[nativeID]; ok {
			nativeID = n.ID
		}
		psec := rp.PortSecurityEnabled != nil && *rp.PortSecurityEnabled
		iso := rp.Isolation != nil && *rp.Isolation
		var psecMACs []string
		for _, m := range rp.PortSecurityMACs {
			if norm := strings.ToLower(strings.TrimSpace(m)); norm != "" {
				psecMACs = append(psecMACs, norm)
			}
		}

		poeStr := strings.TrimSpace(string(rp.PoEPower))
		poeWatts, _ := strconv.ParseFloat(poeStr, 64)

		ports = append(ports, SwitchPort{
			PortIdx:             rp.PortIdx,
			Name:                strings.TrimSpace(rp.Name),
			Enabled:             enabled,
			Up:                  rp.Up,
			Speed:               rp.Speed,
			Media:               strings.TrimSpace(rp.Media),
			IsUplink:            rp.IsUplink,
			IsWAN:               isWAN,
			OpMode:              opMode,
			Forward:             fwd,
			TaggedVLANMgmt:      tagged,
			TaggedVLANUnknown:   taggedUnknown,
			TaggedNetworkIDs:    portNetworkIDs(rp.TaggedNetworkIDs, netByID),
			ExcludedNetworkIDs:  portNetworkIDs(rp.ExcludedNetworkIDs, netByID),
			NativeNetworkID:     nativeID,
			NativeNetworkName:   nativeName,
			PortConfID:          rp.PortConfID,
			ProfileManaged:      profileManaged,
			PoEEnabled:          rp.PoEEnable,
			PoEMode:             strings.ToLower(strings.TrimSpace(rp.PoEMode)),
			PoEPower:            poeStr,
			PoEPowerWatts:       poeWatts,
			PortSecurityEnabled: psec,
			PortSecurityUnknown: missingProfile,
			PortSecurityMACs:    psecMACs,
			Isolation:           iso,
			IsolationUnknown:    profileManaged && !profileFound,
			MACTableCount:       rp.MACTableCount,
			STPState:            strings.ToLower(strings.TrimSpace(rp.STPState)),
			STPStateChanges:     int(rp.STPStateChangeCount),
			RXErrors:            rp.RXErrors,
			TXErrors:            rp.TXErrors,
			RXDropped:           rp.RXDropped,
			TXDropped:           rp.TXDropped,
		})
	}
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].PortIdx < ports[j].PortIdx
	})
	return ports
}

// convertPortForwards normalizes wire port-forward rules into domain PortForward values.
func convertPortForwards(raw []rawPortForward, groups groupIndex) []PortForward {
	forwards := make([]PortForward, 0, len(raw))
	for _, rf := range raw {
		ipVer := strings.ToLower(strings.TrimSpace(rf.IPVersion))
		if ipVer == "" {
			ipVer = "ipv4"
		}
		src := strings.TrimSpace(rf.Src)
		unknown := false
		// When modern controllers emit src_limiting_enabled, treat it as
		// authoritative over legacy src: false resets to "any", FIREWALL_GROUP
		// resolves against legacy address groups, and invalid or unrecognized
		// limiters set SourceUnknown so source restriction is never assumed.
		if rf.SrcLimitingEnabled != nil {
			switch {
			case !*rf.SrcLimitingEnabled:
				src = "any"
			case strings.EqualFold(rf.SrcLimitingType, "FIREWALL_GROUP"):
				ips, ok := groups.addressGroup(rf.SrcGroupID)
				src = strings.Join(ips, ",")
				unknown = !ok
			case strings.EqualFold(rf.SrcLimitingType, "IP") || rf.SrcLimitingType == "":
				unknown = !validIPSelector(src)
			default:
				unknown = true
			}
		}
		if unknown {
			src = "unresolved"
		}
		forwards = append(forwards, PortForward{
			ID:      rf.ID,
			Name:    rf.Name,
			Enabled: rf.Enabled,
			Proto:   strings.ToLower(rf.Proto),
			DstPort: string(rf.DstPort),
			FwdIP:   strings.TrimSpace(rf.Fwd),
			FwdPort: string(rf.FwdPort),
			Src:     src, SourceUnknown: unknown, DestinationIP: rf.DestinationIP,
			Interface: strings.ToLower(strings.TrimSpace(rf.PfwdInterface)),
			IPVersion: ipVer,
		})
	}
	return forwards
}

// enrichGatewayIPv6Subnets merges live delegated prefixes with configured ones
// before client addresses are assigned to VLANs. Gateway tables can use either
// API's network IDs, and some firmware supplies only the network name.
func enrichGatewayIPv6Subnets(networks []Network, ids aliases, devices []rawDevice) {
	byID := make(map[string]*Network)
	byName := make(map[string]*Network)
	for i := range networks {
		n := &networks[i]
		if n.ID != "" {
			byID[n.ID] = n
		}
		if name := strings.ToLower(strings.TrimSpace(n.Name)); name != "" {
			if _, exists := byName[name]; exists {
				byName[name] = nil
			} else {
				byName[name] = n
			}
		}
	}
	for _, d := range devices {
		if len(d.NetworkTable) == 0 {
			continue
		}
		switch strings.ToLower(firstNonEmpty(d.Type, inferDeviceTypeFromModel(d.Model))) {
		case "udm", "udr", "udw", "ucg", "uxg", "ugw", "usg", "efg", "gateway", "router":
		default:
			continue
		}
		for _, row := range d.NetworkTable {
			local, external := ids[row.ID], ids[row.ExternalID]
			if local != "" && external != "" && local != external {
				continue
			}
			n := byID[firstNonEmpty(local, external)]
			if row.ID == "" && row.ExternalID == "" {
				n = byName[strings.ToLower(strings.TrimSpace(row.Name))]
			}
			if n != nil {
				n.IPv6Subnets = append(n.IPv6Subnets, row.IPv6Subnets...)
				n.IPv6Subnets = append(n.IPv6Subnets, row.IPv6Subnet, row.IPv6StaticSubnet)
			}
		}
	}
	for i := range networks {
		n := &networks[i]
		prefixes := n.Prefixes()
		n.IPv6Subnet, n.IPv6Subnets = "", nil
		for _, p := range prefixes {
			if p.Addr().Is6() {
				n.IPv6Subnets = append(n.IPv6Subnets, p.String())
			}
		}
		if len(n.IPv6Subnets) > 0 {
			n.IPv6Subnet = n.IPv6Subnets[0]
		}
	}
}

// extractIntegrationSubnet returns the CIDR string from an integrationNetwork,
// checking both the direct subnet field and nested ipv4Configuration.
func extractIntegrationSubnet(rn integrationNetwork) string {
	if rn.Subnet != "" {
		return rn.Subnet
	}
	if rn.IPv4Configuration != nil && rn.IPv4Configuration.HostIPAddress != "" && rn.IPv4Configuration.PrefixLength > 0 {
		return fmt.Sprintf("%s/%d", rn.IPv4Configuration.HostIPAddress, rn.IPv4Configuration.PrefixLength)
	}
	return ""
}

// ipv6Prefixes collects every configured subnet before the network selects its
// primary prefix, since firmware can report different values in each field.
func (rn rawNetwork) ipv6Prefixes() []string {
	return append([]string{rn.IPv6Subnet, rn.IPv6StaticSubnet}, rn.IPv6Subnets...)
}

// ipv6Prefixes includes the interface address alongside bare delegated prefixes.
func (rn integrationNetwork) ipv6Prefixes() []string {
	prefixes := []string{rn.IPv6Subnet}
	if cfg := rn.IPv6Configuration; cfg != nil {
		prefixes = append(prefixes, cfg.Subnet, cfg.Prefix)
		if cfg.HostIPAddress != "" && cfg.PrefixLength > 0 {
			prefixes = append(prefixes, fmt.Sprintf("%s/%d", cfg.HostIPAddress, cfg.PrefixLength))
		}
	}
	return prefixes
}

func integrationDHCPDisabled(rn integrationNetwork) bool {
	if rn.IPv4Configuration == nil || rn.IPv4Configuration.DHCPConfiguration == nil {
		return false
	}
	dc := rn.IPv4Configuration.DHCPConfiguration
	if dc.Enabled != nil && !*dc.Enabled {
		return true
	}
	mode := strings.ToUpper(strings.TrimSpace(dc.Mode))
	return mode == "NONE" || mode == "DISABLED" || mode == "OFF"
}

func extractIntegrationDHCPStart(rn integrationNetwork) string {
	if integrationDHCPDisabled(rn) {
		return ""
	}
	if s := strings.TrimSpace(rn.DHCPStart); s != "" {
		return s
	}
	if rn.IPv4Configuration != nil && rn.IPv4Configuration.DHCPConfiguration != nil && rn.IPv4Configuration.DHCPConfiguration.IPAddressRange != nil {
		return strings.TrimSpace(rn.IPv4Configuration.DHCPConfiguration.IPAddressRange.Start)
	}
	return ""
}

func extractIntegrationDHCPEnd(rn integrationNetwork) string {
	if integrationDHCPDisabled(rn) {
		return ""
	}
	if s := strings.TrimSpace(rn.DHCPEnd); s != "" {
		return s
	}
	if rn.IPv4Configuration != nil && rn.IPv4Configuration.DHCPConfiguration != nil && rn.IPv4Configuration.DHCPConfiguration.IPAddressRange != nil {
		return strings.TrimSpace(rn.IPv4Configuration.DHCPConfiguration.IPAddressRange.Stop)
	}
	return ""
}

func extractIntegrationDomainName(rn integrationNetwork) string {
	if s := strings.TrimSpace(rn.DomainName); s != "" {
		return s
	}
	if rn.IPv4Configuration != nil && rn.IPv4Configuration.DHCPConfiguration != nil {
		return strings.TrimSpace(rn.IPv4Configuration.DHCPConfiguration.DomainName)
	}
	return ""
}

func extractIntegrationDNS(rn integrationNetwork) []string {
	if len(rn.DNSServers) > 0 {
		return dedupeIPs(rn.DNSServers)
	}
	if rn.IPv4Configuration != nil && rn.IPv4Configuration.DHCPConfiguration != nil {
		dc := rn.IPv4Configuration.DHCPConfiguration
		if len(dc.DNSOverride) > 0 {
			return dedupeIPs(dc.DNSOverride)
		}
		return dedupeIPs(dc.DNSServerIPAddresses)
	}
	return nil
}

func dedupeIPs(ips []string) []string {
	if len(ips) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ips))
	var out []string
	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		k := strings.ToLower(ip)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func shortFetchErr(err error) string {
	var httpErr *httpStatusError
	if errors.As(err, &httpErr) {
		return fmt.Sprintf("HTTP %d", httpErr.status)
	}
	var apiErr *apiEnvelopeError
	if errors.As(err, &apiErr) && apiErr.msg != "" {
		return apiErr.msg
	}
	return "request failed"
}

// convertIntegrationPolicies normalizes wire Integration v1 firewall policies
// into domain FirewallPolicy values with resolved zone names, explicit ordering,
// connection-state/return-traffic semantics, negation, and unsupported selector markers.
func convertIntegrationPolicies(raw []integrationFirewallPolicy, zoneNames map[string]string, tmlByID map[string]integrationTrafficMatchingList) []FirewallPolicy {
	out := make([]FirewallPolicy, 0, len(raw))
	for i, rp := range raw {
		origin := ""
		if rp.Metadata != nil {
			origin = rp.Metadata.Origin
		}
		proto := "all"
		protoNegated := false
		ipVersion := "both"
		unsupported := ""
		if rp.IPProtocolScope != nil {
			switch strings.ToUpper(strings.TrimSpace(rp.IPProtocolScope.IPVersion)) {
			case "IPV4", "V4":
				ipVersion = "ipv4"
			case "IPV6", "V6":
				ipVersion = "ipv6"
			case "IPV4_AND_IPV6", "BOTH", "":
				ipVersion = "both"
			default:
				unsupported = "ipProtocolScope.ipVersion"
			}
			if rp.IPProtocolScope.ProtocolFilter != nil {
				pf := rp.IPProtocolScope.ProtocolFilter
				pName := firstNonEmpty(
					extractProtocolName(pf.Protocol),
					pf.NamedProtocol,
					extractProtocolName(pf.Preset),
					pf.PresetName,
				)
				switch {
				case pName != "":
					proto = strings.ToLower(strings.TrimSpace(pName))
					protoNegated = pf.MatchOpposite
				case pf.Type != "" && !strings.EqualFold(pf.Type, "ALL") && !strings.EqualFold(pf.Type, "ANY"):
					unsupported = fmt.Sprintf("protocol filter type %q", pf.Type)
				}
			}
		}

		idx := i + 1
		if rp.Index != nil {
			idx = *rp.Index
		}
		if rp.IPSecFilter != "" {
			unsupported = "ipsecFilter"
		}
		if rp.IPProtocolScope != nil && rp.IPProtocolScope.ProtocolFilter != nil {
			var named struct {
				Type json.RawMessage `json:"typenameFilter"`
			}
			_ = json.Unmarshal(rp.IPProtocolScope.ProtocolFilter.Protocol, &named)
			if len(named.Type) > 0 && string(named.Type) != "null" && !strings.EqualFold(string(named.Type), `"ANY"`) {
				unsupported = "protocol.typenameFilter"
			}
		}
		if !slices.Contains([]string{"ALLOW", "BLOCK", "DROP", "REJECT"}, strings.ToUpper(rp.Action.Type)) {
			unsupported = "action.type"
		}
		var states []string
		for _, cs := range rp.ConnectionStateFilter {
			if norm := strings.ToLower(strings.TrimSpace(cs)); norm != "" {
				if !slices.Contains([]string{"new", "established", "related", "invalid"}, norm) {
					unsupported = "connectionStateFilter"
					states = nil
					break
				}
				states = append(states, norm)
			}
		}
		schedule := ""
		if rp.Schedule != nil && !strings.EqualFold(rp.Schedule.Mode, "ALWAYS") && (rp.Schedule.Mode != "" || rp.Schedule.Name != "") {
			schedule = firstNonEmpty(rp.Schedule.Name, rp.Schedule.Mode)
		}

		srcEP := convertPolicyEndpoint(rp.Source, zoneNames, tmlByID)
		dstEP := convertPolicyEndpoint(rp.Destination, zoneNames, tmlByID)
		out = append(out, FirewallPolicy{
			ID:                 rp.ID,
			Name:               rp.Name,
			Enabled:            rp.Enabled,
			Action:             strings.ToUpper(strings.TrimSpace(rp.Action.Type)),
			Origin:             origin,
			Index:              idx,
			IPVersion:          ipVersion,
			Protocol:           proto,
			ProtocolNegated:    protoNegated,
			ConnectionStates:   states,
			MatchReturnTraffic: strings.EqualFold(rp.Action.Type, "ALLOW") && (rp.MatchReturnTraffic || rp.Action.AllowReturnTraffic),
			Schedule:           schedule,
			UnsupportedReason:  unsupported,
			Source:             srcEP,
			Destination:        dstEP,
			LoggingEnabled:     rp.LoggingEnabled,
		})
	}
	return out
}

// convertIntegrationACLs converts UniFi Integration API v1 /acl-rules entries
// into domain SwitchACL rules, resolving enforcing device IDs to MACs and
// preserving unsupported selector markers for safe unknown verdicts.
func convertIntegrationACLs(raw []integrationACLRule, devMACByID map[string]string) []SwitchACL {
	if len(raw) == 0 {
		return nil
	}
	out := make([]SwitchACL, 0, len(raw))
	for _, rr := range raw {
		idx := 0
		if rr.Index != nil {
			idx = *rr.Index
		}
		source := convertACLEndpoint(rr.SourceFilter)
		destination := convertACLEndpoint(rr.DestinationFilter)
		ipVer := strings.ToLower(rr.Type)
		if rr.Type == "MAC" {
			ipVer = "both"
		}
		proto := "all"
		for _, p := range rr.ProtocolFilter {
			switch strings.ToLower(p) {
			case "tcp", "udp":
				if proto == "all" {
					proto = strings.ToLower(p)
				} else if proto != strings.ToLower(p) {
					proto = "tcp_udp"
				}
			default:
				source.UnsupportedSelector = "acl.protocolFilter"
			}
		}
		var devMACs []string
		if rr.EnforcingDeviceFilter != nil {
			// A device-scoped ACL must never degrade silently into a site-wide
			// rule when a referenced device ID cannot be resolved to a MAC.
			filter := rr.EnforcingDeviceFilter
			if len(filter.DeviceIDs) == 0 || (filter.Type != "DEVICES" && filter.Type != "DEVICE_IDS") {
				source.UnsupportedSelector = "unresolved enforcing device filter"
			}
			for _, did := range filter.DeviceIDs {
				if m, ok := devMACByID[did]; ok && m != "" {
					devMACs = append(devMACs, m)
				} else {
					source.UnsupportedSelector = "unresolved enforcing device"
				}
			}
		}
		var netIDs []string
		if id := strings.TrimSpace(rr.NetworkIDFilter); id != "" {
			netIDs = append(netIDs, id)
		}
		for _, id := range rr.NetworkIDs {
			if id = strings.TrimSpace(id); id != "" {
				netIDs = append(netIDs, id)
			} else {
				source.UnsupportedSelector = "acl.networkIds"
			}
		}
		// Record schema and required-field errors on the rule even when
		// disabled so aclCoverage marks switch ACL coverage partial instead of
		// treating malformed rules as complete.
		switch {
		case rr.wireError != "":
			source.UnsupportedSelector = rr.wireError
		case rr.Enabled == nil:
			source.UnsupportedSelector = "acl.enabled"
		case rr.Index == nil || idx < 0:
			source.UnsupportedSelector = "acl.index"
		case rr.ID == "":
			source.UnsupportedSelector = "acl.id"
		case rr.Type != "IPV4" && rr.Type != "IPV6" && rr.Type != "MAC":
			source.UnsupportedSelector = "acl.type"
		case rr.Action != "ALLOW" && rr.Action != "BLOCK":
			source.UnsupportedSelector = "acl.action"
		case rr.Type == "MAC" && len(rr.ProtocolFilter) > 0:
			source.UnsupportedSelector = "acl.protocolFilter"
		}
		out = append(out, SwitchACL{
			RuleType:    rr.Type,
			ID:          rr.ID,
			Name:        rr.Name,
			Enabled:     rr.Enabled != nil && *rr.Enabled,
			Index:       idx,
			Action:      strings.ToUpper(strings.TrimSpace(rr.Action)),
			IPVersion:   ipVer,
			Protocol:    proto,
			Source:      source,
			Destination: destination,
			DeviceMACs:  devMACs,
			NetworkIDs:  netIDs,
		})
	}
	return out
}

// convertACLEndpoint normalizes one Integration v1 switch ACL endpoint filter
// into a PolicyEndpoint, marking UnsupportedSelector whenever the controller
// uses an unrecognized filter type, empty port filter, non-exact MAC prefix
// mask, negated compound target+port selector, or malformed address/MAC.
func convertACLEndpoint(ep *integrationACLEndpoint) PolicyEndpoint {
	out := PolicyEndpoint{
		AnyTarget: true,
		AnyPort:   true,
	}
	if ep == nil {
		return out
	}
	out.NegateTarget = ep.MatchOpposite
	for _, id := range ep.NetworkIDs {
		if strings.TrimSpace(id) == "" {
			out.UnsupportedSelector = "empty ACL network ID"
		} else {
			out.NetworkIDs = append(out.NetworkIDs, id)
		}
	}
	addresses := append(append([]string(nil), ep.IPAddressesOrSubnets...), ep.IPAddresses...)
	for _, ip := range append(addresses, ep.IPs...) {
		if ip = strings.TrimSpace(ip); ip != "" {
			out.IPs = append(out.IPs, ip)
		} else {
			out.UnsupportedSelector = "empty ACL address"
		}
	}
	for _, mac := range ep.MACAddresses {
		if mac = strings.ToLower(strings.TrimSpace(mac)); mac != "" {
			out.MACs = append(out.MACs, mac)
		} else {
			out.UnsupportedSelector = "empty ACL MAC"
		}
	}
	for _, p := range append(append([]int(nil), ep.Ports...), ep.PortFilter...) {
		if p > 0 && p <= 65535 {
			out.Ports = append(out.Ports, p)
		} else {
			out.UnsupportedSelector = "invalid switch ACL port"
		}
	}
	epType := strings.ToUpper(strings.TrimSpace(ep.Type))
	for _, item := range ep.Items {
		val := strings.TrimSpace(string(item.Value))
		kind := strings.ToUpper(strings.TrimSpace(item.Type))
		if kind == "" {
			kind = epType
		}
		switch kind {
		case "PORT_NUMBER_RANGE", "PORT_RANGE":
			end := item.End
			if item.Stop != 0 {
				if end != 0 && end != item.Stop {
					out.UnsupportedSelector = "conflicting ACL port range"
					continue
				}
				end = item.Stop
			}
			if item.Start < 1 || end < item.Start || end > 65535 {
				out.UnsupportedSelector = "invalid ACL port range"
			} else {
				out.PortRanges = append(out.PortRanges, PortRange{item.Start, end})
			}
		case "PORT", "PORTS", "PORT_NUMBER":
			p, err := strconv.Atoi(val)
			if err != nil || p < 1 || p > 65535 {
				out.UnsupportedSelector = "invalid ACL port item"
			} else {
				out.Ports = append(out.Ports, p)
			}
		case "MAC", "MAC_ADDRESS", "MAC_ADDRESSES":
			if m := canonicalMAC(val); m == "" {
				out.UnsupportedSelector = "invalid ACL MAC item"
			} else {
				out.MACs = append(out.MACs, m)
			}
		case "NETWORK", "NETWORKS":
			if val == "" {
				out.UnsupportedSelector = "invalid ACL network item"
			} else {
				out.NetworkIDs = append(out.NetworkIDs, val)
			}
		case "IP_ADDRESS", "SUBNET", "IP_ADDRESSES", "IP_ADDRESSES_OR_SUBNETS":
			out.IPs = append(out.IPs, val)
		default:
			out.UnsupportedSelector = "unknown ACL item type"
		}
	}
	if (epType == "ANY" || epType == "ALL") && (len(out.NetworkIDs)+len(out.IPs)+len(out.MACs) > 0) {
		out.UnsupportedSelector = "conflicting ACL endpoint selector"
	}
	if len(out.NetworkIDs) > 0 || len(out.IPs) > 0 || len(out.MACs) > 0 {
		out.AnyTarget = false
	} else if epType != "" && epType != "ANY" && epType != "ALL" && !strings.Contains(epType, "PORT") {
		out.AnyTarget = false
		out.UnsupportedSelector = fmt.Sprintf("opaque switch ACL filter (%q)", ep.Type)
	}
	if len(out.Ports) > 0 || len(out.PortRanges) > 0 {
		out.AnyPort = false
	}
	// Reject empty PORTS/portFilter selectors and non-exact MAC prefix masks
	// (PrefixLength != 48), which cannot be evaluated as exact host MACs.
	emptyPorts := epType == "PORTS" && out.AnyPort
	emptyPortFilter := ep.PortFilter != nil && len(ep.PortFilter) == 0
	nonExactMACPrefix := ep.PrefixLength != nil && *ep.PrefixLength != 48
	if emptyPorts || emptyPortFilter || nonExactMACPrefix {
		out.UnsupportedSelector = "unsupported or empty switch ACL filter"
	}
	switch epType {
	case "ANY", "ALL":
		if len(out.NetworkIDs)+len(out.IPs)+len(out.MACs) > 0 {
			out.UnsupportedSelector = "conflicting ACL endpoint selector"
		}
	case "PORTS":
		if len(out.NetworkIDs)+len(out.IPs)+len(out.MACs) > 0 {
			out.UnsupportedSelector = "conflicting ACL PORTS selector"
		}
	case "NETWORK", "NETWORKS":
		if len(out.NetworkIDs) == 0 || len(out.IPs)+len(out.MACs) > 0 {
			out.UnsupportedSelector = "mismatched ACL NETWORKS selector"
		}
	case "IP_ADDRESSES_OR_SUBNETS", "IP_ADDRESSES":
		if len(out.IPs) == 0 || len(out.NetworkIDs)+len(out.MACs) > 0 {
			out.UnsupportedSelector = "mismatched ACL IP selector"
		}
	case "MAC_ADDRESSES", "MAC":
		if len(out.MACs) == 0 || len(out.NetworkIDs)+len(out.IPs) > 0 {
			out.UnsupportedSelector = "mismatched ACL MAC selector"
		}
	default:
		out.UnsupportedSelector = "unsupported switch ACL filter type"
	}
	// A negated compound (target AND port) selector cannot be split into
	// independently negated target and port sets; only port-only negation maps
	// directly onto NegatePort.
	if ep.MatchOpposite && !out.AnyPort {
		if !out.AnyTarget {
			out.UnsupportedSelector = "negated compound switch ACL selector"
		} else {
			out.NegateTarget = false
			out.NegatePort = true
		}
	}
	for _, ip := range out.IPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			if _, err := netip.ParsePrefix(ip); err != nil {
				out.UnsupportedSelector = "invalid switch ACL address"
			}
		}
	}
	for _, m := range out.MACs {
		if canonicalMAC(m) == "" {
			out.UnsupportedSelector = "invalid switch ACL MAC"
		}
	}
	return out
}

// extractProtocolName decodes a UniFi Integration v1 protocol or preset field
// whether the controller emits a plain string ("TCP_UDP") or an object
// ({"name":"TCP_UDP"} / {"type":"TCP_UDP"} / {"value":"TCP_UDP"}).
func extractProtocolName(raw json.RawMessage) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ""
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		Name  string `json:"name"`
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(trimmed, &obj); err == nil {
		return strings.TrimSpace(firstNonEmpty(obj.Name, obj.Type, obj.Value))
	}
	return ""
}

// convertPolicyEndpoint extracts zone identity, IP addresses, network IDs, MACs,
// port numbers, negation flags, and unsupported traffic filters from an
// Integration v1 firewall policy endpoint.
func convertPolicyEndpoint(ep integrationPolicyEndpoint, zoneNames map[string]string, tmlByID map[string]integrationTrafficMatchingList) PolicyEndpoint {
	out := PolicyEndpoint{
		ZoneID:    ep.ZoneID,
		ZoneName:  zoneNames[ep.ZoneID],
		AnyTarget: true,
		AnyPort:   true,
	}
	tf := ep.TrafficFilter
	if tf == nil {
		return out
	}

	recognized := false
	if tf.IPAddressFilter != nil {
		if len(tf.IPAddressFilter.Items) > 0 {
			recognized = true
			out.AnyTarget = false
			out.NegateTarget = out.NegateTarget || tf.IPAddressFilter.MatchOpposite
			for _, item := range tf.IPAddressFilter.Items {
				v := strings.TrimSpace(string(item.Value))
				if item.Start != "" || item.Stop != "" {
					v = item.Start + "-" + item.Stop
				}
				if !validIPSelector(v) {
					out.UnsupportedSelector = "invalid IP filter item"
				} else {
					out.IPs = append(out.IPs, v)
				}
			}
			if len(out.IPs) == 0 {
				out.UnsupportedSelector = fmt.Sprintf("opaque ipAddressFilter (%q)", tf.IPAddressFilter.Type)
			}
		} else if list, ok := tmlByID[strings.TrimSpace(tf.IPAddressFilter.TrafficMatchingListID)]; ok && len(list.Items) > 0 {
			recognized = true
			out.AnyTarget = false
			out.NegateTarget = out.NegateTarget || tf.IPAddressFilter.MatchOpposite
			for _, item := range list.Items {
				if v := strings.TrimSpace(string(item.Value)); v != "" {
					out.IPs = append(out.IPs, v)
				} else if s, e := strings.TrimSpace(string(item.Start)), strings.TrimSpace(string(item.Stop)); s != "" && e != "" {
					out.IPs = append(out.IPs, s+"-"+e)
				}
			}
			if list.Type != "IPV4_ADDRESSES" && list.Type != "IPV6_ADDRESSES" || len(out.IPs) != len(list.Items) {
				out.UnsupportedSelector = "invalid IP list"
			}
			if len(out.IPs) == 0 {
				out.UnsupportedSelector = fmt.Sprintf("opaque ipAddressFilter list (%q)", list.Name)
			}
		} else {
			out.AnyTarget = false
			out.UnsupportedSelector = fmt.Sprintf("reference ipAddressFilter (%q)", firstNonEmpty(tf.IPAddressFilter.Type, "empty"))
		}
	}
	if tf.NetworkFilter != nil {
		if len(tf.NetworkFilter.NetworkIDs) > 0 {
			recognized = true
			out.AnyTarget = false
			out.NegateTarget = out.NegateTarget || tf.NetworkFilter.MatchOpposite
			out.NetworkIDs = append(out.NetworkIDs, tf.NetworkFilter.NetworkIDs...)
		} else {
			out.AnyTarget = false
			out.UnsupportedSelector = "reference networkFilter (empty)"
		}
	}
	if tf.MACAddressFilter != nil {
		if len(tf.MACAddressFilter.MACAddresses) > 0 {
			recognized = true
			out.AnyTarget = false
			out.NegateTarget = out.NegateTarget || tf.MACAddressFilter.MatchOpposite
			for _, m := range tf.MACAddressFilter.MACAddresses {
				if norm := strings.ToLower(strings.TrimSpace(m)); norm != "" {
					out.MACs = append(out.MACs, norm)
				}
			}
		} else {
			out.AnyTarget = false
			out.UnsupportedSelector = "reference macAddressFilter (empty)"
		}
	}
	if tf.PortFilter != nil {
		if len(tf.PortFilter.Items) > 0 {
			recognized = true
			out.AnyPort = false
			out.NegatePort = out.NegatePort || tf.PortFilter.MatchOpposite
			for _, item := range tf.PortFilter.Items {
				if item.Stop != 0 {
					if item.End != 0 && item.Stop != item.End {
						out.UnsupportedSelector = "conflicting port range"
						continue
					}
					item.End = item.Stop
				}
				if item.Start >= 1 && item.End >= item.Start && item.End <= 65535 {
					if item.End-item.Start+1 <= 16 {
						for p := item.Start; p <= item.End; p++ {
							out.Ports = append(out.Ports, p)
						}
					} else {
						out.PortRanges = append(out.PortRanges, PortRange{Start: item.Start, End: item.End})
					}
					continue
				}
				if item.Start != 0 || item.End != 0 {
					// Out-of-range port bounds (e.g., > 65535 or negative) cannot be trusted.
					out.UnsupportedSelector = fmt.Sprintf("invalid port range %d-%d", item.Start, item.End)
					continue
				}
				if v := strings.TrimSpace(string(item.Value)); v != "" {
					ports, ranges, bad := parsePolicyPortSpec(v)
					out.Ports = append(out.Ports, ports...)
					out.PortRanges = append(out.PortRanges, ranges...)
					if bad {
						out.UnsupportedSelector = fmt.Sprintf("unrecognized port spec %q", v)
					}
				} else {
					out.UnsupportedSelector = "invalid port item"
				}
			}
			if !out.HasPortConstraint() && out.UnsupportedSelector == "" {
				out.UnsupportedSelector = fmt.Sprintf("opaque portFilter (%q)", tf.PortFilter.Type)
			}
		} else if list, ok := tmlByID[strings.TrimSpace(tf.PortFilter.TrafficMatchingListID)]; ok && len(list.Items) > 0 {
			recognized = true
			out.AnyPort = false
			out.NegatePort = out.NegatePort || tf.PortFilter.MatchOpposite
			for _, item := range list.Items {
				if list.Type != "PORTS" {
					out.UnsupportedSelector = "invalid port list type"
					break
				}
				startNum, sErr := strconv.Atoi(strings.TrimSpace(string(item.Start)))
				stopNum := item.End
				if stopNum == 0 {
					if parsed, err := strconv.Atoi(strings.TrimSpace(string(item.Stop))); err == nil {
						stopNum = parsed
					}
				}
				if sErr == nil && startNum >= 1 && stopNum >= startNum && stopNum <= 65535 {
					if stopNum-startNum+1 <= 16 {
						for p := startNum; p <= stopNum; p++ {
							out.Ports = append(out.Ports, p)
						}
					} else {
						out.PortRanges = append(out.PortRanges, PortRange{Start: startNum, End: stopNum})
					}
					continue
				}
				if v := strings.TrimSpace(string(item.Value)); v != "" {
					ports, ranges, bad := parsePolicyPortSpec(v)
					out.Ports = append(out.Ports, ports...)
					out.PortRanges = append(out.PortRanges, ranges...)
					if bad {
						out.UnsupportedSelector = fmt.Sprintf("unrecognized port list item %q", v)
					}
				} else {
					out.UnsupportedSelector = "invalid port item"
				}
			}
			if !out.HasPortConstraint() && out.UnsupportedSelector == "" {
				out.UnsupportedSelector = fmt.Sprintf("opaque portFilter list (%q)", list.Name)
			}
		} else {
			out.AnyPort = false
			out.UnsupportedSelector = fmt.Sprintf("reference portFilter (%q)", firstNonEmpty(tf.PortFilter.Type, "empty"))
		}
	}
	// If the controller supplied a non-empty trafficFilter type (e.g., REGION,
	// DOMAIN, APPLICATION, OBJECT_GROUP) that is not modeled by the decoded
	// IP/Network/MAC/Port sub-filters, always mark it unsupported even when a
	// sibling portFilter was also present so a narrowed BLOCK never shadows
	// later ALLOW rules.
	tfType := strings.ToUpper(strings.TrimSpace(tf.Type))
	if out.UnsupportedSelector == "" && tfType != "" && tfType != "ANY" && tfType != "ALL" {
		if !trafficFilterTypeDecoded(tfType, tf.IPAddressFilter != nil, tf.NetworkFilter != nil, tf.MACAddressFilter != nil, tf.PortFilter != nil) || !recognized {
			out.AnyTarget = false
			out.UnsupportedSelector = fmt.Sprintf("traffic filter type %q", tf.Type)
		}
	}
	for _, v := range out.IPs {
		if !validIPSelector(v) {
			out.UnsupportedSelector = "invalid IP selector"
		}
	}
	for i, v := range out.MACs {
		out.MACs[i] = canonicalMAC(v)
		if out.MACs[i] == "" {
			out.UnsupportedSelector = "invalid MAC selector"
		}
	}
	if out.NegateTarget && out.HasCompoundTarget() {
		out.UnsupportedSelector = "mixed target negation"
	}
	return out
}

// trafficFilterTypeDecoded reports whether a declared Integration v1
// trafficFilter.type corresponds to one of the decoded IP, Network, MAC, or
// Port sub-filter blocks rather than an unmodeled filter type (such as REGION
// or APPLICATION).
func trafficFilterTypeDecoded(tfType string, hasIP, hasNet, hasMAC, hasPort bool) bool {
	switch tfType {
	case "", "ANY", "ALL":
		return true
	case "PORT", "PORTS", "PORT_FILTER":
		return hasPort
	case "IP_ADDRESS", "IP", "IP_ADDRESSES", "IP_RANGE", "SUBNET":
		return hasIP
	case "NETWORK", "NETWORKS":
		return hasNet
	case "MAC_ADDRESS", "MAC", "MAC_ADDRESSES":
		return hasMAC
	default:
		return false
	}
}

// parsePolicyPortSpec decodes a port specification string ("443", "80,443",
// "400-500", "1-65535") without dropping ranges wider than 16 ports: small
// ranges <=16 expand into concrete ports while wider valid ranges are preserved
// in PortRanges.
func parsePolicyPortSpec(spec string) (ports []int, ranges []PortRange, hadInvalid bool) {
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			hadInvalid = true
			continue
		}
		if startStr, endStr, ok := strings.Cut(token, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(startStr))
			end, err2 := strconv.Atoi(strings.TrimSpace(endStr))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || end < start {
				hadInvalid = true
				continue
			}
			if end-start+1 <= 16 {
				for p := start; p <= end; p++ {
					ports = append(ports, p)
				}
			} else {
				ranges = append(ranges, PortRange{Start: start, End: end})
			}
			continue
		}
		p, err := strconv.Atoi(token)
		if err != nil || p < 1 || p > 65535 {
			hadInvalid = true
			continue
		}
		ports = append(ports, p)
	}
	return ports, ranges, hadInvalid
}

// enrichIntegrationNetworks fills in missing IPv4 subnets, isolation flags,
// zone IDs, and network purposes from bounded detail reads and legacy inventory.
// Older consoles without a v1 network collection only use the legacy inventory.
func (c *Controller) enrichIntegrationNetworks(ctx context.Context, siteBase string, items []integrationNetwork, legacyNets []rawNetwork, legacyFallback bool) error {
	// A fixed worker pool bounds goroutines as well as HTTP concurrency.
	jobs := make(chan int, len(items))
	if !legacyFallback {
		for i := range items {
			jobs <- i
		}
	}
	close(jobs)
	var wg sync.WaitGroup
	errs := make(chan error, len(items))
	for range min(4, len(items)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				n := &items[i]
				var detail integrationNetwork
				if err := c.getJSON(ctx, siteBase+"/networks/"+url.PathEscape(n.ID), &detail); err != nil {
					errs <- err
					continue
				}
				if detail.ID != "" && detail.ID != n.ID {
					errs <- errors.New("network detail ID mismatch")
					continue
				}
				if detail.IPv4Configuration != nil {
					n.IPv4Configuration = detail.IPv4Configuration
				}
				n.collectedIPv6 = detail.ipv6Prefixes()
				n.IsolationEnabled = n.IsolationEnabled || detail.IsolationEnabled
				if detail.InternetAccessEnabled != nil {
					n.InternetAccessEnabled = detail.InternetAccessEnabled
				}
				n.DeviceID = firstNonEmpty(detail.DeviceID, n.DeviceID)
				n.ZoneID = firstNonEmpty(detail.ZoneID, n.ZoneID)
				n.DomainName = firstNonEmpty(detail.DomainName, n.DomainName)
				n.Subnet = firstNonEmpty(detail.Subnet, n.Subnet)
				n.Purpose = firstNonEmpty(detail.Purpose, n.Purpose)
				if detail.Management != "" {
					n.Management = detail.Management
				}
				if detail.MDNSForwardingEnabled != nil {
					n.MDNSEnabled = detail.MDNSForwardingEnabled
				}
				if detail.DHCPGuarding != nil {
					on := true
					n.DHCPGuardEnabled = &on
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	rows, names, vlans := joinByUniqueField(legacyNets)
	refs := make(aliases)
	for _, r := range legacyNets {
		refs.add(r.ID, r.ID, r.ExternalID)
	}
	itemNameCounts := make(map[string]int, len(items))
	for _, it := range items {
		if k := strings.ToLower(strings.TrimSpace(it.Name)); k != "" {
			itemNameCounts[k]++
		}
	}
	for i := range items {
		items[i].collectedIPv6 = append(items[i].collectedIPv6, items[i].ipv6Prefixes()...)
		id, ok := refs[items[i].ID]
		if !ok {
			nameKey := strings.ToLower(strings.TrimSpace(items[i].Name))
			name, named := names[nameKey]
			if itemNameCounts[nameKey] > 1 {
				named = false
			}
			vlan, tagged := vlans[string(items[i].VLANID)]
			switch {
			case named && tagged && name == vlan:
				id = name
			case named && !tagged && (items[i].VLANID == "" || rows[name].VLAN == "" || rows[name].VLAN == items[i].VLANID):
				id = name
			case tagged && !named:
				id = vlan
			}
		}
		rn, ok := rows[id]
		if !ok || (rn.ExternalID != "" && rn.ExternalID != items[i].ID && rn.ID != items[i].ID) {
			continue
		}
		if extractIntegrationSubnet(items[i]) == "" && rn.IPSubnet != "" {
			items[i].Subnet = rn.IPSubnet
		}
		items[i].collectedIPv6 = append(items[i].collectedIPv6, rn.ipv6Prefixes()...)
		if items[i].Purpose == "" && rn.Purpose != "" {
			items[i].Purpose = rn.Purpose
		}
		if rn.NetworkIsolationEnabled {
			items[i].IsolationEnabled = true
		}
		if items[i].InternetAccessEnabled == nil && rn.InternetAccessEnabled != nil {
			items[i].InternetAccessEnabled = rn.InternetAccessEnabled
		}
		if extractIntegrationDomainName(items[i]) == "" && strings.TrimSpace(rn.DomainName) != "" {
			items[i].DomainName = strings.TrimSpace(rn.DomainName)
		}
		if strings.EqualFold(rn.GatewayType, "switch") {
			items[i].Management = "SWITCH"
		}
		if items[i].RouterDeviceMAC == "" && strings.EqualFold(strings.TrimSpace(rn.GatewayType), "switch") && rn.GatewayDevice != "" {
			items[i].RouterDeviceMAC = strings.ToLower(strings.TrimSpace(rn.GatewayDevice))
		}
		if rn.DHCPDEnabled == nil || *rn.DHCPDEnabled {
			if extractIntegrationDHCPStart(items[i]) == "" && rn.DHCPDStart != "" {
				items[i].DHCPStart = rn.DHCPDStart
			}
			if extractIntegrationDHCPEnd(items[i]) == "" && rn.DHCPDStop != "" {
				items[i].DHCPEnd = rn.DHCPDStop
			}
		} else {
			items[i].DHCPStart = ""
			items[i].DHCPEnd = ""
		}
		if items[i].DHCPGuardEnabled == nil && rn.DHCPGuardEnabled != nil {
			items[i].DHCPGuardEnabled = rn.DHCPGuardEnabled
		}
		if items[i].MDNSEnabled == nil && rn.MDNSEnabled != nil {
			items[i].MDNSEnabled = rn.MDNSEnabled
		}
		if items[i].IGMPSnooping == nil && rn.IGMPSnooping != nil {
			items[i].IGMPSnooping = rn.IGMPSnooping
		}
		if len(extractIntegrationDNS(items[i])) == 0 {
			if s := strings.TrimSpace(rn.DHCPDDNS1); s != "" {
				items[i].DNSServers = append(items[i].DNSServers, s)
			}
			if s := strings.TrimSpace(rn.DHCPDDNS2); s != "" {
				items[i].DNSServers = append(items[i].DNSServers, s)
			}
		}
	}
	return <-errs
}

// cachedDenial remembers an optional feed's denial until it is worth re-probing.
type cachedDenial struct {
	err   *httpStatusError
	until time.Time
}

// httpStatusError preserves the HTTP status code and optional controller error
// message on failed requests so callers can distinguish missing endpoints (404),
// session expiry (401), and explicit permission errors (NoPermission).
type httpStatusError struct {
	method string
	path   string
	status int
	apiMsg string
}

// Error formats a concise description of the non-2xx HTTP status.
func (e *httpStatusError) Error() string {
	method := e.method
	if method == "" {
		method = http.MethodGet
	}
	if e.apiMsg != "" {
		return fmt.Sprintf("%s %s returned HTTP %d (%s)", method, e.path, e.status, e.apiMsg)
	}
	return fmt.Sprintf("%s %s returned HTTP %d", method, e.path, e.status)
}

// apiEnvelopeError reports a UniFi REST envelope carrying meta.rc == "error"
// even when the controller replied with HTTP 200.
type apiEnvelopeError struct {
	path string
	msg  string
}

// Error formats the controller API path and envelope error message.
func (e *apiEnvelopeError) Error() string {
	if e.msg != "" {
		return fmt.Sprintf("API %s returned error: %s", e.path, e.msg)
	}
	return fmt.Sprintf("API %s returned meta.rc=error", e.path)
}

func extractAPIErrorMsg(body []byte) string {
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	var parsed struct {
		Meta *struct {
			Msg string `json:"msg"`
		} `json:"meta"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		if parsed.Meta != nil && strings.TrimSpace(parsed.Meta.Msg) != "" {
			return strings.TrimSpace(parsed.Meta.Msg)
		}
		if msg := firstNonEmpty(parsed.Code, parsed.Message, parsed.Error); msg != "" {
			return msg
		}
	}
	return ""
}

func isPermissionDeniedMsg(msg string) bool {
	low := strings.ToLower(strings.TrimSpace(msg))
	if low == "" {
		return false
	}
	return strings.Contains(low, "nopermission") ||
		strings.Contains(low, "forbidden") ||
		strings.Contains(low, "permission denied") ||
		strings.Contains(low, "access denied") ||
		strings.Contains(low, "insufficient")
}

func checkAPIEnvelopeError(path string, body []byte) error {
	var metaOnly struct {
		Meta *struct {
			RC  string `json:"rc"`
			Msg string `json:"msg"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &metaOnly); err == nil && metaOnly.Meta != nil {
		if strings.EqualFold(strings.TrimSpace(metaOnly.Meta.RC), "error") {
			return &apiEnvelopeError{path: path, msg: strings.TrimSpace(metaOnly.Meta.Msg)}
		}
	}
	return nil
}

func isSessionExpiredError(err error) bool {
	var httpErr *httpStatusError
	if errors.As(err, &httpErr) && httpErr.status == http.StatusUnauthorized {
		if isPermissionDeniedMsg(httpErr.apiMsg) {
			return false
		}
		return true
	}
	var apiErr *apiEnvelopeError
	if errors.As(err, &apiErr) && strings.Contains(strings.ToLower(apiErr.msg), "loginrequired") {
		return true
	}
	return false
}

// waitTurn admits requests before the HTTP timeout starts. Only the caller at
// the head of a paced queue needs a timer. It rechecks the shared deadline
// after waking because an in-flight request may have received another 429.
func (c *Controller) waitTurn(ctx context.Context) error {
	if c.requestDelay > 0 {
		select {
		case c.paceSlot <- struct{}{}:
			defer func() { <-c.paceSlot }()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.paceMu.Lock()
		start := c.rateLimitUntil
		if c.nextRequestAt.After(start) {
			start = c.nextRequestAt
		}
		now := time.Now()
		if !start.After(now) {
			if c.requestDelay > 0 {
				c.nextRequestAt = now.Add(c.requestDelay)
			}
			c.paceMu.Unlock()
			return nil
		}
		c.paceMu.Unlock()
		if err := waitForRetry(ctx, start.Sub(now)); err != nil {
			return err
		}
	}
}

// cooldownEndsBefore reports whether the shared 429 cooldown ends before the
// caller's deadline, so a retry never consumes the rest of a bounded poll.
func (c *Controller) cooldownEndsBefore(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	c.paceMu.Lock()
	defer c.paceMu.Unlock()
	return c.rateLimitUntil.Before(deadline)
}

// waitForRetry lets cancellation interrupt either a pacing slot or a transient retry.
func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// parseRetryAfter bounds both forms of the HTTP header before converting seconds
// to a Duration so even an overflowing integer cannot bypass the cooldown.
func parseRetryAfter(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	if secs, err := strconv.ParseUint(header, 10, 64); err == nil || errors.Is(err, strconv.ErrRange) {
		return time.Duration(min(secs, uint64(defaultRateLimitMax/time.Second))) * time.Second
	}
	if when, err := http.ParseTime(header); err == nil {
		return min(max(0, when.Sub(now)), defaultRateLimitMax)
	}
	return 0
}

// readResponse applies the controller concurrency limit and quota to HTTP
// requests, including login. A 429 delays other callers as soon as its headers
// arrive. When attachCSRF is true, the current CSRF token is read after pacing
// so an intervening relogin cannot pair an old token with a refreshed cookie.
func (c *Controller) readResponse(req *http.Request, path string, attachCSRF bool) (*http.Response, []byte, error) {
	select {
	case c.inFlight <- struct{}{}:
		defer func() { <-c.inFlight }()
	case <-req.Context().Done():
		return nil, nil, req.Context().Err()
	}
	if err := c.waitTurn(req.Context()); err != nil {
		return nil, nil, err
	}
	var epoch uint64
	if attachCSRF {
		var tok string
		tok, epoch = c.currentCSRFTokenAndEpoch()
		if tok != "" {
			req.Header.Set("X-CSRF-Token", tok)
		} else {
			req.Header.Del("X-CSRF-Token")
		}
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s: %w", req.Method, path, err)
	}
	defer resp.Body.Close()

	if attachCSRF {
		if tok := resp.Header.Get("X-CSRF-Token"); tok != "" {
			c.setCSRFTokenIfEpoch(epoch, tok)
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		now := time.Now()
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), now)
		// Share the server's cooldown, or one base interval, across all callers;
		// exponential backoff stays local to the caller that keeps being refused.
		delay := min(c.rateLimitMax, max(retryAfter, c.rateLimitBase+rand.N(c.rateLimitBase/8+1)))
		until := now.Add(delay)
		c.paceMu.Lock()
		if until.After(c.rateLimitUntil) {
			c.rateLimitUntil = until
		}
		c.paceMu.Unlock()
	}

	body, err := readControllerBody(resp.Body)
	if err != nil && resp.StatusCode != http.StatusTooManyRequests {
		return resp, nil, fmt.Errorf("read %s: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, nil, &httpStatusError{
			method: req.Method, path: path, status: resp.StatusCode,
			apiMsg: extractAPIErrorMsg(body),
		}
	}
	return resp, body, nil
}

// getJSON reads a controller feed using the retry policy shared with telemetry queries.
func (c *Controller) getJSON(ctx context.Context, fullPath string, dst any) error {
	return c.queryJSON(ctx, http.MethodGet, fullPath, nil, dst)
}

// queryJSON retries read-only queries after throttling, a transient failure, or
// cookie expiry. An explicit login starts a new session and clears cached denials.
func (c *Controller) queryJSON(ctx context.Context, method, fullPath string, raw []byte, dst any) error {
	var cacheKey string
	var unsupported map[string]cachedDenial
	path := strings.TrimPrefix(fullPath, "/proxy/network")
	if c.apiKey != "" && (strings.HasPrefix(path, "/api/s/") || strings.HasPrefix(path, "/v2/api/")) {
		cacheKey = method + " " + fullPath
		c.authMu.RLock()
		// Only Integration v1 sessions have a cache. Keep this session's map
		// so a late response cannot suppress a feed after a new login.
		unsupported = c.unsupportedPaths
		cached, hit := unsupported[cacheKey]
		c.authMu.RUnlock()
		if hit && time.Now().Before(cached.until) {
			return cached.err
		}
	}

	relogged, retriedTransient := false, false
	for attempt := 0; ; attempt++ {
		epoch := c.currentAuthEpoch()
		err := c.queryJSONOnce(ctx, method, fullPath, raw, dst)
		if err != nil && !relogged && c.canRelogin() && isSessionExpiredError(err) && !c.isPathUnauthorized(fullPath) {
			relogged = true
			if loginErr := c.relogin(ctx, epoch); loginErr != nil {
				return fmt.Errorf("re-authentication failed: %w (after %w)", loginErr, err)
			}
			// Replaying with the new cookie does not consume a transient retry.
			err = c.queryJSONOnce(ctx, method, fullPath, raw, dst)
			if isSessionExpiredError(err) {
				c.markPathUnauthorized(fullPath)
			}
		}
		if err == nil {
			c.clearPathUnauthorized(fullPath)
			return nil
		}
		var apiErr *apiEnvelopeError
		if errors.As(err, &apiErr) {
			return err
		}
		var httpErr *httpStatusError
		if errors.As(err, &httpErr) {
			switch httpErr.status {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
				if unsupported != nil {
					c.authMu.Lock()
					unsupported[cacheKey] = cachedDenial{err: httpErr, until: time.Now().Add(c.reloginSuppressTTLDuration())}
					c.authMu.Unlock()
				}
				return err
			case http.StatusTooManyRequests:
				if attempt+1 >= maxRateLimitAttempts || !c.cooldownEndsBefore(ctx) {
					return err
				}
				backoff := c.rateLimitBase << attempt
				backoff = min(c.rateLimitMax, backoff+rand.N(backoff/8+1))
				if deadline, ok := ctx.Deadline(); ok && !time.Now().Add(backoff).Before(deadline) {
					return err
				}
				if err := waitForRetry(ctx, backoff); err != nil {
					return err
				}
				continue
			}
			if httpErr.status < 500 {
				return err
			}
		}
		if retriedTransient || attempt+1 == maxRateLimitAttempts {
			return err
		}
		retriedTransient = true
		if err := waitForRetry(ctx, 250*time.Millisecond); err != nil {
			return err
		}
	}
}

// queryJSONOnce sends one read-only query. Rebuilding the request on each
// attempt replays the POST payload and picks up any refreshed session token.
func (c *Controller) queryJSONOnce(ctx context.Context, method, fullPath string, raw []byte, dst any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+fullPath, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	_, body, err := c.readResponse(req, fullPath, true)
	if err != nil {
		return err
	}
	if err := checkAPIEnvelopeError(fullPath, body); err != nil {
		return err
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode %s: %w", fullPath, err)
	}
	return nil
}
