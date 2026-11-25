// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestCLIHelpNegativeLimitCacheDirStateCheckAndReportCounts verifies core CLI
// invariants: -h returns flag.ErrHelp, negative -limit is rejected without
// panic, cve subcommands honor config.yaml cve.cache_dir, unwritable state
// paths fail fast, printReport distinguishes probed vs skipped hosts, and
// cancelled contexts abort executeCycle cleanly.
func TestCLIHelpNegativeLimitCacheDirStateCheckAndReportCounts(t *testing.T) {
	// -h returns flag.ErrHelp so main() exits 0.
	var out, errBuf bytes.Buffer
	err := run([]string{"scan", "-h"}, &out, &errBuf)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("expected flag.ErrHelp for `scan -h`, got %v", err)
	}

	// Negative -limit in cve explore and printCVEMatchTable must not panic.
	err = run([]string{"cve", "explore", "-limit", "-1"}, &out, &errBuf)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected error for negative -limit, got %v", err)
	}
	printCVEMatchTable(&out, []cve.Match{{}}, -5)

	// resolveCVECacheDir honors config.yaml cve.cache_dir when -cache is omitted.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	customCache := filepath.Join(dir, "custom-cve")
	cfgYAML := "unifi:\n  url: https://192.0.2.1\n  api_key: k\ncve:\n  cache_dir: " + customCache + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveCVECacheDir("", cfgPath, true)
	if err != nil || got != customCache {
		t.Fatalf("resolveCVECacheDir = (%q, %v), want (%q, nil)", got, err, customCache)
	}
	got, err = resolveCVECacheDir("/explicit/cache", cfgPath, true)
	if err != nil || got != "/explicit/cache" {
		t.Fatalf("explicit -cache override failed: got (%q, %v)", got, err)
	}

	// verifyStatePathWritable fails fast on a read-only directory.
	roDir := filepath.Join(dir, "ro")
	if err := os.MkdirAll(roDir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(roDir, 0o755) }()
	if os.Geteuid() != 0 {
		if err := verifyStatePathWritable(filepath.Join(roDir, "state.json")); err == nil {
			t.Fatal("expected verifyStatePathWritable to fail on read-only dir")
		}
	}

	// printReport reports probed vs skipped hosts separately.
	var repBuf bytes.Buffer
	snap := &unifi.Snapshot{Site: "default", ControllerType: "integration-v1"}
	rep := risk.Report{ClientCount: 10, CleanClients: 10}
	profiles := make([]probe.HostProfile, 7)
	printReport(&repBuf, snap, rep, profiles, nil, nil, false)
	if !strings.Contains(repBuf.String(), "7/7 probed host(s) passed (3 skipped/excluded)") {
		t.Fatalf("expected probed vs skipped count in report, got:\n%s", repBuf.String())
	}

	// A pre-cancelled context passed to executeCycle must abort with context.Canceled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := config.Default()
	cfg.UniFi.URL = "https://127.0.0.1:1"
	cfg.UniFi.APIKey = "test-key"
	_, _, _, err = executeCycle(ctx, cfg, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from executeCycle with cancelled ctx, got %v", err)
	}
}

// TestRunScanWithoutSaveStateSkipsWritableStateCheck verifies that a read-only
// one-shot `uniblue scan` neither requires a writable state directory nor
// creates missing state directories unless -save-state is explicitly enabled.
func TestRunScanWithoutSaveStateSkipsWritableStateCheck(t *testing.T) {
	dir := t.TempDir()
	uncreatedDir := filepath.Join(dir, "should-not-be-created")
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := "unifi:\n  url: https://127.0.0.1:1\n  api_key: test-key\nstate:\n  path: " + filepath.Join(uncreatedDir, "state.json") + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var out, errBuf bytes.Buffer
	err := runScan(ctx, []string{"-config", cfgPath}, &out, &errBuf)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected scan without -save-state to reach controller call (context.Canceled), got %v", err)
	}
	if _, statErr := os.Stat(uncreatedDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("plain scan without -save-state must not create state dir %q, statErr=%v", uncreatedDir, statErr)
	}

	// With a read-only state directory: plain scan must not fail on writability,
	// whereas -save-state must fail fast with a writability error.
	if os.Geteuid() != 0 {
		roDir := filepath.Join(dir, "ro-state")
		if err := os.MkdirAll(roDir, 0o555); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(roDir, 0o755) }()

		roCfgPath := filepath.Join(dir, "ro-config.yaml")
		roCfgYAML := "unifi:\n  url: https://127.0.0.1:1\n  api_key: test-key\nstate:\n  path: " + filepath.Join(roDir, "state.json") + "\n"
		if err := os.WriteFile(roCfgPath, []byte(roCfgYAML), 0o600); err != nil {
			t.Fatal(err)
		}

		err = runScan(ctx, []string{"-config", roCfgPath}, &out, &errBuf)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("plain scan with read-only state dir should not fail writability check, got %v", err)
		}
		err = runScan(ctx, []string{"-config", roCfgPath, "-save-state"}, &out, &errBuf)
		if err == nil || !strings.Contains(err.Error(), "is not writable") {
			t.Fatalf("scan -save-state with read-only state dir should fail fast, got %v", err)
		}
	}
}

// TestWatchSessionRetainsInMemoryBaselineOnSaveFailure verifies that a runtime
// SaveState error keeps the updated baseline in memory so subsequent intervals
// do not reload stale on-disk state and re-send identical webhook alerts.
func TestWatchSessionRetainsInMemoryBaselineOnSaveFailure(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	cfg := config.Default()
	cfg.State.Path = statePath

	snap := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{IP: "192.168.1.20", MAC: "aa:bb:cc:00:00:20", Name: "nas"},
		},
		PortForwards: []unifi.PortForward{
			{ID: "pf-1", Name: "RDP Forward", Enabled: true, Proto: "tcp", DstPort: "3389", FwdIP: "192.168.1.20", FwdPort: "3389", Src: "any"},
		},
	}
	report := risk.Evaluate(snap, nil, cfg.Network)
	profiles := []probe.HostProfile{{Client: snap.Clients[0]}}

	var logBuf bytes.Buffer
	var loadCalls, sendCalls, saveCalls int
	saveErr := os.ErrPermission
	var sendErr error

	sess := &watchSession{
		cfg:    cfg,
		minSev: checks.SeverityMedium,
		logger: slog.New(slog.NewTextHandler(&logBuf, nil)),
		scanFn: func(context.Context) (*unifi.Snapshot, []probe.HostProfile, risk.Report, error) {
			return snap, profiles, report, nil
		},
		sendFn: func(context.Context, string, risk.Diff) error {
			sendCalls++
			return sendErr
		},
		loadFn: func(path string) (*risk.State, error) {
			loadCalls++
			return risk.LoadState(path)
		},
		saveFn: func(path string, st *risk.State) error {
			saveCalls++
			if saveErr != nil {
				return saveErr
			}
			return risk.SaveState(path, st)
		},
	}

	// Cycle 1: notification fails -> previous baseline preserved so next cycle retries.
	sendErr = errors.New("webhook down")
	sess.runCycle(context.Background())
	if sendCalls != 1 || saveCalls != 0 {
		t.Fatalf("cycle 1: sendCalls=%d saveCalls=%d, want 1 and 0", sendCalls, saveCalls)
	}

	// Cycle 2: notification succeeds, SaveState fails -> alert sent once,
	// baseline retained in memory despite persistence failure.
	sendErr = nil
	sess.runCycle(context.Background())
	if sendCalls != 2 || saveCalls != 1 {
		t.Fatalf("cycle 2: sendCalls=%d saveCalls=%d, want 2 and 1", sendCalls, saveCalls)
	}
	if !strings.Contains(logBuf.String(), "retaining updated baseline in memory") {
		t.Fatalf("expected runtime persistence warning in watch log, got:\n%s", logBuf.String())
	}

	// Cycle 3: SaveState still fails -> in-memory baseline prevents duplicate alert.
	sess.runCycle(context.Background())
	if sendCalls != 2 {
		t.Fatalf("cycle 3 re-sent duplicate alert after SaveState failure: sendCalls=%d, want 2", sendCalls)
	}
	if loadCalls != 1 {
		t.Fatalf("expected initial state to load once, got %d load calls", loadCalls)
	}

	// Cycle 4: storage recovers -> SaveState writes the up-to-date baseline cleanly.
	saveErr = nil
	sess.runCycle(context.Background())
	if sendCalls != 2 {
		t.Fatalf("cycle 4 sent unexpected alert: sendCalls=%d, want 2", sendCalls)
	}
	persisted, err := risk.LoadState(statePath)
	if err != nil || persisted == nil || len(persisted.Findings) == 0 {
		t.Fatalf("expected recovered state persisted to disk, got state=%+v err=%v", persisted, err)
	}
}

// TestResolveCVECacheDirParsesCacheDirWithoutCredentials verifies that
// resolveCVECacheDir reads only cve.cache_dir without requiring UniFi API
// credentials or failing on unrelated fields, while returning errors when an
// explicit -config file is missing or malformed.
func TestResolveCVECacheDirParsesCacheDirWithoutCredentials(t *testing.T) {
	dir := t.TempDir()
	customCache := filepath.Join(dir, "nvd-cache")

	// Config with empty credentials (supplied via env in production) and an
	// unrelated unknown field must still honor cve.cache_dir.
	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := `unifi:
  url: ""
  api_key: ""
notify:
  webhook_url: "not-a-valid-url"
unknown_unrelated_key: true
cve:
  cache_dir: "` + customCache + `"
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveCVECacheDir("", cfgPath, true)
	if err != nil {
		t.Fatalf("resolveCVECacheDir with credential-free config failed: %v", err)
	}
	if got != customCache {
		t.Fatalf("resolveCVECacheDir = %q, want %q", got, customCache)
	}

	// Explicit -config pointing to a missing file must return an error.
	if _, err := resolveCVECacheDir("", filepath.Join(dir, "missing.yaml"), true); err == nil {
		t.Fatal("expected error for explicit missing -config path")
	}

	// Implicit default config pointing to a missing file falls back to default dir.
	gotDefault, err := resolveCVECacheDir("", filepath.Join(dir, "missing.yaml"), false)
	if err != nil || gotDefault != cve.DefaultCacheDir() {
		t.Fatalf("implicit missing config = (%q, %v), want (%q, nil)", gotDefault, err, cve.DefaultCacheDir())
	}

	// Explicit -config with malformed YAML must return an error.
	badYAML := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(badYAML, []byte("cve:\n  cache_dir: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCVECacheDir("", badYAML, true); err == nil {
		t.Fatal("expected parse error for malformed YAML config")
	}

	// Explicit -cache overrides even a missing -config path.
	gotOverride, err := resolveCVECacheDir("/explicit/dir", filepath.Join(dir, "missing.yaml"), true)
	if err != nil || gotOverride != "/explicit/dir" {
		t.Fatalf("explicit -cache override = (%q, %v), want (/explicit/dir, nil)", gotOverride, err)
	}
}

// TestSiteSubnetsExtractsRoutedIPv4AndIPv6Prefixes verifies that siteSubnets
// extracts both routed public IPv4 subnets and global IPv6 prefixes from a
// UniFi snapshot while ignoring empty or malformed values.
func TestSiteSubnetsExtractsRoutedIPv4AndIPv6Prefixes(t *testing.T) {
	snap := &unifi.Snapshot{
		Networks: []unifi.Network{
			{Name: "RoutedLAN", Subnet: "198.51.100.1/29", IPv6Subnet: "2a02:1234:5678:10::1/64"},
			{Name: "Invalid", Subnet: "not-a-cidr", IPv6Subnet: ""},
		},
	}
	prefixes := siteSubnets(snap)
	if len(prefixes) != 2 {
		t.Fatalf("expected 2 parsed prefixes, got %v", prefixes)
	}
	wantV4 := netip.MustParsePrefix("198.51.100.0/29")
	wantV6 := netip.MustParsePrefix("2a02:1234:5678:10::/64")
	if prefixes[0] != wantV4 || prefixes[1] != wantV6 {
		t.Fatalf("siteSubnets = %v, want [%v %v]", prefixes, wantV4, wantV6)
	}
	if got := siteSubnets(nil); got != nil {
		t.Fatalf("siteSubnets(nil) = %v, want nil", got)
	}
}

// TestRunCheckTestOUIResolutionIPGuardAndHints verifies that `check test`
// populates Client.OUI from -mac (via built-in and local IEEE OUI caches) or
// -oui, explicitly warns and errors when -target is refused by the IP guard,
// and prints clear unevaluable-check hints for both single-check and full runs.
func TestRunCheckTestOUIResolutionIPGuardAndHints(t *testing.T) {
	// 1. Public IP and hostname targets are refused with an explicit warning
	// instead of silently printing "Open ports: []" / "No findings matched.".
	for _, badTarget := range []string{"203.0.113.10", "example.com"} {
		var out, errBuf bytes.Buffer
		err := runCheckTest(context.Background(), []string{"-target", badTarget}, &out, &errBuf)
		if err == nil {
			t.Fatalf("expected error for refused target %q, got nil", badTarget)
		}
		if !strings.Contains(errBuf.String(), "refused by the local-IP probe guard") {
			t.Fatalf("expected explicit IP-guard warning on stderr for %q, got:\n%s", badTarget, errBuf.String())
		}
		if strings.Contains(out.String(), "No findings matched.") {
			t.Fatalf("refused target %q must not print misleading 'No findings matched.'", badTarget)
		}
	}

	// 2. buildCheckTestClient resolves built-in virtual OUIs from -mac.
	clVirt := buildCheckTestClient("127.0.0.1", "", "52-54-00-11-22-33", "")
	if clVirt.MAC != "52:54:00:11:22:33" || clVirt.OUI != "QEMU/KVM" {
		t.Fatalf("expected canonical MAC + QEMU/KVM OUI, got %+v", clVirt)
	}

	// 3. buildCheckTestClient resolves synced IEEE OUI entries from local cache.
	cacheRoot := t.TempDir()
	ouiDir := filepath.Join(cacheRoot, "uniblue", "oui")
	if err := os.MkdirAll(ouiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(ouiDir, "ieee-oui.tsv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	_, _ = gz.Write([]byte("001cb3\tApple, Inc.\n"))
	_ = gz.Close()
	_ = f.Close()

	// Point os.UserCacheDir() at cacheRoot (macOS uses HOME/Library/Caches, Linux uses XDG_CACHE_HOME).
	macCache := filepath.Join(cacheRoot, "Library", "Caches", "uniblue", "oui")
	if err := os.MkdirAll(macCache, 0o755); err != nil {
		t.Fatal(err)
	}
	rawOUI, err := os.ReadFile(filepath.Join(ouiDir, "ieee-oui.tsv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macCache, "ieee-oui.tsv.gz"), rawOUI, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", cacheRoot)
	t.Setenv("HOME", cacheRoot)

	clApple := buildCheckTestClient("127.0.0.1", "", "00:1c:b3:aa:bb:cc", "")
	if clApple.OUI != "Apple, Inc." {
		t.Fatalf("expected Apple OUI resolved from local IEEE cache, got %+v", clApple)
	}

	// Explicit -oui override works even without a MAC.
	clOverride := buildCheckTestClient("127.0.0.1", "", "", "CustomVendor")
	if clOverride.OUI != "CustomVendor" {
		t.Fatalf("expected explicit -oui override, got %+v", clOverride)
	}

	// 4. reportUnevaluableCheckHints surfaces missing preconditions for both
	// single-check and full-suite runs, including unresolved -mac OUI lookups.
	testChecks := []*checks.Check{
		{ID: "UB-T1", Preconditions: checks.Preconditions{HostnameRegex: "foo"}},
		{ID: "UB-T2", Preconditions: checks.Preconditions{OUIContains: []string{"Apple"}}},
		{ID: "UB-T3", Preconditions: checks.Preconditions{MDNSTypeAny: []string{"_hap._tcp"}}},
	}

	var hintAll bytes.Buffer
	reportUnevaluableCheckHints(&hintAll, testChecks, unifi.Client{IP: "127.0.0.1"}, false)
	allMsg := hintAll.String()
	for _, want := range []string{"hostname-gated", "OUI-gated", "LAN-discovery-gated"} {
		if !strings.Contains(allMsg, want) {
			t.Fatalf("expected full-suite hint to mention %q, got:\n%s", want, allMsg)
		}
	}

	var hintUnresolvedOUI bytes.Buffer
	reportUnevaluableCheckHints(&hintUnresolvedOUI, []*checks.Check{testChecks[1]}, unifi.Client{IP: "127.0.0.1", MAC: "aa:bb:cc:dd:ee:ff"}, true)
	if !strings.Contains(hintUnresolvedOUI.String(), "uniblue oui sync") {
		t.Fatalf("expected single-check unresolved OUI hint, got:\n%s", hintUnresolvedOUI.String())
	}
}

// TestPrintReportCleanProbedExcludesSkippedHostFindings verifies that
// printReport counts clean probed hosts directly from profiles so a finding on
// a skipped/excluded host (such as a WAN port forward to an excluded NAS) does
// not decrement the clean count of actually probed hosts.
func TestPrintReportCleanProbedExcludesSkippedHostFindings(t *testing.T) {
	snap := &unifi.Snapshot{Site: "default", ControllerType: "integration-v1"}
	probedClient := unifi.Client{IP: "192.168.1.50", MAC: "aa:bb:cc:00:00:50", Name: "clean-host"}
	excludedNAS := unifi.Client{IP: "192.168.1.20", MAC: "aa:bb:cc:00:00:20", Name: "excluded-nas"}

	rep := risk.Report{
		ClientCount:  4, // 1 probed + 3 skipped/excluded
		CleanClients: 3, // excluded-nas has a port-forward finding; probed host is clean
		Findings: []checks.Finding{
			{
				CheckID:           "UB-UNIFI-PORTFWD",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            excludedNAS,
			},
			{
				CheckID:           "UB-INV-INFO",
				ClaimKind:         checks.ClaimServiceObserved,
				BaseSeverity:      checks.SeverityInfo,
				EffectiveSeverity: checks.SeverityInfo,
				Client:            probedClient,
			},
		},
	}
	profiles := []probe.HostProfile{{Client: probedClient}}

	var buf bytes.Buffer
	printReport(&buf, snap, rep, profiles, nil, nil, false)
	if !strings.Contains(buf.String(), "1/1 probed host(s) passed (3 skipped/excluded)") {
		t.Fatalf("expected 1/1 clean probed hosts when only excluded host has finding, got:\n%s", buf.String())
	}

	// When the probed host itself has a non-inventory finding, count drops to 0/1.
	rep.Findings = append(rep.Findings, checks.Finding{
		CheckID:           "UB-0001",
		EffectiveSeverity: checks.SeverityHigh,
		Client:            probedClient,
	})
	buf.Reset()
	printReport(&buf, snap, rep, profiles, nil, nil, false)
	if !strings.Contains(buf.String(), "0/1 probed host(s) passed (3 skipped/excluded)") {
		t.Fatalf("expected 0/1 clean probed hosts when probed host has finding, got:\n%s", buf.String())
	}
}

// TestEnrichSiteAndProfilesMatchesDeviceChildrenForOfflineExport verifies that
// CLI enrichment attaches child devices owned by a UniFi infrastructure device
// (such as a UDM Pro / UNVR recorder) so offline topology exports match the
// live dashboard.
func TestEnrichSiteAndProfilesMatchesDeviceChildrenForOfflineExport(t *testing.T) {
	dir := t.TempDir()
	invPath := filepath.Join(dir, "nvr.yaml")
	invYAML := `parent_mac: "aa:00:00:00:00:01"
devices:
  - id: "cam-front"
    name: "Front Porch Camera"
    category: "camera"
    role: "PoE Security Camera"
`
	if err := os.WriteFile(invPath, []byte(invYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{MAC: "aa:00:00:00:00:01", IP: "10.0.1.1", Name: "UDM-Pro Protect", Model: "UDM-Pro", Type: "udm"},
		},
	}
	devChildren := enrichSiteAndProfiles(snap, nil, config.NetworkConfig{
		BridgeInventories: []config.BridgeInventoryConfig{
			{Format: "nvr", Path: invPath},
		},
	})
	if len(devChildren["aa:00:00:00:00:01"]) != 1 || devChildren["aa:00:00:00:00:01"][0].Name != "Front Porch Camera" {
		t.Fatalf("expected offline CLI enrichment to match recorder child camera, got %+v", devChildren)
	}
}
