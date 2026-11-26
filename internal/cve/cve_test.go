// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/fingerprints"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestCompareVersionsAndRange verifies version ordering (including patch and
// pre-release suffixes) and CPE version-range boundary matching.
func TestCompareVersionsAndRange(t *testing.T) {
	if CompareVersions("6.0.17", "6.0.9") <= 0 {
		t.Fatal("expected 6.0.17 > 6.0.9")
	}
	if CompareVersions("9.6p1", "9.6p2") >= 0 {
		t.Fatal("expected 9.6p1 < 9.6p2")
	}
	if CompareVersions("1.24.0-rc1", "1.24.0") >= 0 {
		t.Fatal("expected pre-release 1.24.0-rc1 < 1.24.0")
	}

	m := CPEMatch{Vendor: "f5", Product: "nginx", StartIncl: "1.20.0", EndExcl: "1.25.3"}
	if ok, conf := MatchesRange("1.24.0", m); !ok || conf != ConfidenceExact {
		t.Fatalf("expected 1.24.0 exact match, got ok=%v conf=%v", ok, conf)
	}
	if ok, _ := MatchesRange("1.25.3", m); ok {
		t.Fatal("expected fixed version 1.25.3 not to match EndExcl")
	}
	if ok, conf := MatchesRange("", m); !ok || conf != ConfidencePotential {
		t.Fatalf("expected empty version to produce potential match, got ok=%v conf=%v", ok, conf)
	}
}

// TestPatternMatchingPreventsPrefixLeakage verifies that exact CPE product
// tokens do not match sibling prefixes while explicit wildcards match families.
func TestPatternMatchingPreventsPrefixLeakage(t *testing.T) {
	// Exact patterns must not bleed into similarly prefixed sibling products.
	if matchesAnyPattern([]string{"nginx", "nginx_open_source"}, "nginx_unit") {
		t.Fatal("exact pattern nginx must not match nginx_unit")
	}
	if !matchesAnyPattern([]string{"nginx", "nginx_open_source"}, "nginx_open_source") {
		t.Fatal("expected exact match for nginx_open_source")
	}
	// Explicit wildcard patterns match targeted hardware families cleanly.
	if !matchesAnyPattern([]string{"*laserjet*m404*"}, "laserjet_pro_m404-m405_firmware") {
		t.Fatal("expected wildcard pattern to match M404 LaserJet firmware")
	}
	if matchesAnyPattern([]string{"*laserjet*m404*"}, "laserjet_pro_m203_firmware") {
		t.Fatal("expected M404 wildcard not to match M203 firmware")
	}
}

// TestSyncMatchLookupAndSearch exercises end-to-end NVD + KEV cache syncing,
// exact vs. potential CVE matching with age filtering, single-CVE lookup, search,
// and per-product summary rollups.
func TestSyncMatchLookupAndSearch(t *testing.T) {
	sampleNVD := `{
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2026-9999",
					"published": "2026-06-01T00:00:00.000",
					"vulnStatus": "Analyzed",
					"descriptions": [{"lang": "en", "value": "Critical flaw in OpenSSH before 9.8p1"}],
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
					"configurations": [{
						"nodes": [{
							"cpeMatch": [{
								"vulnerable": true,
								"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
								"versionStartIncluding": "8.5p1",
								"versionEndExcluding": "9.8p1"
							}]
						}]
					}]
				}
			},
			{
				"cve": {
					"id": "CVE-2026-8888",
					"published": "2026-05-01T00:00:00.000",
					"vulnStatus": "Analyzed",
					"descriptions": [{"lang": "en", "value": "High flaw in TrueNAS firmware"}],
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
					"configurations": [{
						"nodes": [{
							"cpeMatch": [{
								"vulnerable": true,
								"criteria": "cpe:2.3:o:ixsystems:truenas_firmware:*:*:*:*:*:*:*:*"
							}]
						}]
					}]
				}
			},
			{
				"cve": {
					"id": "CVE-2012-0001",
					"published": "2012-01-01T00:00:00.000",
					"vulnStatus": "Analyzed",
					"descriptions": [{"lang": "en", "value": "Ancient TrueNAS issue"}],
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}]},
					"configurations": [{
						"nodes": [{
							"cpeMatch": [{
								"vulnerable": true,
								"criteria": "cpe:2.3:o:ixsystems:truenas_firmware:*:*:*:*:*:*:*:*"
							}]
						}]
					}]
				}
			}
		]
	}`

	sum := sha256.Sum256([]byte(sampleNVD))
	shaStr := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-9999"}]}`))
	})
	mux.HandleFunc("/nvd/nvdcve-2.0-2026.meta", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("lastModifiedDate:2026-06-02\nsha256:" + shaStr + "\n"))
	})
	mux.HandleFunc("/nvd/nvdcve-2.0-2026.json.gz", func(w http.ResponseWriter, r *http.Request) {
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(sampleNVD))
		_ = gz.Close()
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cache := NewCache(t.TempDir())
	cache.nvdBaseURL = srv.URL + "/nvd"
	cache.kevURL = srv.URL + "/kev.json"

	stats, err := cache.Sync(context.Background(), SyncOptions{SinceYear: 2026, EndYear: 2026})
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if stats.TotalCVEs != 3 || stats.KEVCount != 1 || stats.VendorCount != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFingerprinter: %v", err)
	}

	profiles := []probe.HostProfile{
		{
			Client:    unifi.Client{IP: "192.168.10.2", MAC: "aa:01", Name: "truenas-01", NetworkName: "LAN"},
			SSHBanner: "SSH-2.0-OpenSSH_9.2p1",
		},
	}
	products := fp.Identify(nil, profiles)

	// With PotentialMaxAgeYears=2, ancient 2012 non-KEV potential CVE is filtered
	// while recent 2026 TrueNAS + exact OpenSSH KEV remain.
	matches, err := cache.MatchProducts(products, MatchOptions{
		MinSeverity:          checks.SeverityMedium,
		PotentialMaxAgeYears: 2,
	})
	if err != nil {
		t.Fatalf("MatchProducts: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches (exact OpenSSH KEV + recent TrueNAS), got %d: %+v", len(matches), matches)
	}
	if matches[0].Record.ID != "CVE-2026-9999" || matches[0].Confidence != ConfidenceExact || !matches[0].Record.KEV {
		t.Fatalf("expected first match to be exact KEV CVE-2026-9999, got %+v", matches[0])
	}
	if matches[1].Record.ID != "CVE-2026-8888" || matches[1].Confidence != ConfidencePotential {
		t.Fatalf("expected second match to be recent potential CVE-2026-8888, got %+v", matches[1])
	}

	// Verify single-CVE offline inspection.
	rec, err := cache.LookupCVE(context.Background(), "CVE-2026-9999")
	if err != nil || rec.ID != "CVE-2026-9999" || !rec.KEV {
		t.Fatalf("LookupCVE = %+v, err=%v", rec, err)
	}

	// Verify single-vendor Search enforces Limit cleanly.
	found, err := cache.Search(context.Background(), "", SearchOptions{Vendor: "ixsystems", Limit: 1})
	if err != nil || len(found) != 1 {
		t.Fatalf("Search(vendor=ixsystems, limit=1) = %+v, err=%v", found, err)
	}

	// Verify deterministic rollup and computed MinFixedVersion.
	summaries := RollupMatches(matches)
	if len(summaries) != 2 {
		t.Fatalf("expected 2 rollup summaries, got %d", len(summaries))
	}
	if summaries[0].MinFixedVersion != "9.8p1" || summaries[0].KEVCount != 1 {
		t.Fatalf("unexpected OpenSSH rollup summary: %+v", summaries[0])
	}
	profiles[0].SSHBanner += " Debian-2+deb12u3"
	matches, err = cache.MatchProducts(fp.Identify(nil, profiles), MatchOptions{PotentialMaxAgeYears: 2})
	if err != nil || len(matches) != 2 {
		t.Fatalf("packaged OpenSSH matches: %v, %v", matches, err)
	}
	m := matches[0]
	if m.Product.Version != "9.2p1" || m.Confidence != ConfidenceVersionAmbiguous || !m.Record.KEV ||
		!slices.Equal(m.Product.Ports, []EndpointPort{{"tcp", 22}}) {
		t.Fatalf("packaged OpenSSH match: %+v", m)
	}
	summary := RollupMatches(matches)[0]
	if summary.Confidence != ConfidenceVersionAmbiguous || summary.MinFixedVersion != "" || !strings.Contains(summary.Headline(), "distribution") {
		t.Fatalf("packaged OpenSSH verification: %+v", summary)
	}
	profiles[0].SSHBanner = "SSH-2.0-OpenSSH_9.8p1 Ubuntu-1"
	matches, err = cache.MatchProducts(fp.Identify(nil, profiles), MatchOptions{PotentialMaxAgeYears: 2})
	if err != nil || len(matches) != 1 || matches[0].Product.Label == "OpenSSH" {
		t.Fatalf("out-of-range packaged OpenSSH: %v, %v", matches, err)
	}

}

// TestSyncCancelPreventsPartialStats verifies that cancelling a Sync context
// during indexing returns an error without persisting stats.json, so a later
// Sync repairs the cache instead of reporting already up to date.
func TestSyncCancelPreventsPartialStats(t *testing.T) {
	sampleNVD := `{
		"vulnerabilities": [{
			"cve": {
				"id": "CVE-2026-1001",
				"published": "2026-01-15T00:00:00.000",
				"vulnStatus": "Analyzed",
				"descriptions": [{"lang": "en", "value": "Test CVE"}],
				"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
				"configurations": [{
					"nodes": [{
						"cpeMatch": [{
							"vulnerable": true,
							"criteria": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
						}]
					}]
				}]
			}
		}]
	}`
	sum := sha256.Sum256([]byte(sampleNVD))
	shaStr := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	})
	mux.HandleFunc("/nvd/nvdcve-2.0-2026.meta", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("sha256:" + shaStr + "\n"))
	})
	mux.HandleFunc("/nvd/nvdcve-2.0-2026.json.gz", func(w http.ResponseWriter, r *http.Request) {
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(sampleNVD))
		_ = gz.Close()
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cache := NewCache(t.TempDir())
	cache.nvdBaseURL = srv.URL + "/nvd"
	cache.kevURL = srv.URL + "/kev.json"

	ctx, cancel := context.WithCancel(context.Background())
	_, err := cache.Sync(ctx, SyncOptions{
		SinceYear: 2026,
		EndYear:   2026,
		Progress: func(msg string) {
			if strings.HasPrefix(msg, "Indexing ") {
				cancel()
			}
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from cancelled Sync, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(cache.Dir(), "stats.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected stats.json not to be written after cancelled Sync, stat err=%v", statErr)
	}

	// Re-running with an active context must build the full index cleanly.
	stats, err := cache.Sync(context.Background(), SyncOptions{SinceYear: 2026, EndYear: 2026})
	if err != nil {
		t.Fatalf("follow-up Sync failed: %v", err)
	}
	if stats.VendorCount != 1 || stats.TotalCVEs != 1 {
		t.Fatalf("expected full index after retry, got %+v", stats)
	}
}

// TestBuildVendorIndexCancelsAndDrainsOnError verifies that buildVendorIndex
// cancels its worker pool and drains all channels on an early parse error so
// no background goroutines leak.
func TestBuildVendorIndexCancelsAndDrainsOnError(t *testing.T) {
	dir := t.TempDir()
	feedsDir := filepath.Join(dir, "feeds")
	vendorsDir := filepath.Join(dir, "vendors")
	if err := os.MkdirAll(feedsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(vendorsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create more feed files than workers so the producer would block on jobs
	// if cancellation did not drain the pool cleanly.
	var feedFiles []string
	for i := range 12 {
		p := filepath.Join(feedsDir, "feed-"+string(rune('a'+i))+".json.gz")
		if i == 0 {
			// Corrupt gzip file triggers an immediate parse error.
			if err := os.WriteFile(p, []byte("not-a-gzip-stream"), 0o644); err != nil {
				t.Fatal(err)
			}
		} else {
			f, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			gz := gzip.NewWriter(f)
			_, _ = gz.Write([]byte(`{"vulnerabilities":[]}`))
			_ = gz.Close()
			_ = f.Close()
		}
		feedFiles = append(feedFiles, p)
	}

	baseGoroutines := runtime.NumGoroutine()
	cache := NewCache(dir)
	_, err := cache.buildVendorIndex(context.Background(), feedFiles, vendorsDir, nil, "kevsha", map[string]string{}, 0, time.Now())
	if err == nil {
		t.Fatal("expected parse error from corrupt gzip feed")
	}

	// Allow any finishing goroutines a brief moment to settle, then verify no leak.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseGoroutines+1 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseGoroutines+1 {
		t.Fatalf("goroutine leak detected: before=%d after=%d", baseGoroutines, got)
	}
}

// TestSyncInvalidYearRange verifies that Sync rejects out-of-range SinceYear
// and EndYear values (such as --since 2030 or --since 2001) with a clean error
// instead of panicking.
func TestSyncInvalidYearRange(t *testing.T) {
	cache := NewCache(t.TempDir())
	futureYear := time.Now().UTC().Year() + 5

	for _, tc := range []struct {
		name string
		opts SyncOptions
	}{
		{"future since year", SyncOptions{SinceYear: futureYear}},
		{"too early since year", SyncOptions{SinceYear: 2001}},
		{"negative since year", SyncOptions{SinceYear: -1}},
		{"since greater than end", SyncOptions{SinceYear: 2025, EndYear: 2024}},
		{"end before 2002", SyncOptions{EndYear: 1999}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cache.Sync(context.Background(), tc.opts); err == nil {
				t.Fatalf("expected error for %+v, got nil", tc.opts)
			}
		})
	}
}

// TestSyncRebuildsOnKEVChange verifies that Sync persists the CISA KEV catalog
// hash in stats.json and rebuilds vendor shards when newly KEV-listed CVEs
// appear even if all NVD yearly feed SHAs remain unchanged.
func TestSyncRebuildsOnKEVChange(t *testing.T) {
	sampleNVD := `{
		"vulnerabilities": [{
			"cve": {
				"id": "CVE-2026-7777",
				"published": "2026-03-01T00:00:00.000",
				"vulnStatus": "Analyzed",
				"descriptions": [{"lang": "en", "value": "Example CVE"}],
				"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}}]},
				"configurations": [{
					"nodes": [{
						"cpeMatch": [{
							"vulnerable": true,
							"criteria": "cpe:2.3:a:vendorx:prodx:1.0:*:*:*:*:*:*:*"
						}]
					}]
				}]
			}
		}]
	}`
	sum := sha256.Sum256([]byte(sampleNVD))
	shaStr := hex.EncodeToString(sum[:])

	var kevListed atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		if kevListed.Load() {
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-7777"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	})
	mux.HandleFunc("/nvd/nvdcve-2.0-2026.meta", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("sha256:" + shaStr + "\n"))
	})
	mux.HandleFunc("/nvd/nvdcve-2.0-2026.json.gz", func(w http.ResponseWriter, r *http.Request) {
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(sampleNVD))
		_ = gz.Close()
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cache := NewCache(t.TempDir())
	cache.nvdBaseURL = srv.URL + "/nvd"
	cache.kevURL = srv.URL + "/kev.json"

	// Initial sync: CVE-2026-7777 is not yet in KEV.
	st1, err := cache.Sync(context.Background(), SyncOptions{SinceYear: 2026, EndYear: 2026})
	if err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	if st1.KEVSHA == "" || st1.KEVCount != 0 {
		t.Fatalf("unexpected initial KEV stats: %+v", st1)
	}
	recs, err := cache.LookupVendor("vendorx")
	if err != nil || len(recs) != 1 || recs[0].KEV {
		t.Fatalf("expected non-KEV record initially, got %+v err=%v", recs, err)
	}

	// Second sync with unchanged NVD and unchanged KEV skips rebuild.
	var skipped bool
	if _, err := cache.Sync(context.Background(), SyncOptions{
		SinceYear: 2026,
		EndYear:   2026,
		Progress: func(msg string) {
			if strings.Contains(msg, "already up to date") {
				skipped = true
			}
		},
	}); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
	if !skipped {
		t.Fatal("expected unchanged NVD + KEV sync to skip rebuild")
	}

	// Third sync: CISA adds CVE-2026-7777 to KEV while NVD SHA stays identical.
	kevListed.Store(true)
	st3, err := cache.Sync(context.Background(), SyncOptions{SinceYear: 2026, EndYear: 2026})
	if err != nil {
		t.Fatalf("third Sync after KEV update: %v", err)
	}
	if st3.KEVCount != 1 || st3.KEVSHA == st1.KEVSHA {
		t.Fatalf("expected updated KEV stats after catalog change, got %+v", st3)
	}
	recs, err = cache.LookupVendor("vendorx")
	if err != nil || len(recs) != 1 || !recs[0].KEV {
		t.Fatalf("expected CVE-2026-7777 to be marked KEV after rebuild, got %+v err=%v", recs, err)
	}
}

// TestFingerprintHTTPDeterminismAndVersionBinding verifies that independent HTTP
// listeners retain their own versions and produce a stable product listing.
func TestFingerprintHTTPDeterminismAndVersionBinding(t *testing.T) {
	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFingerprinter: %v", err)
	}

	profile := probe.HostProfile{
		Client: unifi.Client{IP: "192.168.1.50", MAC: "aa:bb:cc:dd:ee:01", Name: "web-01"},
		HTTP: map[int]probe.HTTPBanner{
			80:   {Server: "nginx/1.18.0"},
			8080: {Server: "nginx"},
			8443: {Server: "nginx/1.25.4"},
		},
	}

	wantVersions := []string{"", "1.18.0", "1.25.4"}
	for i := range 100 {
		prods := fp.Identify(nil, []probe.HostProfile{profile})
		var gotVersions []string
		for _, p := range prods {
			if p.Label == "Nginx" {
				gotVersions = append(gotVersions, p.Version)
			}
		}
		if !reflect.DeepEqual(gotVersions, wantVersions) {
			t.Fatalf("iteration %d: got nginx versions %v, want %v", i, gotVersions, wantVersions)
		}
	}

}

// TestMapUniFiDeviceProducts verifies that UniFi device product mapping uses
// dev.Type and model codes only (never user Name substrings), orders AP and
// switch cases ahead of UDM/Pro Max consoles, handles classic model codes, and
// never falls back to unifi_network_application.
func TestMapUniFiDeviceProducts(t *testing.T) {
	tests := []struct {
		name string
		dev  unifi.Device
		want []string
	}{
		{
			name: "classic switch US8P60 without Type",
			dev:  unifi.Device{Model: "US8P60", Name: "Office", Version: "7.1.26"},
			want: []string{"unifi_switch_firmware"},
		},
		{
			name: "classic switch USL16LP",
			dev:  unifi.Device{Model: "USL16LP", Name: "Rack", Version: "7.1.26"},
			want: []string{"unifi_switch_firmware"},
		},
		{
			name: "classic AP UAL6",
			dev:  unifi.Device{Model: "UAL6", Name: "Hallway", Version: "6.6.77"},
			want: []string{"unifi_uap_firmware"},
		},
		{
			name: "gateway UXGPRO",
			dev:  unifi.Device{Model: "UXGPRO", Name: "Edge", Version: "4.0.20"},
			want: []string{"unifi_next-generation_gateway_pro_firmware", "unifi_gateway_firmware"},
		},
		{
			name: "U7 Pro Max AP is not misclassified as UDM Pro Max",
			dev:  unifi.Device{Type: "uap", Model: "U7 Pro Max", Name: "Living Room", Version: "7.0.66"},
			want: []string{"unifi_uap_firmware"},
		},
		{
			name: "U7 Pro Max AP without Type",
			dev:  unifi.Device{Model: "U7 Pro Max", Name: "Living Room", Version: "7.0.66"},
			want: []string{"unifi_uap_firmware"},
		},
		{
			name: "USW Pro Max switch is not misclassified as UDM Pro Max",
			dev:  unifi.Device{Type: "usw", Model: "USW Pro Max 24 PoE", Name: "Core", Version: "7.1.26"},
			want: []string{"unifi_switch_firmware"},
		},
		{
			name: "USW Pro Max switch without Type",
			dev:  unifi.Device{Model: "USW Pro Max 24 PoE", Name: "Core", Version: "7.1.26"},
			want: []string{"unifi_switch_firmware"},
		},
		{
			name: "Duck pond AP ignores uck substring in Name",
			dev:  unifi.Device{Type: "uap", Model: "U6-Pro", Name: "Duck pond AP", Version: "6.6.77"},
			want: []string{"unifi_uap_firmware"},
		},
		{
			name: "Audrey AP ignores udr substring in Name",
			dev:  unifi.Device{Model: "U6-Lite", Name: "Audrey Bedroom", Version: "6.6.77"},
			want: []string{"unifi_uap_firmware"},
		},
		{
			name: "UDM Pro Max console",
			dev:  unifi.Device{Type: "udm", Model: "UDMPROMAX", Name: "Gateway", Version: "4.0.21"},
			want: []string{"unifi_dream_machine_pro_max_firmware", "unifi_os"},
		},
		{
			name: "Flex Mini switch stays on its own branch",
			dev:  unifi.Device{Type: "usw", Model: "USMINI", Name: "Desk", Version: "2.0.0"},
			want: []string{"unifi_switch_flex_mini_firmware"},
		},
		{
			name: "unknown model never falls back to unifi_network_application",
			dev:  unifi.Device{Model: "UNKNOWN-MODEL-99", Name: "Duck UDR Pro Max", Version: "7.1.26"},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapUniFiDeviceProducts(tc.dev)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mapUniFiDeviceProducts(%+v) = %v, want %v", tc.dev, got, tc.want)
			}
			for _, p := range got {
				if p == "unifi_network_application" {
					t.Fatalf("device %+v must never map to unifi_network_application", tc.dev)
				}
			}
		})
	}
}

// TestVersionComponentCountAndPrefixMatching verifies that CompareVersions
// treats missing trailing components as 0 against numeric tokens and that
// MatchesRange returns ConfidencePotential when an observed version is only a
// coarse numeric prefix of a more-specific CPE bound.
func TestVersionComponentCountAndPrefixMatching(t *testing.T) {
	if CompareVersions("2.4", "2.4.7") >= 0 {
		t.Fatal("expected 2.4 < 2.4.7")
	}
	if CompareVersions("2.4", "2.4.0") != 0 {
		t.Fatal("expected 2.4 == 2.4.0")
	}
	if CompareVersions("8.0.3", "8.0") <= 0 {
		t.Fatal("expected 8.0.3 > 8.0")
	}
	if CompareVersions("6.0.17", "6.0") <= 0 {
		t.Fatal("expected 6.0.17 > 6.0")
	}

	// CUPS/2.4 against EndExcl 2.4.7 must not be hidden and must be Potential.
	if ok, conf := MatchesRange("2.4", CPEMatch{EndExcl: "2.4.7"}); !ok || conf != ConfidencePotential {
		t.Fatalf("MatchesRange(2.4, EndExcl 2.4.7) = (%v, %v), want (true, potential)", ok, conf)
	}
	// Observed 2.4 against EndExcl 2.4.0 is strictly >= 2.4.0 (not vulnerable).
	if ok, _ := MatchesRange("2.4", CPEMatch{EndExcl: "2.4.0"}); ok {
		t.Fatal("MatchesRange(2.4, EndExcl 2.4.0) should be false")
	}
	// Observed 2.4 against EndExcl 2.5.0 is unambiguously below 2.5.0 (Exact).
	if ok, conf := MatchesRange("2.4", CPEMatch{EndExcl: "2.5.0"}); !ok || conf != ConfidenceExact {
		t.Fatalf("MatchesRange(2.4, EndExcl 2.5.0) = (%v, %v), want (true, exact)", ok, conf)
	}
	// Observed 2.4 against [2.4.2, 2.4.7) overlaps potentially.
	if ok, conf := MatchesRange("2.4", CPEMatch{StartIncl: "2.4.2", EndExcl: "2.4.7"}); !ok || conf != ConfidencePotential {
		t.Fatalf("MatchesRange(2.4, [2.4.2, 2.4.7)) = (%v, %v), want (true, potential)", ok, conf)
	}
	// Observed 8.0.3 exceeds EndIncl 8.0 (must not match).
	if ok, _ := MatchesRange("8.0.3", CPEMatch{EndIncl: "8.0"}); ok {
		t.Fatal("MatchesRange(8.0.3, EndIncl 8.0) should be false")
	}
	// Observed 6.0.17 is not equal to exact Version 6.0.
	if ok, _ := MatchesRange("6.0.17", CPEMatch{Version: "6.0"}); ok {
		t.Fatal("MatchesRange(6.0.17, Version 6.0) should be false")
	}
	// Observed 6.0.17 is strictly greater than StartExcl 6.0 (must match Exact).
	if ok, conf := MatchesRange("6.0.17", CPEMatch{StartExcl: "6.0"}); !ok || conf != ConfidenceExact {
		t.Fatalf("MatchesRange(6.0.17, StartExcl 6.0) = (%v, %v), want (true, exact)", ok, conf)
	}
	// Coarse observed 2.4 against exact Version 2.4.7 is Potential.
	if ok, conf := MatchesRange("2.4", CPEMatch{Version: "2.4.7"}); !ok || conf != ConfidencePotential {
		t.Fatalf("MatchesRange(2.4, Version 2.4.7) = (%v, %v), want (true, potential)", ok, conf)
	}
}

// TestVersionSingleLetterPatchOrdering verifies that single trailing letters
// like "a" and "b" (used by OpenSSL and ProFTPD) sort after the base release
// while full pre-release words ("alpha", "beta", "rc", "dev", "pre") sort before.
func TestVersionSingleLetterPatchOrdering(t *testing.T) {
	ordered := []string{"1.1.1-alpha1", "1.1.1-beta1", "1.1.1-rc1", "1.1.1", "1.1.1a", "1.1.1b", "1.1.1c", "1.1.2"}
	for i := 0; i < len(ordered)-1; i++ {
		if cmp := CompareVersions(ordered[i], ordered[i+1]); cmp >= 0 {
			t.Fatalf("expected %s < %s, got %d", ordered[i], ordered[i+1], cmp)
		}
		if cmp := CompareVersions(ordered[i+1], ordered[i]); cmp <= 0 {
			t.Fatalf("expected %s > %s, got %d", ordered[i+1], ordered[i], cmp)
		}
	}

	// OpenSSL 1.1.1a must NOT match EndExcl 1.1.1.
	if ok, _ := MatchesRange("1.1.1a", CPEMatch{EndExcl: "1.1.1"}); ok {
		t.Fatal("expected 1.1.1a not to match EndExcl 1.1.1")
	}
	// OpenSSL 1.1.1a must match [1.1.1, 1.1.1c).
	if ok, conf := MatchesRange("1.1.1a", CPEMatch{StartIncl: "1.1.1", EndExcl: "1.1.1c"}); !ok || conf != ConfidenceExact {
		t.Fatalf("expected 1.1.1a to match [1.1.1, 1.1.1c) exact, got (%v, %v)", ok, conf)
	}
}

// TestParseCPE23UpdateField verifies that ParseCPE23 and parseVersionedCPE23
// fold non-wildcard CPE update fields (parts[6]) into Version so OpenSSH patch
// levels and pre-releases match accurately without false exact hits.
func TestParseCPE23UpdateField(t *testing.T) {
	m1, ok := ParseCPE23("cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*")
	if !ok || m1.Version != "8.5p1" {
		t.Fatalf("ParseCPE23(8.5:p1) = (%+v, %v), want Version=8.5p1", m1, ok)
	}
	if matched, conf := MatchesRange("8.5p1", m1); !matched || conf != ConfidenceExact {
		t.Fatalf("expected 8.5p1 to match 8.5:p1 exact, got (%v, %v)", matched, conf)
	}

	m2, ok := ParseCPE23("cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*")
	if !ok || m2.Version != "9.3p1" {
		t.Fatalf("ParseCPE23(9.3:p1) = (%+v, %v), want Version=9.3p1", m2, ok)
	}
	if matched, _ := MatchesRange("9.3", m2); matched {
		t.Fatal("native OpenSSH 9.3 must not match portable 9.3:p1 CPE")
	}

	m3, ok := ParseCPE23("cpe:2.3:a:example:app:2.0:rc1:*:*:*:*:*:*")
	if !ok || m3.Version != "2.0-rc1" {
		t.Fatalf("ParseCPE23(2.0:rc1) = (%+v, %v), want Version=2.0-rc1", m3, ok)
	}
	if matched, _ := MatchesRange("2.0", m3); matched {
		t.Fatal("release 2.0 must not match prerelease 2.0:rc1 CPE")
	}

	m4, ok := ParseCPE23("cpe:2.3:a:example:app:2.0:beta1:*:*:*:*:*:*")
	if !ok || m4.Version != "2.0-beta1" {
		t.Fatalf("ParseCPE23(2.0:beta1) = (%+v, %v), want Version=2.0-beta1", m4, ok)
	}

	v, p, ver, ok := parseVersionedCPE23("cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*")
	if !ok || v != "openbsd" || p != "openssh" || ver != "8.5p1" {
		t.Fatalf("parseVersionedCPE23(8.5:p1) = (%q, %q, %q, %v)", v, p, ver, ok)
	}
}

// TestIdentifyDeduplicatesByCanonicalVendorProduct verifies that a product
// matched by both a built-in fingerprint rule and a Nerva CPE 2.3 string is
// emitted once per host/vendor/product/version so rollups are never doubled.
func TestIdentifyDeduplicatesByCanonicalVendorProduct(t *testing.T) {
	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFingerprinter: %v", err)
	}

	profile := probe.HostProfile{
		Client:    unifi.Client{IP: "192.168.10.10", MAC: "aa:bb:cc:00:00:10", Name: "web-srv"},
		SSHBanner: "SSH-2.0-OpenSSH_9.6p1 Debian-1",
		HTTP: map[int]probe.HTTPBanner{
			80: {Server: "Apache/2.4.41 (Ubuntu)"},
		},
		Services: []probe.Service{
			{
				Port: 80,
				CPEs: []string{"cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"},
			},
			{
				Port: 22,
				CPEs: []string{"cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"},
			},
		},
	}

	prods := fp.Identify(nil, []probe.HostProfile{profile})
	if len(prods) != 2 {
		t.Fatalf("expected 2 deduplicated products (Apache HTTP Server + OpenSSH), got %d: %+v", len(prods), prods)
	}
	if prods[0].Label != "Apache HTTP Server" || prods[0].Version != "2.4.41" {
		t.Fatalf("unexpected first product: %+v", prods[0])
	}
	if prods[1].Label != "OpenSSH" || prods[1].Version != "9.6p1" {
		t.Fatalf("unexpected second product: %+v", prods[1])
	}
}

// TestRollupTracksEndIncludingBounds verifies that RollupMatches tracks both
// versionEndExcluding and versionEndIncluding bounds so upgrade advice never
// suggests a version that is still inside a matched inclusive vulnerable range.
func TestRollupTracksEndIncludingBounds(t *testing.T) {
	prod := Product{HostIP: "192.168.1.1", Label: "UniFi Gateway", Version: "8.0.7"}

	// Case 1: EndIncl (8.3.32) is newer than EndExcl (8.1.127).
	// Must NOT suggest ">= 8.1.127"; must suggest "> 8.3.32".
	sums := RollupMatches([]Match{
		{
			Record:     Record{ID: "CVE-2026-0001", Severity: checks.SeverityHigh, CVSS: 7.5},
			Product:    prod,
			Confidence: ConfidenceExact,
			MatchedCPE: CPEMatch{EndExcl: "8.1.127"},
		},
		{
			Record:     Record{ID: "CVE-2026-0002", Severity: checks.SeverityCritical, CVSS: 9.8},
			Product:    prod,
			Confidence: ConfidenceExact,
			MatchedCPE: CPEMatch{EndIncl: "8.3.32"},
		},
	})
	if len(sums) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(sums))
	}
	if sums[0].MinFixedVersion != "" {
		t.Fatalf("expected empty MinFixedVersion when EndIncl >= EndExcl, got %q", sums[0].MinFixedVersion)
	}
	if sums[0].MaxAffectedVersion != "8.3.32" {
		t.Fatalf("expected MaxAffectedVersion 8.3.32, got %q", sums[0].MaxAffectedVersion)
	}
	if hl := sums[0].Headline(); !strings.Contains(hl, "verify > 8.3.32") || strings.Contains(hl, "8.1.127") {
		t.Fatalf("unexpected headline: %q", hl)
	}

	// Case 2: EndExcl (8.3.32) equals EndIncl (8.3.32) -> 8.3.32 is still vulnerable.
	sumsEq := RollupMatches([]Match{
		{
			Record:     Record{ID: "CVE-2026-0003", Severity: checks.SeverityHigh, CVSS: 8.0},
			Product:    prod,
			Confidence: ConfidenceExact,
			MatchedCPE: CPEMatch{EndExcl: "8.3.32"},
		},
		{
			Record:     Record{ID: "CVE-2026-0004", Severity: checks.SeverityHigh, CVSS: 8.0},
			Product:    prod,
			Confidence: ConfidenceExact,
			MatchedCPE: CPEMatch{EndIncl: "8.3.32"},
		},
	})
	if sumsEq[0].MinFixedVersion != "" || sumsEq[0].MaxAffectedVersion != "8.3.32" {
		t.Fatalf("equal EndExcl/EndIncl should require > 8.3.32, got %+v", sumsEq[0])
	}

	// Case 3: EndExcl (8.4.0) strictly exceeds EndIncl (8.3.32) -> >= 8.4.0 is safe.
	sumsSafe := RollupMatches([]Match{
		{
			Record:     Record{ID: "CVE-2026-0005", Severity: checks.SeverityHigh, CVSS: 8.0},
			Product:    prod,
			Confidence: ConfidenceExact,
			MatchedCPE: CPEMatch{EndExcl: "8.4.0"},
		},
		{
			Record:     Record{ID: "CVE-2026-0006", Severity: checks.SeverityHigh, CVSS: 8.0},
			Product:    prod,
			Confidence: ConfidenceExact,
			MatchedCPE: CPEMatch{EndIncl: "8.3.32"},
		},
	})
	if sumsSafe[0].MinFixedVersion != "8.4.0" || sumsSafe[0].MaxAffectedVersion != "" {
		t.Fatalf("expected MinFixedVersion 8.4.0 when EndExcl > EndIncl, got %+v", sumsSafe[0])
	}
	if hl := sumsSafe[0].Headline(); !strings.Contains(hl, "verify >= 8.4.0") {
		t.Fatalf("expected >= 8.4.0 in headline, got %q", hl)
	}
}

// TestFingerprintRejectsPortOnlyAndCoyoteFalsePositives verifies that open
// ports alone never attribute a vendor without an identity signal and that the
// anchored Apache HTTP Server regex rejects Tomcat's Apache-Coyote header.
func TestFingerprintRejectsPortOnlyAndCoyoteFalsePositives(t *testing.T) {
	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFingerprinter: %v", err)
	}

	// A Supermicro BMC with IPMI/virtual-media ports open must not be tagged
	// as AMI MegaRAC / ASUS ASMB, and generic ports (9091, 11434, 8123, 1880,
	// 16992) without matching identity signals must not emit vendor products.
	profiles := []probe.HostProfile{
		{
			Client:    unifi.Client{IP: "10.0.0.10", MAC: "00:25:90:00:00:01", Name: "supermicro-bmc"},
			OpenPorts: []int{623, 5120, 5123, 7578},
			HTTP: map[int]probe.HTTPBanner{
				443: {Title: "Supermicro BMC"},
			},
		},
		{
			Client:    unifi.Client{IP: "10.0.0.11", MAC: "aa:bb:cc:00:00:11", Name: "auth-gw"},
			OpenPorts: []int{1880, 8123, 9091, 11434, 16992},
			HTTP: map[int]probe.HTTPBanner{
				9091: {Title: "Authelia"},
			},
		},
		{
			Client: unifi.Client{IP: "10.0.0.12", MAC: "aa:bb:cc:00:00:12", Name: "tomcat-01"},
			HTTP: map[int]probe.HTTPBanner{
				8080: {Server: "Apache-Coyote/1.1"},
			},
		},
		{
			Client: unifi.Client{IP: "10.0.0.13", MAC: "aa:bb:cc:00:00:13", Name: "httpd-01"},
			HTTP: map[int]probe.HTTPBanner{
				80: {Server: "Apache/2.4.58 (Debian)"},
			},
		},
	}

	prods := fp.Identify(nil, profiles)
	for _, p := range prods {
		switch p.HostIP {
		case "10.0.0.10":
			if p.Label != "Supermicro IPMI / BMC" {
				t.Fatalf("Supermicro BMC received unexpected vendor attribution: %+v", p)
			}
		case "10.0.0.11":
			t.Fatalf("host with only generic open ports should not match any vendor rule, got %+v", p)
		case "10.0.0.12":
			t.Fatalf("Apache-Coyote/1.1 must not match Apache HTTP Server, got %+v", p)
		case "10.0.0.13":
			if p.Label != "Apache HTTP Server" || p.Version != "2.4.58" {
				t.Fatalf("unexpected httpd-01 match: %+v", p)
			}
		}
	}

	// Verify that even a custom rule containing only ports_any never matches
	// without an identity signal.
	portOnlyRule := &FingerprintRule{
		Name:     "Port Only Vendor",
		PortsAny: []int{9999},
		Vendors:  []string{"example"},
		Products: []string{"widget"},
	}
	if err := portOnlyRule.compile(); err != nil {
		t.Fatal(err)
	}
	if hits := portOnlyRule.matchAll(probe.HostProfile{OpenPorts: []int{9999}}); len(hits) != 0 {
		t.Fatalf("expected port-only rule not to match, got %+v", hits)
	}
}

// TestIdentifyIPv6OnlyHostPopulatesHostIP verifies that versioned products
// discovered on an IPv6-only client carry the host's IPv6 address in HostIP
// rather than an empty string so downstream advisory attachment works.
func TestIdentifyIPv6OnlyHostPopulatesHostIP(t *testing.T) {
	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFingerprinter: %v", err)
	}
	v6Client := unifi.Client{
		MAC:         "00:17:88:aa:bb:cc",
		IPv6:        []string{"fd00:20::42"},
		Name:        "hue-bridge-v6",
		NetworkName: "IoT",
	}
	profiles := []probe.HostProfile{
		{
			Client: v6Client,
			HTTP:   map[int]probe.HTTPBanner{443: {Server: "nginx/1.24.0"}},
			Services: []probe.Service{
				{Port: 443, Transport: "tcp", Protocol: "https", AddressFamily: "ipv6", CPEs: []string{"cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"}},
			},
		},
	}
	prods := fp.Identify(&unifi.Snapshot{Clients: []unifi.Client{v6Client}}, profiles)
	if len(prods) < 2 {
		t.Fatalf("expected at least 2 products for IPv6-only host, got %+v", prods)
	}
	for _, p := range prods {
		if p.HostIP != "fd00:20::42" {
			t.Fatalf("expected IPv6-only product %q to carry HostIP=fd00:20::42, got %q", p.Label, p.HostIP)
		}
	}
}

// TestUniFiFirmwareBuildSuffixNormalizationAndTotalOrder verifies that UniFi
// 4-part firmware versions remain intact on Product.Version, match 3-part NVD
// bounds via their 3-part release prefix (including builds < 1000), compare all
// 4 parts directly against 4-part NVD bounds, and preserve CompareVersions
// strict total order.
func TestUniFiFirmwareBuildSuffixNormalizationAndTotalOrder(t *testing.T) {
	// Verify CompareVersions remains a strict total order (antisymmetric and transitive)
	// and keeps 6.6.55.15189 > 6.6.55 for general version comparison.
	if CompareVersions("6.6.55.15189", "6.6.55") <= 0 {
		t.Fatal("expected CompareVersions(6.6.55.15189, 6.6.55) > 0")
	}
	corpus := []string{
		"1.1.1-alpha1", "1.1.1-rc1", "1.1.1", "1.1.1a", "1.1.2",
		"2.4", "2.4.0", "2.4.7", "6.0", "6.0.17",
		"6.6.55", "6.6.55.1", "6.6.55.999", "6.6.55.15189", "8.0", "8.0.3",
	}
	for _, a := range corpus {
		if CompareVersions(a, a) != 0 {
			t.Fatalf("non-reflexive CompareVersions(%q, %q)", a, a)
		}
		for _, b := range corpus {
			ab := CompareVersions(a, b)
			ba := CompareVersions(b, a)
			if ab != -ba {
				t.Fatalf("antisymmetry violated for (%q, %q): %d vs %d", a, b, ab, ba)
			}
			for _, c := range corpus {
				bc := CompareVersions(b, c)
				ac := CompareVersions(a, c)
				if ab <= 0 && bc <= 0 && ac > 0 {
					t.Fatalf("transitivity violated: %q <= %q <= %q but %q > %q", a, b, c, a, c)
				}
			}
		}
	}

	// Direct MatchesRange checks for 3-part vs 4-part UniFi NVD bounds.
	if ok, conf := MatchesRange("6.6.55.999", CPEMatch{Vendor: "ui", Product: "unifi_uap_firmware", EndIncl: "6.6.55"}); !ok || conf != ConfidenceExact {
		t.Fatalf("6.6.55.999 against 3-part EndIncl 6.6.55 = (%v, %v), want (true, exact)", ok, conf)
	}
	if ok, conf := MatchesRange("6.6.55.15100", CPEMatch{Vendor: "ui", Product: "unifi_uap_firmware", EndExcl: "6.6.55.15200"}); !ok || conf != ConfidenceExact {
		t.Fatalf("6.6.55.15100 against 4-part EndExcl 6.6.55.15200 = (%v, %v), want (true, exact)", ok, conf)
	}
	if ok, _ := MatchesRange("6.6.55.15300", CPEMatch{Vendor: "ui", Product: "unifi_uap_firmware", EndExcl: "6.6.55.15200"}); ok {
		t.Fatal("6.6.55.15300 must NOT match 4-part EndExcl 6.6.55.15200")
	}

	// End-to-end: Identify + MatchProducts against a local ui vendor shard with
	// both 3-part and 4-part bounds.
	cacheDir := t.TempDir()
	vendorsDir := filepath.Join(cacheDir, "vendors")
	if err := os.MkdirAll(vendorsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	uiRecords := []Record{
		{
			ID:        "CVE-2026-5001",
			Published: "2026-01-10",
			Severity:  checks.SeverityHigh,
			CVSS:      8.1,
			Matches:   []CPEMatch{{Vendor: "ui", Product: "unifi_uap_firmware", EndIncl: "6.6.55"}},
		},
		{
			ID:        "CVE-2026-5002",
			Published: "2026-01-10",
			Severity:  checks.SeverityHigh,
			CVSS:      7.8,
			Matches:   []CPEMatch{{Vendor: "ui", Product: "unifi_uap_firmware", Version: "6.6.55"}},
		},
		{
			ID:        "CVE-2026-5003",
			Published: "2026-01-10",
			Severity:  checks.SeverityHigh,
			CVSS:      7.5,
			Matches:   []CPEMatch{{Vendor: "ui", Product: "unifi_uap_firmware", EndExcl: "6.6.55"}},
		},
		{
			ID:        "CVE-2026-5004",
			Published: "2026-01-10",
			Severity:  checks.SeverityHigh,
			CVSS:      7.5,
			Matches:   []CPEMatch{{Vendor: "ui", Product: "unifi_uap_firmware", EndIncl: "6.6.54"}},
		},
		{
			ID:        "CVE-2026-5005",
			Published: "2026-01-10",
			Severity:  checks.SeverityCritical,
			CVSS:      9.0,
			Matches:   []CPEMatch{{Vendor: "ui", Product: "unifi_uap_firmware", EndExcl: "6.6.55.15200"}},
		},
	}
	if _, err := writeGzipJSONAtomic(filepath.Join(vendorsDir, "ui.json.gz"), uiRecords); err != nil {
		t.Fatal(err)
	}

	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	snap := &unifi.Snapshot{
		Devices: []unifi.Device{
			{Name: "Hallway AP", Model: "U6-Lite", Type: "uap", IP: "192.168.1.10", Version: "6.6.55.15189"},
			{Name: "Office AP", Model: "U6-Lite", Type: "uap", IP: "192.168.1.11", Version: "6.6.55.15300"},
			{Name: "Garage AP", Model: "U6-Lite", Type: "uap", IP: "192.168.1.12", Version: "6.6.55.999"},
		},
	}
	prods := fp.Identify(snap, nil)
	if len(prods) != 3 {
		t.Fatalf("expected 3 UniFi products, got %+v", prods)
	}
	if prods[0].Version != "6.6.55.15189" || prods[1].Version != "6.6.55.15300" || prods[2].Version != "6.6.55.999" {
		t.Fatalf("expected raw 4-part UniFi versions preserved, got %+v", prods)
	}
	matches, err := NewCache(cacheDir).MatchProducts(prods, MatchOptions{MinSeverity: checks.SeverityMedium})
	if err != nil {
		t.Fatal(err)
	}
	byHost := make(map[string]map[string]Confidence)
	for _, m := range matches {
		if byHost[m.Product.HostIP] == nil {
			byHost[m.Product.HostIP] = make(map[string]Confidence)
		}
		byHost[m.Product.HostIP][m.Record.ID] = m.Confidence
	}
	// 6.6.55.15189 matches 3-part EndIncl 6.6.55, 3-part exact 6.6.55, and 4-part EndExcl 6.6.55.15200.
	if len(byHost["192.168.1.10"]) != 3 ||
		byHost["192.168.1.10"]["CVE-2026-5001"] != ConfidenceExact ||
		byHost["192.168.1.10"]["CVE-2026-5002"] != ConfidenceExact ||
		byHost["192.168.1.10"]["CVE-2026-5005"] != ConfidenceExact {
		t.Fatalf("unexpected matches for 6.6.55.15189: %+v", byHost["192.168.1.10"])
	}
	// 6.6.55.15300 matches 3-part 6.6.55 bounds, but NOT 4-part EndExcl 6.6.55.15200.
	if len(byHost["192.168.1.11"]) != 2 ||
		byHost["192.168.1.11"]["CVE-2026-5001"] != ConfidenceExact ||
		byHost["192.168.1.11"]["CVE-2026-5002"] != ConfidenceExact {
		t.Fatalf("unexpected matches for 6.6.55.15300 (must not match 4-part EndExcl 6.6.55.15200): %+v", byHost["192.168.1.11"])
	}
	// 6.6.55.999 (build < 1000) matches 3-part 6.6.55 bounds AND 4-part EndExcl 6.6.55.15200.
	if len(byHost["192.168.1.12"]) != 3 ||
		byHost["192.168.1.12"]["CVE-2026-5001"] != ConfidenceExact ||
		byHost["192.168.1.12"]["CVE-2026-5002"] != ConfidenceExact ||
		byHost["192.168.1.12"]["CVE-2026-5005"] != ConfidenceExact {
		t.Fatalf("unexpected matches for 6.6.55.999: %+v", byHost["192.168.1.12"])
	}
}

// TestMapUniFiDeviceProductsInferredUGWAndUDMProSE verifies that UXG and UniFi
// Express devices never map to legacy USG firmware even when dev.Type is "ugw"
// (inferred in integration-only snapshots), and that UDMPROSE maps to UDM SE.
func TestMapUniFiDeviceProductsInferredUGWAndUDMProSE(t *testing.T) {
	tests := []struct {
		name string
		dev  unifi.Device
		want []string
	}{
		{
			name: "UXGPRO with inferred ugw type maps to UXG Pro",
			dev:  unifi.Device{Type: "ugw", Model: "UXGPRO", Name: "Edge", Version: "4.0.6"},
			want: []string{"unifi_next-generation_gateway_pro_firmware", "unifi_gateway_firmware"},
		},
		{
			name: "UXG-Lite with inferred ugw type maps to gateway firmware",
			dev:  unifi.Device{Type: "ugw", Model: "UXG-Lite", Name: "Edge", Version: "4.0.6"},
			want: []string{"unifi_gateway_firmware"},
		},
		{
			name: "UniFi Express UX with inferred ugw type never maps to USG",
			dev:  unifi.Device{Type: "ugw", Model: "UX", Name: "Express", Version: "4.0.9"},
			want: []string{"unifi_express_firmware", "unifi_gateway_firmware", "unifi_os"},
		},
		{
			name: "UniFi Express 7 UX7 with inferred ugw type never maps to USG",
			dev:  unifi.Device{Type: "ugw", Model: "UX7", Name: "Express 7", Version: "4.1.0"},
			want: []string{"unifi_express_firmware", "unifi_gateway_firmware", "unifi_os"},
		},
		{
			name: "classic USG-3P with ugw type maps to USG firmware",
			dev:  unifi.Device{Type: "ugw", Model: "USG-3P", Name: "Legacy GW", Version: "4.4.57.5578372"},
			want: []string{"unifi_security_gateway_firmware"},
		},
		{
			name: "UDMPROSE maps to UDM Special Edition firmware",
			dev:  unifi.Device{Type: "udm", Model: "UDMPROSE", Name: "Rack GW", Version: "4.0.21"},
			want: []string{"unifi_dream_machine_special_edition_firmware", "unifi_os"},
		},
		{
			name: "UDMPROSE without type maps to UDM Special Edition firmware",
			dev:  unifi.Device{Model: "UDMPROSE", Name: "Rack GW", Version: "4.0.21"},
			want: []string{"unifi_dream_machine_special_edition_firmware", "unifi_os"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapUniFiDeviceProducts(tc.dev)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mapUniFiDeviceProducts(%+v) = %v, want %v", tc.dev, got, tc.want)
			}
		})
	}

	// End-to-end: UXG-Pro with Type="ugw" must not match USG-only CVEs.
	cacheDir := t.TempDir()
	vendorsDir := filepath.Join(cacheDir, "vendors")
	if err := os.MkdirAll(vendorsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	uiRecords := []Record{
		{
			ID:        "CVE-2025-1111",
			Published: "2025-02-01",
			Severity:  checks.SeverityCritical,
			CVSS:      9.8,
			Matches:   []CPEMatch{{Vendor: "ui", Product: "unifi_security_gateway_firmware", EndIncl: "4.4.57"}},
		},
		{
			ID:        "CVE-2025-2222",
			Published: "2025-02-01",
			Severity:  checks.SeverityHigh,
			CVSS:      8.2,
			Matches:   []CPEMatch{{Vendor: "ui", Product: "unifi_next-generation_gateway_pro_firmware", EndExcl: "4.1.0"}},
		},
	}
	if _, err := writeGzipJSONAtomic(filepath.Join(vendorsDir, "ui.json.gz"), uiRecords); err != nil {
		t.Fatal(err)
	}
	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	prods := fp.Identify(&unifi.Snapshot{
		Devices: []unifi.Device{{Name: "Edge UXG", Model: "UXGPRO", Type: "ugw", IP: "192.168.1.1", Version: "4.0.6"}},
	}, nil)
	matches, err := NewCache(cacheDir).MatchProducts(prods, MatchOptions{MinSeverity: checks.SeverityMedium})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Record.ID != "CVE-2025-2222" || matches[0].Confidence != ConfidenceExact {
		t.Fatalf("expected only UXG-Pro CVE-2025-2222, got %+v", matches)
	}
}

// TestVersionlessRuleSupersededByVersionedCPEAndMatchDedup verifies that a
// host matched by both a versionless built-in rule and a versioned Nerva CPE
// emits only the versioned product, and that MatchProducts deduplicates
// (host, CVE) pairs preferring Exact over Potential regardless of input order.
func TestVersionlessRuleSupersededByVersionedCPEAndMatchDedup(t *testing.T) {
	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}

	profiles := []probe.HostProfile{
		{
			Client: unifi.Client{IP: "10.0.1.10", MAC: "aa:bb:cc:00:01:01", Name: "metrics"},
			HTTP:   map[int]probe.HTTPBanner{3000: {Title: "Grafana"}},
			Services: []probe.Service{
				{Port: 3000, CPEs: []string{"cpe:2.3:a:grafana:grafana:10.2.3:*:*:*:*:*:*:*"}},
			},
		},
		{
			Client: unifi.Client{IP: "10.0.1.11", MAC: "aa:bb:cc:00:01:02", Name: "proxy"},
			HTTP:   map[int]probe.HTTPBanner{8080: {Title: "Traefik"}},
			Services: []probe.Service{
				{Port: 8080, CPEs: []string{"cpe:2.3:a:traefik:traefik:2.10.5:*:*:*:*:*:*:*"}},
			},
		},
		{
			Client: unifi.Client{IP: "10.0.1.12", MAC: "aa:bb:cc:00:01:03", Name: "homeassistant"},
			HTTP:   map[int]probe.HTTPBanner{8123: {Title: "Home Assistant"}},
			Services: []probe.Service{
				{Port: 8123, CPEs: []string{"cpe:2.3:a:home-assistant:home-assistant:2024.1.0:*:*:*:*:*:*:*"}},
			},
		},
		{
			Client: unifi.Client{IP: "10.0.1.13", MAC: "aa:bb:cc:00:01:04", Name: "ollama"},
			HTTP:   map[int]probe.HTTPBanner{11434: {Title: "Ollama"}},
			Services: []probe.Service{
				{Port: 11434, CPEs: []string{"cpe:2.3:a:ollama:ollama:0.1.30:*:*:*:*:*:*:*"}},
			},
		},
	}

	prods := fp.Identify(nil, profiles)
	if len(prods) != 4 {
		t.Fatalf("expected exactly 4 versioned products with versionless duplicates dropped, got %d: %+v", len(prods), prods)
	}
	for _, p := range prods {
		if p.Version == "" {
			t.Fatalf("unexpected surviving versionless product: %+v", p)
		}
	}

	// Verify end-to-end Grafana matching produces only the exact CVE affecting 10.2.3
	// and never leaks unrelated Grafana CVEs via a versionless potential rollup.
	cacheDir := t.TempDir()
	vendorsDir := filepath.Join(cacheDir, "vendors")
	if err := os.MkdirAll(vendorsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	grafanaRecs := []Record{
		{
			ID:        "CVE-2026-3001",
			Published: "2026-02-01",
			Severity:  checks.SeverityHigh,
			CVSS:      8.5,
			Matches:   []CPEMatch{{Vendor: "grafana", Product: "grafana", StartIncl: "10.0.0", EndExcl: "10.2.4"}},
		},
		{
			ID:        "CVE-2026-3002",
			Published: "2026-02-01",
			Severity:  checks.SeverityCritical,
			CVSS:      9.1,
			Matches:   []CPEMatch{{Vendor: "grafana", Product: "grafana", StartIncl: "11.0.0", EndExcl: "11.1.0"}},
		},
	}
	if _, err := writeGzipJSONAtomic(filepath.Join(vendorsDir, "grafana.json.gz"), grafanaRecs); err != nil {
		t.Fatal(err)
	}

	cache := NewCache(cacheDir)
	matches, err := cache.MatchProducts(prods, MatchOptions{MinSeverity: checks.SeverityMedium})
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Record.ID != "CVE-2026-3001" || matches[0].Confidence != ConfidenceExact {
		t.Fatalf("expected single Exact match CVE-2026-3001, got %+v", matches)
	}

	// Also verify MatchProducts itself deduplicates (host, CVE) preferring Exact
	// over Potential even when a caller supplies both versionless and versioned
	// products directly (in either order).
	versionless := Product{Label: "Grafana", Vendors: []string{"grafana"}, Products: []string{"grafana"}, Version: "", HostIP: "10.0.1.10", HostName: "metrics"}
	versioned := Product{Label: "Grafana", Vendors: []string{"grafana"}, Products: []string{"grafana"}, Version: "10.2.3", HostIP: "10.0.1.10", HostName: "metrics"}
	for _, pair := range [][]Product{{versionless, versioned}, {versioned, versionless}} {
		m, err := cache.MatchProducts(pair, MatchOptions{MinSeverity: checks.SeverityMedium})
		if err != nil {
			t.Fatal(err)
		}
		var seen3001 []Match
		for _, hit := range m {
			if hit.Record.ID == "CVE-2026-3001" {
				seen3001 = append(seen3001, hit)
			}
		}
		if len(seen3001) != 1 || seen3001[0].Confidence != ConfidenceExact {
			t.Fatalf("expected CVE-2026-3001 once with ConfidenceExact, got %+v", seen3001)
		}
	}
}

// TestJoinCPEVersionUpdatePreservesNumericUpdates verifies that numeric CPE
// update tokens matching the final digit of the base version (such as 1.1:1 or
// 2.0:0) are preserved rather than dropped, while already-embedded non-numeric
// update suffixes (such as 8.5p1:p1 or 2.0-rc1:rc1) are not duplicated.
func TestJoinCPEVersionUpdatePreservesNumericUpdates(t *testing.T) {
	cases := []struct {
		cpe     string
		wantVer string
	}{
		{"cpe:2.3:a:vendor:app:1.1:1:*:*:*:*:*:*", "1.1-1"},
		{"cpe:2.3:a:vendor:app:2.0:0:*:*:*:*:*:*", "2.0-0"},
		{"cpe:2.3:a:vendor:app:1.10:0:*:*:*:*:*:*", "1.10-0"},
		{"cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*", "8.5p1"},
		{"cpe:2.3:a:openbsd:openssh:8.5p1:p1:*:*:*:*:*:*", "8.5p1"},
		{"cpe:2.3:a:example:app:2.0-rc1:rc1:*:*:*:*:*:*", "2.0-rc1"},
		{"cpe:2.3:a:openssl:openssl:1.1.1a:a:*:*:*:*:*:*", "1.1.1a"},
	}
	for _, tc := range cases {
		m, ok := ParseCPE23(tc.cpe)
		if !ok || m.Version != tc.wantVer {
			t.Fatalf("ParseCPE23(%q) = (%q, %v), want %q", tc.cpe, m.Version, ok, tc.wantVer)
		}
		_, _, ver, ok := parseVersionedCPE23(tc.cpe)
		if !ok || ver != tc.wantVer {
			t.Fatalf("parseVersionedCPE23(%q) = (%q, %v), want %q", tc.cpe, ver, ok, tc.wantVer)
		}
	}

	m11, _ := ParseCPE23("cpe:2.3:a:vendor:app:1.1:1:*:*:*:*:*:*")
	if matched, conf := MatchesRange("1.1", m11); matched && conf == ConfidenceExact {
		t.Fatal("observed version 1.1 must not match CPE 1.1 update 1 as Exact")
	}
	if matched, _ := MatchesRange("1.1.0", m11); matched {
		t.Fatal("observed version 1.1.0 must not match CPE 1.1 update 1")
	}
	if matched, conf := MatchesRange("1.1-1", m11); !matched || conf != ConfidenceExact {
		t.Fatalf("observed version 1.1-1 should match CPE 1.1 update 1 exact, got (%v, %v)", matched, conf)
	}
}

// TestMatchProductsPreservesSharedCVEAcrossDistinctProductsAndVersions verifies
// that MatchProducts retains shared CVEs across distinct products and distinct
// versions on the same host (preserving KEV flags and per-product upgrade
// advice) while deduplicating duplicate vendor-alias hits for the same product
// and version.
func TestMatchProductsPreservesSharedCVEAcrossDistinctProductsAndVersions(t *testing.T) {
	cacheDir := t.TempDir()
	vendorsDir := filepath.Join(cacheDir, "vendors")
	if err := os.MkdirAll(vendorsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	sharedKEV := "CVE-2023-44487"
	f5Recs := []Record{{
		ID:        sharedKEV,
		Published: "2023-10-10",
		Severity:  checks.SeverityHigh,
		CVSS:      7.5,
		KEV:       true,
		Matches:   []CPEMatch{{Vendor: "f5", Product: "nginx", StartIncl: "1.9.5", EndExcl: "1.25.3"}},
	}}
	nginxRecs := []Record{{
		ID:        sharedKEV,
		Published: "2023-10-10",
		Severity:  checks.SeverityHigh,
		CVSS:      7.5,
		KEV:       true,
		Matches:   []CPEMatch{{Vendor: "nginx", Product: "nginx", StartIncl: "1.9.5", EndExcl: "1.25.3"}},
	}}
	apacheRecs := []Record{{
		ID:        sharedKEV,
		Published: "2023-10-10",
		Severity:  checks.SeverityHigh,
		CVSS:      7.5,
		KEV:       true,
		Matches:   []CPEMatch{{Vendor: "apache", Product: "http_server", StartIncl: "2.4.17", EndExcl: "2.4.58"}},
	}}
	for name, recs := range map[string][]Record{
		"f5":     f5Recs,
		"nginx":  nginxRecs,
		"apache": apacheRecs,
	} {
		if _, err := writeGzipJSONAtomic(filepath.Join(vendorsDir, name+".json.gz"), recs); err != nil {
			t.Fatal(err)
		}
	}

	cache := NewCache(cacheDir)

	// 1. Distinct products on one host (Nginx 1.25.2 + Apache 2.4.57) plus
	// duplicate vendor aliases [f5, nginx] on Nginx must produce exactly 2
	// matches (one per product) with separate MinFixedVersion rollups.
	prods := []Product{
		{
			Label:    "Nginx",
			Vendors:  []string{"f5", "nginx"},
			Products: []string{"nginx"},
			Version:  "1.25.2",
			HostIP:   "192.168.1.50",
			HostName: "edge-proxy",
		},
		{
			Label:    "Apache HTTP Server",
			Vendors:  []string{"apache"},
			Products: []string{"http_server"},
			Version:  "2.4.57",
			HostIP:   "192.168.1.50",
			HostName: "edge-proxy",
		},
	}
	matches, err := cache.MatchProducts(prods, MatchOptions{MinSeverity: checks.SeverityMedium})
	if err != nil {
		t.Fatalf("MatchProducts: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches (Nginx 1.25.2 + Apache 2.4.57), got %d: %+v", len(matches), matches)
	}
	sums := RollupMatches(matches)
	if len(sums) != 2 {
		t.Fatalf("expected 2 rollup summaries, got %d: %+v", len(sums), sums)
	}
	fixByLabel := make(map[string]string, len(sums))
	for _, s := range sums {
		if s.KEVCount != 1 {
			t.Fatalf("expected KEVCount=1 for %s, got %+v", s.Product.Label, s)
		}
		fixByLabel[s.Product.Label] = s.MinFixedVersion
	}
	if fixByLabel["Nginx"] != "1.25.3" || fixByLabel["Apache HTTP Server"] != "2.4.58" {
		t.Fatalf("unexpected per-product MinFixedVersion: %+v", fixByLabel)
	}

	// 2. Distinct versions of the same product on one host (Nginx 1.18.0 and
	// Nginx 1.24.0) must each retain their match.
	multiVer := []Product{
		{Label: "Nginx", Vendors: []string{"f5", "nginx"}, Products: []string{"nginx"}, Version: "1.18.0", HostIP: "192.168.1.51"},
		{Label: "Nginx", Vendors: []string{"f5", "nginx"}, Products: []string{"nginx"}, Version: "1.24.0", HostIP: "192.168.1.51"},
	}
	mvMatches, err := cache.MatchProducts(multiVer, MatchOptions{MinSeverity: checks.SeverityMedium})
	if err != nil {
		t.Fatalf("MatchProducts multi-version: %v", err)
	}
	if len(mvMatches) != 2 {
		t.Fatalf("expected 2 matches for distinct versions on same host, got %d: %+v", len(mvMatches), mvMatches)
	}
}

// TestVersionlessSupersedingMergesUncoveredVendorAliases verifies that when a
// versioned Nerva CPE covers one vendor of a multi-vendor versionless rule
// (e.g., f5:nginx:1.18.0 vs rule vendors [f5, nginx]), uncovered vendor and
// exact product aliases are merged into the versioned product so CVEs indexed
// under the alternate vendor shard still match with Exact confidence.
func TestVersionlessSupersedingMergesUncoveredVendorAliases(t *testing.T) {
	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}

	profile := probe.HostProfile{
		Client: unifi.Client{IP: "10.0.2.20", MAC: "aa:bb:cc:00:02:20", Name: "reverse-proxy"},
		HTTP:   map[int]probe.HTTPBanner{80: {Server: "nginx"}},
		Services: []probe.Service{
			{Port: 80, CPEs: []string{"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}},
		},
	}

	prods := fp.Identify(nil, []probe.HostProfile{profile})
	if len(prods) != 1 {
		t.Fatalf("expected 1 consolidated versioned product, got %d: %+v", len(prods), prods)
	}
	if prods[0].Version != "1.18.0" {
		t.Fatalf("expected version 1.18.0, got %+v", prods[0])
	}
	hasF5, hasNginx := false, false
	for _, v := range prods[0].Vendors {
		switch v {
		case "f5":
			hasF5 = true
		case "nginx":
			hasNginx = true
		}
	}
	if !hasF5 || !hasNginx {
		t.Fatalf("expected merged vendors [f5, nginx], got %v", prods[0].Vendors)
	}

	cacheDir := t.TempDir()
	vendorsDir := filepath.Join(cacheDir, "vendors")
	if err := os.MkdirAll(vendorsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	nginxOnlyRecs := []Record{
		{
			ID:        "CVE-2021-23017",
			Published: "2021-06-01",
			Severity:  checks.SeverityHigh,
			CVSS:      8.1,
			Matches:   []CPEMatch{{Vendor: "nginx", Product: "nginx", StartIncl: "0.6.18", EndExcl: "1.20.1"}},
		},
		{
			ID:        "CVE-2025-99999",
			Published: "2025-01-01",
			Severity:  checks.SeverityHigh,
			CVSS:      7.5,
			Matches:   []CPEMatch{{Vendor: "nginx", Product: "nginx", StartIncl: "1.25.0", EndExcl: "1.25.4"}},
		},
	}
	if _, err := writeGzipJSONAtomic(filepath.Join(vendorsDir, "nginx.json.gz"), nginxOnlyRecs); err != nil {
		t.Fatal(err)
	}

	matches, err := NewCache(cacheDir).MatchProducts(prods, MatchOptions{MinSeverity: checks.SeverityMedium})
	if err != nil {
		t.Fatalf("MatchProducts: %v", err)
	}
	if len(matches) != 1 || matches[0].Record.ID != "CVE-2021-23017" || matches[0].Confidence != ConfidenceExact {
		t.Fatalf("expected exact match CVE-2021-23017 from merged nginx vendor shard, got %+v", matches)
	}
}

// TestProductEndpointExposure checks that a forward reaches the observed transport
// and internal port, including when multiple fingerprint sources agree on the product.
func TestProductEndpointExposure(t *testing.T) {
	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	const ip = "192.0.2.10"
	const ssh = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
	hp := probe.HostProfile{Client: unifi.Client{IP: ip, Name: "truenas"}, SSHBanner: ssh,
		HTTP: map[int]probe.HTTPBanner{443: {Server: "nginx/1.18.0-1.el9"}, 8443: {Server: "nginx/1.18.0"}},
		Services: []probe.Service{
			{Port: 443, Transport: "tcp", Protocol: "https", State: probe.ServiceStateObservedProtocol, CPEs: []string{"cpe:2.3:a:f5:nginx:1.18.0"}},
			{Port: 51820, Transport: "udp", Protocol: "wireguard", State: probe.ServiceStateObservedProtocol, CPEs: []string{"cpe:2.3:a:wireguard:wireguard:1.0"}},
			{Port: 2222, Transport: "tcp", Protocol: "ssh", Banner: ssh},
		},
	}
	snap := &unifi.Snapshot{PortForwards: []unifi.PortForward{
		{Enabled: true, FwdIP: ip, Proto: "udp", FwdPort: "51820"},
		{Enabled: true, FwdIP: ip, Proto: "udp", FwdPort: "443"},
		{Enabled: true, FwdIP: "192.0.2.11", Proto: "tcp", FwdPort: "443"},
		{FwdIP: ip, Proto: "tcp", FwdPort: "443", DstPort: "10443"},
	}}
	for _, enabled := range []bool{false, true} {
		snap.PortForwards[3].Enabled = enabled
		prods := fp.Identify(snap, []probe.HostProfile{hp})
		if len(prods) != 4 {
			t.Fatalf("unexpected products: %+v", prods)
		}
		for _, p := range prods {
			switch p.Source {
			case "http-server":
				if p.WANExposed != enabled || p.HighConfidence || !p.VersionAmbiguous || p.Version != "1.18.0" ||
					!slices.Equal(p.Ports, []EndpointPort{{"tcp", 443}, {"tcp", 8443}}) {
					t.Fatalf("nginx evidence with HTTPS forward enabled=%v: %+v", enabled, p)
				}
			case "ssh-banner":
				if p.WANExposed || !p.VersionAmbiguous || !slices.Equal(p.Ports, []EndpointPort{{"tcp", 2222}}) {
					t.Fatalf("alternate SSH endpoint: %+v", p)
				}
			case "nerva-cpe":
				if !p.WANExposed || !p.HighConfidence || !slices.Equal(p.Ports, []EndpointPort{{"udp", 51820}}) {
					t.Fatalf("Nerva endpoint: %+v", p)
				}
			case "hostname":
				if !p.WANExposed || len(p.Ports) != 0 || p.HighConfidence {
					t.Fatalf("host-only evidence: %+v", p)
				}
			default:
				t.Fatalf("unexpected fingerprint: %+v", p)
			}
		}
	}
}

// TestOfflineIndexMigration checks that cached inputs suffice for a schema upgrade
// and that the next freshness check leaves the rebuilt shards alone.
func TestOfflineIndexMigration(t *testing.T) {
	const vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"
	feed := `{"vulnerabilities":[
		{"cve":{"id":"CVE-2024-1001","published":"2025-01-02","metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8,"vectorString":"` + vector + `"}}]},
		"weaknesses":[{"description":[{"value":"CWE-79"},{"value":"CWE-79"},{"value":"NVD-CWE-noinfo"}]}],
		"configurations":[{"operator":"AND","nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:example:portal:1"}]},
		{"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:example:os:2"}]}]},
		{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:example:portal:2"}]}]}]}},
		{"cve":{"id":"CVE-2024-1002","published":"2025-01-03"}},
		{"cve":{"id":"CVE-2024-1003","published":"2025-01-04","vulnStatus":"Rejected"}}]}`
	const kev = `{"vulnerabilities":[{"cveID":"CVE-2024-1001","dateAdded":"2025-02-01","knownRansomwareCampaignUse":"Known"}]}`
	dir := t.TempDir()
	cache := NewCache(dir)
	feedDir := filepath.Join(dir, "feeds")
	if err := os.Mkdir(feedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := writeGzipJSONAtomic(filepath.Join(feedDir, "nvdcve-2.0-2024.json.gz"), json.RawMessage(feed)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kev.json"), []byte(kev), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(filepath.Join(dir, "stats.json"), CacheStats{}); err != nil {
		t.Fatal(err)
	}
	// Simulate a legacy shard for a vendor whose last CPE has been withdrawn.
	staleDir := filepath.Join(dir, "vendors")
	if err := os.Mkdir(staleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := writeGzipJSONAtomic(filepath.Join(staleDir, "withdrawn.json.gz"), []Record{{ID: "CVE-2024-9999"}}); err != nil {
		t.Fatal(err)
	}
	// Any upstream access during migration would fail immediately.
	cache.kevURL, cache.nvdBaseURL = "offline:", "offline:"
	indexes := 0
	opts := SyncOptions{SinceYear: 2024, EndYear: 2024, Progress: func(msg string) {
		if strings.HasPrefix(msg, "Indexing ") {
			indexes++
		}
	}}
	st, err := cache.Sync(t.Context(), opts)
	if err != nil || st.SchemaVersion != 2 || st.YearCoverage["2025"] != (YearCoverageStats{Total: 2, WithCPE: 1}) {
		t.Fatalf("migrated stats: %+v, %v", st, err)
	}
	if obsolete, err := cache.LookupVendor("withdrawn"); err != nil || len(obsolete) > 0 {
		t.Fatalf("withdrawn product survived rebuild: %v, %v", obsolete, err)
	}
	recs, err := cache.LookupVendor("example")
	if err != nil || len(recs) != 1 {
		t.Fatalf("migrated shard: %v, %v", recs, err)
	}
	r := recs[0]
	if r.CVSSVector != vector || r.AttackVector != "N" || r.PrivilegesRequired != "L" || r.UserInteraction != "R" ||
		!slices.Equal(r.CWEs, []string{"CWE-79"}) || !r.KEV || !r.KEVRansomware || r.KEVDateAdded != "2025-02-01" || !r.NeedsContext {
		t.Fatalf("missing enrichment: %+v", r)
	}
	for version, want := range map[string]Confidence{"1": ConfidencePotential, "2": ConfidenceExact} {
		p := Product{Vendors: []string{"example"}, Products: []string{"portal"}, Version: version}
		m, err := cache.MatchProducts([]Product{p}, MatchOptions{})
		if err != nil || len(m) != 1 || m[0].Confidence != want {
			t.Fatalf("version %s: %+v, %v", version, m, err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev":
			fmt.Fprint(w, kev)
		case "/nvdcve-2.0-2024.meta":
			fmt.Fprint(w, "sha256:"+strings.ToUpper(st.YearSHAs["2024"]))
		default:
			t.Errorf("unexpected archive request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cache.kevURL, cache.nvdBaseURL = srv.URL+"/kev", srv.URL
	next, err := cache.Sync(t.Context(), opts)
	if err != nil || indexes != 1 || !st.SyncedAt.Equal(next.SyncedAt) {
		t.Fatalf("unchanged sync: %+v, %v, %d rebuilds", next, err, indexes)
	}
}

// TestTargetVelocity separates a sustained network CVE history from a burst,
// incomplete coverage, and weak product identity.
func TestTargetVelocity(t *testing.T) {
	cache := NewCache(t.TempDir())
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	coverage := make(map[string]YearCoverageStats)
	for year := 2021; year <= 2026; year++ {
		coverage[fmt.Sprint(year)] = YearCoverageStats{Total: 5, WithCPE: 3}
	}
	if err := os.Mkdir(filepath.Join(cache.dir, "vendors"), 0o755); err != nil {
		t.Fatal(err)
	}
	records := []Record{}
	for i, date := range []string{"2026-06-01", "2024-07-01", "2023-06-01", "2021-06-01", "2021-05-31", "2026-06-02"} {
		records = append(records, Record{ID: fmt.Sprintf("CVE-2021-%04d", i), Published: date, AttackVector: "N",
			Severity: checks.SeverityHigh, Matches: []CPEMatch{{Vendor: "example", Product: "portal"}}})
	}
	for _, av := range []string{"A", "L", "P"} {
		r := records[0]
		r.ID, r.AttackVector = "local-"+av, av
		records = append(records, r)
	}
	records = append(records, records[0])
	if _, err := writeGzipJSONAtomic(filepath.Join(cache.dir, "vendors", "example.json.gz"), records); err != nil {
		t.Fatal(err)
	}
	p := Product{Vendors: []string{"example"}, Products: []string{"portal"}, HighConfidence: true}
	query := func() TargetVelocity {
		t.Helper()
		if err := writeJSONAtomic(filepath.Join(cache.dir, "stats.json"), CacheStats{SchemaVersion: 2, YearCoverage: coverage}); err != nil {
			t.Fatal(err)
		}
		h, err := cache.ProductVelocity(p, now)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	h := query()
	if h.Class != VelocityHighProfile || h.TotalCVEs != 8 || !reflect.DeepEqual(h.NetworkHigh, map[int]int{1: 1, 3: 3, 5: 4}) {
		t.Fatalf("complete windows: %+v", h)
	}
	coverage["2024"] = YearCoverageStats{Total: 5, WithCPE: 2}
	h = query()
	if h.Class != VelocityObserved || !reflect.DeepEqual(h.NetworkHigh, map[int]int{1: 1}) || !slices.Equal(h.IncompleteYears, []string{"2024"}) {
		t.Fatalf("incomplete windows: %+v", h)
	}
	const kev = `{"vulnerabilities":[
		{"cveID":"CVE-2021-0000","dateAdded":"2020-03-01","knownRansomwareCampaignUse":"Known"},
		{"cveID":"CVE-2026-5000","vendorProject":"Example","product":"Portal","dateAdded":"2026-05-02"},
		{"cveID":"CVE-2026-6000","vendorProject":"Example","product":"Portal Pro","dateAdded":"2026-06-01"}
	]}`
	if err := os.WriteFile(filepath.Join(cache.dir, "kev.json"), []byte(kev), 0o600); err != nil {
		t.Fatal(err)
	}
	h = query()
	if h.Class != VelocityHighProfile || h.TotalCVEs != 9 || h.KEVCount != 2 || h.RansomwareCount != 1 || h.LatestKEV != "2026-05-02" {
		t.Fatalf("KEV history: %+v", h)
	}
	// Before the recent listings, the older ransomware-linked KEV still qualifies.
	past, err := cache.ProductVelocity(p, now.AddDate(-1, 0, 0))
	if err != nil || past.Class != VelocityHighProfile || past.KEVCount != 1 || past.LatestKEV != "2020-03-01" {
		t.Fatalf("older ransomware history: %+v, %v", past, err)
	}
	p.HighConfidence = false
	if h := query(); h.Class != VelocityUnknown || h.KEVCount != 2 {
		t.Fatalf("unconfirmed identity: %+v", h)
	}
}

// TestCVSSMetricPrecedence checks the older metric layouts and keeps the score,
// vector, and compact fields together when both v3 and v2 are available.
func TestCVSSMetricPrecedence(t *testing.T) {
	var advisory nvdCVE
	err := json.Unmarshal([]byte(`{"metrics":{
		"cvssMetricV30":[{"cvssData":{"baseScore":7.2,"vectorString":"CVSS:3.0/AV:A/PR:L/UI:N"}}],
		"cvssMetricV2":[{"baseSeverity":"HIGH","userInteractionRequired":true,"cvssData":{"baseScore":7.5,"vectorString":"AV:N/AC:L/Au:S/C:P/I:P/A:P"}}]}}`), &advisory)
	if err != nil {
		t.Fatal(err)
	}
	r := advisory.record(nil)
	if r.CVSS != 7.2 || r.AttackVector != "A" || r.PrivilegesRequired != "L" || r.UserInteraction != "N" {
		t.Fatalf("v3.0 score and vector: %+v", r)
	}
	advisory.Metrics.CVSSMetricV30 = nil
	r = advisory.record(nil)
	if r.CVSS != 7.5 || r.AttackVector != "N" || r.PrivilegesRequired != "" || r.UserInteraction != "R" {
		t.Fatalf("v2.0 score and vector: %+v", r)
	}
}

// TestFirmwareHardwareANDAndDistroBackports verifies that NVD firmware+hardware
// AND nodes stay exact, unbounded wildcard CPEs on distro packages never promote
// above potential, RHEL rebuilds/FreeBSD flag version-ambiguous, and superseding
// a host-only product preserves WAN exposure.
func TestFirmwareHardwareANDAndDistroBackports(t *testing.T) {
	// 1. Firmware AND hardware node must stay exact (NeedsContext=false).
	var fwAdvisory nvdCVE
	if err := json.Unmarshal([]byte(`{"id":"CVE-2026-34910","configurations":[{"operator":"AND","nodes":[
		{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:ui:unifi_dream_machine_pro_firmware:*:*:*:*:*:*:*:*","versionEndExcluding":"5.1.12"}]},
		{"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:h:ui:unifi_dream_machine_pro:-:*:*:*:*:*:*:*"}]}
	]}]}`), &fwAdvisory); err != nil {
		t.Fatal(err)
	}
	fwMatches := extractVendorMatches(fwAdvisory.Configurations)["ui"]
	if len(fwMatches) != 1 || fwMatches[0].NeedsContext {
		t.Fatalf("firmware+hardware AND must not set NeedsContext: %+v", fwMatches)
	}
	// Wildcard OS prerequisite (o:microsoft:*) still marks NeedsContext=true.
	var osWildAdvisory nvdCVE
	if err := json.Unmarshal([]byte(`{"id":"CVE-2026-34911","configurations":[{"operator":"AND","nodes":[
		{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:example:portal:2.0:*:*:*:*:*:*:*"}]},
		{"cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:*:*:*:*:*:*:*:*"}]}
	]}]}`), &osWildAdvisory); err != nil {
		t.Fatal(err)
	}
	if osMatches := extractVendorMatches(osWildAdvisory.Configurations)["example"]; len(osMatches) != 1 || !osMatches[0].NeedsContext {
		t.Fatalf("wildcard OS prerequisite must set NeedsContext: %+v", osMatches)
	}

	// 2. Wildcard CPE + VersionAmbiguous stays ConfidencePotential and honors age cutoff.
	cache := NewCache(t.TempDir())
	if err := os.Mkdir(filepath.Join(cache.dir, "vendors"), 0o755); err != nil {
		t.Fatal(err)
	}
	recs := []Record{
		{ID: "CVE-1999-1237", Published: "1999-06-01", Severity: checks.SeverityCritical, CVSS: 10.0,
			Matches: []CPEMatch{{Part: "a", Vendor: "apache", Product: "http_server"}}},
		{ID: "CVE-2024-9999", Published: "2024-06-01", Severity: checks.SeverityHigh, CVSS: 7.5,
			Matches: []CPEMatch{{Part: "a", Vendor: "apache", Product: "http_server", EndExcl: "2.4.60"}}},
	}
	if _, err := writeGzipJSONAtomic(filepath.Join(cache.dir, "vendors", "apache.json.gz"), recs); err != nil {
		t.Fatal(err)
	}
	prod := Product{Vendors: []string{"apache"}, Products: []string{"http_server"}, Version: "2.4.6", VersionAmbiguous: true}
	got, err := cache.MatchProducts([]Product{prod}, MatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Confidence{}
	for _, m := range got {
		byID[m.Record.ID] = m.Confidence
	}
	if byID["CVE-1999-1237"] != ConfidencePotential {
		t.Fatalf("wildcard CPE on distro package should stay potential, got %+v", byID)
	}
	if byID["CVE-2024-9999"] != ConfidenceVersionAmbiguous {
		t.Fatalf("bounded CPE on distro package should be version-ambiguous, got %+v", byID)
	}
	aged, err := cache.MatchProducts([]Product{prod}, MatchOptions{PotentialMaxAgeYears: 5})
	if err != nil || len(aged) != 1 || aged[0].Record.ID != "CVE-2024-9999" {
		t.Fatalf("ancient wildcard CPE should be filtered by PotentialMaxAgeYears: %+v, %v", aged, err)
	}
	// Versionless product with NeedsContext still respects PotentialMaxAgeYears,
	// and NeedsContext outranks distro ambiguity on a bounded range.
	if _, err := writeGzipJSONAtomic(filepath.Join(cache.dir, "vendors", "apache.json.gz"), []Record{
		{ID: "CVE-2010-0001", Published: "2010-01-01", Severity: checks.SeverityHigh, NeedsContext: true,
			Matches: []CPEMatch{{Part: "a", Vendor: "apache", Product: "http_server", EndExcl: "2.4.60", NeedsContext: true}}},
	}); err != nil {
		t.Fatal(err)
	}
	if aged, err := cache.MatchProducts([]Product{{Vendors: []string{"apache"}, Products: []string{"http_server"}}}, MatchOptions{PotentialMaxAgeYears: 5}); err != nil || len(aged) != 0 {
		t.Fatalf("ancient versionless NeedsContext CVE bypassed PotentialMaxAgeYears: %+v, %v", aged, err)
	}
	if m, err := cache.MatchProducts([]Product{prod}, MatchOptions{}); err != nil || len(m) != 1 || m[0].Confidence != ConfidencePotential {
		t.Fatalf("NeedsContext must outrank VersionAmbiguous: %+v, %v", m, err)
	}

	// 3. RHEL rebuilds, Fedora, Amazon Linux, and FreeBSD banners trigger distroPackage.
	for _, raw := range []string{
		"Apache/2.4.6 (CentOS)",
		"Apache/2.4.57 (Rocky Linux)",
		"Apache/2.4.57 (AlmaLinux)",
		"Apache/2.4.57 (Oracle Linux Server)",
		"Apache/2.4.57 (Amazon Linux)",
		"Apache/2.4.58 (Fedora Linux)",
		"OpenSSH_9.6 FreeBSD-20240806",
	} {
		if !distroPackage.MatchString(raw) {
			t.Errorf("expected distroPackage to match %q", raw)
		}
	}

	// 4. Superseding a host-only WAN-exposed product retains WANExposed on the survivor.
	fp, err := LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	snap := &unifi.Snapshot{
		PortForwards: []unifi.PortForward{{Enabled: true, FwdIP: "192.0.2.50", FwdPort: "5001", DstPort: "5001", Proto: "tcp"}},
	}
	hp := probe.HostProfile{
		Client: unifi.Client{MAC: "00:11:32:aa:bb:cc", IP: "192.0.2.50", Name: "synology-nas"},
		HTTP:   map[int]probe.HTTPBanner{5000: {Title: "DiskStation"}, 8443: {Title: "DiskStation"}},
		Services: []probe.Service{{
			Port: 5000, Transport: "tcp", Protocol: "http", State: probe.ServiceStateObservedProtocol,
			CPEs: []string{"cpe:2.3:o:synology:diskstation_manager:7.2:*:*:*:*:*:*:*"},
		}},
	}
	prods := fp.Identify(snap, []probe.HostProfile{hp})
	found := false
	for _, p := range prods {
		if slices.Contains(p.Vendors, "synology") && p.Version == "7.2" {
			found = true
			if !p.WANExposed {
				t.Fatalf("versioned product dropped WANExposed inherited from host-only rule: %+v", p)
			}
		}
	}
	if !found {
		t.Fatalf("expected synology 7.2 product, got %+v", prods)
	}
	// Versionless distro banner and WAN exposure stay scoped to their matching port,
	// without bleeding onto an unrelated listener on another port.
	hpDistro := probe.HostProfile{
		Client: unifi.Client{IP: "192.0.2.51"},
		HTTP:   map[int]probe.HTTPBanner{443: {Server: "nginx (Rocky Linux)"}, 8443: {Server: "nginx"}},
		Services: []probe.Service{
			{Port: 443, Transport: "tcp", Protocol: "http", CPEs: []string{"cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"}},
			{Port: 8443, Transport: "tcp", Protocol: "http", CPEs: []string{"cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*"}},
		},
	}
	nginxSnap := &unifi.Snapshot{
		PortForwards: []unifi.PortForward{{Enabled: true, FwdIP: "192.0.2.51", FwdPort: "443", DstPort: "443", Proto: "tcp"}},
	}
	distroProds := fp.Identify(nginxSnap, []probe.HostProfile{hpDistro})
	if len(distroProds) != 2 {
		t.Fatalf("expected 2 versioned nginx products, got %+v", distroProds)
	}
	for _, p := range distroProds {
		if p.Version == "1.24.0" && (!p.VersionAmbiguous || !p.WANExposed) {
			t.Fatalf("port 443 distro banner lost VersionAmbiguous or WANExposed: %+v", p)
		}
		if p.Version == "1.25.0" && (p.VersionAmbiguous || p.WANExposed) {
			t.Fatalf("port 443 distro ambiguity or WANExposed bled onto unforwarded port 8443: %+v", p)
		}
	}
	// Two plain versionless nginx banners on 443 (forwarded) and 8443 (not forwarded)
	// must never leak WANExposed onto the unforwarded versioned listener on 8443.
	hpPlain := probe.HostProfile{
		Client: unifi.Client{IP: "192.0.2.51"},
		HTTP:   map[int]probe.HTTPBanner{443: {Server: "nginx"}, 8443: {Server: "nginx"}},
		Services: []probe.Service{
			{Port: 443, Transport: "tcp", Protocol: "http", CPEs: []string{"cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"}},
			{Port: 8443, Transport: "tcp", Protocol: "http", CPEs: []string{"cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*"}},
		},
	}
	for _, p := range fp.Identify(nginxSnap, []probe.HostProfile{hpPlain}) {
		if p.Version == "1.25.0" && p.WANExposed {
			t.Fatalf("port 443 WANExposed leaked onto unforwarded port 8443: %+v", p)
		}
	}
}
