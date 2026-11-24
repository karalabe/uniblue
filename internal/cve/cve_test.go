package cve

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/karalabe/uniblue/fingerprints"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/unifi"
)

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

func TestPatternMatchingPreventsPrefixLeakage(t *testing.T) {
	// Exact patterns must not bleed into similarly prefixed sibling products.
	if matchesAnyPattern([]string{"nginx", "nginx_open_source"}, "nginx_unit") {
		t.Fatal("exact pattern nginx must not match nginx_unit")
	}
	if !matchesAnyPattern([]string{"nginx", "nginx_open_source"}, "nginx_open_source") {
		t.Fatal("expected exact match for nginx_open_source")
	}
	// Explicit wildcard patterns match targeted hardware families cleanly.
	if !matchesAnyPattern([]string{"*laserjet*m453*"}, "laserjet_pro_m453-m454_w1y40a_firmware") {
		t.Fatal("expected wildcard pattern to match M453 LaserJet firmware")
	}
	if matchesAnyPattern([]string{"*laserjet*m453*"}, "laserjet_pro_m404-m405_firmware") {
		t.Fatal("expected M453 wildcard not to match M404 firmware")
	}
}

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
			Client:    unifi.Client{IP: "192.168.10.2", MAC: "aa:01", Name: "truenas-01", NetworkName: "Servers"},
			SSHBanner: "SSH-2.0-OpenSSH_9.6p1 Debian-1",
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
}
