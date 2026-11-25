// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCVECacheRejectsCorruptLocalFeedAndPastYear404(t *testing.T) {
	validJSON := []byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2024-99001","descriptions":[{"lang":"en","value":"test vuln"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]},"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*","versionEndExcluding":"1.27.0"}]}]}]}}]}`)
	sum := sha256.Sum256(validJSON)
	validSHA := hex.EncodeToString(sum[:])

	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	_, _ = gzw.Write(validJSON)
	_ = gzw.Close()
	validGZ := gzBuf.Bytes()

	return404ForPastYear := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
		case "/nvdcve-2.0-2024.meta":
			if return404ForPastYear {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, "lastModifiedDate:2026-01-01T00:00:00Z\nsha256:%s\n", validSHA)
		case "/nvdcve-2.0-2024.json.gz":
			_, _ = w.Write(validGZ)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	cache := NewCache(dir)
	cache.nvdBaseURL = srv.URL
	cache.kevURL = srv.URL + "/kev.json"
	opts := SyncOptions{
		SinceYear: 2024,
		EndYear:   2024,
	}

	// First sync builds valid cache.
	st, err := cache.Sync(context.Background(), opts)
	if err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if st.VendorCount != 1 {
		t.Fatalf("expected 1 vendor after initial sync, got %d", st.VendorCount)
	}

	// Corrupt the cached local yearly feed file with an HTML error page while
	// keeping .meta SHA identical: the next sync must detect corruption and
	// re-download cleanly instead of reusing the corrupt file.
	feedPath := filepath.Join(dir, "feeds", "nvdcve-2.0-2024.json.gz")
	if err := os.WriteFile(feedPath, []byte("<html>502 Bad Gateway</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Sync(context.Background(), opts); err != nil {
		t.Fatalf("sync after local feed corruption should recover via re-download, got: %v", err)
	}
	if err := verifyFeedGzipFile(feedPath, validSHA); err != nil {
		t.Fatalf("expected healed feed file to verify cleanly, got: %v", err)
	}

	// A past-year 404 on .meta must return an error instead of silently skipping.
	if time.Now().UTC().Year() > 2024 {
		return404ForPastYear = true
		if _, err := cache.Sync(context.Background(), opts); err == nil {
			t.Fatal("expected error when past-year NVD feed returns HTTP 404")
		}
	}
}

func TestCVEProductSummaryHeadlineFourPartBuildBeyondMaxAffected(t *testing.T) {
	s := ProductSummary{
		Product: Product{
			Label:   "UniFi Network",
			Version: "7.2.95.1",
		},
		Confidence:         ConfidenceExact,
		TotalCVEs:          1,
		MaxAffectedVersion: "7.2.95",
	}
	got := s.Headline()
	if !strings.Contains(got, "verify > 7.2.95.x") {
		t.Fatalf("expected 4-part build beyond 3-part MaxAffectedVersion to emit verify hint, got %q", got)
	}
}

func TestCVECacheCleansStaleArtifactsMergesCollisionsResumesAndGuardsCurrentYear404(t *testing.T) {
	curYear := time.Now().UTC().Year()
	feedJSON := []byte(`{"vulnerabilities":[
		{"cve":{"id":"CVE-2026-10001","descriptions":[{"lang":"en","value":"v1"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.1,"baseSeverity":"HIGH"}}]},"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}},
		{"cve":{"id":"CVE-2026-10002","descriptions":[{"lang":"en","value":"v2"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.1,"baseSeverity":"CRITICAL"}}]},"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:acme.:gadget:*:*:*:*:*:*:*:*","versionEndExcluding":"3.0"}]}]}]}}
	]}`)
	sum := sha256.Sum256(feedJSON)
	shaHex := hex.EncodeToString(sum[:])

	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	_, _ = gzw.Write(feedJSON)
	_ = gzw.Close()
	feedGZ := gzBuf.Bytes()

	feedGets := 0
	return404 := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
		case fmt.Sprintf("/nvdcve-2.0-%d.meta", curYear):
			if return404 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = fmt.Fprintf(w, "sha256:%s\n", shaHex)
		case fmt.Sprintf("/nvdcve-2.0-%d.json.gz", curYear):
			feedGets++
			_, _ = w.Write(feedGZ)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	// Plant stale spill dir and temp files from a simulated earlier hard kill.
	staleSpill := filepath.Join(dir, ".index-stale123")
	if err := os.MkdirAll(staleSpill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleSpill, "bucket-00.ndjson"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	feedsDir := filepath.Join(dir, "feeds")
	if err := os.MkdirAll(feedsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	staleTmp := filepath.Join(feedsDir, "nvdcve-2.0-2024.json.gz.abc.tmp")
	if err := os.WriteFile(staleTmp, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Pre-populate a valid feed archive simulating an interrupted first sync
	// before stats.json was written.
	preFeed := filepath.Join(feedsDir, fmt.Sprintf("nvdcve-2.0-%d.json.gz", curYear))
	if err := os.WriteFile(preFeed, feedGZ, 0o600); err != nil {
		t.Fatal(err)
	}

	cache := NewCache(dir)
	cache.nvdBaseURL = srv.URL
	cache.kevURL = srv.URL + "/kev.json"
	opts := SyncOptions{SinceYear: curYear, EndYear: curYear}

	st, err := cache.Sync(context.Background(), opts)
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if feedGets != 0 {
		t.Fatalf("expected valid on-disk feed from interrupted first sync to be reused with 0 downloads, got %d", feedGets)
	}
	if _, err := os.Stat(staleSpill); !os.IsNotExist(err) {
		t.Fatalf("expected stale spill dir removed, stat err=%v", err)
	}
	if _, err := os.Stat(staleTmp); !os.IsNotExist(err) {
		t.Fatalf("expected stale feed temp file removed, stat err=%v", err)
	}
	// Colliding raw vendor names ("acme" and "acme.") must merge into 1 shard
	// without losing either CVE.
	if st.VendorCount != 1 {
		t.Fatalf("expected merged colliding vendors to produce 1 shard, got VendorCount=%d", st.VendorCount)
	}
	recs, err := cache.Search(context.Background(), "", SearchOptions{Vendor: "acme", Limit: 10})
	if err != nil || len(recs) != 2 {
		t.Fatalf("expected both colliding vendor CVEs preserved in acme shard, err=%v recs=%+v", err, recs)
	}

	// Once current year is in prevSHAs, a transient 404 on current year must fail
	// rather than silently dropping it from the index.
	return404 = true
	if _, err := cache.Sync(context.Background(), opts); err == nil {
		t.Fatal("expected error on transient 404 for already-synced current year")
	}
}
