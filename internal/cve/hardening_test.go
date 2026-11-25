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
