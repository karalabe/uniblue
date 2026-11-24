// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
)

const (
	// defaultNVDBaseURL hosts NIST's official NVD JSON 2.0 yearly bulk feeds.
	defaultNVDBaseURL = "https://nvd.nist.gov/feeds/json/cve/2.0"

	// defaultKEVURL hosts CISA's Known Exploited Vulnerabilities catalog.
	defaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// firstNVDYear is the earliest yearly feed published by NVD.
	firstNVDYear = 2002

	// syncWorkers bounds parallel downloads against NIST's CDN to stay polite.
	syncWorkers = 4

	// maxDescriptionLen caps cached English CVE summaries so vendor shards stay
	// compact while retaining readable context for `uniblue cve show`.
	maxDescriptionLen = 600
)

// DefaultCacheDir returns the default on-disk directory for UniBlue's local
// CVE cache (~/.cache/uniblue/cve).
func DefaultCacheDir() string {
	if base, err := os.UserCacheDir(); err == nil && base != "" {
		return filepath.Join(base, "uniblue", "cve")
	}
	return filepath.Join(".", ".uniblue-cve")
}

// SyncOptions tunes how Cache.Sync fetches and compiles upstream feeds.
type SyncOptions struct {
	// SinceYear sets the earliest yearly NVD feed to fetch (defaults to 2002
	// for the entire CVE database).
	SinceYear int

	// EndYear optionally overrides the latest yearly feed (defaults to current year).
	EndYear int

	// Force re-downloads feeds and rebuilds vendor shards even when .meta
	// checksums match the previous sync.
	Force bool

	// Progress receives optional human-readable status updates during sync.
	Progress func(msg string)
}

// SearchOptions filters offline searches over the local CVE cache.
type SearchOptions struct {
	// Vendor restricts the search to a single vendor shard when non-empty.
	Vendor string

	// KEVOnly returns only CVEs present in CISA's Known Exploited Vulnerabilities catalog.
	KEVOnly bool

	// MinSeverity filters out CVEs below this severity level.
	MinSeverity checks.Severity

	// Limit caps the number of returned records (0 means default 50).
	Limit int
}

// Cache manages UniBlue's local NVD JSON 2.0 + CISA KEV vulnerability cache.
type Cache struct {
	// dir is the root cache directory holding feeds/, vendors/, kev.json, and stats.json.
	dir string

	// nvdBaseURL and kevURL are overridable for offline unit tests.
	nvdBaseURL string
	kevURL     string

	// httpClient performs upstream feed downloads with generous timeouts for
	// large yearly archives.
	httpClient *http.Client
}

// NewCache opens or prepares a local CVE cache at dir.
func NewCache(dir string) *Cache {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultCacheDir()
	}
	return &Cache{
		dir:        dir,
		nvdBaseURL: defaultNVDBaseURL,
		kevURL:     defaultKEVURL,
		httpClient: &http.Client{Timeout: 2 * time.Minute},
	}
}

// Dir returns the filesystem path of the local CVE cache.
func (c *Cache) Dir() string {
	return c.dir
}

// Stats reads the summary metadata produced by the most recent Sync.
func (c *Cache) Stats() (*CacheStats, error) {
	raw, err := os.ReadFile(filepath.Join(c.dir, "stats.json"))
	if err != nil {
		return nil, err
	}
	var st CacheStats
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse cve stats: %w", err)
	}
	return &st, nil
}

// Sync downloads CISA KEV and all changed NVD JSON 2.0 yearly feeds, then
// compiles a fast vendor-sharded index under <dir>/vendors/.
func (c *Cache) Sync(ctx context.Context, opts SyncOptions) (*CacheStats, error) {
	start := time.Now()
	progress := opts.Progress
	if progress == nil {
		progress = func(string) {}
	}

	since := opts.SinceYear
	if since < firstNVDYear {
		since = firstNVDYear
	}
	endYear := opts.EndYear
	if endYear <= 0 {
		endYear = time.Now().UTC().Year()
	}

	feedsDir := filepath.Join(c.dir, "feeds")
	vendorsDir := filepath.Join(c.dir, "vendors")
	if err := os.MkdirAll(feedsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create feeds dir: %w", err)
	}
	if err := os.MkdirAll(vendorsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create vendors dir: %w", err)
	}

	prevStats, _ := c.Stats()
	prevSHAs := map[string]string{}
	if prevStats != nil && !opts.Force {
		prevSHAs = prevStats.YearSHAs
	}

	// Step 1: Fetch CISA KEV catalog (single ~1.5 MB JSON file, fast and zero rate limits).
	progress("Fetching CISA KEV catalog...")
	kevSet, err := c.fetchKEV(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch cisa kev: %w", err)
	}
	progress(fmt.Sprintf("Loaded %d CISA KEV entries.", len(kevSet)))

	// Step 2: Build the list of yearly feed keys to check and download changed
	// archives concurrently over a bounded channel worker pool.
	years := make([]string, 0, endYear-since+1)
	for y := since; y <= endYear; y++ {
		years = append(years, strconv.Itoa(y))
	}

	type feedResult struct {
		year     string
		sha      string
		filePath string
		size     int64
		changed  bool
		skipped  bool
		err      error
	}

	jobs := make(chan string)
	results := make(chan feedResult, len(years))
	done := make(chan struct{}, syncWorkers)

	for range syncWorkers {
		go func() {
			defer func() { done <- struct{}{} }()
			for year := range jobs {
				results <- c.syncYearFeed(ctx, feedsDir, year, prevSHAs[year], opts.Force)
			}
		}()
	}
	go func() {
		for range syncWorkers {
			<-done
		}
		close(results)
	}()
	go func() {
		defer close(jobs)
		for _, y := range years {
			select {
			case <-ctx.Done():
				return
			case jobs <- y:
			}
		}
	}()

	newSHAs := make(map[string]string, len(years))
	var feedFiles []string
	var rawBytes int64
	downloaded := 0
	var errs []error

	for res := range results {
		if res.err != nil {
			errs = append(errs, res.err)
			continue
		}
		if res.skipped {
			continue
		}
		newSHAs[res.year] = res.sha
		feedFiles = append(feedFiles, res.filePath)
		rawBytes += res.size
		if res.changed {
			downloaded++
			progress(fmt.Sprintf("Downloaded nvdcve-2.0-%s.json.gz (%.1f MB)", res.year, float64(res.size)/(1024*1024)))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("sync nvd feeds: %w", err)
	}
	sort.Strings(feedFiles)

	// Skip rebuilding vendor shards when nothing changed and shards already exist.
	if downloaded == 0 && !opts.Force && prevStats != nil && prevStats.VendorCount > 0 && len(prevStats.YearSHAs) == len(newSHAs) {
		progress("All NVD yearly feeds are already up to date.")
		return prevStats, nil
	}

	// Step 3: Parse all local yearly .json.gz feeds concurrently over channels
	// and merge them into vendor-sharded compressed index files.
	progress(fmt.Sprintf("Indexing %d NVD yearly feeds into vendor shards...", len(feedFiles)))
	stats, err := c.buildVendorIndex(ctx, feedFiles, vendorsDir, kevSet, newSHAs, rawBytes, start)
	if err != nil {
		return nil, err
	}

	if err := writeJSONAtomic(filepath.Join(c.dir, "stats.json"), stats); err != nil {
		return nil, err
	}
	return stats, nil
}

// syncYearFeed fetches the .meta checksum for a single NVD year and downloads
// nvdcve-2.0-<year>.json.gz only when the local copy is missing or outdated.
func (c *Cache) syncYearFeed(ctx context.Context, feedsDir, year, prevSHA string, force bool) struct {
	year     string
	sha      string
	filePath string
	size     int64
	changed  bool
	skipped  bool
	err      error
} {
	out := struct {
		year     string
		sha      string
		filePath string
		size     int64
		changed  bool
		skipped  bool
		err      error
	}{
		year:     year,
		filePath: filepath.Join(feedsDir, fmt.Sprintf("nvdcve-2.0-%s.json.gz", year)),
	}

	metaURL := fmt.Sprintf("%s/nvdcve-2.0-%s.meta", c.nvdBaseURL, year)
	sha, status, err := c.fetchMetaSHA(ctx, metaURL)
	if err != nil {
		// Gracefully skip a not-yet-published year (e.g., future clock or early Jan).
		if status == http.StatusNotFound {
			out.skipped = true
			return out
		}
		out.err = fmt.Errorf("fetch meta %s: %w", year, err)
		return out
	}
	out.sha = sha

	if !force && sha != "" && sha == prevSHA {
		if info, statErr := os.Stat(out.filePath); statErr == nil && info.Size() > 0 {
			out.size = info.Size()
			return out
		}
	}

	feedURL := fmt.Sprintf("%s/nvdcve-2.0-%s.json.gz", c.nvdBaseURL, year)
	size, err := c.downloadFile(ctx, feedURL, out.filePath)
	if err != nil {
		out.err = fmt.Errorf("download feed %s: %w", year, err)
		return out
	}
	out.size = size
	out.changed = true
	return out
}

// fetchKEV downloads CISA's KEV catalog, persists it locally, and returns a
// lookup map of all actively exploited CVE IDs.
func (c *Cache) fetchKEV(ctx context.Context) (map[string]struct{}, error) {
	kevPath := filepath.Join(c.dir, "kev.json")
	if _, err := c.downloadFile(ctx, c.kevURL, kevPath); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(kevPath)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode kev json: %w", err)
	}
	set := make(map[string]struct{}, len(payload.Vulnerabilities))
	for _, v := range payload.Vulnerabilities {
		if id := strings.ToUpper(strings.TrimSpace(v.CVEID)); id != "" {
			set[id] = struct{}{}
		}
	}
	return set, nil
}

// fetchMetaSHA downloads an NVD .meta file and extracts its sha256 line.
func (c *Cache) fetchMetaSHA(ctx context.Context, metaURL string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "UniBlue/0.2")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", resp.StatusCode, fmt.Errorf("HTTP %d from %s", resp.StatusCode, metaURL)
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 4096))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(strings.ToLower(line), "sha256:") {
			return strings.TrimSpace(line[len("sha256:"):]), resp.StatusCode, nil
		}
	}
	return "", resp.StatusCode, nil
}

// downloadFile streams url into a temporary file and atomically renames it to dst.
func (c *Cache) downloadFile(ctx context.Context, url, dst string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "UniBlue/0.2")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return 0, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		return 0, errors.Join(copyErr, closeErr)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	return n, nil
}

// buildVendorIndex parses all yearly NVD .json.gz feeds in parallel over a
// channel worker pool, groups Records by CPE vendor, and writes compact
// gzipped vendor shard files under vendorsDir.
func (c *Cache) buildVendorIndex(ctx context.Context, feedFiles []string, vendorsDir string, kevSet map[string]struct{}, yearSHAs map[string]string, rawBytes int64, started time.Time) (*CacheStats, error) {
	type parsedFeed struct {
		total    int
		withCPE  int
		byVendor map[string][]Record
		err      error
	}

	workers := syncWorkers
	if len(feedFiles) < workers && len(feedFiles) > 0 {
		workers = len(feedFiles)
	}

	jobs := make(chan string)
	results := make(chan parsedFeed, workers)
	done := make(chan struct{}, workers)

	for range workers {
		go func() {
			defer func() { done <- struct{}{} }()
			for path := range jobs {
				if ctx.Err() != nil {
					return
				}
				total, withCPE, byVendor, err := parseNVDFeed(path, kevSet)
				results <- parsedFeed{total: total, withCPE: withCPE, byVendor: byVendor, err: err}
			}
		}()
	}
	go func() {
		for range workers {
			<-done
		}
		close(results)
	}()
	go func() {
		defer close(jobs)
		for _, p := range feedFiles {
			select {
			case <-ctx.Done():
				return
			case jobs <- p:
			}
		}
	}()

	// Merge per-year vendor buckets in the single collector goroutine (zero locks).
	merged := make(map[string][]Record, 4096)
	totalCVEs := 0
	indexedCPECVEs := 0
	for pf := range results {
		if pf.err != nil {
			return nil, pf.err
		}
		totalCVEs += pf.total
		indexedCPECVEs += pf.withCPE
		for vendor, recs := range pf.byVendor {
			merged[vendor] = append(merged[vendor], recs...)
		}
	}

	// Write vendor shard files concurrently using a channel worker pool so
	// thousands of small gzipped shards flush quickly.
	type vendorJob struct {
		vendor string
		recs   []Record
	}
	type writeRes struct {
		size int64
		err  error
	}

	writeJobs := make(chan vendorJob)
	writeResults := make(chan writeRes, syncWorkers*2)
	writeDone := make(chan struct{}, syncWorkers*2)

	for range syncWorkers * 2 {
		go func() {
			defer func() { writeDone <- struct{}{} }()
			for vj := range writeJobs {
				// Sort newest/highest-severity CVEs first inside each vendor shard.
				sort.Slice(vj.recs, func(i, j int) bool {
					if vj.recs[i].KEV != vj.recs[j].KEV {
						return vj.recs[i].KEV
					}
					if vj.recs[i].Severity != vj.recs[j].Severity {
						return vj.recs[i].Severity > vj.recs[j].Severity
					}
					return vj.recs[i].ID > vj.recs[j].ID
				})
				shardPath := filepath.Join(vendorsDir, sanitizeVendor(vj.vendor)+".json.gz")
				sz, err := writeGzipJSONAtomic(shardPath, vj.recs)
				writeResults <- writeRes{size: sz, err: err}
			}
		}()
	}
	go func() {
		for range syncWorkers * 2 {
			<-writeDone
		}
		close(writeResults)
	}()
	go func() {
		defer close(writeJobs)
		for vendor, recs := range merged {
			select {
			case <-ctx.Done():
				return
			case writeJobs <- vendorJob{vendor: vendor, recs: recs}:
			}
		}
	}()

	var indexBytes int64
	for wr := range writeResults {
		if wr.err != nil {
			return nil, wr.err
		}
		indexBytes += wr.size
	}

	return &CacheStats{
		SyncedAt:       time.Now().UTC(),
		TotalCVEs:      totalCVEs,
		IndexedCPECVEs: indexedCPECVEs,
		VendorCount:    len(merged),
		KEVCount:       len(kevSet),
		RawFeedBytes:   rawBytes,
		IndexBytes:     indexBytes,
		ElapsedMS:      time.Since(started).Milliseconds(),
		YearSHAs:       yearSHAs,
	}, nil
}

// parseNVDFeed streams a single nvdcve-2.0-<year>.json.gz archive and extracts
// slim Records grouped by CPE vendor.
func parseNVDFeed(path string, kevSet map[string]struct{}) (int, int, map[string][]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, nil, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("gunzip %s: %w", path, err)
	}
	defer gz.Close()

	var feed nvdFeedFile
	if err := json.NewDecoder(gz).Decode(&feed); err != nil {
		return 0, 0, nil, fmt.Errorf("decode %s: %w", path, err)
	}

	byVendor := make(map[string][]Record, 512)
	total := 0
	withCPE := 0

	for _, item := range feed.Vulnerabilities {
		c := item.CVE
		if strings.EqualFold(c.VulnStatus, "Rejected") || c.ID == "" {
			continue
		}
		total++

		vendorMatches := extractVendorMatches(c.Configurations)
		if len(vendorMatches) == 0 {
			continue
		}
		withCPE++

		sev, score := extractCVSS(c.Metrics)
		_, isKEV := kevSet[strings.ToUpper(c.ID)]
		desc := extractEnglishDesc(c.Descriptions)

		published := c.Published
		if len(published) >= 10 {
			published = published[:10]
		}

		for vendor, matches := range vendorMatches {
			byVendor[vendor] = append(byVendor[vendor], Record{
				ID:          c.ID,
				Published:   published,
				Severity:    sev,
				CVSS:        score,
				KEV:         isKEV,
				Description: desc,
				Matches:     matches,
			})
		}
	}

	return total, withCPE, byVendor, nil
}

// LookupVendor loads all cached CVE Records for a single normalized vendor token.
// Missing vendor shards return (nil, nil) rather than an error.
func (c *Cache) LookupVendor(vendor string) ([]Record, error) {
	safe := sanitizeVendor(vendor)
	if safe == "" {
		return nil, nil
	}
	shardPath := filepath.Join(c.dir, "vendors", safe+".json.gz")
	f, err := os.Open(shardPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open vendor shard %q: %w", vendor, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gunzip vendor shard %q: %w", vendor, err)
	}
	defer gz.Close()

	var recs []Record
	if err := json.NewDecoder(gz).Decode(&recs); err != nil {
		return nil, fmt.Errorf("decode vendor shard %q: %w", vendor, err)
	}
	return recs, nil
}

// MatchProducts evaluates a slice of detected LAN/UniFi Products against the
// local vendor shards, returning deterministic Exact and Potential CVE matches.
func (c *Cache) MatchProducts(products []Product, opts MatchOptions) ([]Match, error) {
	// Load each referenced vendor shard once and reuse it across all products.
	loaded := make(map[string][]Record)
	for _, p := range products {
		for _, v := range p.Vendors {
			key := sanitizeVendor(v)
			if _, ok := loaded[key]; ok {
				continue
			}
			recs, err := c.LookupVendor(key)
			if err != nil {
				return nil, err
			}
			loaded[key] = recs
		}
	}

	var cutoffDate string
	if opts.PotentialMaxAgeYears > 0 {
		cutoffDate = time.Now().UTC().AddDate(-opts.PotentialMaxAgeYears, 0, 0).Format("2006-01-02")
	}

	var matches []Match
	seen := make(map[string]struct{})

	for _, prod := range products {
		for _, vendor := range prod.Vendors {
			recs := loaded[sanitizeVendor(vendor)]
			for _, rec := range recs {
				if !rec.KEV && rec.Severity < opts.MinSeverity {
					continue
				}
				bestConf := Confidence("")
				var bestCPE CPEMatch

				for _, cpe := range rec.Matches {
					if !matchesAnyPattern(prod.Products, cpe.Product) {
						continue
					}
					ok, conf := MatchesRange(prod.Version, cpe)
					if !ok {
						continue
					}
					// Prefer an Exact match over a Potential match if the CVE has
					// multiple CPE entries for the same product.
					if bestConf == "" || (bestConf == ConfidencePotential && conf == ConfidenceExact) {
						bestConf = conf
						bestCPE = cpe
					}
				}
				if bestConf == "" {
					continue
				}

				// For version-unknown matches, suppress ancient non-KEV CVEs so
				// operators see current risks rather than decade-old noise.
				if bestConf == ConfidencePotential && !rec.KEV && cutoffDate != "" && rec.Published != "" && rec.Published < cutoffDate {
					continue
				}

				dedupKey := fmt.Sprintf("%s|%s|%s", rec.ID, prod.HostIP, prod.Label)
				if _, dup := seen[dedupKey]; dup {
					continue
				}
				seen[dedupKey] = struct{}{}

				matches = append(matches, Match{
					Record:     rec,
					Product:    prod,
					Confidence: bestConf,
					MatchedCPE: bestCPE,
				})
			}
		}
	}

	// Sort matches so actionable items surface first: Exact before Potential,
	// KEV before non-KEV, WAN-exposed before LAN-only, then highest CVSS/newest CVE.
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Confidence != matches[j].Confidence {
			return matches[i].Confidence == ConfidenceExact
		}
		if matches[i].Record.KEV != matches[j].Record.KEV {
			return matches[i].Record.KEV
		}
		if matches[i].Product.WANExposed != matches[j].Product.WANExposed {
			return matches[i].Product.WANExposed
		}
		if matches[i].Record.Severity != matches[j].Record.Severity {
			return matches[i].Record.Severity > matches[j].Record.Severity
		}
		if matches[i].Record.CVSS != matches[j].Record.CVSS {
			return matches[i].Record.CVSS > matches[j].Record.CVSS
		}
		return matches[i].Record.ID > matches[j].Record.ID
	})
	return matches, nil
}

// LookupCVE locates a single CVE by its exact ID in the local cache.
// It first reads the corresponding yearly feed (feeds/nvdcve-2.0-<year>.json.gz)
// directly for sub-second lookup with the full untruncated description, and
// falls back to scanning vendor shards if raw feeds are unavailable.
func (c *Cache) LookupCVE(ctx context.Context, cveID string) (*Record, error) {
	want := strings.ToUpper(strings.TrimSpace(cveID))
	if want == "" {
		return nil, errors.New("cve id is required")
	}

	// Fast path: extract the 4-digit year from "CVE-YYYY-NNNN" and scan just
	// that one yearly gzipped NVD feed instead of opening 36k vendor shards.
	if parts := strings.Split(want, "-"); len(parts) == 3 && parts[0] == "CVE" && len(parts[1]) == 4 {
		feedPath := filepath.Join(c.dir, "feeds", fmt.Sprintf("nvdcve-2.0-%s.json.gz", parts[1]))
		if rec, ok, err := c.lookupCVEInFeed(feedPath, want); err == nil && ok {
			return rec, nil
		}
	}

	entries, err := os.ReadDir(filepath.Join(c.dir, "vendors"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("cve cache not initialized at %q (run `uniblue cve sync` first)", c.dir)
		}
		return nil, err
	}

	var shardNames []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json.gz") {
			shardNames = append(shardNames, strings.TrimSuffix(e.Name(), ".json.gz"))
		}
	}

	jobs := make(chan string)
	results := make(chan Record, syncWorkers*2)
	done := make(chan struct{}, syncWorkers*2)

	for range syncWorkers * 2 {
		go func() {
			defer func() { done <- struct{}{} }()
			for vendor := range jobs {
				if ctx.Err() != nil {
					return
				}
				recs, err := c.LookupVendor(vendor)
				if err != nil {
					continue
				}
				for _, r := range recs {
					if strings.EqualFold(r.ID, want) {
						results <- r
						break
					}
				}
			}
		}()
	}
	go func() {
		for range syncWorkers * 2 {
			<-done
		}
		close(results)
	}()
	go func() {
		defer close(jobs)
		for _, v := range shardNames {
			select {
			case <-ctx.Done():
				return
			case jobs <- v:
			}
		}
	}()

	var combined *Record
	for r := range results {
		if combined == nil {
			copyRec := r
			combined = &copyRec
			continue
		}
		combined.Matches = append(combined.Matches, r.Matches...)
	}
	if combined == nil {
		return nil, fmt.Errorf("%s not found in local CVE cache", want)
	}
	return combined, nil
}

// lookupCVEInFeed reads one yearly NVD .json.gz archive to locate a single CVE
// ID with its complete, untruncated English description and all CPE matches.
func (c *Cache) lookupCVEInFeed(feedPath, wantID string) (*Record, bool, error) {
	f, err := os.Open(feedPath)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, false, err
	}
	defer gz.Close()

	var feed nvdFeedFile
	if err := json.NewDecoder(gz).Decode(&feed); err != nil {
		return nil, false, err
	}

	kevSet := c.loadLocalKEVSet()

	for _, item := range feed.Vulnerabilities {
		if !strings.EqualFold(item.CVE.ID, wantID) {
			continue
		}
		sev, score := extractCVSS(item.CVE.Metrics)
		_, isKEV := kevSet[strings.ToUpper(item.CVE.ID)]

		// Keep the full untruncated English description for single-CVE inspection.
		var fullDesc string
		for _, d := range item.CVE.Descriptions {
			if strings.EqualFold(d.Lang, "en") {
				fullDesc = strings.Join(strings.Fields(d.Value), " ")
				break
			}
		}

		published := item.CVE.Published
		if len(published) >= 10 {
			published = published[:10]
		}

		vendorMatches := extractVendorMatches(item.CVE.Configurations)
		var allMatches []CPEMatch
		for _, list := range vendorMatches {
			allMatches = append(allMatches, list...)
		}
		sort.Slice(allMatches, func(i, j int) bool {
			if allMatches[i].Vendor != allMatches[j].Vendor {
				return allMatches[i].Vendor < allMatches[j].Vendor
			}
			return allMatches[i].Product < allMatches[j].Product
		})

		return &Record{
			ID:          item.CVE.ID,
			Published:   published,
			Severity:    sev,
			CVSS:        score,
			KEV:         isKEV,
			Description: fullDesc,
			Matches:     allMatches,
		}, true, nil
	}
	return nil, false, nil
}

// loadLocalKEVSet reads the cached kev.json catalog if present on disk.
func (c *Cache) loadLocalKEVSet() map[string]struct{} {
	raw, err := os.ReadFile(filepath.Join(c.dir, "kev.json"))
	if err != nil {
		return nil
	}
	var payload struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	set := make(map[string]struct{}, len(payload.Vulnerabilities))
	for _, v := range payload.Vulnerabilities {
		if id := strings.ToUpper(strings.TrimSpace(v.CVEID)); id != "" {
			set[id] = struct{}{}
		}
	}
	return set
}

// Search scans the local CVE cache offline (either one vendor shard or all
// shards concurrently via a channel worker pool) for records matching query.
func (c *Cache) Search(ctx context.Context, query string, opts SearchOptions) ([]Record, error) {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	needle := strings.ToLower(strings.TrimSpace(query))

	// Fast path: if the caller narrowed to one vendor, read only that shard and
	// enforce the same sort order and result limit as full-cache search.
	if opts.Vendor != "" {
		recs, err := c.LookupVendor(opts.Vendor)
		if err != nil {
			return nil, err
		}
		matched := filterRecords(recs, needle, opts)
		sortRecords(matched)
		if len(matched) > opts.Limit {
			matched = matched[:opts.Limit]
		}
		return matched, nil
	}

	entries, err := os.ReadDir(filepath.Join(c.dir, "vendors"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("cve cache not initialized at %q (run `uniblue cve sync` first)", c.dir)
		}
		return nil, err
	}

	var shardNames []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json.gz") {
			shardNames = append(shardNames, strings.TrimSuffix(e.Name(), ".json.gz"))
		}
	}

	jobs := make(chan string)
	results := make(chan []Record, syncWorkers*2)
	done := make(chan struct{}, syncWorkers*2)

	for range syncWorkers * 2 {
		go func() {
			defer func() { done <- struct{}{} }()
			for vendor := range jobs {
				if ctx.Err() != nil {
					return
				}
				recs, err := c.LookupVendor(vendor)
				if err != nil || len(recs) == 0 {
					continue
				}
				if matched := filterRecords(recs, needle, opts); len(matched) > 0 {
					results <- matched
				}
			}
		}()
	}
	go func() {
		for range syncWorkers * 2 {
			<-done
		}
		close(results)
	}()
	go func() {
		defer close(jobs)
		for _, v := range shardNames {
			select {
			case <-ctx.Done():
				return
			case jobs <- v:
			}
		}
	}()

	seen := make(map[string]struct{})
	var all []Record
	for batch := range results {
		for _, r := range batch {
			if _, dup := seen[r.ID]; dup {
				continue
			}
			seen[r.ID] = struct{}{}
			all = append(all, r)
		}
	}

	sortRecords(all)
	if len(all) > opts.Limit {
		all = all[:opts.Limit]
	}
	return all, nil
}

// sortRecords orders CVE records by active exploitation (KEV), severity, CVSS,
// and newest CVE ID.
func sortRecords(recs []Record) {
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].KEV != recs[j].KEV {
			return recs[i].KEV
		}
		if recs[i].Severity != recs[j].Severity {
			return recs[i].Severity > recs[j].Severity
		}
		if recs[i].CVSS != recs[j].CVSS {
			return recs[i].CVSS > recs[j].CVSS
		}
		return recs[i].ID > recs[j].ID
	})
}

// filterRecords applies SearchOptions and substring matching against a vendor shard.
func filterRecords(recs []Record, needle string, opts SearchOptions) []Record {
	var out []Record
	for _, r := range recs {
		if opts.KEVOnly && !r.KEV {
			continue
		}
		if r.Severity < opts.MinSeverity {
			continue
		}
		if needle != "" && !recordMatchesQuery(r, needle) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// recordMatchesQuery performs case-insensitive substring matching across CVE ID,
// description, and CPE vendor/product names.
func recordMatchesQuery(r Record, needle string) bool {
	if strings.Contains(strings.ToLower(r.ID), needle) {
		return true
	}
	if strings.Contains(strings.ToLower(r.Description), needle) {
		return true
	}
	for _, m := range r.Matches {
		if strings.Contains(m.Vendor, needle) || strings.Contains(m.Product, needle) {
			return true
		}
	}
	return false
}

// matchesAnyPattern checks whether cpeProduct matches any configured product
// pattern. Patterns without "*" require exact equality (preventing loose
// collisions like "nginx" matching "nginx_unit"); patterns containing "*"
// match wildcard globs (such as "*laserjet*m404*").
func matchesAnyPattern(patterns []string, cpeProduct string) bool {
	cpeProduct = strings.ToLower(strings.TrimSpace(cpeProduct))
	if cpeProduct == "" {
		return false
	}
	for _, pat := range patterns {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == "" {
			continue
		}
		if !strings.Contains(pat, "*") {
			if pat == cpeProduct {
				return true
			}
			continue
		}
		if wildcardMatch(pat, cpeProduct) {
			return true
		}
	}
	return false
}

// wildcardMatch reports whether s matches pattern where "*" matches zero or
// more arbitrary characters.
func wildcardMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		if mid == "" {
			continue
		}
		idx := strings.Index(s, mid)
		if idx < 0 {
			return false
		}
		s = s[idx+len(mid):]
	}
	return strings.HasSuffix(s, last)
}

// ParseCPE23 extracts part, vendor, product, and version from an NVD CPE 2.3
// URI string such as "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*".
func ParseCPE23(criteria string) (CPEMatch, bool) {
	parts := strings.Split(criteria, ":")
	if len(parts) < 6 || parts[0] != "cpe" || parts[1] != "2.3" {
		return CPEMatch{}, false
	}
	vendor := strings.ToLower(strings.TrimSpace(parts[3]))
	product := strings.ToLower(strings.TrimSpace(parts[4]))
	version := strings.TrimSpace(parts[5])
	if vendor == "" || vendor == "*" || product == "" || product == "*" {
		return CPEMatch{}, false
	}
	if version == "*" || version == "-" {
		version = ""
	}
	return CPEMatch{
		Part:    parts[2],
		Vendor:  vendor,
		Product: product,
		Version: version,
	}, true
}

// sanitizeVendor converts a CPE vendor token into a safe filename component.
func sanitizeVendor(vendor string) string {
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	var b strings.Builder
	b.Grow(len(vendor))
	for i := 0; i < len(vendor); i++ {
		ch := vendor[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' {
			b.WriteByte(ch)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" {
		return ""
	}
	return out
}

// writeJSONAtomic encodes v as JSON and atomically replaces path.
func writeJSONAtomic(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// writeGzipJSONAtomic encodes v as gzipped JSON and atomically replaces path,
// returning the compressed byte size on disk.
func writeGzipJSONAtomic(path string, v any) (int64, error) {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	gz := gzip.NewWriter(f)
	encErr := json.NewEncoder(gz).Encode(v)
	gzErr := gz.Close()
	closeErr := f.Close()
	if err := errors.Join(encErr, gzErr, closeErr); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	info, err := os.Stat(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	return info.Size(), nil
}

// --- NVD JSON 2.0 wire types (minimal subset needed for fast parsing) ---

type nvdFeedFile struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	VulnStatus     string          `json:"vulnStatus"`
	Descriptions   []nvdLangValue  `json:"descriptions"`
	Metrics        nvdMetrics      `json:"metrics"`
	Configurations []nvdConfigNode `json:"configurations"`
}

type nvdLangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV40 []nvdCVSSMetric `json:"cvssMetricV40"`
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdConfigNode struct {
	Nodes []struct {
		CPEMatch []struct {
			Vulnerable            bool   `json:"vulnerable"`
			Criteria              string `json:"criteria"`
			VersionStartIncluding string `json:"versionStartIncluding"`
			VersionStartExcluding string `json:"versionStartExcluding"`
			VersionEndIncluding   string `json:"versionEndIncluding"`
			VersionEndExcluding   string `json:"versionEndExcluding"`
		} `json:"cpeMatch"`
	} `json:"nodes"`
}

// extractVendorMatches collects all vulnerable CPE 2.3 entries in a CVE grouped
// by their normalized vendor token.
func extractVendorMatches(configs []nvdConfigNode) map[string][]CPEMatch {
	out := make(map[string][]CPEMatch)
	for _, cfg := range configs {
		for _, node := range cfg.Nodes {
			for _, cm := range node.CPEMatch {
				if !cm.Vulnerable {
					continue
				}
				parsed, ok := ParseCPE23(cm.Criteria)
				if !ok {
					continue
				}
				parsed.StartIncl = cm.VersionStartIncluding
				parsed.StartExcl = cm.VersionStartExcluding
				parsed.EndIncl = cm.VersionEndIncluding
				parsed.EndExcl = cm.VersionEndExcluding
				out[parsed.Vendor] = append(out[parsed.Vendor], parsed)
			}
		}
	}
	return out
}

// extractCVSS selects the highest-precedence CVSS score and severity (v4.0 ->
// v3.1 -> v3.0 -> v2.0).
func extractCVSS(m nvdMetrics) (checks.Severity, float64) {
	groups := [][]nvdCVSSMetric{m.CVSSMetricV40, m.CVSSMetricV31, m.CVSSMetricV30, m.CVSSMetricV2}
	for _, grp := range groups {
		if len(grp) == 0 {
			continue
		}
		first := grp[0]
		score := first.CVSSData.BaseScore
		sevStr := first.CVSSData.BaseSeverity
		if sevStr == "" {
			sevStr = first.BaseSeverity
		}
		if sev, err := checks.ParseSeverity(sevStr); err == nil {
			return sev, score
		}
		return severityFromScore(score), score
	}
	return checks.SeverityInfo, 0
}

// severityFromScore maps a numeric CVSS score onto UniBlue's Severity scale
// when the upstream metric omits a textual baseSeverity.
func severityFromScore(score float64) checks.Severity {
	switch {
	case score >= 9.0:
		return checks.SeverityCritical
	case score >= 7.0:
		return checks.SeverityHigh
	case score >= 4.0:
		return checks.SeverityMedium
	case score > 0:
		return checks.SeverityLow
	default:
		return checks.SeverityInfo
	}
}

// extractEnglishDesc returns a compact single-line English CVE description.
func extractEnglishDesc(descs []nvdLangValue) string {
	for _, d := range descs {
		if strings.EqualFold(d.Lang, "en") {
			clean := strings.Join(strings.Fields(d.Value), " ")
			if len(clean) > maxDescriptionLen {
				return clean[:maxDescriptionLen-3] + "..."
			}
			return clean
		}
	}
	return ""
}
