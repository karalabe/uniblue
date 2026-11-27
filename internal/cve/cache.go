// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
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

// Stats reads the summary metadata for the local vendor index.
func (c *Cache) Stats() (*CacheStats, error) {
	st, err := c.readStats()
	if err != nil {
		return nil, err
	}
	// The metadata can survive the loss of the shards used for matching.
	vendors := filepath.Join(c.dir, "vendors")
	info, err := os.Stat(vendors)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("CVE vendor index %q is not a directory", vendors)
	}
	if st.VendorCount > 0 && !hasVendorShards(vendors) {
		return nil, fmt.Errorf("cve cache vendor shards missing (%d expected)", st.VendorCount)
	}
	return st, nil
}

// hasVendorShards checks that at least one regular shard remains available for matching.
func hasVendorShards(vendorsDir string) bool {
	entries, err := os.ReadDir(vendorsDir)
	return err == nil && slices.ContainsFunc(entries, func(e os.DirEntry) bool {
		return e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".json.gz")
	})
}

// readStats lets Sync reuse verified feed metadata when the vendor index needs rebuilding.
func (c *Cache) readStats() (*CacheStats, error) {
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

	endYear := opts.EndYear
	if endYear == 0 {
		endYear = time.Now().UTC().Year()
	} else if endYear < firstNVDYear {
		return nil, fmt.Errorf("invalid end year %d: must be >= %d", endYear, firstNVDYear)
	}

	since := opts.SinceYear
	if since == 0 {
		since = firstNVDYear
	}
	if since < firstNVDYear || since > endYear {
		return nil, fmt.Errorf("invalid since year %d: must be between %d and %d", since, firstNVDYear, endYear)
	}

	feedsDir := filepath.Join(c.dir, "feeds")
	vendorsDir := filepath.Join(c.dir, "vendors")
	if err := os.MkdirAll(feedsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create feeds dir: %w", err)
	}
	if err := os.MkdirAll(vendorsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create vendors dir: %w", err)
	}

	unlock, err := acquireCacheLock(ctx, filepath.Join(c.dir, ".sync.lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Remove any leftover temporary spill directories or partial temp files
	// from an earlier interrupted/OOM-killed sync while holding the sync lock.
	cleanupStaleSyncArtifacts(c.dir, feedsDir, vendorsDir)

	prevStats, _ := c.readStats()
	prevSHAs := map[string]string{}
	prevMeta := map[string]FeedFileMeta{}
	if prevStats != nil {
		prevSHAs = prevStats.YearSHAs
		prevMeta = prevStats.YearMeta
	}

	// A schema upgrade recompiles the local snapshot. The next regular sync
	// resumes upstream freshness checks, including KEV-only changes.
	migrating := prevStats != nil && prevStats.SchemaVersion != CurrentIndexSchemaVersion && !opts.Force
	kevPath := filepath.Join(c.dir, "kev.json")
	var kevSet map[string]kevEntry
	var kevSHA string
	if migrating {
		kevSet, kevSHA, err = readKEV(kevPath)
	}
	if !migrating || err != nil {
		progress("Fetching CISA KEV catalog...")
		kevSet, kevSHA, err = c.fetchKEV(ctx, kevPath)
		if err != nil {
			return nil, fmt.Errorf("fetch cisa kev: %w", err)
		}
	}
	progress(fmt.Sprintf("Loaded %d CISA KEV entries.", len(kevSet)))

	// Step 2: Build the list of yearly feed keys to check and download changed
	// archives concurrently over a bounded channel worker pool.
	years := make([]string, 0, endYear-since+1)
	for y := since; y <= endYear; y++ {
		years = append(years, strconv.Itoa(y))
	}

	jobs := make(chan string)
	results := make(chan feedResult, len(years))
	done := make(chan struct{}, syncWorkers)

	for range syncWorkers {
		go func() {
			defer func() { done <- struct{}{} }()
			for year := range jobs {
				results <- c.syncYearFeed(ctx, feedsDir, year, prevSHAs[year], prevMeta[year], opts.Force, migrating)
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
	newMeta := make(map[string]FeedFileMeta, len(years))
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
		if res.meta.Size > 0 {
			newMeta[res.year] = res.meta
		}
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Strings(feedFiles)

	// Skip rebuilding vendor shards only when both NVD feeds and the CISA KEV
	// catalog match the last successful build of the current schema.
	if downloaded == 0 && !opts.Force && !migrating && prevStats != nil &&
		prevStats.KEVSHA != "" && prevStats.KEVSHA == kevSHA &&
		equalFeedSHAs(prevStats.YearSHAs, newSHAs) && (prevStats.VendorCount == 0 || hasVendorShards(vendorsDir)) {
		if len(prevStats.YearMeta) == 0 && len(newMeta) > 0 {
			updated := *prevStats
			updated.YearMeta = newMeta
			_ = writeJSONAtomic(filepath.Join(c.dir, "stats.json"), &updated)
			return &updated, nil
		}
		progress("All NVD yearly feeds and CISA KEV catalog are already up to date.")
		return prevStats, nil
	}

	// Step 3: Stream all local yearly .json.gz feeds into hash-partitioned spill
	// buckets and compile vendor-sharded compressed index files.
	progress(fmt.Sprintf("Indexing %d NVD yearly feeds into vendor shards...", len(feedFiles)))
	stats, err := c.buildVendorIndex(ctx, feedFiles, vendorsDir, kevSet, kevSHA, newSHAs, rawBytes, start)
	if err != nil {
		return nil, err
	}
	stats.YearMeta = newMeta
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := writeJSONAtomic(filepath.Join(c.dir, "stats.json"), stats); err != nil {
		return nil, err
	}
	return stats, nil
}

// equalFeedSHAs compares feed digests regardless of the case used by the NVD meta file.
func equalFeedSHAs(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || !strings.EqualFold(bv, v) {
			return false
		}
	}
	return true
}

type feedResult struct {
	year     string
	sha      string
	filePath string
	size     int64
	meta     FeedFileMeta
	changed  bool
	skipped  bool
	err      error
}

// syncYearFeed reuses verified archives during migration. Regular refreshes
// also check the upstream checksum before deciding whether to download.
func (c *Cache) syncYearFeed(ctx context.Context, feedsDir, year, prevSHA string, prevMeta FeedFileMeta, force, migrating bool) feedResult {
	out := feedResult{year: year, filePath: filepath.Join(feedsDir, fmt.Sprintf("nvdcve-2.0-%s.json.gz", year))}
	if migrating && out.reuseArchive(prevSHA, prevSHA, prevMeta) {
		return out
	}

	metaURL := fmt.Sprintf("%s/nvdcve-2.0-%s.meta", c.nvdBaseURL, year)
	sha, status, err := c.fetchMetaSHA(ctx, metaURL)
	if err != nil {
		// Gracefully skip a not-yet-published current/future year ONLY when it
		// has never been synced before (prevSHA == ""). Once a year has been
		// synced, a 404 is treated as a transient error so existing CVEs are
		// never silently dropped from the cache.
		if status == http.StatusNotFound && prevSHA == "" {
			if yNum, parseErr := strconv.Atoi(year); parseErr == nil && yNum >= time.Now().UTC().Year() {
				out.skipped = true
				return out
			}
		}
		out.err = fmt.Errorf("fetch meta %s: %w", year, err)
		return out
	}
	out.sha = sha

	if !force && out.reuseArchive(sha, prevSHA, prevMeta) {
		return out
	}

	feedURL := fmt.Sprintf("%s/nvdcve-2.0-%s.json.gz", c.nvdBaseURL, year)
	size, err := c.downloadFeedFile(ctx, feedURL, out.filePath, sha)
	if err != nil {
		out.err = fmt.Errorf("download feed %s: %w", year, err)
		return out
	}
	out.size = size
	if info, statErr := os.Stat(out.filePath); statErr == nil {
		out.meta = FeedFileMeta{Size: info.Size(), ModTimeUnixNano: info.ModTime().UnixNano()}
	}
	out.changed = true
	return out
}

// reuseArchive checks file metadata or verifies the uncompressed checksum
// before reusing an archive. Older caches may lack either piece of metadata.
func (r *feedResult) reuseArchive(sha, prevSHA string, prev FeedFileMeta) bool {
	info, err := os.Stat(r.filePath)
	if err != nil || info.Size() == 0 {
		return false
	}
	meta := FeedFileMeta{Size: info.Size(), ModTimeUnixNano: info.ModTime().UnixNano()}
	if sha == "" || !strings.EqualFold(sha, prevSHA) || prev != meta {
		digest, err := feedDigest(r.filePath, sha)
		if err != nil {
			return false
		}
		if sha == "" {
			sha = digest
		}
	}
	r.sha, r.meta, r.size = sha, meta, meta.Size
	return true
}

// kevEntry retains CISA's product identity even when NVD has no matching CPE.
type kevEntry struct {
	// CVEID joins the catalog entry to NVD records.
	CVEID string `json:"cveID"`
	// Vendor names the project or vendor in CISA terminology.
	Vendor string `json:"vendorProject"`
	// Product is CISA's product name for exact offline queries.
	Product string `json:"product"`
	// DateAdded records when CISA first listed the CVE.
	DateAdded string `json:"dateAdded"`
	// Ransomware retains CISA's distinction between known and unknown campaign use.
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

// parseKEV validates the catalog before it can replace a previously usable copy.
func parseKEV(raw []byte) (map[string]kevEntry, string, error) {
	var payload struct {
		Vulnerabilities []kevEntry `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, "", err
	}
	if payload.Vulnerabilities == nil {
		return nil, "", errors.New("missing KEV vulnerabilities array")
	}
	set := make(map[string]kevEntry, len(payload.Vulnerabilities))
	for _, entry := range payload.Vulnerabilities {
		if id := strings.ToUpper(strings.TrimSpace(entry.CVEID)); id != "" {
			set[id] = entry
		}
	}
	return set, fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

// readKEV shares the same catalog validation between migration and offline queries.
func readKEV(path string) (map[string]kevEntry, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	return parseKEV(raw)
}

// fetchKEV publishes the catalog only after its entries decode successfully.
func (c *Cache) fetchKEV(ctx context.Context, dst string) (map[string]kevEntry, string, error) {
	url := c.kevURL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "UniBlue/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, "", err
	}
	set, sha, err := parseKEV(raw)
	if err != nil {
		return nil, "", fmt.Errorf("invalid kev json payload: %w", err)
	}
	// A freshness check with the same catalog leaves the cached file untouched.
	if local, err := os.ReadFile(dst); err == nil && bytes.Equal(local, raw) {
		return set, sha, nil
	}
	if err := writeBytesAtomic(dst, raw, 0o644); err != nil {
		return nil, "", err
	}
	return set, sha, nil
}

// fetchMetaSHA downloads an NVD .meta file and extracts its required sha256 line.
func (c *Cache) fetchMetaSHA(ctx context.Context, metaURL string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "UniBlue/1.0")

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
			sha := strings.TrimSpace(line[len("sha256:"):])
			if sha != "" {
				return sha, resp.StatusCode, nil
			}
		}
	}
	return "", resp.StatusCode, fmt.Errorf("missing sha256 line in %s", metaURL)
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// verifyFeedGzipFile validates that path is a readable gzipped JSON object and,
// when expectedSHA is a 64-character hex SHA256 digest, verifies the
// uncompressed JSON payload matches expectedSHA.
func verifyFeedGzipFile(path, expectedSHA string) error {
	_, err := feedDigest(path, expectedSHA)
	return err
}

// feedDigest also supplies the checksum for legacy snapshots without a stored SHA.
func feedDigest(path, expectedSHA string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("invalid gzip header: %w", err)
	}
	defer gz.Close()

	var firstByte [1]byte
	h := sha256.New()
	var buf [32 * 1024]byte
	foundNonSpace := false
	for {
		n, readErr := gz.Read(buf[:])
		if n > 0 {
			chunk := buf[:n]
			if !foundNonSpace {
				trimmed := bytes.TrimLeft(chunk, " \t\r\n")
				if len(trimmed) > 0 {
					firstByte[0] = trimmed[0]
					foundNonSpace = true
				}
			}
			_, _ = h.Write(chunk)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("corrupt gzip stream: %w", readErr)
		}
	}
	if !foundNonSpace || firstByte[0] != '{' {
		return "", errors.New("feed payload is not a JSON object")
	}
	got := hex.EncodeToString(h.Sum(nil))
	if isHexSHA256(expectedSHA) && !strings.EqualFold(got, expectedSHA) {
		return "", fmt.Errorf("feed sha256 mismatch: got %s, want %s", got, expectedSHA)
	}
	return got, nil
}

// downloadFeedFile streams url into a unique temporary file, validates its gzip
// integrity and SHA256 checksum, and atomically replaces dst only when valid.
func (c *Cache) downloadFeedFile(ctx context.Context, url, dst, expectedSHA string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "UniBlue/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return 0, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(dst), ".uniblue-cve-sync-"+filepath.Base(dst)+".*.tmp")
	if err != nil {
		return 0, err
	}
	tmp := tmpFile.Name()
	n, copyErr := io.Copy(tmpFile, resp.Body)
	closeErr := tmpFile.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(tmp)
		return 0, errors.Join(copyErr, closeErr)
	}
	if err := verifyFeedGzipFile(tmp, expectedSHA); err != nil {
		_ = os.Remove(tmp)
		return 0, fmt.Errorf("validate downloaded feed %s: %w", url, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	return n, nil
}

// cleanupStaleSyncArtifacts removes UniBlue-owned temporary spill directories
// and partial staging files left behind by an earlier interrupted or OOM-killed
// sync while leaving unrelated operator files in the cache directory untouched.
func cleanupStaleSyncArtifacts(cacheDir, feedsDir, vendorsDir string) {
	for _, dir := range []string{cacheDir, feedsDir, vendorsDir} {
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			name := entry.Name()
			path := filepath.Join(dir, name)
			if dir == cacheDir && entry.IsDir() && strings.HasPrefix(name, ".uniblue-index-") {
				_ = os.RemoveAll(path)
				continue
			}
			// Older builds used a generic ".index-" directory prefix; only
			// remove recognized spill bucket regular files and the now-empty
			// directory rather than recursively deleting unknown contents.
			if dir == cacheDir && entry.IsDir() && strings.HasPrefix(name, ".index-") {
				children, _ := os.ReadDir(path)
				removed := false
				for _, child := range children {
					if match, _ := filepath.Match("bucket-[0-9][0-9].ndjson", child.Name()); match && child.Type().IsRegular() {
						if os.Remove(filepath.Join(path, child.Name())) == nil {
							removed = true
						}
					}
				}
				if removed {
					_ = os.Remove(path)
				}
				continue
			}
			legacyFeed, _ := filepath.Match("nvdcve-2.0-[0-9][0-9][0-9][0-9].json.gz.*.tmp", name)
			if !entry.IsDir() && ((strings.HasPrefix(name, ".uniblue-cve-sync-") && strings.HasSuffix(name, ".tmp")) || (dir == feedsDir && legacyFeed)) {
				_ = os.Remove(path)
			}
		}
	}
}

// buildVendorIndex streams all yearly NVD .json.gz feeds one CVE at a time into
// hash-partitioned temporary spill buckets on disk, then compiles each bucket
// into compact gzipped vendor shard files under vendorsDir. Partitioning by
// sanitized shard key across 64 buckets avoids vendor filename collisions and
// keeps working memory bounded on the full 400k+ NVD dataset.
func (c *Cache) buildVendorIndex(ctx context.Context, feedFiles []string, vendorsDir string, kevSet map[string]kevEntry, kevSHA string, yearSHAs map[string]string, rawBytes int64, started time.Time) (*CacheStats, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	const numBuckets = 64
	tmpDir, err := os.MkdirTemp(c.dir, ".uniblue-index-*")
	if err != nil {
		return nil, fmt.Errorf("create temp index dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	type spillBucket struct {
		path string
		file *os.File
		buf  *bufio.Writer
		enc  *json.Encoder
	}
	type spillEntry struct {
		Shard  string `json:"s"`
		Record Record `json:"r"`
	}

	buckets := make([]*spillBucket, numBuckets)
	closeBuckets := func() {
		for _, b := range buckets {
			if b != nil {
				if b.buf != nil {
					_ = b.buf.Flush()
				}
				if b.file != nil {
					_ = b.file.Close()
				}
				b.file = nil
				b.buf = nil
			}
		}
	}
	defer closeBuckets()

	for i := range buckets {
		bp := filepath.Join(tmpDir, fmt.Sprintf("bucket-%02d.ndjson", i))
		f, err := os.Create(bp)
		if err != nil {
			return nil, fmt.Errorf("create spill bucket: %w", err)
		}
		bw := bufio.NewWriterSize(f, 32*1024)
		buckets[i] = &spillBucket{
			path: bp,
			file: f,
			buf:  bw,
			enc:  json.NewEncoder(bw),
		}
	}

	shardBucket := func(shardKey string) int {
		h := fnv.New32a()
		_, _ = h.Write([]byte(shardKey))
		return int(h.Sum32() % numBuckets)
	}

	// Pass 1: Stream each yearly feed one CVE record at a time into spill buckets
	// keyed by sanitized vendor shard name so colliding vendor tokens merge cleanly.
	totalCVEs := 0
	indexedCPECVEs := 0
	coverage := make(map[string]YearCoverageStats)
	for _, path := range feedFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		total, withCPE, err := streamNVDFeed(ctx, path, kevSet, coverage, func(vendor string, rec Record) error {
			shardKey := sanitizeVendor(vendor)
			if shardKey == "" {
				return nil
			}
			b := buckets[shardBucket(shardKey)]
			return b.enc.Encode(spillEntry{Shard: shardKey, Record: rec})
		})
		if err != nil {
			return nil, err
		}
		totalCVEs += total
		indexedCPECVEs += withCPE
	}
	for _, b := range buckets {
		if err := b.buf.Flush(); err != nil {
			return nil, err
		}
		if err := b.file.Close(); err != nil {
			return nil, err
		}
		b.file = nil
		b.buf = nil
	}

	// Pass 2: Load one bucket at a time, group/dedup/sort by sanitized shard key,
	// and atomically write each vendor's compressed shard file.
	built := make(map[string]bool)
	var indexBytes int64
	for _, b := range buckets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, err := os.Open(b.path)
		if err != nil {
			return nil, err
		}
		byShard := make(map[string]map[string]Record, 128)
		bucketRecs := 0
		dec := json.NewDecoder(bufio.NewReaderSize(f, 64*1024))
		for {
			var se spillEntry
			err := dec.Decode(&se)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("decode spill bucket: %w", err)
			}
			bucketRecs++
			recMap := byShard[se.Shard]
			if recMap == nil {
				recMap = make(map[string]Record, 4)
				byShard[se.Shard] = recMap
			}
			if prev, dup := recMap[se.Record.ID]; dup {
				// Merge CPE match entries when distinct raw vendor spellings map to
				// the same sanitized shard file for the same CVE.
				prev.Matches = append(prev.Matches, se.Record.Matches...)
				prev.NeedsContext = prev.NeedsContext || se.Record.NeedsContext
				if se.Record.KEV {
					prev.KEV = true
				}
				if se.Record.CVSS > prev.CVSS {
					prev.CVSS = se.Record.CVSS
				}
				if se.Record.Severity > prev.Severity {
					prev.Severity = se.Record.Severity
				}
				recMap[se.Record.ID] = prev
			} else {
				recMap[se.Record.ID] = se.Record
			}
		}
		_ = f.Close()
		_ = os.Remove(b.path)

		if len(byShard) == 0 {
			continue
		}
		for shard := range byShard {
			built[shard] = true
		}

		type vendorJob struct {
			shard string
			recs  []Record
		}
		type writeRes struct {
			size int64
			err  error
		}

		writeCtx, cancelWrite := context.WithCancel(ctx)
		writeWorkers := 2
		if len(byShard) < writeWorkers {
			writeWorkers = len(byShard)
		}
		writeJobs := make(chan vendorJob, writeWorkers)
		writeResults := make(chan writeRes, writeWorkers)

		var writeWG sync.WaitGroup
		for range writeWorkers {
			writeWG.Add(1)
			go func() {
				defer writeWG.Done()
				for vj := range writeJobs {
					if writeCtx.Err() != nil {
						return
					}
					sort.Slice(vj.recs, func(i, j int) bool {
						if vj.recs[i].KEV != vj.recs[j].KEV {
							return vj.recs[i].KEV
						}
						if vj.recs[i].Severity != vj.recs[j].Severity {
							return vj.recs[i].Severity > vj.recs[j].Severity
						}
						return vj.recs[i].ID > vj.recs[j].ID
					})
					shardPath := filepath.Join(vendorsDir, vj.shard+".json.gz")
					sz, err := writeGzipJSONAtomic(shardPath, vj.recs)
					select {
					case writeResults <- writeRes{size: sz, err: err}:
					case <-writeCtx.Done():
						return
					}
				}
			}()
		}
		writeProdDone := make(chan struct{})
		go func() {
			defer close(writeProdDone)
			defer close(writeJobs)
			for shard, recMap := range byShard {
				recs := make([]Record, 0, len(recMap))
				for _, r := range recMap {
					recs = append(recs, r)
				}
				delete(byShard, shard)
				select {
				case <-writeCtx.Done():
					return
				case writeJobs <- vendorJob{shard: shard, recs: recs}:
				}
			}
		}()
		go func() {
			writeWG.Wait()
			<-writeProdDone
			close(writeResults)
		}()

		var writeErr error
		for wr := range writeResults {
			if wr.err != nil {
				if writeErr == nil {
					writeErr = wr.err
					cancelWrite()
				}
				continue
			}
			indexBytes += wr.size
		}
		cancelWrite()
		byShard = nil
		if bucketRecs > 500 {
			runtime.GC()
		}
		if writeErr != nil {
			return nil, writeErr
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	// A vendor can lose its last vulnerable CPE. Remove obsolete generated
	// shards so a successful rebuild cannot serve records from the old index.
	entries, err := os.ReadDir(vendorsDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		shard, ok := strings.CutSuffix(e.Name(), ".json.gz")
		if ok && e.Type().IsRegular() && !built[shard] && shard != "" && sanitizeVendor(shard) == shard {
			if err := os.Remove(filepath.Join(vendorsDir, e.Name())); err != nil {
				return nil, err
			}
		}
	}
	return &CacheStats{
		SchemaVersion:  CurrentIndexSchemaVersion,
		YearCoverage:   coverage,
		SyncedAt:       time.Now().UTC(),
		TotalCVEs:      totalCVEs,
		IndexedCPECVEs: indexedCPECVEs,
		VendorCount:    len(built),
		KEVCount:       len(kevSet),
		KEVSHA:         kevSHA,
		RawFeedBytes:   rawBytes,
		IndexBytes:     indexBytes,
		ElapsedMS:      time.Since(started).Milliseconds(),
		YearSHAs:       yearSHAs,
	}, nil
}

// streamNVDFeed streams a single nvdcve-2.0-<year>.json.gz archive one
// vulnerability item at a time without materializing the whole feed in RAM.
func streamNVDFeed(ctx context.Context, path string, kevSet map[string]kevEntry, coverage map[string]YearCoverageStats, emit func(vendor string, rec Record) error) (int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, 0, fmt.Errorf("gunzip %s: %w", path, err)
	}
	defer gz.Close()

	dec := json.NewDecoder(bufio.NewReaderSize(gz, 64*1024))
	tok, err := dec.Token()
	if err != nil {
		return 0, 0, fmt.Errorf("decode %s: %w", path, err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return 0, 0, fmt.Errorf("decode %s: expected JSON object", path)
	}

	total := 0
	withCPE := 0
	foundVulns := false

	for dec.More() {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		keyTok, err := dec.Token()
		if err != nil {
			return 0, 0, fmt.Errorf("decode %s key: %w", path, err)
		}
		key, _ := keyTok.(string)
		if key != "vulnerabilities" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return 0, 0, fmt.Errorf("decode %s skip %q: %w", path, key, err)
			}
			continue
		}
		foundVulns = true
		arrTok, err := dec.Token()
		if err != nil {
			return 0, 0, fmt.Errorf("decode %s vulnerabilities: %w", path, err)
		}
		if delim, ok := arrTok.(json.Delim); !ok || delim != '[' {
			return 0, 0, fmt.Errorf("decode %s vulnerabilities: expected array", path)
		}
		for dec.More() {
			if err := ctx.Err(); err != nil {
				return 0, 0, err
			}
			var item struct {
				CVE nvdCVE `json:"cve"`
			}
			if err := dec.Decode(&item); err != nil {
				return 0, 0, fmt.Errorf("decode %s item: %w", path, err)
			}
			c := item.CVE
			if strings.EqualFold(c.VulnStatus, "Rejected") || c.ID == "" {
				continue
			}
			total++

			vendorMatches := extractVendorMatches(c.Configurations)
			if len(c.Published) >= 10 {
				year := c.Published[:4]
				count := coverage[year]
				count.Total++
				if len(vendorMatches) > 0 {
					count.WithCPE++
				}
				coverage[year] = count
			}
			if len(vendorMatches) == 0 {
				continue
			}
			withCPE++
			rec := c.record(kevSet)
			if len(rec.Description) > maxDescriptionLen {
				rec.Description = rec.Description[:maxDescriptionLen-3] + "..."
			}
			for vendor, matches := range vendorMatches {
				rec.Matches = matches
				rec.NeedsContext = slices.ContainsFunc(matches, func(m CPEMatch) bool { return m.NeedsContext })
				if err := emit(vendor, rec); err != nil {
					return 0, 0, err
				}
			}
		}
		// Consume closing ']'.
		if _, err := dec.Token(); err != nil {
			return 0, 0, fmt.Errorf("decode %s close array: %w", path, err)
		}
	}
	if !foundVulns {
		return 0, 0, fmt.Errorf("decode %s: missing vulnerabilities array", path)
	}
	return total, withCPE, nil
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
// local vendor shards and retains the evidence for each match.
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
	seenIdx := make(map[string]int)
	exactByHostLabelCVE := make(map[string]struct{})

	for _, prod := range products {
		hostKey := productHostKey(prod)
		labelKey := strings.ToLower(strings.TrimSpace(prod.Label))
		verKey := strings.ToLower(strings.TrimSpace(prod.Version))
		for _, vendor := range prod.Vendors {
			recs := loaded[sanitizeVendor(vendor)]
			for _, rec := range recs {
				if !rec.KEV && rec.Severity < opts.MinSeverity {
					continue
				}
				bestConf := Confidence("")
				var bestCPE CPEMatch

				for _, cpe := range rec.Matches {
					if !strings.EqualFold(vendor, cpe.Vendor) || !matchesAnyPattern(prod.Products, cpe.Product) {
						continue
					}
					ok, conf := matchesRange(prod.Version, cpe, prod.Source == "unifi-firmware" || isUniFiFirmwareCPE(cpe))
					if !ok {
						continue
					}
					// Downgrade exact upstream range hits when the CVE requires
					// unobserved OS/application context or when distro backports
					// obscure patch status, never promoting potential matches.
					if cpe.NeedsContext && conf == ConfidenceExact {
						conf = ConfidencePotential
					} else if prod.VersionAmbiguous && conf == ConfidenceExact {
						conf = ConfidenceVersionAmbiguous
					}
					if conf.rank() > bestConf.rank() {
						bestConf = conf
						bestCPE = cpe
					}
				}
				if bestConf == "" {
					continue
				}

				// For potential matches, suppress ancient non-KEV CVEs so
				// operators see current risks rather than decade-old noise.
				if bestConf == ConfidencePotential && !rec.KEV && cutoffDate != "" && rec.Published != "" && rec.Published < cutoffDate {
					continue
				}

				// Deduplicate by (host, product label, product version, CVE ID)
				// so shared CVEs across distinct products or versions on one host
				// each retain their KEV flag and upgrade advice, while duplicate
				// vendor-alias hits for the same product and version collapse.
				cveID := strings.ToUpper(strings.TrimSpace(rec.ID))
				dedupKey := fmt.Sprintf("%s|%s|%s|%s", hostKey, labelKey, verKey, cveID)
				if bestConf == ConfidenceExact && verKey != "" {
					exactByHostLabelCVE[fmt.Sprintf("%s|%s|%s", hostKey, labelKey, cveID)] = struct{}{}
				}
				candidate := Match{
					Record:     rec,
					Product:    prod,
					Confidence: bestConf,
					MatchedCPE: bestCPE,
				}
				if idx, exists := seenIdx[dedupKey]; exists {
					if bestConf.rank() > matches[idx].Confidence.rank() {
						matches[idx] = candidate
					}
					continue
				}
				seenIdx[dedupKey] = len(matches)
				matches = append(matches, candidate)
			}
		}
	}

	// Suppress versionless Potential hits when a concrete versioned product with
	// the same host and label already matched the same CVE with Exact confidence.
	if len(exactByHostLabelCVE) > 0 {
		filtered := matches[:0]
		for _, m := range matches {
			if m.Confidence == ConfidencePotential && len(m.Product.Ports) == 0 && strings.TrimSpace(m.Product.Version) == "" {
				k := fmt.Sprintf("%s|%s|%s",
					productHostKey(m.Product),
					strings.ToLower(strings.TrimSpace(m.Product.Label)),
					strings.ToUpper(strings.TrimSpace(m.Record.ID)),
				)
				if _, covered := exactByHostLabelCVE[k]; covered {
					continue
				}
			}
			filtered = append(filtered, m)
		}
		matches = filtered
	}

	// Sort matches so actionable items surface first: Exact before Potential,
	// KEV before non-KEV, WAN-exposed before LAN-only, then highest CVSS/newest CVE.
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Confidence != matches[j].Confidence {
			return matches[i].Confidence.rank() > matches[j].Confidence.rank()
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
		combined.NeedsContext = combined.NeedsContext || r.NeedsContext
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

	kevSet, _, err := readKEV(filepath.Join(c.dir, "kev.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}

	for _, item := range feed.Vulnerabilities {
		if !strings.EqualFold(item.CVE.ID, wantID) {
			continue
		}
		rec := item.CVE.record(kevSet)
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

		rec.Matches = allMatches
		rec.NeedsContext = slices.ContainsFunc(allMatches, func(m CPEMatch) bool { return m.NeedsContext })
		return &rec, true, nil
	}
	return nil, false, nil
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
// URI string such as "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*", folding any
// non-wildcard update component (parts[6]) into Version (e.g., "8.5:p1" ->
// "8.5p1", "2.0:rc1" -> "2.0-rc1").
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
	if version != "" && len(parts) > 6 {
		version = joinCPEVersionUpdate(version, parts[6])
	}
	return CPEMatch{
		Part:    parts[2],
		Vendor:  vendor,
		Product: product,
		Version: version,
	}, true
}

// joinCPEVersionUpdate folds a non-wildcard CPE 2.3 update field (parts[6])
// into a concrete version string (e.g., "8.5"+"p1" -> "8.5p1", "2.0"+"rc1" ->
// "2.0-rc1", "1.1"+"1" -> "1.1-1").
func joinCPEVersionUpdate(version, update string) string {
	version = strings.TrimSpace(version)
	update = strings.TrimSpace(update)
	if version == "" || update == "" || update == "*" || update == "-" {
		return version
	}
	lower := strings.ToLower(update)
	if hasUpdateSuffix(strings.ToLower(version), lower) {
		return version
	}
	if isDirectCPEUpdate(lower) {
		return version + update
	}
	return version + "-" + update
}

// hasUpdateSuffix reports whether lowerVer already terminates with a
// non-numeric update token (such as "p1" in "8.5p1" or "rc1" in "2.0-rc1")
// separated from the preceding version characters by a non-letter boundary.
// Numeric update tokens (such as "1" on "1.1" or "0" on "2.0") are never
// skipped so distinct patch updates are preserved.
func hasUpdateSuffix(lowerVer, lowerUpdate string) bool {
	if len(lowerUpdate) == 0 || !strings.HasSuffix(lowerVer, lowerUpdate) {
		return false
	}
	if lowerUpdate[0] >= '0' && lowerUpdate[0] <= '9' {
		return false
	}
	prefixLen := len(lowerVer) - len(lowerUpdate)
	if prefixLen == 0 {
		return false
	}
	prev := lowerVer[prefixLen-1]
	return !(prev >= 'a' && prev <= 'z')
}

// isDirectCPEUpdate reports whether a CPE update token attaches directly to the
// base version without a hyphen (OpenSSH patch levels like "p1" or single-letter
// releases like "a").
func isDirectCPEUpdate(update string) bool {
	if len(update) == 1 && update[0] >= 'a' && update[0] <= 'z' {
		return true
	}
	if len(update) >= 2 && update[0] == 'p' {
		for i := 1; i < len(update); i++ {
			if update[i] < '0' || update[i] > '9' {
				return false
			}
		}
		return true
	}
	return false
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

func writeBytesAtomic(path string, raw []byte, mode os.FileMode) error {
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".uniblue-cve-sync-"+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := tmpFile.Name()
	if err := tmpFile.Chmod(mode); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := tmpFile.Write(raw); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// writeJSONAtomic encodes v as JSON and atomically replaces path using a unique temp file.
func writeJSONAtomic(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeBytesAtomic(path, raw, 0o644)
}

// writeGzipJSONAtomic encodes v as gzipped JSON and atomically replaces path
// using a unique temp file, returning the compressed byte size on disk.
func writeGzipJSONAtomic(path string, v any) (int64, error) {
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".uniblue-cve-sync-"+filepath.Base(path)+".*.tmp")
	if err != nil {
		return 0, err
	}
	tmp := tmpFile.Name()
	gz := gzip.NewWriter(tmpFile)
	encErr := json.NewEncoder(gz).Encode(v)
	gzErr := gz.Close()
	closeErr := tmpFile.Close()
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
	ID           string         `json:"id"`
	Published    string         `json:"published"`
	VulnStatus   string         `json:"vulnStatus"`
	Descriptions []nvdLangValue `json:"descriptions"`
	Metrics      nvdMetrics     `json:"metrics"`
	// Weaknesses holds the CWE assessments from NVD and assigning authorities.
	Weaknesses []struct {
		// Description contains the identifiers and any placeholders for missing analysis.
		Description []nvdLangValue `json:"description"`
	} `json:"weaknesses"`
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
	// UserInteractionRequired is optional in CVSS v2 assessments.
	UserInteractionRequired *bool `json:"userInteractionRequired"`
	CVSSData                struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		// Vector is the serialized set of metric values underlying BaseScore.
		Vector string `json:"vectorString"`
	} `json:"cvssData"`
}

type nvdConfigNode struct {
	// Operator determines whether sibling applicability requirements must hold together.
	Operator string `json:"operator"`
	// Nodes contains the alternatives or prerequisites of this configuration.
	Nodes    []nvdConfigNode `json:"nodes"`
	CPEMatch []struct {
		Vulnerable            bool   `json:"vulnerable"`
		Criteria              string `json:"criteria"`
		VersionStartIncluding string `json:"versionStartIncluding"`
		VersionStartExcluding string `json:"versionStartExcluding"`
		VersionEndIncluding   string `json:"versionEndIncluding"`
		VersionEndExcluding   string `json:"versionEndExcluding"`
	} `json:"cpeMatch"`
}

// hasPlatform reports whether this branch contains a non-hardware environmental
// prerequisite (such as a specific OS or companion app). Hardware nodes (part
// "h") pair firmware with its own appliance model and do not require separate OS
// context.
func (n nvdConfigNode) hasPlatform() bool {
	for _, m := range n.CPEMatch {
		if !m.Vulnerable {
			crit := strings.ToLower(strings.TrimSpace(m.Criteria))
			if crit != "" && !strings.HasPrefix(crit, "cpe:2.3:h:") {
				return true
			}
		}
	}
	return slices.ContainsFunc(n.Nodes, nvdConfigNode.hasPlatform)
}

// collectMatches carries AND prerequisites down to the affected ranges, keeping
// independent alternatives in the same advisory eligible for exact matching.
func (n nvdConfigNode) collectMatches(out map[string][]CPEMatch, needsContext bool) {
	needsContext = needsContext || (strings.EqualFold(n.Operator, "AND") && n.hasPlatform())
	for _, cm := range n.CPEMatch {
		if !cm.Vulnerable {
			continue
		}
		m, ok := ParseCPE23(cm.Criteria)
		if !ok {
			continue
		}
		m.StartIncl, m.StartExcl = cm.VersionStartIncluding, cm.VersionStartExcluding
		m.EndIncl, m.EndExcl = cm.VersionEndIncluding, cm.VersionEndExcluding
		m.NeedsContext = needsContext
		out[m.Vendor] = append(out[m.Vendor], m)
	}
	for _, child := range n.Nodes {
		child.collectMatches(out, needsContext)
	}
}

// extractVendorMatches groups vulnerable ranges for indexing and offline lookup.
func extractVendorMatches(configs []nvdConfigNode) map[string][]CPEMatch {
	out := make(map[string][]CPEMatch)
	for _, cfg := range configs {
		cfg.collectMatches(out, false)
	}
	return out
}

// record uses the same selected metric and catalog entry for shard and feed lookups.
func (c nvdCVE) record(kev map[string]kevEntry) Record {
	entry, listed := kev[strings.ToUpper(c.ID)]
	rec := Record{ID: c.ID, Published: c.Published[:min(10, len(c.Published))],
		KEV: listed, KEVDateAdded: entry.DateAdded, KEVRansomware: entry.Ransomware == "Known"}
	for _, d := range c.Descriptions {
		if strings.EqualFold(d.Lang, "en") {
			rec.Description = strings.Join(strings.Fields(d.Value), " ")
			break
		}
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") && !slices.Contains(rec.CWEs, d.Value) {
				rec.CWEs = append(rec.CWEs, d.Value)
			}
		}
	}
	for _, group := range [][]nvdCVSSMetric{c.Metrics.CVSSMetricV40, c.Metrics.CVSSMetricV31, c.Metrics.CVSSMetricV30, c.Metrics.CVSSMetricV2} {
		if len(group) > 0 {
			group[0].apply(&rec)
			break
		}
	}
	return rec
}

// apply keeps the compact metrics tied to the same vector as the score. CVSS v2
// has no PR metric, but NVD can supply user interaction separately.
func (m nvdCVSSMetric) apply(rec *Record) {
	data := m.CVSSData
	rec.CVSS, rec.CVSSVector = data.BaseScore, data.Vector
	sev, err := checks.ParseSeverity(cmp.Or(data.BaseSeverity, m.BaseSeverity))
	if err != nil {
		sev = severityFromScore(rec.CVSS)
	}
	rec.Severity = sev
	for part := range strings.SplitSeq(strings.Trim(data.Vector, "()"), "/") {
		key, val, _ := strings.Cut(part, ":")
		switch key {
		case "AV":
			rec.AttackVector = val
		case "PR":
			rec.PrivilegesRequired = val
		case "UI":
			rec.UserInteraction = val
		}
	}
	if rec.UserInteraction == "" && m.UserInteractionRequired != nil {
		rec.UserInteraction = "N"
		if *m.UserInteractionRequired {
			rec.UserInteraction = "R"
		}
	}
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
