// Package oui manages a compact local cache of the official IEEE MAC address
// registries (MA-L 24-bit, MA-M 28-bit, MA-S 36-bit, and legacy IAB) for
// deterministic offline hardware vendor resolution.
package oui

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
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
)

const (
	// defaultUserAgent identifies UniBlue politely to the IEEE registry servers.
	defaultUserAgent = "UniBlue-OUI-Sync/0.1"

	// compiledFilename stores the deduplicated, gzipped prefix->vendor table.
	compiledFilename = "ieee-oui.tsv.gz"

	// metaFilename records sync timestamps and prefix counts.
	metaFilename = "meta.json"
)

// registrySource describes one official IEEE CSV registry endpoint and its
// expected assignment prefix length in hex nibbles.
type registrySource struct {
	Name    string
	URL     string
	Nibbles int
}

// defaultSources lists the four official public IEEE MAC assignment registries,
// covering 24-bit (MA-L), 28-bit (MA-M), and 36-bit (MA-S / IAB) vendor blocks.
var defaultSources = []registrySource{
	{Name: "MA-L", URL: "https://standards-oui.ieee.org/oui/oui.csv", Nibbles: 6},
	{Name: "MA-M", URL: "https://standards-oui.ieee.org/oui28/mam.csv", Nibbles: 7},
	{Name: "MA-S", URL: "https://standards-oui.ieee.org/oui36/oui36.csv", Nibbles: 9},
	{Name: "IAB", URL: "https://standards-oui.ieee.org/iab/iab.csv", Nibbles: 9},
}

// builtinVirtualOUIs maps well-known virtualization and container MAC prefixes
// directly so hypervisor guests are identified even without a synced IEEE cache.
var builtinVirtualOUIs = map[string]string{
	"525400": "QEMU/KVM",
	"005056": "VMware",
	"000c29": "VMware",
	"000569": "VMware",
	"001c14": "VMware",
	"00163e": "Xen",
	"00155d": "Microsoft Hyper-V",
	"080027": "Oracle VirtualBox",
	"bc2411": "Proxmox VE",
	"0242ac": "Docker",
}

// Meta records summary metadata for a synced local IEEE OUI database.
type Meta struct {
	// UpdatedAt records when the local OUI table was last compiled.
	UpdatedAt time.Time `json:"updated_at"`

	// TotalEntries is the total number of indexed MAC prefixes across all registries.
	TotalEntries int `json:"total_entries"`

	// MALCount is the number of 24-bit (MA-L) vendor blocks.
	MALCount int `json:"mal_count"`

	// MAMCount is the number of 28-bit (MA-M) vendor blocks.
	MAMCount int `json:"mam_count"`

	// MASCount is the number of 36-bit (MA-S + IAB) vendor blocks.
	MASCount int `json:"mas_count"`

	// CompiledBytes is the size on disk of the compressed lookup table.
	CompiledBytes int64 `json:"compiled_bytes"`
}

// Result captures the deterministic resolution of a single MAC address.
type Result struct {
	// Vendor is the resolved hardware manufacturer or hypervisor name.
	Vendor string `json:"vendor,omitempty"`

	// Prefix is the matched uppercase hex prefix (6, 7, or 9 nibbles).
	Prefix string `json:"prefix,omitempty"`

	// Registry notes which table matched ("MA-S", "MA-M", "MA-L", "virtual", or "local").
	Registry string `json:"registry,omitempty"`

	// IsVirtual is true when the MAC belongs to a known hypervisor/container prefix.
	IsVirtual bool `json:"is_virtual,omitempty"`

	// IsLocallyAdministered is true when the IEEE U/L bit (bit 1 of byte 0) is set,
	// indicating either a randomized private Wi-Fi MAC or a synthetic VM/container MAC.
	IsLocallyAdministered bool `json:"is_locally_administered,omitempty"`
}

// DB holds an in-memory longest-prefix lookup table loaded from the local IEEE
// OUI cache (or an empty table falling back to built-in virtualization prefixes).
type DB struct {
	// dir is the cache directory storing ieee-oui.tsv.gz and meta.json.
	dir string

	// prefixes maps lowercase hex prefixes (6, 7, or 9 nibbles) to vendor names.
	prefixes map[string]string

	// sources allows unit tests to override the IEEE HTTP endpoints.
	sources []registrySource

	// httpClient is used during Sync.
	httpClient *http.Client
}

// DefaultCacheDir returns the OS-appropriate user cache directory for UniBlue's
// local IEEE OUI table (~/.cache/uniblue/oui on Linux, ~/Library/Caches/uniblue/oui on macOS).
func DefaultCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "uniblue", "oui")
}

// New constructs a DB handle bound to cacheDir (defaulting to DefaultCacheDir).
// Call Load to read an existing cache into memory, or Sync to download/refresh it.
func New(cacheDir string) *DB {
	if strings.TrimSpace(cacheDir) == "" {
		cacheDir = DefaultCacheDir()
	}
	return &DB{
		dir:      cacheDir,
		prefixes: make(map[string]string),
		sources:  defaultSources,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Dir returns the cache directory used by this DB.
func (d *DB) Dir() string {
	return d.dir
}

// Load reads the compiled local IEEE OUI table into memory. If the cache has
// not been synced yet, it returns nil so Lookup still functions with built-in
// virtualization prefixes and locally-administered bit detection.
func (d *DB) Load() error {
	path := filepath.Join(d.dir, compiledFilename)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open oui db %q: %w", path, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("decompress oui db: %w", err)
	}
	defer gz.Close()

	table := make(map[string]string, 64000)
	scanner := bufio.NewScanner(gz)
	for scanner.Scan() {
		line := scanner.Text()
		pfx, vendor, ok := strings.Cut(line, "\t")
		if ok && pfx != "" && vendor != "" {
			table[pfx] = vendor
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read oui db: %w", err)
	}
	d.prefixes = table
	return nil
}

// Stats reads metadata for the synced OUI database, returning os.ErrNotExist if
// `uniblue oui sync` has not been run yet.
func (d *DB) Stats() (*Meta, error) {
	raw, err := os.ReadFile(filepath.Join(d.dir, metaFilename))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Sync downloads all official IEEE OUI CSV registries concurrently, compiles
// them into a compact gzipped lookup table, persists it atomically, and loads
// it into memory.
func (d *DB) Sync(ctx context.Context, progress func(string)) (*Meta, error) {
	if err := os.MkdirAll(d.dir, 0o755); err != nil {
		return nil, fmt.Errorf("create oui cache dir: %w", err)
	}

	type fetchRes struct {
		src     registrySource
		entries map[string]string
		err     error
	}

	ch := make(chan fetchRes, len(d.sources))
	for _, src := range d.sources {
		go func(s registrySource) {
			if progress != nil {
				progress(fmt.Sprintf("fetching IEEE %s (%s)...", s.Name, s.URL))
			}
			entries, err := d.fetchCSV(ctx, s)
			ch <- fetchRes{src: s, entries: entries, err: err}
		}(src)
	}

	merged := make(map[string]string, 64000)
	meta := &Meta{UpdatedAt: time.Now().UTC()}
	var errs []error
	for range d.sources {
		res := <-ch
		if res.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", res.src.Name, res.err))
			continue
		}
		for k, v := range res.entries {
			merged[k] = v
		}
		switch res.src.Nibbles {
		case 6:
			meta.MALCount += len(res.entries)
		case 7:
			meta.MAMCount += len(res.entries)
		case 9:
			meta.MASCount += len(res.entries)
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("sync ieee oui registries: %w", errors.Join(errs...))
	}

	// Write compiled table sorted deterministically for reproducible gzip output.
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	outPath := filepath.Join(d.dir, compiledFilename)
	tmpPath := outPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("create temp oui db: %w", err)
	}
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	bw := bufio.NewWriter(gz)
	for _, k := range keys {
		_, _ = bw.WriteString(k)
		_ = bw.WriteByte('\t')
		_, _ = bw.WriteString(merged[k])
		_ = bw.WriteByte('\n')
	}
	if err := bw.Flush(); err != nil {
		_ = gz.Close()
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := gz.Close(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("commit oui db: %w", err)
	}

	if fi, err := os.Stat(outPath); err == nil {
		meta.CompiledBytes = fi.Size()
	}
	meta.TotalEntries = len(merged)

	metaRaw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(d.dir, metaFilename), metaRaw, 0o644); err != nil {
		return nil, fmt.Errorf("write oui metadata: %w", err)
	}

	d.prefixes = merged
	return meta, nil
}

// fetchCSV downloads and parses a single IEEE OUI CSV registry into a map of
// lowercase hex prefix -> trimmed organization name.
func (d *DB) fetchCSV(ctx context.Context, src registrySource) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, src.URL)
	}

	reader := csv.NewReader(resp.Body)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	// Skip CSV header row ("Registry,Assignment,Organization Name,Organization Address").
	if _, err := reader.Read(); err != nil {
		return nil, fmt.Errorf("read csv header: %w", err)
	}

	out := make(map[string]string)
	for {
		rec, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(rec) < 3 {
			continue
		}
		assignment := normalizeHex(rec[1])
		org := cleanOrgName(rec[2])
		if len(assignment) < src.Nibbles || org == "" {
			continue
		}
		// Avoid letting generic IEEE shared-block placeholders overwrite specific sub-blocks.
		pfx := assignment[:src.Nibbles]
		if _, exists := out[pfx]; !exists || !isIEEEPlaceholder(org) {
			out[pfx] = org
		}
	}
	return out, nil
}

// Lookup resolves a MAC address using longest-prefix matching across 36-bit
// (MA-S/IAB), 28-bit (MA-M), 24-bit (MA-L), and built-in virtualization OUIs,
// while also checking the IEEE locally-administered address bit.
func (d *DB) Lookup(mac string) Result {
	hexMAC := normalizeHex(mac)
	if len(hexMAC) < 6 {
		return Result{}
	}

	res := Result{
		IsLocallyAdministered: isLocallyAdministered(hexMAC),
	}

	// Check built-in virtualization prefixes first (e.g., QEMU 52:54:00, Proxmox bc:24:11),
	// since some hypervisor prefixes have the locally-administered bit set.
	if v, ok := builtinVirtualOUIs[hexMAC[:6]]; ok {
		res.Vendor = v
		res.Prefix = strings.ToUpper(hexMAC[:6])
		res.Registry = "virtual"
		res.IsVirtual = true
		return res
	}

	// Longest-prefix match against synced IEEE registries: 36-bit -> 28-bit -> 24-bit.
	if d != nil && len(d.prefixes) > 0 {
		if len(hexMAC) >= 9 {
			if v, ok := d.prefixes[hexMAC[:9]]; ok && !isIEEEPlaceholder(v) {
				res.Vendor = v
				res.Prefix = strings.ToUpper(hexMAC[:9])
				res.Registry = "MA-S"
				return res
			}
		}
		if len(hexMAC) >= 7 {
			if v, ok := d.prefixes[hexMAC[:7]]; ok && !isIEEEPlaceholder(v) {
				res.Vendor = v
				res.Prefix = strings.ToUpper(hexMAC[:7])
				res.Registry = "MA-M"
				return res
			}
		}
		if v, ok := d.prefixes[hexMAC[:6]]; ok && !isIEEEPlaceholder(v) {
			res.Vendor = v
			res.Prefix = strings.ToUpper(hexMAC[:6])
			res.Registry = "MA-L"
			return res
		}
	}

	if res.IsLocallyAdministered {
		res.Registry = "local"
	}
	return res
}

// normalizeHex strips MAC delimiters (":", "-", ".") and lowercases the hex string.
func normalizeHex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		case c >= 'a' && c <= 'f':
			b.WriteByte(c)
		case c >= 'A' && c <= 'F':
			b.WriteByte(c + ('a' - 'A'))
		}
	}
	return b.String()
}

// isLocallyAdministered reports whether bit 1 (0x02) of the first MAC octet is set.
func isLocallyAdministered(hexMAC string) bool {
	if len(hexMAC) < 2 {
		return false
	}
	v, err := strconv.ParseUint(hexMAC[:2], 16, 8)
	if err != nil {
		return false
	}
	return (v & 0x02) != 0
}

// cleanOrgName normalizes whitespace in IEEE CSV organization names.
func cleanOrgName(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

// isIEEEPlaceholder identifies shared MA-M/MA-S parent entries in MA-L that
// defer vendor ownership to a more specific 28-bit or 36-bit registry block.
func isIEEEPlaceholder(org string) bool {
	lower := strings.ToLower(org)
	return strings.Contains(lower, "ieee registration authority") || lower == "private"
}
