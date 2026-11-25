// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cve manages a local vendor-sharded cache of the full NVD JSON 2.0
// vulnerability database enriched with CISA's Known Exploited Vulnerabilities
// (KEV) catalog, plus deterministic device-to-CVE matching and offline search.
package cve

import (
	"time"

	"github.com/karalabe/uniblue/internal/checks"
)

// Confidence distinguishes CVEs confirmed against an observed version string
// from broader product-level matches where the device did not reveal a version.
type Confidence string

const (
	// ConfidenceExact indicates the device's observed version falls inside a
	// CVE's vulnerable CPE version range.
	ConfidenceExact Confidence = "exact"

	// ConfidencePotential indicates the vendor and product matched, but no
	// version string could be observed on the device to confirm or rule it out.
	ConfidencePotential Confidence = "potential"
)

// Record is the slimmed, indexed representation of a single NVD CVE stored in
// UniBlue's local vendor-sharded cache.
type Record struct {
	// ID is the canonical CVE identifier (e.g., "CVE-2024-3094").
	ID string `json:"id"`

	// Published records when the CVE was originally published by NVD.
	Published string `json:"published,omitempty"`

	// Severity is the normalized CVSS severity bucket.
	Severity checks.Severity `json:"severity"`

	// CVSS holds the highest available numeric CVSS base score (v4.0, v3.1, v3.0, or v2.0).
	CVSS float64 `json:"cvss,omitempty"`

	// KEV reports whether this CVE appears in CISA's Known Exploited
	// Vulnerabilities catalog (actively exploited in the wild).
	KEV bool `json:"kev,omitempty"`

	// Description holds a concise English summary of the vulnerability.
	Description string `json:"description,omitempty"`

	// Matches lists the parsed vulnerable CPE 2.3 product/version ranges for
	// this vendor shard.
	Matches []CPEMatch `json:"matches,omitempty"`
}

// CPEMatch represents one vulnerable CPE 2.3 criteria node extracted from NVD.
type CPEMatch struct {
	// Part is the CPE component type: "a" (application), "o" (OS), or "h" (hardware).
	Part string `json:"part,omitempty"`

	// Vendor is the normalized lowercase CPE vendor token (e.g., "ui", "f5", "openbsd").
	Vendor string `json:"vendor"`

	// Product is the normalized lowercase CPE product token (e.g., "unifi_os", "nginx").
	Product string `json:"product"`

	// Version is an exact vulnerable version when not "*" or "-".
	Version string `json:"version,omitempty"`

	// StartIncl / StartExcl bound the lower end of a vulnerable version range.
	StartIncl string `json:"start_incl,omitempty"`
	StartExcl string `json:"start_excl,omitempty"`

	// EndIncl / EndExcl bound the upper end of a vulnerable version range.
	EndIncl string `json:"end_incl,omitempty"`
	EndExcl string `json:"end_excl,omitempty"`
}

// FeedFileMeta records the size and modification timestamp of a verified local
// yearly NVD feed archive so unchanged hourly refreshes can skip re-hashing
// the full uncompressed payload.
type FeedFileMeta struct {
	Size            int64 `json:"size"`
	ModTimeUnixNano int64 `json:"mtime_ns"`
}

// CacheStats records disk footprint, counts, and per-year NVD SHA256 hashes so
// incremental syncs only re-download feeds that actually changed upstream.
type CacheStats struct {
	// SyncedAt records when the last full or incremental sync completed.
	SyncedAt time.Time `json:"synced_at"`

	// TotalCVEs is the total number of non-rejected CVEs indexed across all years.
	TotalCVEs int `json:"total_cves"`

	// IndexedCPECVEs counts how many CVEs had at least one vulnerable CPE entry
	// and were placed into vendor shards.
	IndexedCPECVEs int `json:"indexed_cpe_cves"`

	// VendorCount is the number of distinct vendor shards on disk.
	VendorCount int `json:"vendor_count"`

	// KEVCount is the number of entries in the cached CISA KEV catalog.
	KEVCount int `json:"kev_count"`

	// KEVSHA records the SHA256 digest of the cached CISA KEV catalog so
	// newly KEV-listed CVEs trigger a vendor shard rebuild even when NVD
	// yearly feed SHAs have not changed.
	KEVSHA string `json:"kev_sha,omitempty"`

	// RawFeedBytes is the total compressed size of downloaded NVD .json.gz feeds.
	RawFeedBytes int64 `json:"raw_feed_bytes"`

	// IndexBytes is the total compressed size of all compiled vendor shard files.
	IndexBytes int64 `json:"index_bytes"`

	// ElapsedMS records how long the sync took in milliseconds.
	ElapsedMS int64 `json:"elapsed_ms"`

	// YearSHAs maps each NVD feed key (e.g., "2025", "modified") to its last
	// synced .meta SHA256 checksum.
	YearSHAs map[string]string `json:"year_shas"`

	// YearMeta maps each NVD feed key to the verified local file's size and
	// modification time so unchanged hourly refreshes avoid re-gunzipping all
	// yearly archives on disk.
	YearMeta map[string]FeedFileMeta `json:"year_meta,omitempty"`
}

// Product describes a software service or hardware appliance identified on a
// specific LAN host or UniFi infrastructure device.
type Product struct {
	// Label is a readable display name (e.g., "OpenSSH", "UniFi UDM Pro").
	Label string `json:"label"`

	// Vendors lists one or more candidate NVD CPE vendor shards to query (for
	// example, "ui", or both "f5" and "nginx").
	Vendors []string `json:"vendors"`

	// Products lists one or more CPE product patterns to match. Patterns without
	// "*" require exact equality; patterns containing "*" perform glob matching
	// (e.g., "*laserjet*m404*").
	Products []string `json:"products"`

	// Version is the exact observed version string when available, or empty when
	// only the product identity is known.
	Version string `json:"version,omitempty"`

	// Source notes which passive signal identified the product (e.g., "unifi-firmware",
	// "ssh-banner", "http-server", "hostname").
	Source string `json:"source"`

	// HostName, HostIP, and VLAN identify which network endpoint runs this product.
	HostName   string `json:"host_name"`
	HostIP     string `json:"host_ip"`
	VLAN       string `json:"vlan,omitempty"`
	WANExposed bool   `json:"wan_exposed,omitempty"`
}

// MatchOptions controls filtering when matching detected Products against the
// local CVE cache.
type MatchOptions struct {
	// MinSeverity filters out non-KEV CVEs below this severity threshold.
	MinSeverity checks.Severity

	// PotentialMaxAgeYears restricts version-unknown (Potential) non-KEV matches
	// to CVEs published within the last N years so ancient vulnerabilities do not
	// drown out current risks. Zero disables the age cutoff. Exact-version
	// matches and CISA KEV entries are never hidden by this cutoff.
	PotentialMaxAgeYears int
}

// Match links a cached CVE Record to a specific detected Product on the user's network.
type Match struct {
	// Record is the matching CVE from the local cache.
	Record Record `json:"record"`

	// Product is the fingerprinted host/software that matched.
	Product Product `json:"product"`

	// Confidence records whether an exact version matched or only the product name.
	Confidence Confidence `json:"confidence"`

	// MatchedCPE records the specific CPE vendor/product/range that triggered.
	MatchedCPE CPEMatch `json:"matched_cpe"`
}
