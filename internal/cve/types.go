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

// Confidence describes how precisely the available evidence establishes CVE applicability.
type Confidence string

const (
	// ConfidenceExact indicates the device's observed version falls inside a
	// CVE's vulnerable CPE version range.
	ConfidenceExact Confidence = "exact"

	// ConfidenceVersionAmbiguous means the upstream version matches, but a
	// distribution may already have backported the fix to its package.
	ConfidenceVersionAmbiguous Confidence = "version-ambiguous"

	// ConfidencePotential indicates the vendor and product matched, but the
	// version or platform evidence is insufficient to establish applicability.
	ConfidencePotential Confidence = "potential"
)

// rank orders matches for display and selects the strongest applicable CPE.
func (c Confidence) rank() int {
	switch c {
	case ConfidenceExact:
		return 3
	case ConfidenceVersionAmbiguous:
		return 2
	case ConfidencePotential:
		return 1
	default:
		return 0
	}
}

// Record is the slimmed, indexed representation of a single NVD CVE stored in
// UniBlue's local vendor-sharded cache.
type Record struct {
	// ID is the canonical CVE identifier (e.g., "CVE-2024-3094").
	ID string `json:"id"`

	// Published records when the CVE was originally published by NVD.
	Published string `json:"published,omitempty"`

	// Severity is the normalized CVSS severity bucket.
	Severity checks.Severity `json:"severity"`

	// CVSS holds the base score from the newest available CVSS metric version.
	CVSS float64 `json:"cvss,omitempty"`

	// CVSSVector is the vector associated with the selected base score.
	CVSSVector string `json:"cvss_vector,omitempty"`
	// AttackVector is the compact AV metric from that vector.
	AttackVector string `json:"av,omitempty"`
	// PrivilegesRequired is the compact PR metric when the metric defines it.
	PrivilegesRequired string `json:"pr,omitempty"`
	// UserInteraction is the compact UI metric when the source supplies it.
	UserInteraction string `json:"ui,omitempty"`
	// CWEs lists the distinct weakness identifiers assigned to this CVE.
	CWEs []string `json:"cwes,omitempty"`

	// KEV reports whether this CVE appears in CISA's Known Exploited
	// Vulnerabilities catalog (actively exploited in the wild).
	KEV bool `json:"kev,omitempty"`
	// KEVDateAdded is the date CISA added this CVE to its catalog.
	KEVDateAdded string `json:"kev_date_added,omitempty"`
	// KEVRansomware reports known use in ransomware campaigns according to CISA.
	KEVRansomware bool `json:"kev_ransomware,omitempty"`

	// NeedsContext reports whether any indexed range has a platform prerequisite.
	NeedsContext bool `json:"needs_context,omitempty"`

	// Description holds a concise English summary of the vulnerability.
	Description string `json:"description,omitempty"`

	// Matches lists the parsed vulnerable CPE 2.3 product/version ranges for
	// this vendor shard.
	Matches []CPEMatch `json:"matches,omitempty"`
}

// CPEMatch represents one vulnerable CPE 2.3 criteria node extracted from NVD.
type CPEMatch struct {
	// NeedsContext indicates that this range requires additional platform evidence.
	NeedsContext bool `json:"needs_context,omitempty"`

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

// CurrentIndexSchemaVersion identifies the format compiled from the cached feeds.
const CurrentIndexSchemaVersion = 2

// YearCoverageStats measures NVD enrichment for a publication year.
type YearCoverageStats struct {
	// Total counts published, non-rejected CVEs.
	Total int `json:"total"`
	// WithCPE counts CVEs with at least one indexable vulnerable product.
	WithCPE int `json:"with_cpe"`
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
	// SchemaVersion identifies the format of the compiled vendor shards.
	SchemaVersion int `json:"schema_version,omitempty"`
	// YearCoverage groups CPE enrichment counts by publication year.
	YearCoverage map[string]YearCoverageStats `json:"year_coverage,omitempty"`

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

// EndpointPort identifies the service endpoint that supplied a fingerprint.
type EndpointPort struct {
	// Transport is the lowercase layer 4 protocol.
	Transport string `json:"transport"`
	// Port is the internal service port number.
	Port int `json:"port"`
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

	// Ports lists observed service endpoints. Host inventory has no port binding.
	Ports []EndpointPort `json:"ports,omitempty"`
	// VersionAmbiguous indicates that distribution packaging obscures patch status.
	VersionAmbiguous bool `json:"version_ambiguous,omitempty"`
	// HighConfidence reports whether the product identity came from controller
	// inventory or a protocol-level fingerprint rather than a generic banner.
	HighConfidence bool `json:"high_confidence,omitempty"`

	// Source notes which passive signal identified the product (e.g., "unifi-firmware",
	// "ssh-banner", "http-server", "hostname").
	Source string `json:"source"`

	// HostName is the display name of the host running this product.
	HostName string `json:"host_name"`
	// HostIP is the address associated with the observation.
	HostIP string `json:"host_ip"`
	// VLAN identifies the host's network.
	VLAN string `json:"vlan,omitempty"`
	// WANExposed indicates that a forward reaches a bound endpoint or an unbound host.
	WANExposed bool `json:"wan_exposed,omitempty"`
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

	// Confidence records the strength of the version and platform evidence.
	Confidence Confidence `json:"confidence"`

	// MatchedCPE records the specific CPE vendor/product/range that triggered.
	MatchedCPE CPEMatch `json:"matched_cpe"`
}
