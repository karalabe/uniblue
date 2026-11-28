// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve

import (
	"fmt"
	"sort"

	"github.com/karalabe/uniblue/internal/checks"
)

// ProductSummary groups CVEs for one host, product, version and confidence.
// Client-only advisories have a separate summary because they require different evidence.
type ProductSummary struct {
	// Product identifies the host, VLAN, software name, and observed version.
	Product Product `json:"product"`

	// Confidence describes the evidence for the grouped CVE matches.
	Confidence Confidence `json:"confidence"`

	// NeedsContext reports whether a match requires platform or component verification.
	NeedsContext bool `json:"needs_context,omitempty"`

	// ClientOnly reports whether the advisories concern SSH client tools on a host running sshd.
	ClientOnly bool `json:"client_only,omitempty"`

	// TotalCVEs is the total number of matching CVEs in this rollup.
	TotalCVEs int `json:"total_cves"`

	// CriticalCount is the number of Critical-severity CVEs in this rollup.
	CriticalCount int `json:"critical_count"`
	// HighCount is the number of High-severity CVEs in this rollup.
	HighCount int `json:"high_count"`
	// KEVCount is the number of CISA KEV-listed CVEs in this rollup.
	KEVCount int `json:"kev_count"`

	// MaxSeverity is the highest severity observed across CVEs in this rollup.
	MaxSeverity checks.Severity `json:"max_severity"`
	// MaxCVSS is the highest CVSS base score observed across CVEs in this rollup.
	MaxCVSS float64 `json:"max_cvss"`

	// TopCVEs lists up to 3 highest-priority CVE IDs for quick `uniblue cve show` inspection.
	TopCVEs []string `json:"top_cves"`

	// MinFixedVersion records the highest exclusive upper bound (versionEndExcluding)
	// observed across matching CVEs when it strictly exceeds every matched inclusive
	// upper bound (e.g., "7.3.0" -> operator should verify >= 7.3.0). It is left
	// empty if a matched EndIncl bound is at or above it so callers never suggest
	// upgrading to a still-vulnerable version.
	MinFixedVersion string `json:"min_fixed_version,omitempty"`

	// MaxAffectedVersion records the highest inclusive upper bound
	// (versionEndIncluding or exact vulnerable version) when it is at or above
	// any matched EndExcl bound, indicating the operator must upgrade strictly
	// past this version (> X).
	MaxAffectedVersion string `json:"max_affected_version,omitempty"`
}

// RollupMatches deterministically collapses a slice of granular CVE Matches
// into ProductSummaries sorted by urgency.
// Callers should pre-sort matches by priority (as MatchProducts does) because
// TopCVEs retains the first three CVE IDs encountered in each group.
func RollupMatches(matches []Match) []ProductSummary {
	if len(matches) == 0 {
		return nil
	}

	type groupKey struct {
		hostIP     string
		label      string
		ver        string
		conf       Confidence
		clientOnly bool
	}
	type groupState struct {
		summary *ProductSummary
		maxExcl string
		maxIncl string
	}

	order := make([]groupKey, 0)
	groups := make(map[groupKey]*groupState)

	for _, m := range matches {
		k := groupKey{
			hostIP:     m.Product.HostIP,
			label:      m.Product.Label,
			ver:        m.Product.Version,
			conf:       m.Confidence,
			clientOnly: m.ClientOnly,
		}
		st, exists := groups[k]
		if !exists {
			st = &groupState{
				summary: &ProductSummary{
					Product:    m.Product,
					Confidence: m.Confidence,
					ClientOnly: m.ClientOnly,
				},
			}
			groups[k] = st
			order = append(order, k)
		}
		sum := st.summary

		sum.TotalCVEs++
		sum.NeedsContext = sum.NeedsContext || m.MatchedCPE.NeedsContext || m.ClientOnly
		if m.Record.KEV {
			sum.KEVCount++
		}
		switch m.Record.Severity {
		case checks.SeverityCritical:
			sum.CriticalCount++
		case checks.SeverityHigh:
			sum.HighCount++
		}
		if m.Record.Severity > sum.MaxSeverity {
			sum.MaxSeverity = m.Record.Severity
		}
		if m.Record.CVSS > sum.MaxCVSS {
			sum.MaxCVSS = m.Record.CVSS
		}
		if len(sum.TopCVEs) < 3 {
			sum.TopCVEs = append(sum.TopCVEs, m.Record.ID)
		}

		// A listener cannot establish the installed client version or account for backported fixes.
		if sum.ClientOnly || sum.Confidence == ConfidenceVersionAmbiguous || sum.Product.VersionAmbiguous {
			continue
		}
		// Track both exclusive (EndExcl) and inclusive (EndIncl / exact Version)
		// upper bounds so upgrade advice never recommends a still-vulnerable version.
		if fix := m.MatchedCPE.EndExcl; fix != "" {
			if st.maxExcl == "" || CompareVersions(fix, st.maxExcl) > 0 {
				st.maxExcl = fix
			}
		}
		incl := m.MatchedCPE.EndIncl
		if incl == "" && m.MatchedCPE.Version != "" && m.MatchedCPE.Version != "*" && m.MatchedCPE.Version != "-" {
			incl = m.MatchedCPE.Version
		}
		if incl != "" {
			if st.maxIncl == "" || CompareVersions(incl, st.maxIncl) > 0 {
				st.maxIncl = incl
			}
		}
	}

	out := make([]ProductSummary, 0, len(order))
	for _, k := range order {
		st := groups[k]
		if st.maxExcl != "" && (st.maxIncl == "" || CompareVersions(st.maxExcl, st.maxIncl) > 0) {
			st.summary.MinFixedVersion = st.maxExcl
		} else if st.maxIncl != "" {
			st.summary.MaxAffectedVersion = st.maxIncl
		}
		out = append(out, *st.summary)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence.rank() > out[j].Confidence.rank()
		}
		if (out[i].KEVCount > 0) != (out[j].KEVCount > 0) {
			return out[i].KEVCount > 0
		}
		if out[i].Product.WANExposed != out[j].Product.WANExposed {
			return out[i].Product.WANExposed
		}
		if out[i].MaxSeverity != out[j].MaxSeverity {
			return out[i].MaxSeverity > out[j].MaxSeverity
		}
		if out[i].MaxCVSS != out[j].MaxCVSS {
			return out[i].MaxCVSS > out[j].MaxCVSS
		}
		return out[i].TotalCVEs > out[j].TotalCVEs
	})
	return out
}

// Headline formats a crisp single-line breakdown of a ProductSummary suitable
// for CLI tables and webhook alerts.
func (s ProductSummary) Headline() string {
	ver := ""
	if s.Product.Version != "" {
		ver = " " + s.Product.Version
	}
	extra := ""
	if s.KEVCount > 0 {
		extra += fmt.Sprintf(", %d KEV", s.KEVCount)
	}
	if s.ClientOnly {
		extra += ", verify SSH client tools"
	} else if s.NeedsContext {
		extra += ", verify platform applicability"
	}
	if s.Confidence == ConfidenceVersionAmbiguous {
		extra += ", verify distribution or appliance package fixes"
	} else if s.MinFixedVersion != "" {
		extra += fmt.Sprintf(", verify >= %s", s.MinFixedVersion)
	} else if s.MaxAffectedVersion != "" {
		// When a 4-part UniFi build (e.g. 6.6.55.15189) matched a 3-part
		// inclusive bound (6.6.55), clarify the release train so the advice
		// never reads as already satisfied.
		if s.Product.Version != "" && CompareVersions(s.Product.Version, s.MaxAffectedVersion) > 0 {
			extra += fmt.Sprintf(", verify > %s.x", s.MaxAffectedVersion)
		} else {
			extra += fmt.Sprintf(", verify > %s", s.MaxAffectedVersion)
		}
	}
	return fmt.Sprintf("%s%s: %d CVE(s) (max CVSS %.1f%s)", s.Product.Label, ver, s.TotalCVEs, s.MaxCVSS, extra)
}
