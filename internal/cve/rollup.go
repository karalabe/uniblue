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

// ProductSummary rolls up all CVE matches for a single (Host, Product, Confidence)
// tuple into one compact, operator-friendly summary row, turning dozens of
// repetitive CVE lines into a single prioritized item with a computed minimum
// fixed version.
type ProductSummary struct {
	// Product identifies the host, VLAN, software name, and observed version.
	Product Product `json:"product"`

	// Confidence is either ConfidenceExact (observed version matched) or
	// ConfidencePotential (product matched, version unknown).
	Confidence Confidence `json:"confidence"`

	// TotalCVEs is the total number of matching CVEs in this rollup.
	TotalCVEs int `json:"total_cves"`

	// CriticalCount, HighCount, and KEVCount break down the matched CVEs.
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	KEVCount      int `json:"kev_count"`

	// MaxSeverity and MaxCVSS reflect the worst CVE in this rollup.
	MaxSeverity checks.Severity `json:"max_severity"`
	MaxCVSS     float64         `json:"max_cvss"`

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
// into per-(Host, Product, Confidence) ProductSummaries, sorted by urgency.
func RollupMatches(matches []Match) []ProductSummary {
	if len(matches) == 0 {
		return nil
	}

	type groupKey struct {
		hostIP string
		label  string
		ver    string
		conf   Confidence
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
			hostIP: m.Product.HostIP,
			label:  m.Product.Label,
			ver:    m.Product.Version,
			conf:   m.Confidence,
		}
		st, exists := groups[k]
		if !exists {
			st = &groupState{
				summary: &ProductSummary{
					Product:    m.Product,
					Confidence: m.Confidence,
				},
			}
			groups[k] = st
			order = append(order, k)
		}
		sum := st.summary

		sum.TotalCVEs++
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
			return out[i].Confidence == ConfidenceExact
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
	if s.MinFixedVersion != "" {
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
