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
// tuple into one compact, operator-friendly summary row — turning dozens of
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
	// observed across matching CVEs (e.g., "7.3.0" -> operator should verify >= 7.3.0).
	MinFixedVersion string `json:"min_fixed_version,omitempty"`
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

	order := make([]groupKey, 0)
	groups := make(map[groupKey]*ProductSummary)

	for _, m := range matches {
		k := groupKey{
			hostIP: m.Product.HostIP,
			label:  m.Product.Label,
			ver:    m.Product.Version,
			conf:   m.Confidence,
		}
		sum, exists := groups[k]
		if !exists {
			sum = &ProductSummary{
				Product:    m.Product,
				Confidence: m.Confidence,
			}
			groups[k] = sum
			order = append(order, k)
		}

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

		// Track the highest fixed version bound (EndExcl) so we can tell the
		// operator "verify version >= X" deterministically without guessing.
		if fix := m.MatchedCPE.EndExcl; fix != "" {
			if sum.MinFixedVersion == "" || CompareVersions(fix, sum.MinFixedVersion) > 0 {
				sum.MinFixedVersion = fix
			}
		}
	}

	out := make([]ProductSummary, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
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
	}
	return fmt.Sprintf("%s%s: %d CVE(s) (max CVSS %.1f%s)", s.Product.Label, ver, s.TotalCVEs, s.MaxCVSS, extra)
}
