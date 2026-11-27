// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
)

// VelocityClass describes the exploitation and advisory history of a product family.
type VelocityClass string

const (
	// VelocityHighProfile denotes recent KEV activity, known ransomware use, or sustained network CVEs.
	VelocityHighProfile VelocityClass = "high-profile target"
	// VelocityObserved denotes a known product with some historical advisories.
	VelocityObserved VelocityClass = "observed"
	// VelocityUnknown denotes insufficient product identity or advisory evidence.
	VelocityUnknown VelocityClass = "unknown (opaque firmware - not evidence of safety)"
)

// TargetVelocity summarizes product history independently of the installed version.
type TargetVelocity struct {
	// Class is the historical signal for this product family.
	Class VelocityClass
	// TotalCVEs counts distinct NVD or CISA advisories for the product.
	TotalCVEs int
	// KEVCount counts distinct catalog entries through the query date.
	KEVCount int
	// LatestKEV is the most recent known CISA addition date.
	LatestKEV string
	// RansomwareCount counts KEVs with known ransomware campaign use.
	RansomwareCount int
	// NetworkHigh counts AV:N High or Critical CVEs across trailing 1-, 3-, and
	// 5-year windows (keys 1, 3, and 5). A missing key means one or more calendar
	// years touched by that window failed the 60% CPE coverage threshold.
	NetworkHigh map[int]int
	// IncompleteYears lists missing or under-enriched publication years in order.
	IncompleteYears []string
	// YearCoverage supplies the counts behind the coverage warnings.
	YearCoverage map[string]YearCoverageStats
}

// ProductVelocity computes historical KEV and network-CVE velocity for p using
// only the local vendor shards and CISA KEV catalog. Callers should set
// HighConfidence when querying an explicit vendor and product directly.
func (c *Cache) ProductVelocity(p Product, now time.Time) (TargetVelocity, error) {
	st, err := c.Stats()
	if err != nil {
		return TargetVelocity{}, fmt.Errorf("read CVE cache stats (run uniblue cve sync): %w", err)
	}
	if st.SchemaVersion != CurrentIndexSchemaVersion {
		return TargetVelocity{}, errors.New("CVE history requires an updated index (run uniblue cve sync)")
	}
	records := make(map[string]Record)
	for _, vendor := range p.Vendors {
		recs, err := c.LookupVendor(vendor)
		if err != nil {
			return TargetVelocity{}, err
		}
		for _, r := range recs {
			for _, m := range r.Matches {
				if strings.EqualFold(m.Vendor, vendor) && matchesAnyPattern(p.Products, m.Product) {
					records[r.ID] = r
					break
				}
			}
		}
	}
	// CISA can identify the affected product before NVD supplies any CPE.
	// Match whole catalog names so similarly named products do not inherit its history.
	catalog, _, err := readKEV(filepath.Join(c.dir, "kev.json"))
	if err != nil && (!errors.Is(err, os.ErrNotExist) || st.KEVCount > 0) {
		return TargetVelocity{}, fmt.Errorf("read local KEV catalog: %w", err)
	}
	for id, e := range catalog {
		r, indexed := records[id]
		if !indexed && !(containsCatalogName(p.Vendors, e.Vendor) && containsCatalogName(p.Products, e.Product)) {
			continue
		}
		r.ID, r.KEV, r.KEVDateAdded, r.KEVRansomware = id, true, e.DateAdded, e.Ransomware == "Known"
		records[id] = r
	}
	// The yearly archives are keyed by CVE ID. A few late publications from
	// older archives cannot establish coverage for a year that was never synced.
	for year := range st.YearCoverage {
		if st.YearSHAs != nil && st.YearSHAs[year] == "" {
			delete(st.YearCoverage, year)
		}
	}
	return summarizeVelocity(records, p.HighConfidence, now.UTC(), st.YearCoverage), nil
}

// containsCatalogName accepts CPE underscores in place of spaces in a CISA name.
func containsCatalogName(names []string, catalogName string) bool {
	token := strings.Join(strings.Fields(catalogName), "_")
	return token != "" && slices.ContainsFunc(names, func(name string) bool {
		return strings.EqualFold(name, token) || strings.EqualFold(name, catalogName)
	})
}

// summarizeVelocity requires complete coverage in every calendar year touched by
// a rolling window. Recurring network CVEs must span three annual intervals,
// including the most recent one, so one disclosure burst cannot establish a trend.
func summarizeVelocity(records map[string]Record, trusted bool, now time.Time, coverage map[string]YearCoverageStats) TargetVelocity {
	h := TargetVelocity{Class: VelocityUnknown, NetworkHigh: make(map[int]int), YearCoverage: coverage}
	var since [6]string
	for n := range since {
		since[n] = now.AddDate(-n, 0, 0).Format(time.DateOnly)
	}
	for year := now.Year() - 5; year <= now.Year(); year++ {
		key := strconv.Itoa(year)
		c := coverage[key]
		// Require at least 60% CPE enrichment (WithCPE/Total >= 3/5) for a year
		// to count as complete; NVD backfill lag otherwise undercounts recent years.
		if c.Total == 0 || 5*c.WithCPE < 3*c.Total {
			h.IncompleteYears = append(h.IncompleteYears, key)
		}
	}

	// annual[i] counts AV:N High/Critical CVEs published in trailing 1-year
	// intervals: [since[1], since[0]] for i=0 (inclusive of the query date) and
	// [since[i+1], since[i]) for i=1..4 (up to 4-5 years ago).
	var annual [5]int
	for _, r := range records {
		// Guard against future-dated catalog entries relative to the query date.
		kev := r.KEV && r.KEVDateAdded <= since[0]
		if kev {
			h.KEVCount++
			h.LatestKEV = max(h.LatestKEV, r.KEVDateAdded)
			if r.KEVRansomware {
				h.RansomwareCount++
			}
		}
		// Exclude future-dated non-KEV NVD records (relative to the query date) and
		// orphan non-KEV placeholders with neither a publication date nor CPE
		// matches; a CVE already listed in KEV by the query date still counts toward
		// TotalCVEs while remaining excluded from NetworkHigh below.
		if !kev && (r.Published > since[0] || r.Published == "" && len(r.Matches) == 0) {
			continue
		}
		h.TotalCVEs++
		if r.Severity < checks.SeverityHigh || r.AttackVector != "N" || r.Published > since[0] {
			continue
		}
		for i := range annual {
			if r.Published >= since[i+1] {
				annual[i]++
				break
			}
		}
	}
	sustained := false
	for _, n := range []int{1, 3, 5} {
		if slices.ContainsFunc(h.IncompleteYears, func(year string) bool { return year >= since[n][:4] }) {
			continue
		}
		active := 0
		h.NetworkHigh[n] = 0
		for _, count := range annual[:n] {
			h.NetworkHigh[n] += count
			if count > 0 {
				active++
			}
		}
		// Sustained velocity requires activity in the most recent year plus at
		// least three distinct annual intervals within a complete window.
		sustained = sustained || (annual[0] > 0 && active >= 3)
	}
	// Promote trusted identities with history to VelocityHighProfile when a KEV
	// was added in the last 3 years, any KEV has known ransomware use, or remote
	// High/Critical CVEs recur across at least three annual intervals.
	if trusted && h.TotalCVEs > 0 {
		h.Class = VelocityObserved
		if h.LatestKEV >= since[3] || h.RansomwareCount > 0 || sustained {
			h.Class = VelocityHighProfile
		}
	}
	return h
}
