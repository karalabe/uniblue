// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cve

import (
	"strconv"
	"strings"
)

// MatchesRange checks whether an observed version string falls inside a CPE
// match's vulnerable version constraints.
//
// When version is non-empty:
//   - If the CPE specifies an exact version or any start/end bounds, it returns
//     (inRange, ConfidenceExact).
//   - If the CPE is completely unbounded (version="*" and no start/end bounds),
//     it returns (true, ConfidencePotential) so wildcards never pretend to be
//     exact version confirmations.
//
// When version is empty, it returns (true, ConfidencePotential).
func MatchesRange(version string, m CPEMatch) (bool, Confidence) {
	version = strings.TrimSpace(version)
	if version == "" {
		return true, ConfidencePotential
	}

	hasExact := m.Version != "" && m.Version != "*" && m.Version != "-"
	hasRange := m.StartIncl != "" || m.StartExcl != "" || m.EndIncl != "" || m.EndExcl != ""

	if !hasExact && !hasRange {
		return true, ConfidencePotential
	}
	if hasExact {
		return CompareVersions(version, m.Version) == 0, ConfidenceExact
	}

	if m.StartIncl != "" && CompareVersions(version, m.StartIncl) < 0 {
		return false, ConfidenceExact
	}
	if m.StartExcl != "" && CompareVersions(version, m.StartExcl) <= 0 {
		return false, ConfidenceExact
	}
	if m.EndIncl != "" && CompareVersions(version, m.EndIncl) > 0 {
		return false, ConfidenceExact
	}
	if m.EndExcl != "" && CompareVersions(version, m.EndExcl) >= 0 {
		return false, ConfidenceExact
	}
	return true, ConfidenceExact
}

// CompareVersions compares two software/firmware version strings (such as
// "6.0.17" vs "6.0.9", "9.6p1" vs "9.6p2", or "2024.11.2" vs "2024.12.0")
// returning -1 if a < b, 0 if a == b, and +1 if a > b.
func CompareVersions(a, b string) int {
	ta := tokenizeVersion(a)
	tb := tokenizeVersion(b)

	maxLen := len(ta)
	if len(tb) > maxLen {
		maxLen = len(tb)
	}

	for i := 0; i < maxLen; i++ {
		var va, vb versionToken
		if i < len(ta) {
			va = ta[i]
		}
		if i < len(tb) {
			vb = tb[i]
		}

		// Handle pre-release tokens (alpha/beta/rc) sorting before release
		// versions when one version has an extra pre-release suffix.
		if va.preRelease != vb.preRelease {
			if va.preRelease {
				return -1
			}
			return 1
		}

		if va.isNum && vb.isNum {
			if va.num < vb.num {
				return -1
			}
			if va.num > vb.num {
				return 1
			}
			continue
		}
		if va.text < vb.text {
			return -1
		}
		if va.text > vb.text {
			return 1
		}
	}
	return 0
}

// versionToken represents one numeric or alphabetic segment split out of a
// version string (e.g., "9.6p1" -> [9, 6, "p", 1]).
type versionToken struct {
	isNum      bool
	num        int
	text       string
	preRelease bool
}

// tokenizeVersion breaks a version string into alternating numeric and
// alphabetic segments, ignoring leading "v" prefixes and separator punctuation.
func tokenizeVersion(v string) []versionToken {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "v")

	var tokens []versionToken
	i := 0
	for i < len(v) {
		ch := v[i]
		if ch == '.' || ch == '-' || ch == '_' || ch == '+' {
			i++
			continue
		}
		if ch >= '0' && ch <= '9' {
			start := i
			for i < len(v) && v[i] >= '0' && v[i] <= '9' {
				i++
			}
			n, _ := strconv.Atoi(v[start:i])
			tokens = append(tokens, versionToken{isNum: true, num: n})
			continue
		}
		start := i
		for i < len(v) && !((v[i] >= '0' && v[i] <= '9') || v[i] == '.' || v[i] == '-' || v[i] == '_' || v[i] == '+') {
			i++
		}
		word := v[start:i]
		pre := word == "alpha" || word == "a" || word == "beta" || word == "b" || word == "rc" || word == "dev" || word == "pre"
		tokens = append(tokens, versionToken{text: word, preRelease: pre})
	}
	return tokens
}
