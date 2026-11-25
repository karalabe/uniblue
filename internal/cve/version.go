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
//     (inRange, ConfidenceExact), except when the observed version is only a
//     coarse numeric prefix of a more-specific bound (e.g., "2.4" against
//     EndExcl "2.4.7"), in which case it returns (true, ConfidencePotential).
//   - If the CPE is completely unbounded (version="*" and no start/end bounds),
//     it returns (true, ConfidencePotential) so wildcards never pretend to be
//     exact version confirmations.
//
// When version is empty, it returns (true, ConfidencePotential).
func MatchesRange(version string, m CPEMatch) (bool, Confidence) {
	return matchesRange(version, m, isUniFiFirmwareCPE(m))
}

func matchesRange(version string, m CPEMatch, unifiFirmware bool) (bool, Confidence) {
	version = strings.TrimSpace(version)
	if version == "" {
		return true, ConfidencePotential
	}

	hasExact := m.Version != "" && m.Version != "*" && m.Version != "-"
	hasRange := m.StartIncl != "" || m.StartExcl != "" || m.EndIncl != "" || m.EndExcl != ""

	if !hasExact && !hasRange {
		return true, ConfidencePotential
	}

	eff := func(bound string) string {
		if unifiFirmware {
			return unifiEffectiveVersionForBound(version, bound)
		}
		return version
	}

	if hasExact {
		v := eff(m.Version)
		if isCoarsePrefix(v, m.Version) {
			return true, ConfidencePotential
		}
		return CompareVersions(v, m.Version) == 0, ConfidenceExact
	}

	ambiguous := false

	if m.StartIncl != "" {
		v := eff(m.StartIncl)
		cmp := CompareVersions(v, m.StartIncl)
		if isCoarsePrefix(v, m.StartIncl) {
			// If StartIncl has non-zero trailing components (e.g., "2.4.2"),
			// an observed "2.4" could be either below or at/above the bound.
			// If cmp == 0 (e.g., "2.4.0"), every 2.4.x is >= 2.4.0.
			if cmp < 0 {
				ambiguous = true
			}
		} else if cmp < 0 {
			return false, ConfidenceExact
		}
	}
	if m.StartExcl != "" {
		v := eff(m.StartExcl)
		if isCoarsePrefix(v, m.StartExcl) {
			// Any more-specific StartExcl under the same prefix (e.g., "2.4.0"
			// or "2.4.2") leaves some 2.4.x versions inside and some outside.
			ambiguous = true
		} else if CompareVersions(v, m.StartExcl) <= 0 {
			return false, ConfidenceExact
		}
	}
	if m.EndIncl != "" {
		v := eff(m.EndIncl)
		if isCoarsePrefix(v, m.EndIncl) {
			// Any more-specific EndIncl under the same prefix (e.g., "2.4.0"
			// or "2.4.7") leaves some 2.4.x versions inside and some outside.
			ambiguous = true
		} else if CompareVersions(v, m.EndIncl) > 0 {
			return false, ConfidenceExact
		}
	}
	if m.EndExcl != "" {
		v := eff(m.EndExcl)
		cmp := CompareVersions(v, m.EndExcl)
		if isCoarsePrefix(v, m.EndExcl) {
			// If cmp == 0 (e.g., EndExcl "2.4.0"), no 2.4.x release is < 2.4.0.
			if cmp >= 0 {
				return false, ConfidenceExact
			}
			ambiguous = true
		} else if cmp >= 0 {
			return false, ConfidenceExact
		}
	}
	if ambiguous {
		return true, ConfidencePotential
	}
	return true, ConfidenceExact
}

func isUniFiFirmwareCPE(m CPEMatch) bool {
	v := strings.ToLower(strings.TrimSpace(m.Vendor))
	p := strings.ToLower(strings.TrimSpace(m.Product))
	return (v == "ui" || v == "ubiquiti") && strings.HasPrefix(p, "unifi_")
}

// unifiEffectiveVersionForBound maps a 4-part UniFi firmware string
// (major.minor.patch.build, such as "6.6.55.15189" or "6.6.55.999") to its
// 3-part release prefix ("6.6.55") only when compared against a 3-part NVD
// bound. Against 4-part NVD bounds (such as "6.6.55.15200"), all 4 numeric
// parts are compared directly.
func unifiEffectiveVersionForBound(observed, bound string) string {
	obsParts, ok := numericDotParts(observed, 4)
	if !ok {
		return observed
	}
	if _, boundIs3 := numericDotParts(bound, 3); !boundIs3 {
		return observed
	}
	return obsParts[0] + "." + obsParts[1] + "." + obsParts[2]
}

func numericDotParts(raw string, want int) ([]string, bool) {
	v := strings.TrimSpace(raw)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	parts := strings.Split(v, ".")
	if len(parts) != want {
		return nil, false
	}
	for _, p := range parts {
		if p == "" {
			return nil, false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return nil, false
			}
		}
	}
	return parts, true
}

// isCoarsePrefix reports whether observed has strictly fewer tokens than bound,
// matches every token of bound up to its own length, and bound's next token is
// a numeric component (such as observed "2.4" vs bound "2.4.7" or "2.4.0").
// Non-numeric patch or pre-release suffixes (such as "9.3" vs "9.3p1" or
// "1.1.1" vs "1.1.1a") are distinct releases rather than truncated prefixes.
func isCoarsePrefix(observed, bound string) bool {
	to := tokenizeVersion(observed)
	tb := tokenizeVersion(bound)
	if len(to) == 0 || len(to) >= len(tb) {
		return false
	}
	for i := range to {
		if to[i] != tb[i] {
			return false
		}
	}
	return tb[len(to)].isNum
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
		hasA := i < len(ta)
		hasB := i < len(tb)
		var va, vb versionToken
		if hasA {
			va = ta[i]
		}
		if hasB {
			vb = tb[i]
		}

		// Handle pre-release tokens (alpha/beta/rc/dev/pre) sorting before
		// release versions when one version has an extra pre-release suffix.
		if va.preRelease != vb.preRelease {
			if va.preRelease {
				return -1
			}
			return 1
		}

		// When one side has run out of components, treat its missing trailing
		// component as 0 against a numeric token on the other side, and as less
		// than a non-pre-release alphabetic suffix (e.g., 1.1.1 < 1.1.1a,
		// 9.3 < 9.3p1).
		if !hasA {
			if vb.isNum {
				if vb.num > 0 {
					return -1
				}
				continue
			}
			return -1
		}
		if !hasB {
			if va.isNum {
				if va.num > 0 {
					return 1
				}
				continue
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
		if va.isNum != vb.isNum {
			// A zero numeric component behaves like an omitted component
			// (e.g., 1.0.0 < 1.0p1), whereas a non-zero numeric component
			// sorts after a patch suffix (e.g., 1.0.1 > 1.0p1).
			if va.isNum {
				if va.num == 0 {
					return -1
				}
				return 1
			}
			if vb.num == 0 {
				return 1
			}
			return -1
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
		// Only full pre-release words sort before the base release; single
		// letters like "a" or "b" are post-release patch levels (OpenSSL
		// 1.1.1 < 1.1.1a < 1.1.1b < 1.1.1c, ProFTPD, etc.).
		pre := word == "alpha" || word == "beta" || word == "rc" || word == "dev" || word == "pre"
		tokens = append(tokens, versionToken{text: word, preRelease: pre})
	}
	return tokens
}
