// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import "github.com/karalabe/uniblue/internal/classify"

// EntryAudience describes who can use a path.
type EntryAudience string

const (
	// AudienceInternetAny covers unsolicited access from the public internet.
	AudienceInternetAny EntryAudience = "internet-any"
	// AudienceInternetRestricted covers access from selected external sources.
	AudienceInternetRestricted EntryAudience = "internet-restricted"
	// AudiencePhysical requires access to a network socket.
	AudiencePhysical EntryAudience = "physical"
	// AudienceGuestOrUntrusted covers guests and untrusted networks.
	AudienceGuestOrUntrusted EntryAudience = "guest-or-untrusted"
	// AudienceAssumeBreach assumes a device is already compromised.
	AudienceAssumeBreach EntryAudience = "assume-breach"
	// AudienceTrustedLAN requires a position on the local trusted network.
	AudienceTrustedLAN EntryAudience = "trusted-lan"
)

// ChainDifficulty describes the evidence and prerequisites for a consequence.
type ChainDifficulty string

const (
	// DifficultyTrivial requires no additional privilege or unverified prerequisite.
	DifficultyTrivial ChainDifficulty = "trivial"
	// DifficultyLow requires a known vulnerability or an inferred read permission.
	DifficultyLow ChainDifficulty = "low"
	// DifficultyModerate depends on credentials, pairing or another unverified condition.
	DifficultyModerate ChainDifficulty = "moderate"
	// DifficultyUnknown indicates missing reachability or service evidence.
	DifficultyUnknown ChainDifficulty = "unknown"
)

// Priority is the urgency of a modeled consequence, ordered from P1 to P5.
type Priority string

const (
	// P1 indicates the most urgent work.
	P1 Priority = "P1"
	// P2 indicates high priority.
	P2 Priority = "P2"
	// P3 indicates normal priority.
	P3 Priority = "P3"
	// P4 indicates lower priority.
	P4 Priority = "P4"
	// P5 indicates the lowest priority.
	P5 Priority = "P5"
)

// Rows progress from trivial to unknown. Columns progress from crown to disposable.
// Names, device counts and the number of routes never enter this lookup.
var priorities = map[EntryAudience][4][5]Priority{
	AudienceInternetAny:        {{P1, P1, P2, P2, P2}, {P1, P2, P2, P3, P3}, {P2, P3, P3, P4, P4}, {P4, P4, P5, P5, P5}},
	AudienceInternetRestricted: {{P1, P2, P2, P3, P3}, {P2, P2, P3, P3, P4}, {P3, P3, P4, P4, P5}, {P4, P4, P5, P5, P5}},
	AudiencePhysical:           {{P2, P2, P3, P3, P4}, {P2, P3, P3, P4, P4}, {P3, P3, P4, P4, P5}, {P4, P4, P5, P5, P5}},
	AudienceGuestOrUntrusted:   {{P2, P2, P3, P3, P4}, {P2, P3, P3, P4, P4}, {P3, P3, P4, P4, P5}, {P4, P4, P5, P5, P5}},
	AudienceAssumeBreach:       {{P2, P2, P3, P4, P4}, {P2, P3, P3, P4, P4}, {P3, P3, P4, P4, P5}, {P4, P5, P5, P5, P5}},
	AudienceTrustedLAN:         {{P2, P2, P3, P4, P4}, {P3, P3, P4, P4, P5}, {P3, P4, P4, P5, P5}, {P4, P5, P5, P5, P5}},
}

var difficulties = [...]ChainDifficulty{DifficultyTrivial, DifficultyLow, DifficultyModerate, DifficultyUnknown}
var tiers = map[classify.AssetTier]int{classify.TierCrown: 0, classify.TierHigh: 1, classify.TierMedium: 2, classify.TierLow: 3, classify.TierDisposable: 4}

// PromotePriority steps a priority one level more urgent (e.g. P2 -> P1),
// capped at P1. Used only for additive high-profile target velocity boosts.
func PromotePriority(p Priority) Priority {
	switch p {
	case P2:
		return P1
	case P3:
		return P2
	case P4:
		return P3
	case P5:
		return P4
	default:
		return p
	}
}

// PriorityFor looks up urgency from audience, evidence and asset value.
func PriorityFor(audience EntryAudience, difficulty ChainDifficulty, assetValue classify.AssetTier) Priority {
	row, ok := priorities[audience]
	if !ok {
		return P5
	}
	col, ok := tiers[assetValue]
	if !ok {
		col = tiers[classify.TierMedium]
	}
	for i, d := range difficulties {
		if d == difficulty {
			return row[i][col]
		}
	}
	return row[3][col]
}
