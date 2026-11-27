// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import (
	"cmp"
	"slices"
	"strings"
)

// prioritiesByFact computes the highest urgency for each distinct (asset,
// consequence) pair along with whether a high-profile target signal backs that
// winning pair and whether that signal applies on an untrusted-LAN entry point.
// When baseline is non-nil (counterfactual evaluation), any confirmed path that
// only degrades to unknown retains its prior difficulty so leaving an
// unresolved route behind never earns mitigation credit.
func (g *graph) prioritiesByFact(baseline, states [][]uint8, cuts []bool, pairs []int) ([]Priority, []bool, []bool) {
	out := make([]Priority, len(g.facts))
	hp := make([]bool, len(g.facts))
	untrustedHP := make([]bool, len(g.facts))
	for n, f := range g.facts {
		if f.kind != consequence && f.kind != permission {
			continue
		}
		for i, dist := range states {
			var base []uint8
			if baseline != nil {
				base = baseline[i]
			}
			d := dist[n]
			hpDist := dist
			hpCuts := cuts
			if d >= unknown {
				if base != nil && d == unknown && base[n] < unknown {
					d, hpDist, hpCuts = base[n], base, nil
				} else {
					continue
				}
			}
			if f.kind == permission {
				d = max(d, moderate)
			}
			s := starts[i]
			p := g.factPriority(s, n, f, d, hpDist, base, hpCuts)
			isHP := g.isHighProfileIn(n, f, hpDist, base, hpCuts)
			// Exclude CloudEgress even though it shares AudienceAssumeBreach: outbound
			// vendor telemetry is not lateral reach from an untrusted peer, so it
			// should not trigger the untrusted-LAN high-profile tie-breaker.
			isUntrusted := isHP && s.entry != CloudEgress && (s.audience == AudienceGuestOrUntrusted || s.audience == AudienceAssumeBreach || s.audience == AudiencePhysical)
			key := pairs[n]
			if out[key] == "" || p < out[key] {
				out[key] = p
				hp[key] = isHP
				untrustedHP[key] = isUntrusted
			} else if p == out[key] {
				if isHP {
					hp[key] = true
				}
				if isUntrusted {
					untrustedHP[key] = true
				}
			}
		}
	}
	return out, hp, untrustedHP
}

// pairIndexes counts one patch benefit per product and one hygiene benefit per
// host. This keeps unrelated product updates independently actionable while
// several advisories fixed by the same update count only once.
func (g *graph) pairIndexes() []int {
	pairs := make([]int, len(g.facts))
	first := map[fact]int{}
	for n, f := range g.facts {
		switch {
		case strings.HasPrefix(f.detail, "CVE-"):
			f.detail = "unpatched software: " + g.patchProducts[n]
		case strings.HasPrefix(f.detail, "service setting: "):
			f.detail = "service settings"
		}
		if i, ok := first[f]; ok {
			pairs[n] = i
		} else {
			first[f] = n
			pairs[n] = n
		}
	}
	return pairs
}

// impact compares two fixpoint priority tables. Each downgraded (asset,
// consequence) pair counts once at its prior priority, capped at 3 per tier.
func impact(before, after []Priority) (Priority, [5]int) {
	var counts [5]int
	var highest Priority
	for n, p := range before {
		if p == "" || (after[n] != "" && after[n] <= p) {
			continue
		}
		if highest == "" || p < highest {
			highest = p
		}
		i := int(p[1] - '1')
		counts[i] = min(3, counts[i]+1)
	}
	return highest, counts
}

func laneOrder(l Lane) int {
	switch l {
	case LaneFixNow:
		return 0
	case LaneReduceExposure:
		return 1
	default:
		return 2
	}
}

// precedes reports whether candidate a ranks ahead of b:
//  1. More improved pairs in PairsByTier (P1 down to P5, lexicographically)
//  2. Untrusted-LAN / physical / assume-breach high-profile tie-breaker (tieBreakHP)
//  3. Lane precedence (LaneFixNow < LaneReduceExposure < LaneVerify)
//  4. Lower effort
//  5. Lexicographically smaller action ID
func precedes(a, b candidate) bool {
	for i, n := range a.PairsByTier {
		if n != b.PairsByTier[i] {
			return n > b.PairsByTier[i]
		}
	}
	if a.tieBreakHP != b.tieBreakHP {
		return a.tieBreakHP
	}
	return cmp.Or(cmp.Compare(laneOrder(a.Lane), laneOrder(b.Lane)), cmp.Compare(a.effort, b.effort), cmp.Compare(a.ID, b.ID)) < 0
}

// activeByRoot reports, for each starting root, which action IDs currently
// touch a reachable edge, plus which verification notices are reachable.
func (g *graph) activeByRoot(states [][]uint8, cuts []bool) ([len(starts)][]bool, []bool) {
	var byRoot [len(starts)][]bool
	notices := make([]bool, len(g.actions))
	for i, dist := range states {
		row := make([]bool, len(g.actions))
		for n, d := range dist {
			if d == unreachable {
				continue
			}
			f := g.facts[n]
			if f.kind == notice {
				notices[g.actionIDs[f.detail]] = true
			}
			if d >= unknown {
				continue
			}
			for _, e := range g.edges[n] {
				if e.level < unknown && !cuts[e.cut] && !cuts[e.bundle] && !cuts[e.tagCut] {
					row[e.cut] = true
					row[e.bundle] = true
					row[e.tagCut] = true
				}
			}
		}
		byRoot[i] = row
	}
	return byRoot, notices
}

// rank greedily orders actionable changes by strictly positive marginal impact.
// Once no single remaining change reduces exposure on its own, the loop stops
// rather than silently applying arbitrary zero-credit cuts; remaining actions
// and verification items are appended in deterministic order with zero credit.
func (g *graph) rank(states [][]uint8) []Action {
	// Record direct targets before ranking removes overlapping benefits. Bundles
	// cover each of their member edges even when a narrower fix ranks first.
	for _, edges := range g.edges {
		for _, e := range edges {
			for _, id := range [...]int{e.cut, e.bundle, e.tagCut} {
				if id != 0 {
					g.actions[id].addTarget(g.facts[e.to].asset)
				}
			}
		}
	}
	cuts := make([]bool, len(g.actions))
	byRoot, notices := g.activeByRoot(states, cuts)
	var remaining, verify []int
	for i := 1; i < len(g.actions); i++ {
		if g.actions[i].Lane == LaneVerify {
			if notices[i] {
				slices.Sort(g.actions[i].BreaksApproved)
				verify = append(verify, i)
			}
			continue
		}
		touched := false
		for r := range byRoot {
			if byRoot[r][i] {
				touched = true
				break
			}
		}
		if touched {
			slices.Sort(g.actions[i].BreaksApproved)
			remaining = append(remaining, i)
		}
	}
	slices.SortFunc(verify, func(i, j int) int {
		return cmp.Compare(g.actions[i].ID, g.actions[j].ID)
	})

	pairs := g.pairIndexes()
	initialStates := states
	currentStates := states
	before, beforeHP, beforeUntrustedHP := g.prioritiesByFact(nil, currentStates, cuts, pairs)
	out := make([]Action, 0, len(remaining)+len(verify))

	// Reuse scratch buffers across candidate evaluations to avoid heap churn.
	var rootScratch [len(starts)][]uint8
	for i := range rootScratch {
		rootScratch[i] = make([]uint8, len(g.facts))
	}
	queue := make([]int, 0, len(g.facts))
	trial := make([][]uint8, len(starts))

	for len(remaining) > 0 {
		best := -1
		var winning []Priority
		for j, id := range remaining {
			c := &g.actions[id]
			c.HighestTierReduced, c.PairsByTier = "", [5]int{}
			touchedAny := false
			for i := range starts {
				if byRoot[i][id] {
					touchedAny = true
					break
				}
			}
			if !touchedAny {
				continue
			}
			cuts[id] = true
			// Cutting an action that touches no reachable edge from root i cannot
			// change root i's fixpoint, so reuse currentStates[i] without re-solving.
			for i, r := range g.roots {
				if byRoot[i][id] {
					g.solveRoot(r, cuts, rootScratch[i], queue[:0])
					trial[i] = rootScratch[i]
				} else {
					trial[i] = currentStates[i]
				}
			}
			after, _, _ := g.prioritiesByFact(initialStates, trial, cuts, pairs)
			cuts[id] = false
			c.HighestTierReduced, c.PairsByTier = impact(before, after)
			c.HighProfile = false
			c.tieBreakHP = false
			if c.HighestTierReduced != "" {
				for n, p := range before {
					if p != "" && (after[n] == "" || after[n] > p) {
						if beforeHP[n] {
							c.HighProfile = true
						}
						if beforeUntrustedHP[n] {
							c.tieBreakHP = true
						}
					}
				}
			}
			if c.HighestTierReduced != "" && (best < 0 || precedes(*c, g.actions[remaining[best]])) {
				best = j
				winning = after
			}
		}
		if best < 0 {
			// No remaining single action improves any exposure on its own.
			slices.SortFunc(remaining, func(i, j int) int {
				a, b := g.actions[i], g.actions[j]
				return cmp.Or(cmp.Compare(laneOrder(a.Lane), laneOrder(b.Lane)), cmp.Compare(a.effort, b.effort), cmp.Compare(a.ID, b.ID))
			})
			// Clear any transient scoring fields from earlier candidate trials before
			// appending the zero-credit residual actions.
			for _, id := range remaining {
				g.actions[id].HighestTierReduced = ""
				g.actions[id].PairsByTier = [5]int{}
				g.actions[id].Benefits = nil
				g.actions[id].AffectedAssets = nil
				g.actions[id].HighProfile = false
				g.actions[id].tieBreakHP = false
				out = append(out, g.actions[id].Action)
			}
			break
		}
		winner := remaining[best]
		type protectedAsset struct {
			key  string
			name string
			pri  Priority
		}
		bestByAsset := map[string]Priority{}
		for n, p := range before {
			if p != "" && (winning[n] == "" || winning[n] > p) {
				ak := g.facts[n].asset
				if prev, ok := bestByAsset[ak]; !ok || p < prev {
					bestByAsset[ak] = p
				}
			}
		}
		protected := make([]protectedAsset, 0, len(bestByAsset))
		for ak, p := range bestByAsset {
			g.actions[winner].addTarget(ak)
			protected = append(protected, protectedAsset{key: ak, name: cmp.Or(g.assets[ak].name, ak), pri: p})
		}
		slices.SortFunc(protected, func(a, b protectedAsset) int {
			return cmp.Or(cmp.Compare(a.pri, b.pri), cmp.Compare(a.name, b.name), cmp.Compare(a.key, b.key))
		})
		limit := min(6, len(protected))
		assets := make([]string, 0, limit)
		names := make([]string, 0, min(3, limit))
		for i, pa := range protected[:limit] {
			assets = append(assets, pa.key)
			if i < 3 {
				names = append(names, pa.name)
			}
		}
		g.actions[winner].Benefits = names
		g.actions[winner].AffectedAssets = assets
		out = append(out, g.actions[winner].Action)

		cuts[winner] = true
		nextStates := make([][]uint8, len(starts))
		// Only re-solve roots whose reachable edges included the winning cut.
		for i, r := range g.roots {
			if byRoot[i][winner] {
				dist := make([]uint8, len(g.facts))
				g.solveRoot(r, cuts, dist, queue[:0])
				nextStates[i] = dist
			} else {
				nextStates[i] = currentStates[i]
			}
		}
		currentStates = nextStates
		before, beforeHP, beforeUntrustedHP = g.prioritiesByFact(initialStates, currentStates, cuts, pairs)
		byRoot, _ = g.activeByRoot(currentStates, cuts)
		remaining = slices.Delete(remaining, best, best+1)
	}
	for _, id := range verify {
		out = append(out, g.actions[id].Action)
	}
	return out
}
