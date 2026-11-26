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
// consequence) pair. When baseline is non-nil (counterfactual evaluation), any
// confirmed path that only degrades to unknown retains its prior difficulty so
// leaving an unresolved route behind never earns mitigation credit.
func (g *graph) prioritiesByFact(baseline, states [][]uint8, pairs []int) []Priority {
	out := make([]Priority, len(g.facts))
	for n, f := range g.facts {
		if f.kind != consequence && f.kind != permission {
			continue
		}
		for i, dist := range states {
			d := dist[n]
			if d >= unknown {
				if baseline != nil && d == unknown && baseline[i][n] < unknown {
					d = baseline[i][n]
				} else {
					continue
				}
			}
			if f.kind == permission {
				d = max(d, moderate)
			}
			p := PriorityFor(starts[i].audience, difficulties[d], g.assets[f.asset].profile.Tier)
			if key := pairs[n]; out[key] == "" || p < out[key] {
				out[key] = p
			}
		}
	}
	return out
}

// pairIndexes collapses multiple CVEs or generic service settings on the same
// host into one pair so noisy scanners cannot inflate ranking counts. Published
// services keep their port and transport because each is a distinct exposure.
func (g *graph) pairIndexes() []int {
	pairs := make([]int, len(g.facts))
	first := map[fact]int{}
	for n, f := range g.facts {
		switch {
		case strings.HasPrefix(f.detail, "CVE-"):
			f.detail = "unpatched software"
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

func precedes(a, b candidate) bool {
	for i, n := range a.PairsByTier {
		if n != b.PairsByTier[i] {
			return n > b.PairsByTier[i]
		}
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
				if e.level < unknown && !cuts[e.cut] && !cuts[e.bundle] {
					row[e.cut] = true
					row[e.bundle] = true
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
	before := g.prioritiesByFact(nil, currentStates, pairs)
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
			for i, r := range g.roots {
				if byRoot[i][id] {
					g.solveRoot(r, cuts, rootScratch[i], queue[:0])
					trial[i] = rootScratch[i]
				} else {
					trial[i] = currentStates[i]
				}
			}
			cuts[id] = false
			after := g.prioritiesByFact(initialStates, trial, pairs)
			c.HighestTierReduced, c.PairsByTier = impact(before, after)
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
			for _, id := range remaining {
				g.actions[id].HighestTierReduced = ""
				g.actions[id].PairsByTier = [5]int{}
				g.actions[id].Benefits = nil
				out = append(out, g.actions[id].Action)
			}
			break
		}
		winner := remaining[best]
		var names []string
		for n, p := range before {
			if p != "" && p == g.actions[winner].HighestTierReduced && (winning[n] == "" || winning[n] > p) {
				names = append(names, g.assets[g.facts[n].asset].name)
			}
		}
		slices.Sort(names)
		names = slices.Compact(names)
		g.actions[winner].Benefits = names[:min(3, len(names))]
		out = append(out, g.actions[winner].Action)

		cuts[winner] = true
		nextStates := make([][]uint8, len(starts))
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
		before = g.prioritiesByFact(initialStates, currentStates, pairs)
		byRoot, _ = g.activeByRoot(currentStates, cuts)
		remaining = slices.Delete(remaining, best, best+1)
	}
	for _, id := range verify {
		out = append(out, g.actions[id].Action)
	}
	return out
}
