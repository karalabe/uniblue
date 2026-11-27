// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

type factKind uint8

const (
	origin factKind = iota
	position
	endpoint
	consequence
	permission
	blocked
	notice
)

// A fact has one identity across routes. Only endpoint facts carry an address;
// consequences deliberately lose it so a surviving second family retains credit.
type fact struct {
	kind          factKind
	asset, detail string
}
type edge struct {
	to, cut, bundle int
	level           uint8
}

const (
	trivial uint8 = iota
	low
	moderate
	unknown
	unreachable
)

type start struct {
	entry    Entry
	audience EntryAudience
}

var starts = [...]start{
	{Internet, AudienceInternetAny}, {InternetSource, AudienceInternetRestricted}, {WiFi, AudienceGuestOrUntrusted},
	{Physical, AudiencePhysical}, {AssumeBreach, AudienceAssumeBreach}, {CloudEgress, AudienceAssumeBreach}, {TrustedLAN, AudienceTrustedLAN},
}

type asset struct {
	name    string
	profile classify.AssetProfile
}
type highProfileEdge struct {
	src int
	cut int
}

type graph struct {
	ids                map[fact]int
	facts              []fact
	edges              [][]edge
	assets             map[string]asset
	actionIDs          map[string]int
	actions            []candidate
	roots              [len(starts)]int
	highProfileHost    map[string]bool
	highProfileFamily  map[string]bool
	highProfilePorts   map[string]bool
	highProfileSockets map[string]bool
	highProfileSources map[int][]highProfileEdge
}
type candidate struct {
	Action
	effort     int
	tieBreakHP bool
}

// Evaluate computes reachable consequences and ranks hypothetical changes without
// modifying the snapshot, observed devices, or controller settings.
func Evaluate(in Input) Report {
	if in.Snapshot == nil {
		in.Snapshot = &unifi.Snapshot{}
	}
	if in.Oracle == nil {
		in.Oracle = risk.NewOracle(in.Snapshot, in.NetCfg)
	}
	if in.Assets == nil {
		in.Assets, _ = classify.ResolveAssets(in.Snapshot, in.Profiles, in.NetCfg.Assets)
	}
	g := graph{
		ids:                make(map[fact]int),
		assets:             make(map[string]asset),
		actionIDs:          make(map[string]int),
		actions:            []candidate{{}},
		highProfileHost:    make(map[string]bool),
		highProfileFamily:  make(map[string]bool),
		highProfilePorts:   make(map[string]bool),
		highProfileSockets: make(map[string]bool),
		highProfileSources: make(map[int][]highProfileEdge),
	}
	for i, s := range starts {
		g.roots[i] = g.node(root(s.entry))
	}
	b := builder{Input: in, graph: &g}
	b.inventory()
	b.indexTargetSignals()
	b.services()
	b.entries()
	b.routes()
	result := Report{Cloud: b.cloud}
	states := g.solve(nil)
	result.Exposures = g.exposures(states)
	result.Actions = g.rank(states)
	result.Simulation = b.buildSimulation(result)
	return result
}

func root(e Entry) fact             { return fact{origin, "", string(e)} }
func hostKey(c unifi.Client) string { return cmp.Or(canonicalMAC(c.MAC), c.ID, c.PrimaryIP()) }

// node interns facts so every queue update and action overlay uses compact indexes.
func (g *graph) node(f fact) int {
	if i, ok := g.ids[f]; ok {
		return i
	}
	i := len(g.facts)
	g.ids[f] = i
	g.facts = append(g.facts, f)
	g.edges = append(g.edges, nil)
	return i
}

// link keeps alternate routes separate, including cuts narrower than a whole service.
func (g *graph) link(from, to fact, level uint8, cut, bundle int) {
	a, b := g.node(from), g.node(to)
	g.edges[a] = append(g.edges[a], edge{b, cut, bundle, level})
}

func (g *graph) action(id, title, reason string, lane Lane, effort int) int {
	if i, ok := g.actionIDs[id]; ok {
		// A shared rule can have several witnesses. Choose its wording independently of input order.
		a := &g.actions[i]
		if cmp.Or(cmp.Compare(title, a.Title), cmp.Compare(reason, a.Reason)) < 0 {
			a.Title, a.Reason = title, reason
		}
		if lane == LaneFixNow {
			a.Lane = lane
		}
		return i
	}
	i := len(g.actions)
	g.actionIDs[id] = i
	g.actions = append(g.actions, candidate{Action: Action{ID: id, Title: title, Reason: reason, Lane: lane}, effort: effort})
	return i
}

// verify ties missing evidence to its reachable source. Collecting it earns no
// hypothetical protection because its answer might be either allow or deny.
func (g *graph) verify(from fact, code, target, title, reason string) {
	id := "act:verify:" + code + ":" + target
	g.action(id, title, reason, LaneVerify, 0)
	g.link(from, fact{notice, target, id}, unknown, 0, 0)
}

// solve computes the least fixpoint for each starting point. Each node's
// difficulty can improve at most four times, so cyclic management or pivot
// relations always terminate quickly.
func (g *graph) solve(cuts []bool) [][]uint8 {
	states := make([][]uint8, len(starts))
	queue := make([]int, 0, len(g.facts))
	for i, r := range g.roots {
		dist := make([]uint8, len(g.facts))
		g.solveRoot(r, cuts, dist, queue[:0])
		states[i] = dist
	}
	return states
}

// solveRoot runs the monotone fixpoint from a single starting root r into the
// caller-supplied dist slice (which must have length len(g.facts)).
func (g *graph) solveRoot(r int, cuts []bool, dist []uint8, queue []int) {
	for k := range dist {
		dist[k] = unreachable
	}
	dist[r] = trivial
	queue = append(queue[:0], r)
	for head := 0; head < len(queue); head++ {
		n := queue[head]
		for _, e := range g.edges[n] {
			if cuts != nil && (cuts[e.cut] || cuts[e.bundle]) {
				continue
			}
			level := max(dist[n], e.level)
			if level < dist[e.to] {
				dist[e.to] = level
				queue = append(queue, e.to)
			}
		}
	}
}

// addHighProfileSource records that consequence node cf is backed by high-profile
// listener or entry node src gated by action cut so target velocity applies only
// when that exact edge survives and src is reachable in the same entry state.
func (g *graph) addHighProfileSource(cf, src, cut int) {
	he := highProfileEdge{src: src, cut: cut}
	if !slices.Contains(g.highProfileSources[cf], he) {
		g.highProfileSources[cf] = append(g.highProfileSources[cf], he)
	}
}

// isHighProfileIn reports whether fact n/f is backed by a high-profile target
// signal reachable in state dist (falling back to base when a listener degraded
// to unknown under a counterfactual cut) along an uncut edge.
func (g *graph) isHighProfileIn(n int, f fact, dist, base []uint8, cuts []bool) bool {
	if g.highProfileHost[f.asset] {
		return true
	}
	for _, he := range g.highProfileSources[n] {
		if cuts != nil && he.cut != 0 && cuts[he.cut] {
			continue
		}
		if he.src >= len(dist) {
			continue
		}
		sd := dist[he.src]
		if base != nil && sd == unknown && he.src < len(base) && base[he.src] < unknown {
			sd = base[he.src]
		}
		if sd < unknown {
			return true
		}
	}
	return false
}

// factPriority applies the base priority matrix and the additive high-profile
// target velocity rule (+1 step on any-source external reach not already P1).
// Version-matched CVE facts are excluded so product-history velocity never
// outranks or inverts an exact KEV match on the same product.
func (g *graph) factPriority(s start, n int, f fact, d uint8, dist, base []uint8, cuts []bool) Priority {
	p := PriorityFor(s.audience, difficulties[d], g.assets[f.asset].profile.Tier)
	if s.audience == AudienceInternetAny && d < unknown && p > P1 && !strings.HasPrefix(f.detail, "CVE-") && g.isHighProfileIn(n, f, dist, base, cuts) {
		return PromotePriority(p)
	}
	return p
}

// exposure translates a reachable fact into an owner-facing assessment.
func (g *graph) exposure(s start, n int, f fact, level uint8, dist []uint8) Exposure {
	a := g.assets[f.asset]
	e := Exposure{Entry: s.entry, Asset: f.asset, Name: cmp.Or(a.name, f.asset), Consequence: f.detail, State: "exposed", Difficulty: difficulties[level], HighProfile: g.isHighProfileIn(n, f, dist, nil, nil)}
	if f.kind == blocked {
		e.State = "contained"
		e.Difficulty = ""
		return e
	}
	if f.kind == permission && level != unknown {
		e.State = "no-known-path"
		level = max(level, moderate)
		e.Difficulty = difficulties[level]
	}
	e.Priority = g.factPriority(s, n, f, level, dist, nil, nil)
	switch {
	case level == unknown:
		e.State = "unknown"
		e.Lane = LaneVerify
	case level == moderate && f.kind != permission:
		e.State = "needs-verification"
		e.Lane = LaneVerify
	case s.entry == Physical || s.entry == AssumeBreach || s.entry == CloudEgress:
		e.Lane = LaneReduceExposure
	case e.Priority <= P2:
		e.Lane = LaneFixNow
	default:
		e.Lane = LaneReduceExposure
	}
	return e
}

// exposures publishes a negative assessment only when a stronger fact for the
// same starting point and asset does not supersede it.
func (g *graph) exposures(states [][]uint8) []Exposure {
	out := make([]Exposure, 0)
	for i, dist := range states {
		best := map[string]int{}
		var rows []Exposure
		for n, d := range dist {
			f := g.facts[n]
			if d == unreachable || (f.kind != consequence && f.kind != permission && f.kind != blocked) {
				continue
			}
			e := g.exposure(starts[i], n, f, d, dist)
			order := stateOrder(e.State)
			best[f.asset] = max(best[f.asset], order)
			rows = append(rows, e)
		}
		for _, e := range rows {
			if e.State == "exposed" || e.State == "unknown" || e.State == "needs-verification" || best[e.Asset] == stateOrder(e.State) {
				out = append(out, e)
			}
		}
	}
	slices.SortFunc(out, func(a, b Exposure) int {
		return cmp.Or(cmp.Compare(a.Entry, b.Entry), cmp.Compare(a.Asset, b.Asset), cmp.Compare(a.Consequence, b.Consequence), cmp.Compare(a.State, b.State))
	})
	return out
}

func stateOrder(s string) int {
	switch s {
	case "exposed":
		return 4
	case "unknown", "needs-verification":
		return 3
	case "no-known-path":
		return 2
	default:
		return 1
	}
}

// addAsset keeps offline platform targets visible even without a network attachment.
func (g *graph) addAsset(key, name string, p classify.AssetProfile) {
	if !p.Tier.Valid() {
		p.Tier = classify.TierMedium
	}
	g.assets[key] = asset{cmp.Or(name, key), p}
}

func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

func serviceName(proto string, port int) string { return fmt.Sprintf("%s/%d", proto, port) }
