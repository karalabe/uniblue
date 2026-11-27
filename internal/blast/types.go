// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package blast estimates which changes would limit exposure in a site snapshot.
package blast

import (
	"slices"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TargetSignal binds a high-confidence historical CVE velocity signal to one
// asset (and optional service port) without changing finding severities.
type TargetSignal struct {
	// Asset is the canonical MAC, controller ID, or IP matching hostKey.
	Asset string
	// Proto is the optional transport ("tcp" or "udp"). Empty matches any service on Asset.
	Proto string
	// Port is the optional service port. Zero matches any service on Asset.
	Port int
	// Product is an optional human-readable software label (e.g. "nginx").
	Product string
	// Velocity is the historical CISA KEV / network-CVE signal from the local cache.
	Velocity cve.TargetVelocity
}

// Input holds the inventory and evidence from one scan. Evaluate borrows all fields.
type Input struct {
	// ControllerHost is the configured controller address without credentials or a port.
	ControllerHost string

	// Snapshot describes the site's inventory, policies and publications.
	Snapshot *unifi.Snapshot
	// Profiles holds observations made on individual hosts.
	Profiles []probe.HostProfile
	// Findings holds matched checks and their original observations.
	Findings []checks.Finding
	// Checks defines the permissions that each matched check can establish.
	Checks []*checks.Check
	// CVEMatches binds vulnerable product versions to observed services.
	CVEMatches []cve.Match
	// TargetSignals supplies high-confidence historical CVE velocity per asset/service.
	TargetSignals []TargetSignal
	// Isolation holds optional precomputed isolation results; blast computes
	// reachability and network roles directly from Snapshot, NetCfg, and Oracle.
	Isolation *risk.IsolationMatrix
	// SwitchPorts supplies the physical perimeter and effective port settings.
	SwitchPorts []risk.SwitchDeviceView
	// Assets supplies asset values and ownership relations keyed by MAC or ID.
	Assets map[string]classify.AssetProfile
	// NetCfg records site intent and approved workflows.
	NetCfg config.NetworkConfig
	// Oracle resolves reachability against this snapshot. Evaluate builds one if omitted.
	Oracle *risk.Oracle
}

// Lane groups work by the kind of decision an owner needs to make.
type Lane string

const (
	// LaneFixNow covers direct exposures with a known remedy.
	LaneFixNow Lane = "fix-now"
	// LaneReduceExposure covers changes that limit access or contain a future compromise.
	LaneReduceExposure Lane = "reduce-exposure"
	// LaneVerify covers missing evidence and unconfirmed prerequisites.
	LaneVerify Lane = "verify"
)

// Entry describes a starting point for the assessment.
type Entry string

const (
	// Internet represents unrestricted inbound access.
	Internet Entry = "internet"
	// InternetSource represents inbound access limited to selected sources.
	InternetSource Entry = "internet-src"
	// WiFi represents someone joining an open or guest wireless network.
	WiFi Entry = "wifi"
	// Physical represents access to an exposed network socket.
	Physical Entry = "physical"
	// AssumeBreach represents an already compromised guest or appliance.
	AssumeBreach Entry = "assume-breach"
	// CloudEgress represents an appliance's outbound vendor connection.
	CloudEgress Entry = "cloud-egress"
	// TrustedLAN represents the local observer of a matched service.
	TrustedLAN Entry = "trusted-lan"
)

// Exposure summarizes one consequence at its easiest modeled difficulty.
type Exposure struct {
	// Entry identifies where access begins.
	Entry Entry `json:"entry"`
	// Asset is the stable device identity.
	Asset string `json:"asset"`
	// Name is the display name of the affected device.
	Name string `json:"name"`
	// Consequence identifies the permission, publication or boundary affected.
	Consequence string `json:"consequence"`
	// State distinguishes exposure, containment, missing evidence and an incomplete chain.
	State string `json:"state"`
	// Difficulty describes the strongest prerequisite on the path.
	Difficulty ChainDifficulty `json:"difficulty,omitempty"`
	// Priority describes the urgency for this starting point and asset.
	Priority Priority `json:"priority,omitempty"`
	// Lane groups the response when there is work to do.
	Lane Lane `json:"lane,omitempty"`
	// HighProfile marks high-confidence targets with recent KEV or sustained remote CVE history.
	HighProfile bool `json:"high_profile,omitempty"`
}

// Action describes a single proposed change and its marginal value in queue order.
type Action struct {
	// ID identifies the control independently of scan order.
	ID string `json:"id"`
	// Title describes the change in everyday language.
	Title string `json:"title"`
	// Reason explains why the change matters.
	Reason string `json:"reason"`
	// Lane identifies the kind of work involved.
	Lane Lane `json:"lane"`
	// HighestTierReduced is the most urgent priority improved by this change.
	HighestTierReduced Priority `json:"highest_tier_reduced,omitempty"`
	// PairsByTier counts distinct device and consequence pairs improved at P1 through P5, capped at three each.
	PairsByTier [5]int `json:"pairs_by_tier"`
	// Benefits names up to three devices helped most by this change, ordered by
	// highest priority reduced first.
	Benefits []string `json:"benefits,omitempty"`
	// AffectedAssets lists up to six devices with a marginal benefit, in priority order.
	AffectedAssets []string `json:"affected_assets,omitempty"`
	// HighProfile marks actions that help protect a frequently targeted software stack.
	HighProfile bool `json:"high_profile,omitempty"`
	// BreaksApproved names approved workflows affected by this change.
	BreaksApproved []string `json:"breaks_approved,omitempty"`

	// targetAssets includes direct targets and all devices helped by this change.
	targetAssets map[string]bool
}

// TargetsAsset reports whether the action applies to a host, including when an
// earlier action in the queue already accounts for its benefit.
func (a Action) TargetsAsset(key string) bool {
	if a.targetAssets == nil {
		return slices.Contains(a.AffectedAssets, key)
	}
	return a.targetAssets[key]
}

// addTarget keeps host filtering independent of the ranked benefit chips.
func (a *Action) addTarget(key string) {
	if key == "" {
		return
	}
	if a.targetAssets == nil {
		a.targetAssets = make(map[string]bool)
	}
	a.targetAssets[key] = true
}

// ClientEgress describes one client's policy and evidence of cloud use.
type ClientEgress struct {
	// Asset identifies the client in the inventory.
	Asset string `json:"asset"`
	// Name is the client's display name.
	Name string `json:"name"`
	// State summarizes policy reachability and observed vendor use.
	State string `json:"state"`
	// Reason explains the evidence for this state.
	Reason string `json:"reason"`
}

// Report contains the deterministic result of evaluating a single scan.
type Report struct {
	// Exposures records reachable consequences and network boundary assessments.
	Exposures []Exposure `json:"exposures"`
	// Actions orders changes by their additional benefit after earlier changes.
	Actions []Action `json:"actions"`
	// Cloud lists per-client egress assessments.
	Cloud []ClientEgress `json:"cloud"`
	// Simulation provides the real topology graph and candidate cuts for interactive UI exploration.
	Simulation *Simulation `json:"simulation,omitempty"`
}
