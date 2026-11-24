// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/topology"
	"github.com/karalabe/uniblue/internal/unifi"
)

func TestBuildPresentationModelInvariants(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "Servers", VLAN: "2", Subnet: "192.0.2.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "n2", Name: "IoT", VLAN: "30", Subnet: "198.51.100.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.0.2.1", Model: "UDM Pro", Type: "udm"},
			{Name: "Orphan Switch", MAC: "aa:00:00:00:00:02", IP: "192.0.2.2", Model: "USW-8", Type: "usw"},
		},
		Clients: []unifi.Client{
			// Regression fixture: 0 check findings + 3 exact CVEs -> MUST be Exposed, never OK/Clean!
			{MAC: "11:11:11:11:11:01", IP: "192.0.2.10", Name: "app-cve-host", NetworkName: "Servers", IsWired: true},
			// Unscanned host -> MUST be Unknown, never OK!
			{MAC: "11:11:11:11:11:02", IP: "192.0.2.11", Name: "unscanned-host", NetworkName: "Servers", IsWired: true},
			// BMC host -> MUST be placed in LogicalLane.BMCIDs (never collapsed into CleanHostIDs) with Weight=3!
			{MAC: "11:11:11:11:11:03", IP: "192.0.2.5", Name: "Server Management Console", NetworkName: "Servers", IsWired: true},
			// Freshly scanned clean host -> MUST be OK!
			{MAC: "11:11:11:11:11:04", IP: "192.0.2.12", Name: "clean-host", NetworkName: "Servers", IsWired: true},
		},
	}

	classes := map[string]classify.Result{
		"192.0.2.10": {Category: classify.CategoryServer, Role: "Server"},
		"192.0.2.11": {Category: classify.CategoryPersonal, Role: "Laptop"},
		"192.0.2.5":  {Category: classify.CategoryBMC, Role: "Out-of-Band BMC / IPMI"},
		"192.0.2.12": {Category: classify.CategoryServer, Role: "Server"},
	}

	clientViews := []ClientView{
		{Client: snap.Clients[0], Class: classes["192.0.2.10"], MaxSeverity: "clean", LastScannedAt: &now},
		{Client: snap.Clients[1], Class: classes["192.0.2.11"], MaxSeverity: "clean", LastScannedAt: nil},
		{Client: snap.Clients[2], Class: classes["192.0.2.5"], MaxSeverity: "clean", LastScannedAt: &now},
		{Client: snap.Clients[3], Class: classes["192.0.2.12"], MaxSeverity: "clean", LastScannedAt: &now},
	}

	exactCVEs := []cve.ProductSummary{
		{
			Product: cve.Product{
				HostIP:   "192.0.2.10",
				HostName: "app-cve-host",
				Label:    "OpenSSH",
				Version:  "8.9p1",
			},
			Confidence:  cve.ConfidenceExact,
			TotalCVEs:   3,
			MaxSeverity: checks.SeverityHigh,
			MaxCVSS:     8.1,
			TopCVEs:     []string{"CVE-2024-6387", "CVE-2023-38408", "CVE-2023-48795"},
		},
	}

	report := risk.Evaluate(snap, nil, config.NetworkConfig{})
	topo := topology.Build(snap, classes, config.NetworkConfig{})
	pm := BuildPresentationModel(snap, report, topo, clientViews, exactCVEs, nil, nil)

	// 1. Exact-CVE-only host MUST be Exposed (never OK/Clean), with 3 exact CVEs.
	cveEnt := pm.Entities["host:11:11:11:11:11:01"]
	if cveEnt == nil || cveEnt.State != VerdictExposed || cveEnt.ExactCVECount != 3 || cveEnt.MaxSeverity != "high" {
		t.Fatalf("expected exact-CVE host to be Exposed/high/3 CVEs, got %+v", cveEnt)
	}

	// 2. Unscanned host MUST be Unknown.
	unscanned := pm.Entities["host:11:11:11:11:11:02"]
	if unscanned == nil || unscanned.State != VerdictUnknown {
		t.Fatalf("expected unscanned host to be Unknown, got %+v", unscanned)
	}

	// 3. BMC MUST be marked IsBMC, Weight >= 3, Exposed (UB-UNIFI-BMC-SHARED-VLAN), and placed in Servers BMCIDs.
	bmc := pm.Entities["host:11:11:11:11:11:03"]
	if bmc == nil || !bmc.IsBMC || bmc.Weight < 3 || bmc.State != VerdictExposed {
		t.Fatalf("expected BMC to be IsBMC=true Weight>=3 Exposed, got %+v", bmc)
	}
	foundBMCInLane := false
	for _, lane := range pm.Logical {
		if lane.Name == "Servers" && len(lane.BMCIDs) == 1 && lane.BMCIDs[0] == bmc.ID {
			foundBMCInLane = true
		}
	}
	if !foundBMCInLane {
		t.Fatalf("expected BMC in Servers lane BMCIDs, got %+v", pm.Logical)
	}

	// 4. Clean assessed host MUST be OK.
	clean := pm.Entities["host:11:11:11:11:11:04"]
	if clean == nil || clean.State != VerdictOK {
		t.Fatalf("expected freshly scanned clean host to be OK, got %+v", clean)
	}

	// 5. Switch missing uplink MUST be marked UplinkUnknown rather than Root Gateway.
	foundUnknown := false
	for _, row := range pm.Physical {
		if row.Name == "Orphan Switch" && row.UplinkUnknown {
			foundUnknown = true
		}
	}
	if !foundUnknown {
		t.Fatalf("expected Orphan Switch to have UplinkUnknown=true, got %+v", pm.Physical)
	}

	// 6. Census counts MUST match entity predicates.
	if pm.Census.BMCCount != 1 || pm.Census.ExactCVEHosts != 1 || pm.Census.UnassessedCount != 1 {
		t.Fatalf("unexpected census counts: %+v", pm.Census)
	}
}
