// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package topology

import (
	"testing"

	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestBuildTopologyPlacement verifies that Build groups clients by VLAN and
// assigns PlacementIsolate to internal IoT appliances and PlacementReview to WAN proxies.
func TestBuildTopologyPlacement(t *testing.T) {
	snap := &unifi.Snapshot{
		Site:           "default",
		ControllerType: "integration-v1",
		Devices: []unifi.Device{
			{Name: "Gateway", Model: "UDM Pro", IP: "192.168.1.1", Version: "4.1.0"},
			{Name: "Core Switch", Model: "USW 24 PoE", IP: "192.168.1.2", Version: "7.1.0", MAC: "aa:00:00:00:00:01", UplinkName: "Gateway", UplinkPort: 11},
		},
		Zones: []unifi.FirewallZone{
			{ID: "z1", Name: "Internal", NetworkIDs: []string{"n1"}},
			{ID: "z2", Name: "Hotspot", NetworkIDs: []string{"n2"}},
			{ID: "z3", Name: "Dmz"},
		},
		Networks: []unifi.Network{
			{ID: "n1", Name: "LAN-Main", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "n2", Name: "VLAN-Isolated", VLAN: "50", Subnet: "192.168.50.1/24", Purpose: "guest", ZoneName: "Hotspot"},
		},
		Clients: []unifi.Client{
			{IP: "192.168.1.10", MAC: "aa:bb:cc:00:00:01", Name: "laptop-1", NetworkID: "n1", NetworkName: "LAN-Main"},
			{IP: "192.168.1.20", MAC: "aa:bb:cc:00:00:02", Name: "appliance-1", NetworkID: "n1", NetworkName: "LAN-Main", IsWired: true, SwitchMAC: "aa:00:00:00:00:01", SwitchPort: 4},
			{IP: "192.168.1.30", MAC: "aa:bb:cc:00:00:03", Name: "proxy-1", NetworkID: "n1", NetworkName: "LAN-Main", IsWired: true},
		},
		PortForwards: []unifi.PortForward{
			{Name: "HTTPS", Enabled: true, Proto: "tcp", DstPort: "443", FwdIP: "192.168.1.30", FwdPort: "443"},
		},
	}

	classes := map[string]classify.Result{
		"192.168.1.10": {Category: classify.CategoryPersonal, Role: "Mobile / Workstation"},
		"192.168.1.20": {Category: classify.CategoryIoT, Role: "IoT / Building Control"},
		"192.168.1.30": {Category: classify.CategoryNetService, Role: "WAN Web Entrypoint"},
	}

	model := Build(snap, classes, config.NetworkConfig{})
	if model.Gateway == nil || model.Gateway.Name != "Gateway" {
		t.Fatalf("expected Gateway device to be detected, got %+v", model.Gateway)
	}
	if !model.HasUnusedDMZ {
		t.Fatal("expected HasUnusedDMZ=true when WAN proxy sits in Internal and DMZ zone is empty")
	}

	// Verify appliance-1 gets PlacementIsolate and proxy-1 gets PlacementReview.
	placements := make(map[string]Placement)
	for _, vg := range model.VLANs {
		for _, cl := range vg.Clients {
			placements[cl.IP] = cl.Placement
		}
	}
	if placements["192.168.1.10"] != PlacementOK {
		t.Fatalf("laptop placement = %q, want ok", placements["192.168.1.10"])
	}
	if placements["192.168.1.20"] != PlacementIsolate {
		t.Fatalf("iot appliance placement = %q, want isolate", placements["192.168.1.20"])
	}
	if placements["192.168.1.30"] != PlacementReview {
		t.Fatalf("wan proxy placement = %q, want review", placements["192.168.1.30"])
	}
}

// TestBuildGroupsUnassignedClientsIntoSingleVLAN verifies that multiple clients
// without a resolvable NetworkName or NetworkID share a single "Unassigned"
// VLAN group rather than creating one duplicate group per client.
func TestBuildGroupsUnassignedClientsIntoSingleVLAN(t *testing.T) {
	snap := &unifi.Snapshot{
		Site:           "default",
		ControllerType: "classic",
		Networks: []unifi.Network{
			{ID: "n1", Name: "Default", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
		},
		Clients: []unifi.Client{
			{IP: "192.168.1.10", MAC: "aa:bb:cc:00:00:01", Name: "known-host", NetworkID: "n1", NetworkName: "Default"},
			{IP: "192.168.1.20", MAC: "aa:bb:cc:00:00:02", Name: "orphan-1"},
			{IP: "192.168.1.21", MAC: "aa:bb:cc:00:00:03", Name: "orphan-2", NetworkName: "   "},
			{IP: "192.168.1.22", MAC: "aa:bb:cc:00:00:04", Name: "orphan-3", NetworkID: "missing-net"},
		},
	}

	model := Build(snap, nil, config.NetworkConfig{})
	if len(model.VLANs) != 2 {
		t.Fatalf("got %d VLAN groups (%+v), want 2 (Default + single Unassigned)", len(model.VLANs), model.VLANs)
	}

	unassignedGroups := 0
	unassignedClients := 0
	for _, vg := range model.VLANs {
		if vg.Name == "Unassigned" {
			unassignedGroups++
			unassignedClients += len(vg.Clients)
		}
	}
	if unassignedGroups != 1 {
		t.Fatalf("got %d Unassigned VLAN groups, want 1", unassignedGroups)
	}
	if unassignedClients != 3 {
		t.Fatalf("got %d clients in Unassigned VLAN group, want 3", unassignedClients)
	}
}
