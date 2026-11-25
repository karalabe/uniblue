// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"testing"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestAnalyzeSwitchPortsExternalDeviceAndFeederTracing verifies external switch
// sorting, LLDP feeder cable tracing, and exterior port security findings.
func TestAnalyzeSwitchPortsExternalDeviceAndFeederTracing(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{
				Name:  "Core Switch",
				MAC:   "aa:aa:aa:aa:aa:01",
				IP:    "192.168.1.2",
				Model: "USW-24-PoE",
				Type:  "usw",
				Ports: []unifi.SwitchPort{
					{
						PortIdx:           1,
						Name:              "Port 1",
						Enabled:           true,
						Up:                true,
						Speed:             1000,
						IsUplink:          true,
						NativeNetworkName: "Default",
						Forward:           "all",
						TaggedVLANMgmt:    "auto",
					},
					{
						PortIdx:           5,
						Name:              "Port 5",
						Enabled:           true,
						Up:                true,
						Speed:             1000,
						NativeNetworkName: "Default",
						Forward:           "all",
						TaggedVLANMgmt:    "auto",
					},
					{
						PortIdx:           10,
						Name:              "Port 10",
						Enabled:           true,
						Up:                true,
						Speed:             1000,
						NativeNetworkName: "IoT",
						Forward:           "all",
						TaggedVLANMgmt:    "auto",
					},
					{
						PortIdx:           11,
						Name:              "Port 11",
						Enabled:           true,
						Up:                true,
						Speed:             1000,
						NativeNetworkName: "IoT",
						Forward:           "native",
						TaggedVLANMgmt:    "block_all",
					},
					{
						PortIdx:           12,
						Name:              "Port 12",
						Enabled:           true,
						Up:                false,
						NativeNetworkName: "Default",
						Forward:           "all",
						TaggedVLANMgmt:    "auto",
					},
				},
			},
			{
				Name:       "Outbuilding Switch",
				MAC:        "bb:bb:bb:bb:bb:02",
				IP:         "192.168.1.3",
				Model:      "USW-Flex-Mini",
				Type:       "usw",
				UplinkName: "Core Switch",
				UplinkMAC:  "aa:aa:aa:aa:aa:01",
				UplinkPort: 5,
				Ports: []unifi.SwitchPort{
					{
						PortIdx:           1,
						Name:              "Port 1",
						Enabled:           true,
						Up:                true,
						Speed:             1000,
						IsUplink:          true,
						NativeNetworkName: "Default",
						Forward:           "all",
						TaggedVLANMgmt:    "auto",
					},
					{
						PortIdx:           2,
						Name:              "Port 2",
						Enabled:           true,
						Up:                true,
						Speed:             100,
						NativeNetworkName: "Default",
						Forward:           "all",
						TaggedVLANMgmt:    "auto",
					},
					{
						PortIdx:             3,
						Name:                "Port 3",
						Enabled:             true,
						Up:                  true,
						Speed:               100,
						NativeNetworkName:   "IoT",
						Forward:             "native",
						TaggedVLANMgmt:      "block_all",
						PortSecurityEnabled: true,
						PortSecurityMACs:    []string{"cc:cc:cc:cc:cc:03"},
					},
					{
						PortIdx:           4,
						Name:              "Port 4",
						Enabled:           true,
						Up:                false,
						NativeNetworkName: "Default",
						Forward:           "all",
						TaggedVLANMgmt:    "auto",
					},
					{
						PortIdx: 5,
						Name:    "Port 5",
						Enabled: false,
						Up:      false,
					},
				},
			},
		},
		Clients: []unifi.Client{
			{
				Name:        "Unsecured Wallbox",
				MAC:         "cc:cc:cc:cc:cc:02",
				IP:          "192.168.1.50",
				IsWired:     true,
				SwitchMAC:   "bb:bb:bb:bb:bb:02",
				SwitchPort:  2,
				NetworkName: "Default",
			},
			{
				Name:        "Locked Charger",
				MAC:         "cc:cc:cc:cc:cc:03",
				IP:          "192.168.20.51",
				IsWired:     true,
				SwitchMAC:   "bb:bb:bb:bb:bb:02",
				SwitchPort:  3,
				NetworkName: "IoT",
			},
			{
				Name:        "IoT Bridge",
				MAC:         "cc:cc:cc:cc:cc:10",
				IP:          "192.168.20.10",
				IsWired:     true,
				SwitchMAC:   "aa:aa:aa:aa:aa:01",
				SwitchPort:  10,
				NetworkName: "IoT",
			},
			{
				Name:        "Locked IoT Hub",
				MAC:         "cc:cc:cc:cc:cc:11",
				IP:          "192.168.20.11",
				IsWired:     true,
				SwitchMAC:   "aa:aa:aa:aa:aa:01",
				SwitchPort:  11,
				NetworkName: "IoT",
			},
		},
	}

	netCfg := config.NetworkConfig{
		ExternalDevices: []string{"Outbuilding Switch"},
		PhysicalPorts: []config.PhysicalPortRule{
			{
				Device:      "Outbuilding Switch",
				Port:        3,
				Zone:        "external",
				Label:       "Locked EV Charger",
				AllowedMACs: []string{"cc:cc:cc:cc:cc:03"},
			},
		},
	}
	trusted := map[string]struct{}{"default": {}}
	isolated := map[string]struct{}{"iot": {}}

	views, findings, notes := AnalyzeSwitchPorts(snap, netCfg, trusted, isolated)
	if len(views) != 2 {
		t.Fatalf("expected 2 switch views, got %d", len(views))
	}

	// External switches should sort first.
	if !views[0].ExternalDevice || views[0].Name != "Outbuilding Switch" {
		t.Fatalf("expected Outbuilding Switch first as external device, got %+v", views[0])
	}
	if views[0].ZoneSource != "config" {
		t.Errorf("expected config zone source, got %q", views[0].ZoneSource)
	}

	// Verify Core Switch Port 5 was automatically traced as external_uplink.
	var corePort5, extPort3, extPort5 *SwitchPortView
	for i := range views {
		for j := range views[i].Ports {
			p := &views[i].Ports[j]
			if views[i].Name == "Core Switch" && p.PortIdx == 5 {
				corePort5 = p
			}
			if views[i].Name == "Outbuilding Switch" && p.PortIdx == 3 {
				extPort3 = p
			}
			if views[i].Name == "Outbuilding Switch" && p.PortIdx == 5 {
				extPort5 = p
			}
		}
	}
	if corePort5 == nil || corePort5.Zone != "external_uplink" || corePort5.Status != "critical" {
		t.Fatalf("expected Core Switch Port 5 to be critical external_uplink, got %+v", corePort5)
	}
	if extPort3 == nil || extPort3.Status != "ok" {
		t.Fatalf("expected properly locked external Port 3 to be ok, got %+v", extPort3)
	}
	if extPort5 == nil || extPort5.State != "disabled" || extPort5.Status != "ok" {
		t.Fatalf("expected disabled external Port 5 to be ok, got %+v", extPort5)
	}

	// Verify expected findings were emitted.
	seen := make(map[string]checks.Severity)
	for _, f := range findings {
		seen[f.CheckID] = f.EffectiveSeverity
	}
	wantFindings := map[string]checks.Severity{
		"UB-UNIFI-PORT-EXT-UPLINK":       checks.SeverityCritical,
		"UB-UNIFI-PORT-EXT-UNRESTRICTED": checks.SeverityCritical,
		"UB-UNIFI-PORT-EXT-UNUSED-OPEN":  checks.SeverityHigh,
		"UB-UNIFI-PORT-VLAN-HOP":         checks.SeverityHigh,
	}
	for id, wantSev := range wantFindings {
		gotSev, ok := seen[id]
		if !ok {
			t.Errorf("missing expected finding %s", id)
		} else if gotSev != wantSev {
			t.Errorf("finding %s severity = %v, want %v", id, gotSev, wantSev)
		}
	}
	if len(notes) == 0 {
		t.Error("expected indoor unused port posture note on Core Switch Port 12")
	}
}

// TestAnalyzeSwitchPortsUnauthorizedMACAndAutoExternal verifies explicit
// allowed_macs enforcement and automatic outdoor switch inference by device name.
func TestAnalyzeSwitchPortsUnauthorizedMACAndAutoExternal(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{
				Name:  "Garage Switch",
				MAC:   "dd:dd:dd:dd:dd:01",
				IP:    "192.168.1.9",
				Model: "USW-Flex",
				Type:  "usw",
				Ports: []unifi.SwitchPort{
					{
						PortIdx:             2,
						Name:                "Port 2",
						Enabled:             true,
						Up:                  true,
						Speed:               1000,
						NativeNetworkName:   "IoT",
						Forward:             "native",
						TaggedVLANMgmt:      "block_all",
						PortSecurityEnabled: true,
					},
				},
			},
		},
		Clients: []unifi.Client{
			{
				Name:        "Rogue Laptop",
				MAC:         "ee:ee:ee:ee:ee:99",
				IP:          "192.168.20.99",
				IsWired:     true,
				SwitchMAC:   "dd:dd:dd:dd:dd:01",
				SwitchPort:  2,
				NetworkName: "IoT",
			},
		},
	}

	netCfg := config.NetworkConfig{
		PhysicalPorts: []config.PhysicalPortRule{
			{
				Device:      "Garage Switch",
				Port:        2,
				Zone:        "external",
				AllowedMACs: []string{"11:22:33:44:55:66"},
			},
		},
	}

	views, findings, _ := AnalyzeSwitchPorts(snap, netCfg, map[string]struct{}{"default": {}}, map[string]struct{}{"iot": {}})
	if len(views) != 1 || !views[0].ExternalDevice || views[0].ZoneSource != "auto" {
		t.Fatalf("expected Garage Switch to auto-classify as external, got %+v", views)
	}
	foundUnauth := false
	for _, f := range findings {
		if f.CheckID == "UB-UNIFI-PORT-UNAUTHORIZED-MAC" && f.EffectiveSeverity == checks.SeverityCritical {
			foundUnauth = true
		}
	}
	if !foundUnauth {
		t.Fatalf("expected CRITICAL UB-UNIFI-PORT-UNAUTHORIZED-MAC finding, got %+v", findings)
	}
}
