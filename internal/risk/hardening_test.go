// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

func TestZoneIsolationRecognizesNetworkIDsBlanketBlock(t *testing.T) {
	snap := &unifi.Snapshot{
		Networks: []unifi.Network{
			{ID: "net-main", Name: "Default", Purpose: "corporate", ZoneName: "Internal", Subnet: "192.168.1.1/24"},
			{ID: "net-iot", Name: "IoT", Purpose: "corporate", ZoneName: "IoT", Subnet: "192.168.20.1/24", VLAN: "20"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID:               "pol-iot-block",
				Name:             "Block IoT to Internal",
				Enabled:          true,
				Action:           "BLOCK",
				Protocol:         "all",
				IPVersion:        "BOTH",
				ConnectionStates: []string{"NEW"},
				Source: unifi.PolicyEndpoint{
					ZoneName:   "IoT",
					NetworkIDs: []string{"net-iot"},
				},
				Destination: unifi.PolicyEndpoint{
					ZoneName:   "Internal",
					NetworkIDs: []string{"net-main"},
				},
			},
		},
	}

	iotClient := unifi.Client{MAC: "aa:bb:cc:dd:ee:20", IP: "192.168.20.50", NetworkName: "IoT", VLAN: "20"}
	if IsClientOnTrustedVLAN(snap, iotClient, config.NetworkConfig{}) {
		t.Fatal("IoT zone blocked via explicit NetworkIDs must be treated as isolated, not trusted")
	}
	mainClient := unifi.Client{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.50", NetworkName: "Default"}
	if !IsClientOnTrustedVLAN(snap, mainClient, config.NetworkConfig{}) {
		t.Fatal("Default Internal network should remain trusted")
	}
}

func TestLegacyFourPartUDPFindingKeyMigratesWithoutReAlert(t *testing.T) {
	cl := unifi.Client{MAC: "aa:bb:cc:dd:ee:53", IP: "192.168.1.53", NetworkName: "Default"}
	snap := &unifi.Snapshot{Clients: []unifi.Client{cl}}
	f := checks.Finding{
		CheckID:           "UB-0010",
		Client:            cl,
		Port:              53,
		Transport:         "udp",
		Property:          "dns-open-recursion",
		BaseSeverity:      checks.SeverityLow,
		EffectiveSeverity: checks.SeverityLow,
	}
	report := Report{Findings: []checks.Finding{f}}
	prev := &State{
		UpdatedAt: time.Now().UTC(),
		Findings: map[string]checks.Severity{
			"UB-0010|aa:bb:cc:dd:ee:53|53|udp": checks.SeverityLow,
		},
		TrustedClients: map[string]string{cl.MAC: cl.DisplayName()},
		PortForwards:   map[string]string{},
	}

	diff := ComputeDiffWithProbed(prev, snap, report, config.NetworkConfig{}, map[string]struct{}{cl.MAC: {}})
	if len(diff.NewFindings) != 0 || len(diff.ResolvedKeys) != 0 {
		t.Fatalf("legacy 4-part UDP key should migrate cleanly without re-alert, got new=%+v resolved=%+v", diff.NewFindings, diff.ResolvedKeys)
	}
}
