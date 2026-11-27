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
		ScoringVersion: CurrentScoringVersion,
		UpdatedAt:      time.Now().UTC(),
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

func TestSplitZoneBlocksCoverEveryNetworkPair(t *testing.T) {
	nets := []unifi.Network{
		{ID: "a", Name: "Sensors", ZoneName: "IoT", Subnet: "10.0.10.0/24"},
		{ID: "b", Name: "Doorbells", ZoneName: "IoT", Subnet: "10.0.11.0/24"},
		{ID: "c", Name: "LAN", ZoneName: "Internal", Subnet: "10.0.1.0/24"},
		{ID: "d", Name: "Servers", ZoneName: "Internal", Subnet: "10.0.2.0/24"},
	}
	endpoint := func(zone, network string) unifi.PolicyEndpoint {
		ep := unifi.PolicyEndpoint{ZoneName: zone, AnyPort: true, AnyTarget: network == ""}
		if network != "" {
			ep.NetworkIDs = []string{network}
		}
		return ep
	}
	block := func(src, dst, action string) unifi.FirewallPolicy {
		return unifi.FirewallPolicy{ID: src + "-" + dst, Enabled: true, Action: action, IPVersion: "both", Protocol: "all",
			Source: endpoint("IoT", src), Destination: endpoint("Internal", dst)}
	}
	assertZones := func(t *testing.T, policies []unifi.FirewallPolicy, intent, enforced bool) {
		t.Helper()
		snap := &unifi.Snapshot{Networks: nets, FirewallPolicies: policies}
		if got := intendedIsolatedZoneSet(snap)["iot"]; got != intent {
			t.Errorf("isolation intent = %t, want %t", got, intent)
		}
		if got := IsolatedZones(snap)["iot"]; got != enforced {
			t.Errorf("isolation enforced = %t, want %t", got, enforced)
		}
	}
	rows := []unifi.FirewallPolicy{block("a", "", "DROP"), block("Doorbells", "", "REJECT")}
	assertZones(t, rows, true, true)
	assertZones(t, []unifi.FirewallPolicy{block("", "LAN", "BLOCK"), block("", "d", "DROP")}, true, true)
	assertZones(t, []unifi.FirewallPolicy{block("a", "c", "BLOCK"), block("b", "d", "BLOCK")}, false, false)
	assertZones(t, append([]unifi.FirewallPolicy{block("b", "d", "ALLOW")}, rows...), true, false)

	for name, narrow := range map[string]func(*unifi.FirewallPolicy){
		"scheduled":   func(p *unifi.FirewallPolicy) { p.Schedule = "night" },
		"tcp":         func(p *unifi.FirewallPolicy) { p.Protocol = "tcp" },
		"established": func(p *unifi.FirewallPolicy) { p.ConnectionStates = []string{"established"} },
		"ipv6":        func(p *unifi.FirewallPolicy) { p.IPVersion = "ipv6" },
		"source_port": func(p *unifi.FirewallPolicy) {
			p.Source.AnyPort = false
			p.Source.Ports = []int{53}
		},
		"dest_port": func(p *unifi.FirewallPolicy) {
			p.Destination.AnyPort = false
			p.Destination.Ports = []int{53}
		},
	} {
		t.Run(name, func(t *testing.T) {
			second := rows[1]
			narrow(&second)
			assertZones(t, []unifi.FirewallPolicy{rows[0], second}, false, false)
		})
	}
}

func TestApprovedRolesMatchPluralsAndWholePhrases(t *testing.T) {
	for _, tc := range []struct {
		role, host string
		want       bool
	}{
		{"NASes", "synology", true}, {"printers", "laserjet", true}, {"upses", "ups01", true},
		{"switches", "switch01", true}, {"routers", "router", true}, {"servers", "server", true},
		{"cameras", "camera", true}, {"router", "routers", true},
		{"home-assistant", "home-nas", false}, {"media-server", "file-server", false},
		{"home-assistant", "home-assistant01", true}, {"media-servers", "media-server01", true},
		{"UPS", "cups-printserver", false}, {"printer", "cup", false}, {"---", "server", false},
	} {
		if got := clientMatchesApprovedRole(unifi.Client{Hostname: tc.host}, nil, tc.role, ""); got != tc.want {
			t.Errorf("role %q, hostname %q: got %t, want %t", tc.role, tc.host, got, tc.want)
		}
	}
}
