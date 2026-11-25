// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestEvaluateBlastRadiusScoring verifies severity escalation on trusted VLANs,
// de-escalation on isolated VLANs, and Critical promotion on WAN port forwards.
func TestEvaluateBlastRadiusScoring(t *testing.T) {
	netCfg := config.NetworkConfig{
		TrustedVLANs:  []string{"Default"},
		IsolatedVLANs: []string{"IoT"},
	}

	snap := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{IP: "192.168.1.10", MAC: "aa:01", Name: "hvac-trusted", NetworkName: "Default"},
			{IP: "192.168.20.10", MAC: "aa:02", Name: "hvac-iot", NetworkName: "IoT"},
			{IP: "192.168.20.20", MAC: "aa:03", Name: "cam-exposed", NetworkName: "IoT"},
		},
		PortForwards: []unifi.PortForward{
			{Name: "Cam-WAN", Enabled: true, Proto: "tcp", DstPort: "554", FwdIP: "192.168.20.20", FwdPort: "554", Src: "any"},
		},
	}

	raw := []checks.Finding{
		{CheckID: "UB-0003", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[0], Port: 502},
		{CheckID: "UB-0003", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[1], Port: 502},
		{CheckID: "UB-0004", BaseSeverity: checks.SeverityMedium, Client: snap.Clients[2], Port: 554},
	}

	report := Evaluate(snap, raw, netCfg)
	got := make(map[string]checks.Severity)
	for _, f := range report.Findings {
		got[f.Key()] = f.EffectiveSeverity
	}

	// Trusted VLAN bumps high -> critical.
	if got["UB-0003|aa:01|502"] != checks.SeverityCritical {
		t.Fatalf("trusted VLAN finding = %v, want critical", got["UB-0003|aa:01|502"])
	}
	// Isolated VLAN lowers high -> medium.
	if got["UB-0003|aa:02|502"] != checks.SeverityMedium {
		t.Fatalf("isolated VLAN finding = %v, want medium", got["UB-0003|aa:02|502"])
	}
	// WAN port forward forces medium -> critical even on IoT VLAN.
	if got["UB-0004|aa:03|554"] != checks.SeverityCritical {
		t.Fatalf("WAN-exposed finding = %v, want critical", got["UB-0004|aa:03|554"])
	}
}

// TestStatePersistenceAndDiffing verifies state save/load round-trips and diff
// detection for escalated findings and newly appearing trusted clients.
func TestStatePersistenceAndDiffing(t *testing.T) {
	netCfg := config.NetworkConfig{
		TrustedVLANs:  []string{"Default"},
		IsolatedVLANs: []string{"IoT"},
	}

	// First scan: device sits safely on IoT VLAN.
	snap1 := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{IP: "192.168.20.10", MAC: "aa:02", Name: "hvac", NetworkName: "IoT"},
		},
	}
	raw1 := []checks.Finding{
		{CheckID: "UB-0003", BaseSeverity: checks.SeverityHigh, Client: snap1.Clients[0], Port: 502},
	}
	rep1 := Evaluate(snap1, raw1, netCfg)
	st1 := BuildState(snap1, rep1, netCfg)

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := SaveState(statePath, st1); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	loaded, err := LoadState(statePath)
	if err != nil || loaded == nil {
		t.Fatalf("LoadState: %v (loaded=%v)", err, loaded)
	}

	// Second scan: same device moved onto Trusted VLAN + a brand new device joins Trusted VLAN.
	snap2 := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{IP: "192.168.1.10", MAC: "aa:02", Name: "hvac", NetworkName: "Default"},
			{IP: "192.168.1.99", MAC: "bb:99", Name: "rogue-laptop", NetworkName: "Default"},
		},
	}
	raw2 := []checks.Finding{
		{CheckID: "UB-0003", BaseSeverity: checks.SeverityHigh, Client: snap2.Clients[0], Port: 502},
	}
	rep2 := Evaluate(snap2, raw2, netCfg)

	diff := ComputeDiff(loaded, snap2, rep2, netCfg)
	if len(diff.EscalatedFindings) != 1 {
		t.Fatalf("expected 1 escalated finding, got %d", len(diff.EscalatedFindings))
	}
	if len(diff.NewTrustedClients) != 2 {
		t.Fatalf("expected 2 newly seen trusted clients (moved hvac + rogue-laptop), got %d", len(diff.NewTrustedClients))
	}
	if !diff.HasAlerts(checks.SeverityHigh) {
		t.Fatal("expected diff to trigger high-severity alert")
	}
}

// TestExposureClassificationAndPostureNotes verifies WAN forward classification
// (expected P2P vs. critical RPC) and unused isolated VLAN posture notes.
func TestExposureClassificationAndPostureNotes(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "VLAN-Alpha", VLAN: "1", ZoneName: "Internal", Purpose: "corporate"},
			{ID: "n2", Name: "VLAN-Beta", VLAN: "40", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		Clients: []unifi.Client{
			{IP: "10.0.1.50", MAC: "aa:01", Name: "appliance-1", NetworkName: "VLAN-Alpha"},
			{IP: "10.0.1.60", MAC: "aa:02", Name: "node-1", NetworkName: "VLAN-Alpha"},
		},
		PortForwards: []unifi.PortForward{
			{Name: "Ethereum DevP2P", Enabled: true, Proto: "tcp_udp", DstPort: "30303", FwdIP: "10.0.1.60", FwdPort: "30303", Src: "any"},
			{Name: "Accidental Eth RPC", Enabled: true, Proto: "tcp", DstPort: "8545", FwdIP: "10.0.1.60", FwdPort: "8545", Src: "any"},
		},
	}

	raw := []checks.Finding{
		{CheckID: "UB-2026-0001", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[0], Port: 56747},
	}

	report := Evaluate(snap, raw, config.NetworkConfig{})

	// Expect 2 WAN surface entries: DevP2P classified INFO (expected-p2p), RPC classified CRITICAL (dangerous-rpc).
	if len(report.WANSurface) != 2 {
		t.Fatalf("expected 2 WAN surface items, got %d", len(report.WANSurface))
	}
	if report.WANSurface[0].Class != "dangerous-rpc" || report.WANSurface[0].Severity != checks.SeverityCritical {
		t.Fatalf("expected RPC forward to be CRITICAL dangerous-rpc, got %+v", report.WANSurface[0])
	}
	if report.WANSurface[1].Class != "expected-p2p" || report.WANSurface[1].Severity != checks.SeverityInfo {
		t.Fatalf("expected DevP2P forward to be INFO expected-p2p, got %+v", report.WANSurface[1])
	}

	// Only the CRITICAL RPC forward (not expected DevP2P) should appear as a Finding.
	portFwdFindings := 0
	for _, f := range report.Findings {
		if f.CheckID == "UB-UNIFI-PORTFWD" {
			portFwdFindings++
		}
	}
	if portFwdFindings != 1 {
		t.Fatalf("expected exactly 1 actionable port-forward finding (RPC only), got %d", portFwdFindings)
	}

	// Unused structurally-isolated VLAN posture note should fire regardless of VLAN name.
	if len(report.PostureNotes) == 0 || !strings.Contains(report.PostureNotes[0].Title, "VLAN-Beta") {
		t.Fatalf("expected posture note flagging unused isolated VLAN-Beta, got %+v", report.PostureNotes)
	}
}

// TestStructuralZoneIsolationAndFlatTopology verifies zone-based isolation
// resolution without relying on VLAN names, plus flat-topology posture reporting.
func TestStructuralZoneIsolationAndFlatTopology(t *testing.T) {
	// Use completely opaque VLAN names ("ZoneA", "ZoneB", "ZoneC") to guarantee
	// zero reliance on user-chosen network names.
	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "ZoneA", VLAN: "10", ZoneName: "Internal", Purpose: "corporate"},
			{ID: "n2", Name: "ZoneB", VLAN: "20", ZoneName: "Hotspot"},
			{ID: "n3", Name: "ZoneC", VLAN: "30", ZoneName: "CustomSegmented"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID:      "p-block-custom",
				Name:    "Block CustomSegmented to Internal",
				Enabled: true,
				Action:  "BLOCK",
				Origin:  "USER_DEFINED",
				Source:  unifi.PolicyEndpoint{ZoneName: "CustomSegmented", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{
					ZoneName:  "Internal",
					AnyTarget: true,
					AnyPort:   true,
				},
			},
		},
		Clients: []unifi.Client{
			{IP: "10.10.0.5", MAC: "aa:01", Name: "host-a", NetworkName: "ZoneA", VLAN: "10"},
			{IP: "10.20.0.5", MAC: "aa:02", Name: "host-b", NetworkName: "ZoneB", VLAN: "20"},
			{IP: "10.30.0.5", MAC: "aa:03", Name: "host-c", NetworkName: "ZoneC", VLAN: "30"},
		},
	}
	raw := []checks.Finding{
		{CheckID: "UB-0001", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[0], Port: 23},
		{CheckID: "UB-0001", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[1], Port: 23},
		{CheckID: "UB-0001", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[2], Port: 23},
	}

	report := Evaluate(snap, raw, config.NetworkConfig{})
	got := make(map[string]checks.Severity)
	for _, f := range report.Findings {
		got[f.Key()] = f.EffectiveSeverity
	}
	if got["UB-0001|aa:01|23"] != checks.SeverityCritical {
		t.Fatalf("expected Internal-zone VLAN to bump high->critical, got %v", got["UB-0001|aa:01|23"])
	}
	if got["UB-0001|aa:02|23"] != checks.SeverityMedium {
		t.Fatalf("expected Hotspot-zone VLAN to lower high->medium, got %v", got["UB-0001|aa:02|23"])
	}
	if got["UB-0001|aa:03|23"] != checks.SeverityMedium {
		t.Fatalf("expected custom policy-blocked zone to lower high->medium, got %v", got["UB-0001|aa:03|23"])
	}

	// Flat network (no isolated VLANs at all) should emit a flat-topology posture note.
	flatSnap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "OnlyNet", VLAN: "1", ZoneName: "Internal", Purpose: "corporate"},
		},
		Clients: []unifi.Client{
			{IP: "192.168.1.50", MAC: "aa:01", Name: "host-a", NetworkName: "OnlyNet", VLAN: "1"},
		},
	}
	flatReport := Evaluate(flatSnap, []checks.Finding{
		{CheckID: "UB-0001", BaseSeverity: checks.SeverityHigh, Client: flatSnap.Clients[0], Port: 23},
	}, config.NetworkConfig{})
	if len(flatReport.PostureNotes) != 1 || !strings.Contains(strings.ToLower(flatReport.PostureNotes[0].Title), "flat") {
		t.Fatalf("expected flat-topology posture note, got %+v", flatReport.PostureNotes)
	}
}

// TestFirewallPolicyAuditing verifies flagging of broad WAN-to-Gateway, WAN-to-LAN,
// and isolated-to-Internal ALLOW policies while ignoring system rules and pinpoint pinholes.
func TestFirewallPolicyAuditing(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", IP: "192.168.1.1", Model: "UDMPRO"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID:          "fw-1",
				Name:        "Allow WAN Admin",
				Enabled:     true,
				Action:      "ALLOW",
				Origin:      "USER_DEFINED",
				Protocol:    "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, AnyPort: true},
			},
			{
				ID:          "fw-2",
				Name:        "System WireGuard",
				Enabled:     true,
				Action:      "ALLOW",
				Origin:      "SYSTEM_DEFINED",
				Protocol:    "udp",
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", Ports: []int{51820}},
			},
			{
				ID:          "fw-3",
				Name:        "Hotspot Leak",
				Enabled:     true,
				Action:      "ALLOW",
				Origin:      "USER_DEFINED",
				Protocol:    "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
			{
				ID:          "fw-4",
				Name:        "Pinpoint MQTT Pinhole",
				Enabled:     true,
				Action:      "ALLOW",
				Origin:      "USER_DEFINED",
				Protocol:    "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.10"}, Ports: []int{1883}},
			},
		},
	}

	report := Evaluate(snap, nil, config.NetworkConfig{})
	byID := make(map[string]checks.Finding)
	for _, f := range report.Findings {
		byID[f.CheckID] = f
	}
	if f, ok := byID["UB-UNIFI-FW-WAN-GW"]; !ok || f.EffectiveSeverity != checks.SeverityCritical {
		t.Fatalf("expected CRITICAL UB-UNIFI-FW-WAN-GW finding, got %+v", byID)
	}
	if f, ok := byID["UB-UNIFI-FW-ISO-LEAK"]; !ok || f.EffectiveSeverity != checks.SeverityHigh {
		t.Fatalf("expected HIGH UB-UNIFI-FW-ISO-LEAK finding, got %+v", byID)
	}
	// System WireGuard and pinpoint MQTT pinhole should NOT generate findings.
	if len(report.Findings) != 2 {
		t.Fatalf("expected exactly 2 firewall findings, got %d: %+v", len(report.Findings), report.Findings)
	}
}

// TestSemiTrustedZoneNarrowBlockNotTreatedAsIsolationIntended verifies that a
// semi-trusted custom zone (such as Work) with only a narrow host/port BLOCK
// plus ALLOW all toward Internal is not classified as isolation-intended and
// does not raise false UB-UNIFI-FW-ISO-LEAK or UB-UNIFI-ISO-TRUSTED-TRANSIT.
func TestSemiTrustedZoneNarrowBlockNotTreatedAsIsolationIntended(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks: []unifi.Network{
			{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-work", Name: "Work", VLAN: "15", Subnet: "192.168.15.1/24", Purpose: "corporate", ZoneName: "Work"},
		},
		Clients: []unifi.Client{
			{MAC: "02:aa:00:00:00:15", IP: "192.168.15.10", Name: "work-laptop", NetworkID: "net-work", NetworkName: "Work", VLAN: "15"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-block-ssh", Index: 10, Name: "Block Work SSH to Server", Enabled: true, Action: "BLOCK", Origin: "USER_DEFINED",
				IPVersion: "both", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Work", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.20"}, Ports: []int{22}},
			},
			{
				ID: "p-allow-work", Index: 20, Name: "Allow Work to Internal", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
				IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Work", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	if intendedIsolatedZoneSet(snap)["work"] {
		t.Fatal("semi-trusted Work zone with narrow SSH block must not be marked isolation-intended")
	}
	if isolatedZoneSet(snap)["work"] {
		t.Fatal("semi-trusted Work zone must not be marked isolated")
	}

	rep := Evaluate(snap, nil, config.NetworkConfig{})
	for _, f := range rep.Findings {
		if f.CheckID == "UB-UNIFI-FW-ISO-LEAK" || f.CheckID == "UB-UNIFI-ISO-TRUSTED-TRANSIT" {
			t.Fatalf("semi-trusted Work zone must not emit %s: %+v", f.CheckID, f)
		}
	}
}

// TestIsolatedZoneSetThoroughBoundaryChecks verifies that isolatedZoneSet
// checks every (srcNet, Internal dstNet) pair, rejects shadowed-443 leaks,
// negated-port ALLOWs, /25 half-subnet ALLOWs, and AnyPort single-host ALLOWs
// (never downgrading findings on such zones), while still honoring genuine
// single-host /32 narrow-port pinholes.
func TestIsolatedZoneSetThoroughBoundaryChecks(t *testing.T) {
	baseNetworks := []unifi.Network{
		{ID: "net-int1", Name: "LAN1", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
		{ID: "net-int2", Name: "LAN2", VLAN: "2", Subnet: "192.168.2.1/24", Purpose: "corporate", ZoneName: "Internal"},
		{ID: "net-iot1", Name: "IoT1", VLAN: "20", Subnet: "192.168.20.1/24", Purpose: "corporate", ZoneName: "IoTZone"},
		{ID: "net-iot2", Name: "IoT2", VLAN: "21", Subnet: "192.168.21.1/24", Purpose: "corporate", ZoneName: "IoTZone"},
	}
	blockAll := unifi.FirewallPolicy{
		ID: "p-block-all", Index: 200, Name: "Block IoTZone to Internal", Enabled: true, Action: "BLOCK", Origin: "USER_DEFINED",
		IPVersion: "both", Protocol: "all",
		Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
	}

	notIsolatedCases := []struct {
		name string
		pols []unifi.FirewallPolicy
	}{
		{
			name: "second_internal_net_open",
			pols: []unifi.FirewallPolicy{
				{
					ID: "p-allow-int2", Index: 10, Name: "Allow IoT to LAN2", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
					IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", NetworkIDs: []string{"net-int2"}, AnyPort: true},
				},
				blockAll,
			},
		},
		{
			name: "second_source_net_open",
			pols: []unifi.FirewallPolicy{
				{
					ID: "p-allow-src2", Index: 10, Name: "Allow IoT2 to Internal", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
					IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", NetworkIDs: []string{"net-iot2"}, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
				blockAll,
			},
		},
		{
			name: "shadowed_443_tcp_any_open",
			pols: []unifi.FirewallPolicy{
				{
					ID: "p-block-443", Index: 10, Name: "Block 443", Enabled: true, Action: "BLOCK", Origin: "USER_DEFINED",
					IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{443}},
				},
				{
					ID: "p-allow-tcp-any", Index: 20, Name: "Allow TCP Any", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
					IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
				blockAll,
			},
		},
		{
			name: "negated_port_allow",
			pols: []unifi.FirewallPolicy{
				{
					ID: "p-allow-not-443", Index: 10, Name: "Allow Except 443", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
					IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{443}, NegatePort: true},
				},
				blockAll,
			},
		},
		{
			name: "slash25_half_subnet_allow",
			pols: []unifi.FirewallPolicy{
				{
					ID: "p-allow-slash25", Index: 10, Name: "Allow Half Subnet DNS", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
					IPVersion: "ipv4", Protocol: "udp",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.0/25"}, Ports: []int{53}},
				},
				blockAll,
			},
		},
		{
			name: "single_host_any_port_allow",
			pols: []unifi.FirewallPolicy{
				{
					ID: "p-allow-host-anyport", Index: 10, Name: "Allow All Ports to Host", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
					IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.53/32"}, AnyPort: true},
				},
				blockAll,
			},
		},
	}

	for _, tc := range notIsolatedCases {
		t.Run(tc.name, func(t *testing.T) {
			client := unifi.Client{MAC: "02:cc:00:00:00:20", IP: "192.168.20.20", Name: "iot-sensor", NetworkID: "net-iot1", NetworkName: "IoT1", VLAN: "20"}
			snap := &unifi.Snapshot{
				Site: "default",
				Devices: []unifi.Device{
					{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
				},
				Networks:         baseNetworks,
				Clients:          []unifi.Client{client},
				FirewallPolicies: tc.pols,
				Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
			}
			if isolatedZoneSet(snap)["iotzone"] {
				t.Fatalf("%s: expected IoTZone NOT to be counted isolated", tc.name)
			}
			raw := []checks.Finding{{CheckID: "UB-0001", BaseSeverity: checks.SeverityHigh, Client: client, Port: 23}}
			rep := Evaluate(snap, raw, config.NetworkConfig{})
			for _, f := range rep.Findings {
				if f.CheckID == "UB-0001" && f.EffectiveSeverity < checks.SeverityHigh {
					t.Fatalf("%s: non-isolated IoTZone finding must not be downgraded, got %v (%+v)", tc.name, f.EffectiveSeverity, f.RiskReasons)
				}
			}
		})
	}

	// Positive control: single-host /32 narrow-port DNS/NTP pinhole stays isolated.
	t.Run("single_host_narrow_port_pinhole_stays_isolated", func(t *testing.T) {
		client := unifi.Client{MAC: "02:cc:00:00:00:20", IP: "192.168.20.20", Name: "iot-sensor", NetworkID: "net-iot1", NetworkName: "IoT1", VLAN: "20"}
		snap := &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
			},
			Networks: baseNetworks,
			Clients:  []unifi.Client{client},
			FirewallPolicies: []unifi.FirewallPolicy{
				{
					ID: "p-allow-dns-ntp", Index: 10, Name: "Allow DNS and NTP to Pi-hole", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
					IPVersion: "ipv4", Protocol: "udp",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.53/32"}, Ports: []int{53, 123}},
				},
				blockAll,
			},
			Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}
		if !isolatedZoneSet(snap)["iotzone"] {
			t.Fatal("expected IoTZone with /32 DNS/NTP pinhole to remain isolated")
		}
		raw := []checks.Finding{{CheckID: "UB-0001", BaseSeverity: checks.SeverityHigh, Client: client, Port: 23}}
		rep := Evaluate(snap, raw, config.NetworkConfig{})
		for _, f := range rep.Findings {
			if f.CheckID == "UB-0001" && f.EffectiveSeverity != checks.SeverityMedium {
				t.Fatalf("expected isolated IoTZone finding to downgrade High->Medium, got %v", f.EffectiveSeverity)
			}
		}
	})
}

// TestOnlineUnprobedHostCarryForwardTTL verifies that findings on an online but
// unprobed host (e.g., newly excluded from scanning) are carried forward with
// the 7-day TTL without being re-listed in ResolvedKeys on every cycle, and
// expire cleanly once past the TTL.
func TestOnlineUnprobedHostCarryForwardTTL(t *testing.T) {
	netCfg := config.NetworkConfig{TrustedVLANs: []string{"LAN"}}
	host := unifi.Client{MAC: "aa:bb:cc:dd:ee:10", IP: "192.168.1.10", Name: "nas-01", NetworkName: "LAN"}
	other := unifi.Client{MAC: "aa:bb:cc:dd:ee:20", IP: "192.168.1.20", Name: "desktop-01", NetworkName: "LAN"}
	snap := &unifi.Snapshot{
		Site:    "default",
		Clients: []unifi.Client{host, other},
	}

	raw := []checks.Finding{
		{CheckID: "UB-0001", BaseSeverity: checks.SeverityHigh, Client: host, Port: 23},
	}
	probedAll := map[string]struct{}{
		host.MAC:  {},
		host.IP:   {},
		other.MAC: {},
		other.IP:  {},
	}
	probedWithoutHost := map[string]struct{}{
		other.MAC: {},
		other.IP:  {},
	}

	// Cycle 1: host is online and probed.
	rep1 := Evaluate(snap, raw, netCfg)
	st1 := BuildStateWithPrev(nil, snap, rep1, netCfg, probedAll)
	key := "UB-0001|aa:bb:cc:dd:ee:10|23"
	if _, ok := st1.Findings[key]; !ok {
		t.Fatalf("expected %q in st1.Findings, got %+v", key, st1.Findings)
	}

	// Cycle 2: host remains online, omitted from probedHostKeys.
	repEmpty := Evaluate(snap, nil, netCfg)
	diff2 := ComputeDiffWithProbed(st1, snap, repEmpty, netCfg, probedWithoutHost)
	if len(diff2.ResolvedKeys) != 0 {
		t.Fatalf("cycle 2: online-unprobed carried finding must not be in ResolvedKeys, got %+v", diff2.ResolvedKeys)
	}
	st2 := BuildStateWithPrev(st1, snap, repEmpty, netCfg, probedWithoutHost)
	if _, ok := st2.Findings[key]; !ok || !st2.CarriedFindings[key] {
		t.Fatalf("cycle 2: expected %q carried forward in st2, got findings=%+v carried=%+v", key, st2.Findings, st2.CarriedFindings)
	}

	// Cycles 3 & 4: even 4-arg ComputeDiff must not re-list carried-forward keys as resolved.
	diff3 := ComputeDiff(st2, snap, repEmpty, netCfg)
	if len(diff3.ResolvedKeys) != 0 {
		t.Fatalf("cycle 3: carried-forward key must not repeat in ResolvedKeys, got %+v", diff3.ResolvedKeys)
	}
	st3 := BuildStateWithPrev(st2, snap, repEmpty, netCfg, probedWithoutHost)
	diff4 := ComputeDiff(st3, snap, repEmpty, netCfg)
	if len(diff4.ResolvedKeys) != 0 {
		t.Fatalf("cycle 4: carried-forward key must not repeat in ResolvedKeys, got %+v", diff4.ResolvedKeys)
	}

	// Simulate 8 days elapsed (> offlineFindingTTL): expires once and is pruned.
	aged := &State{
		UpdatedAt:       time.Now().UTC().Add(-8 * 24 * time.Hour),
		Findings:        map[string]checks.Severity{key: st3.Findings[key]},
		FindingLastSeen: map[string]time.Time{key: time.Now().UTC().Add(-8 * 24 * time.Hour)},
		CarriedFindings: map[string]bool{key: true},
		TrustedClients:  st3.TrustedClients,
		PortForwards:    st3.PortForwards,
	}
	diffExp := ComputeDiff(aged, snap, repEmpty, netCfg)
	if len(diffExp.ResolvedKeys) != 1 || diffExp.ResolvedKeys[0] != key {
		t.Fatalf("expected expired online-unprobed key %q to resolve once, got %+v", key, diffExp.ResolvedKeys)
	}
	stExp := BuildStateWithPrev(aged, snap, repEmpty, netCfg, probedWithoutHost)
	if _, stillPresent := stExp.Findings[key]; stillPresent {
		t.Fatalf("expected expired online-unprobed key %q to be pruned from state", key)
	}
	diffAfter := ComputeDiff(stExp, snap, repEmpty, netCfg)
	if len(diffAfter.ResolvedKeys) != 0 {
		t.Fatalf("expected 0 resolved keys after expiration pruning, got %+v", diffAfter.ResolvedKeys)
	}
}

// TestLegacyThreePartStateKeyMigration verifies that upgrading from a state
// file storing 3-part finding keys to 4-part "|Property" keys does not trigger
// false NewFindings or list the migrated legacy key in ResolvedKeys.
func TestLegacyThreePartStateKeyMigration(t *testing.T) {
	netCfg := config.NetworkConfig{IsolatedVLANs: []string{"IoT"}}
	host := unifi.Client{MAC: "aa:bb:cc:dd:ee:30", IP: "192.168.20.30", Name: "legacy-nas", NetworkName: "IoT"}
	snap := &unifi.Snapshot{
		Site:    "default",
		Clients: []unifi.Client{host},
	}

	legacyKey := "NERVA-SMB-V1-ENABLED|aa:bb:cc:dd:ee:30|445"
	newKey := "NERVA-SMB-V1-ENABLED|aa:bb:cc:dd:ee:30|445|smb-v1"
	prev := &State{
		UpdatedAt:      time.Now().UTC().Add(-10 * time.Minute),
		Findings:       map[string]checks.Severity{legacyKey: checks.SeverityMedium},
		TrustedClients: map[string]string{},
		PortForwards:   map[string]string{},
	}

	// Same effective severity (High base downgraded to Medium on isolated IoT):
	// zero NewFindings, zero EscalatedFindings, zero ResolvedKeys.
	raw := []checks.Finding{
		{CheckID: "NERVA-SMB-V1-ENABLED", Property: "smb-v1", BaseSeverity: checks.SeverityHigh, Client: host, Port: 445},
	}
	rep := Evaluate(snap, raw, netCfg)
	diff := ComputeDiff(prev, snap, rep, netCfg)
	if len(diff.NewFindings) != 0 || len(diff.EscalatedFindings) != 0 || len(diff.ResolvedKeys) != 0 {
		t.Fatalf("legacy 3-part key migration must not alert or resolve, got new=%+v esc=%+v resolved=%+v",
			diff.NewFindings, diff.EscalatedFindings, diff.ResolvedKeys)
	}

	// BuildStateWithPrev replaces the legacy 3-part key with the 4-part key.
	next := BuildStateWithPrev(prev, snap, rep, netCfg, map[string]struct{}{host.MAC: {}, host.IP: {}})
	if _, hasNew := next.Findings[newKey]; !hasNew {
		t.Fatalf("expected migrated 4-part key %q in next state, got %+v", newKey, next.Findings)
	}
	if _, hasOld := next.Findings[legacyKey]; hasOld {
		t.Fatalf("expected legacy 3-part key %q to be retired from next state, got %+v", legacyKey, next.Findings)
	}

	// If severity increased compared to the legacy 3-part baseline, report escalation without false new/resolved.
	rawEsc := []checks.Finding{
		{CheckID: "NERVA-SMB-V1-ENABLED", Property: "smb-v1", BaseSeverity: checks.SeverityCritical, Client: host, Port: 445},
	}
	repEsc := Evaluate(snap, rawEsc, netCfg)
	diffEsc := ComputeDiff(prev, snap, repEsc, netCfg)
	if len(diffEsc.NewFindings) != 0 || len(diffEsc.ResolvedKeys) != 0 || len(diffEsc.EscalatedFindings) != 1 {
		t.Fatalf("expected 1 escalated finding and 0 new/resolved on legacy key escalation, got %+v", diffEsc)
	}
}
