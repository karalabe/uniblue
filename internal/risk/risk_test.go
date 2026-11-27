// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestEvaluateBlastRadiusScoring checks that only a matching WAN forward raises the
// severity of a service finding.
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
			{ID: "custom", Name: "Custom service", Enabled: true, Proto: "tcp", DstPort: "49500", FwdIP: "192.168.1.10", FwdPort: "49500"},
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

	if got["UB-0003|aa:01|502"] != checks.SeverityHigh {
		t.Fatalf("trusted VLAN finding = %v, want high", got["UB-0003|aa:01|502"])
	}
	// A configured VLAN name supplies no containment evidence.
	if got["UB-0003|aa:02|502"] != checks.SeverityHigh {
		t.Fatalf("unverified VLAN finding = %v, want high", got["UB-0003|aa:02|502"])
	}
	// A forward into the trusted VLAN keeps the classifier's own severity.
	if sev := got["UB-UNIFI-PORTFWD|aa:01|49500|portfwd:custom"]; sev != checks.SeverityMedium {
		t.Fatalf("unclassified port forward = %v, want medium", sev)
	}
	// WAN port forward forces medium -> critical even on IoT VLAN.
	if got["UB-0004|aa:03|554"] != checks.SeverityCritical {
		t.Fatalf("WAN-exposed finding = %v, want critical", got["UB-0004|aa:03|554"])
	}
}

// TestStatePersistenceAndDiffing verifies state save/load round-trips and diff
// detection for newly appearing trusted clients.
func TestStatePersistenceAndDiffing(t *testing.T) {
	netCfg := config.NetworkConfig{
		TrustedVLANs:  []string{"Default"},
		IsolatedVLANs: []string{"IoT"},
	}

	// The device initially appears on the IoT VLAN.
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
	if len(diff.EscalatedFindings) != 0 {
		t.Fatalf("moving VLANs escalated findings: %+v", diff.EscalatedFindings)
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
	if got["UB-0001|aa:01|23"] != checks.SeverityHigh {
		t.Fatalf("expected Internal-zone VLAN to retain high severity, got %v", got["UB-0001|aa:01|23"])
	}
	if got["UB-0001|aa:02|23"] != checks.SeverityHigh {
		t.Fatalf("expected Hotspot VLAN with unverified peers to retain high severity, got %v", got["UB-0001|aa:02|23"])
	}
	if got["UB-0001|aa:03|23"] != checks.SeverityHigh {
		t.Fatalf("expected policy-blocked zone with unverified peers to retain high severity, got %v", got["UB-0001|aa:03|23"])
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
			if f.CheckID == "UB-0001" && f.EffectiveSeverity != checks.SeverityHigh {
				t.Fatalf("expected IoTZone finding with a LAN pinhole to retain high severity, got %v", f.EffectiveSeverity)
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
		ScoringVersion:  CurrentScoringVersion,
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
		ScoringVersion: CurrentScoringVersion,
		UpdatedAt:      time.Now().UTC().Add(-10 * time.Minute),
		Findings:       map[string]checks.Severity{legacyKey: checks.SeverityHigh},
		TrustedClients: map[string]string{},
		PortForwards:   map[string]string{},
	}

	// An unchanged severity must migrate without a new, escalated, or resolved alert.
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

// TestVerifiedContainmentPreservesSeverity checks that containment evidence is
// reported separately from the finding severity.
func TestVerifiedContainmentPreservesSeverity(t *testing.T) {
	for _, tt := range []struct {
		name, peers, egress string
	}{
		{"contained", "isolated", "blocked"},
		{"open peers", "open", "blocked"},
		{"LAN leak", "isolated", "open"},
		{"missing ACL", "unknown", "blocked"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := wiredPeerSite(2)
			s.Networks[0].ZoneName, s.Networks[0].VLAN = "Hotspot", "20"
			s.Networks = append(s.Networks, unifi.Network{ID: "lan", Name: "Office", VLAN: "10", ZoneName: "Internal", Subnet: "198.51.100.1/24"})
			s.Visibility = &unifi.SiteVisibility{GatewayPoliciesAvailable: true, SwitchACLsAvailable: tt.peers != "unknown"}
			for i := range s.Devices[0].Ports {
				s.Devices[0].Ports[i].Isolation = tt.peers == "isolated"
			}
			if tt.peers == "unknown" {
				s.SwitchACLCoverage = nil
			}
			if tt.egress == "open" {
				s.FirewallPolicies = []unifi.FirewallPolicy{{ID: "leak", Name: "Sensors to Office", Enabled: true, Action: "ALLOW",
					Source: unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true}, Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true}}}
			}
			cl := s.Clients[0]
			cl.NetworkID, cl.VLAN = s.Networks[0].ID, s.Networks[0].VLAN
			finding := checks.Finding{CheckID: "service", Client: cl, BaseSeverity: checks.SeverityHigh, Port: 23}
			r := Evaluate(s, []checks.Finding{finding}, config.NetworkConfig{IsolatedVLANs: []string{"20"}, TrustedVLANs: []string{"10"}})
			if len(r.Isolation.Containment) != 1 {
				t.Fatalf("unexpected containment entries: %+v", r.Isolation.Containment)
			}
			n := r.Isolation.Containment[0]
			if n.Peers.State != tt.peers || n.LANEgress.State != tt.egress {
				t.Fatalf("expected peers=%s egress=%s, got %+v", tt.peers, tt.egress, n)
			}
			for _, f := range r.Findings {
				if f.CheckID == finding.CheckID {
					if f.EffectiveSeverity != checks.SeverityHigh || len(f.RiskReasons) != 0 {
						t.Fatalf("containment changed severity: %s %v", f.EffectiveSeverity, f.RiskReasons)
					}
					return
				}
			}
			t.Fatal("missing scored finding")
		})
	}
}

// TestLegacyStateScoringVersionSilentRebaseline exercises an upgrade on disk,
// including an empty action queue followed by its first actionable exposure.
func TestLegacyStateScoringVersionSilentRebaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uniblue-state.json")
	const legacy = `{"findings":{"service|02:00:00:00:00:01|23":"medium"}}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	prev, err := LoadState(path)
	if err != nil || !prev.NeedsScoringRebaseline() || prev.Actions != nil {
		t.Fatalf("legacy baseline = %+v, err = %v", prev, err)
	}
	cfg := config.NetworkConfig{IsolatedVLANs: []string{"Sensors"}}
	cl := unifi.Client{MAC: "02:00:00:00:00:01", IP: "192.0.2.1", VLAN: "20", NetworkName: "Sensors"}
	snap := &unifi.Snapshot{Clients: []unifi.Client{cl}}
	findings := []checks.Finding{{CheckID: "service", Port: 23, Client: cl, BaseSeverity: checks.SeverityHigh}}
	report := Evaluate(snap, findings, cfg)
	diff := ComputeDiff(prev, snap, report, cfg)
	next := BuildStateWithPrev(prev, snap, report, cfg, nil)
	diff.NewActions, diff.EscalatedActions, diff.ResolvedActionIDs, next.Actions, next.ActionLastSeen, next.ActionPeakAt, next.CarriedActions, next.ActionAssets, next.KnownClientIPs = ComputeActionDiff(prev, snap, nil, nil, true)
	if diff.HasAlerts(checks.SeverityInfo) || len(diff.ResolvedKeys)+len(diff.ResolvedActionIDs) != 0 || next.Findings[findings[0].Key()] != checks.SeverityHigh {
		t.Fatalf("upgrade diff = %+v, findings = %v", diff, next.Findings)
	}
	if err := SaveState(path, next); err != nil {
		t.Fatal(err)
	}
	prev, err = LoadState(path)
	if err != nil || prev == nil || prev.ScoringVersion != 2 || prev.Actions == nil || len(prev.Actions) != 0 {
		t.Fatalf("reloaded baseline = %+v, err = %v", prev, err)
	}
	action := ActionAlert{ID: "act:check:service:" + cl.MAC + ":23", Priority: "P3"}
	diff.NewActions, _, _, prev.Actions, prev.ActionLastSeen, prev.ActionPeakAt, _, _, _ = ComputeActionDiff(prev, snap, []ActionAlert{action}, nil, true)
	if len(diff.NewActions) != 1 || diff.NewActions[0].ID != action.ID || !diff.HasAlerts(checks.SeverityMedium) {
		t.Fatalf("first action after empty seed = %+v", diff)
	}
	snap.Clients[0].NetworkName = "Building automation"
	findings[0].Client = snap.Clients[0]
	report = Evaluate(snap, findings, cfg)
	diff = ComputeDiff(prev, snap, report, cfg)
	diff.NewActions, diff.EscalatedActions, diff.ResolvedActionIDs, _, _, _, _, _, _ = ComputeActionDiff(prev, snap, []ActionAlert{action}, nil, true)
	if diff.HasAlerts(checks.SeverityInfo) || report.Findings[0].EffectiveSeverity != checks.SeverityHigh {
		t.Fatalf("VLAN rename changed alerts or severity: %+v, %+v", diff, report.Findings)
	}
}

// actionCycle advances the action and client identity baselines together, as a saved scan does.
func actionCycle(prev *State, snap *unifi.Snapshot, current []ActionAlert, probed map[string]struct{}, cveMatched bool) (*State, Diff) {
	next := BuildStateWithPrev(prev, snap, Report{}, config.NetworkConfig{}, probed)
	var d Diff
	d.NewActions, d.EscalatedActions, d.ResolvedActionIDs, next.Actions, next.ActionLastSeen, next.ActionPeakAt, next.CarriedActions, next.ActionAssets, next.KnownClientIPs = ComputeActionDiff(prev, snap, current, probed, cveMatched)
	return next, d
}

func TestLegacyOfflineFindingRebaseline(t *testing.T) {
	cl := unifi.Client{MAC: "02-00-00-00-00-0A", IP: "192.0.2.1", NetworkName: "Sensors"}
	cfg := config.NetworkConfig{IsolatedVLANs: []string{"Sensors"}}
	f := checks.Finding{CheckID: "service", Client: cl, Port: 23, BaseSeverity: checks.SeverityHigh}
	prev := &State{ScoringVersion: 1, Findings: map[string]checks.Severity{f.Key(): checks.SeverityMedium}}
	online := &unifi.Snapshot{Clients: []unifi.Client{cl}}
	host := config.CanonicalMAC(cl.MAC)
	current := []ActionAlert{
		{ID: "act:check:service:" + host + ":tcp/23", Priority: "P3"},
		{ID: "act:service:" + host + ":tcp/23", Priority: "P3"},
		{ID: "act:patch:CVE-1:" + host, Priority: "P3"},
		{ID: "act:wan-service:" + host + ":tcp/23", Priority: "P3"},
	}
	for _, snap := range []*unifi.Snapshot{{}, online} {
		st, _ := actionCycle(prev, snap, nil, map[string]struct{}{}, true)
		if st.Findings[f.Key()] != checks.SeverityHigh {
			t.Fatalf("unobserved legacy score = %v", st.Findings)
		}
		d := ComputeDiff(st, online, Evaluate(online, []checks.Finding{f}, cfg), cfg)
		if len(d.NewFindings)+len(d.EscalatedFindings) != 0 {
			t.Fatalf("reconnect alerted: %+v", d)
		}
		wan := *online
		wan.PortForwards = []unifi.PortForward{{Enabled: true, ID: "telnet", Proto: "tcp", FwdIP: cl.IP, DstPort: "23", FwdPort: "23"}}
		d = ComputeDiff(st, &wan, Evaluate(&wan, []checks.Finding{f}, cfg), cfg)
		if len(d.EscalatedFindings) != 1 || d.EscalatedFindings[0].Key() != f.Key() || d.EscalatedFindings[0].EffectiveSeverity != checks.SeverityCritical {
			t.Fatalf("new WAN exposure = %+v", d)
		}
		probed := map[string]struct{}{host: {}}
		st, _ = actionCycle(st, online, nil, map[string]struct{}{}, true)
		if st.UpgradeCarriedHosts[host].IsZero() {
			t.Fatal("unprobed reconnect lost the upgrade timestamp")
		}
		expired := BuildStateWithPrev(st, online, Report{}, cfg, nil)
		expired.UpgradeCarriedHosts[host] = time.Now().Add(-offlineFindingTTL - time.Hour)
		expired, d = actionCycle(expired, online, current, nil, true)
		if len(expired.UpgradeCarriedHosts) != 0 || len(d.NewActions) != len(current) {
			t.Fatalf("expired upgrade marker: hosts=%v diff=%+v", expired.UpgradeCarriedHosts, d)
		}
		st, d = actionCycle(st, online, current, probed, true)
		if len(d.NewActions) != 0 || len(st.Actions) != len(current) || len(st.UpgradeCarriedHosts) != 0 {
			t.Fatalf("first probe after upgrade: actions=%v hosts=%v diff=%+v", st.Actions, st.UpgradeCarriedHosts, d)
		}
		added := ActionAlert{ID: "act:service:" + host + ":tcp/80", Priority: "P2"}
		_, d = actionCycle(st, online, append(current, added), probed, true)
		if len(d.NewActions) != 1 || d.NewActions[0].ID != added.ID {
			t.Fatalf("new service after reconnect: %+v", d)
		}
	}
}

func TestLegacyUpgradeHostObservations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cl := unifi.Client{ID: "client-a", MAC: "02:00:00:00:00:0a", IP: "192.0.2.10"}
		seen := time.Now().UTC().Add(-6 * 24 * time.Hour)
		const cve = "02:00:00:00:00:0b|service|1|CVE-1"
		prev := &State{
			UpdatedAt:        seen.Add(-time.Hour),
			Findings:         map[string]checks.Severity{"service|" + cl.IP + "|23": checks.SeverityMedium},
			FindingLastSeen:  map[string]time.Time{"service|" + cl.IP + "|23": seen},
			ExactCVEs:        map[string]string{cve: "high", cl.IP + "|service|1|CVE-2": "high", "gateway|router|1|CVE-3": "high"},
			ExactCVELastSeen: map[string]time.Time{cve: seen},
			TrustedClients:   map[string]string{"02-00-00-00-00-0C": "tablet"},
		}
		snap := &unifi.Snapshot{Devices: []unifi.Device{{ID: "gateway"}}}
		st, _ := actionCycle(prev, snap, nil, nil, true)
		want := map[string]time.Time{cl.IP: seen, "02:00:00:00:00:0b": seen, "02:00:00:00:00:0c": prev.UpdatedAt}
		if !maps.Equal(st.UpgradeCarriedHosts, want) {
			t.Fatalf("upgrade observations = %v, want %v", st.UpgradeCarriedHosts, want)
		}
		snap.Clients = []unifi.Client{cl, {MAC: "02:00:00:00:00:0b"}, {MAC: "02:00:00:00:00:0c"}}
		probed := activeClientHostSet(snap)
		actions := []ActionAlert{
			{ID: "act:wan-service:" + cl.ID + ":tcp/23", Priority: "P2"},
			{ID: "act:patch:CVE-1:02:00:00:00:00:0b", Priority: "P2"},
			{ID: "act:service:02:00:00:00:00:0c:tcp/23", Priority: "P2"},
		}
		next, d := actionCycle(st, snap, actions, probed, true)
		if len(d.NewActions) != 0 || len(next.Actions) != len(actions) || len(next.UpgradeCarriedHosts) != 0 {
			t.Fatalf("reconnect: actions=%v markers=%v alerts=%v", next.Actions, next.UpgradeCarriedHosts, d.NewActions)
		}
		time.Sleep(3 * 24 * time.Hour)
		_, d = actionCycle(st, snap, actions, probed, true)
		if len(d.NewActions) != len(actions) {
			t.Fatalf("reconnect after expiry: alerts=%v", d.NewActions)
		}
	})
}

// TestActionDiffOfflineCarryForwardAndEscalation follows the same controls
// across a disconnect, an unprobed reconnect, and a fresh observation.
func TestActionDiffOfflineCarryForwardAndEscalation(t *testing.T) {
	cl := unifi.Client{MAC: "02:00:00:00:00:0a", IP: "192.0.2.10"}
	online := &unifi.Snapshot{Clients: []unifi.Client{cl}}
	ids := []string{"act:check:C:" + cl.MAC + ":53:udp", "act:check:T:" + cl.MAC + ":tcp/80", "act:patch:CVE-1:" + cl.MAC, "act:service:" + cl.MAC + ":tcp/22"}
	var current []ActionAlert
	for _, id := range ids {
		current = append(current, ActionAlert{ID: id, Priority: "P3"})
	}
	current = append(current, ActionAlert{ID: "act:vlan-ingress:lab", Priority: "P2"}, ActionAlert{ID: "act:wan-pf:web", Priority: "P4"},
		ActionAlert{ID: ids[0], Priority: "P5"}, ActionAlert{Priority: "P1"}, ActionAlert{ID: "invalid", Priority: "verify"})
	prev, d := actionCycle(nil, online, current, nil, true)
	if len(d.NewActions) != len(ids)+2 || d.NewActions[0].ID != "act:vlan-ingress:lab" || d.NewActions[1].ID != ids[0] || d.NewActions[1].Severity != checks.SeverityMedium {
		t.Fatalf("first-run action order or priorities = %+v", d.NewActions)
	}
	prev.ActionLastSeen[ids[2]] = time.Now().Add(-3 * time.Hour)
	st, d := actionCycle(prev, &unifi.Snapshot{}, nil, nil, true)
	if !slices.Equal(d.ResolvedActionIDs, []string{"act:vlan-ingress:lab", "act:wan-pf:web"}) || len(st.Actions) != len(ids) || len(st.CarriedActions) != 0 {
		t.Fatalf("offline actions = %v, resolved = %v, carried = %v", st.Actions, d.ResolvedActionIDs, st.CarriedActions)
	}
	for _, id := range ids {
		if st.Actions[id] != "P3" || !st.ActionLastSeen[id].Equal(prev.ActionLastSeen[id]) {
			t.Fatalf("offline action %q lost priority or last observation", id)
		}
	}
	prev = st
	st, d = actionCycle(st, online, nil, map[string]struct{}{}, true)
	if len(d.ResolvedActionIDs) != 0 || len(st.CarriedActions) != len(ids) || !maps.Equal(st.ActionLastSeen, prev.ActionLastSeen) {
		t.Fatalf("unprobed reconnect: resolved=%v, seen=%v, carried=%v", d.ResolvedActionIDs, st.ActionLastSeen, st.CarriedActions)
	}
	st, d = actionCycle(st, online, nil, nil, true)
	if len(d.ResolvedActionIDs) != 0 || len(st.CarriedActions) != len(ids) {
		t.Fatalf("lost previously carried actions without probe evidence: %v %v", d.ResolvedActionIDs, st.CarriedActions)
	}
	st.ActionLastSeen[ids[1]] = time.Now().Add(-offlineFindingTTL - time.Hour)
	_, d = actionCycle(st, online, nil, map[string]struct{}{}, true)
	if !slices.Equal(d.ResolvedActionIDs, []string{ids[1]}) {
		t.Fatalf("TTL resolved = %v", d.ResolvedActionIDs)
	}
	fresh := []ActionAlert{{ID: ids[0], Priority: "P4"}, {ID: ids[0], Priority: "P1"}}
	st, d = actionCycle(st, online, fresh, map[string]struct{}{cl.MAC: {}}, true)
	if len(d.NewActions) != 0 || len(d.EscalatedActions) != 1 || d.EscalatedActions[0].ID != ids[0] || d.EscalatedActions[0].Previous != "P3" || d.EscalatedActions[0].Severity != checks.SeverityCritical ||
		!slices.Equal(d.ResolvedActionIDs, ids[1:]) || len(st.Actions) != 1 || len(st.CarriedActions) != 0 {
		t.Fatalf("rescanned host: %+v, actions=%v carried=%v", d, st.Actions, st.CarriedActions)
	}
}

func TestActionPriorityPeakExpires(t *testing.T) {
	snap := &unifi.Snapshot{}
	a := ActionAlert{ID: "act:vlan-ingress:lab", Priority: "P2"}
	st, _ := actionCycle(nil, snap, []ActionAlert{a}, nil, true)
	peak := time.Now().Add(-6 * 24 * time.Hour)
	// A baseline written before peak timestamps used the last-seen time.
	st.ActionPeakAt = nil
	st.ActionLastSeen[a.ID] = peak
	a.Priority = "P4"
	st, _ = actionCycle(st, snap, []ActionAlert{a}, nil, true)
	if st.Actions[a.ID] != "P2" || !st.ActionPeakAt[a.ID].Equal(peak) || !st.ActionLastSeen[a.ID].After(peak) {
		t.Fatalf("weaker observation: peak=%v seen=%v", st.ActionPeakAt, st.ActionLastSeen)
	}
	a.Priority = "P2"
	st, d := actionCycle(st, snap, []ActionAlert{a}, nil, true)
	if len(d.EscalatedActions) != 0 || !st.ActionPeakAt[a.ID].Equal(st.ActionLastSeen[a.ID]) {
		t.Fatalf("return to peak = %+v, seen = %v", d, st.ActionLastSeen)
	}
	a.Priority = "P4"
	st.ActionPeakAt[a.ID] = time.Now().Add(-offlineFindingTTL - time.Hour)
	st, _ = actionCycle(st, snap, []ActionAlert{a}, nil, true)
	if st.Actions[a.ID] != "P4" || !st.ActionPeakAt[a.ID].Equal(st.ActionLastSeen[a.ID]) {
		t.Fatalf("expired peak = %v %v", st.Actions, st.ActionLastSeen)
	}
}

func TestPatchGraceAfterPriorityDrop(t *testing.T) {
	cl := unifi.Client{MAC: "02:00:00:00:00:0a"}
	snap := &unifi.Snapshot{Clients: []unifi.Client{cl}}
	a := ActionAlert{ID: "act:patch:CVE-1:" + cl.MAC, Priority: "P1"}
	st, _ := actionCycle(nil, snap, []ActionAlert{a}, nil, true)
	peak := time.Now().Add(-3 * time.Hour)
	st.ActionPeakAt[a.ID], st.ActionLastSeen[a.ID] = peak, peak
	a.Priority = "P3"
	st, _ = actionCycle(st, snap, []ActionAlert{a}, nil, true)
	seen := st.ActionLastSeen[a.ID]
	st, d := actionCycle(st, snap, nil, map[string]struct{}{cl.MAC: {}}, true)
	if len(d.ResolvedActionIDs) != 0 || st.Actions[a.ID] != "P1" || !st.ActionPeakAt[a.ID].Equal(peak) || !seen.After(peak) || !st.ActionLastSeen[a.ID].Equal(seen) {
		t.Fatalf("missed banner after weaker observation: %+v, state=%+v", d, st)
	}
	// The client goes offline. Its peak expires three hours before its last observation.
	st.ActionPeakAt[a.ID] = time.Now().Add(-offlineFindingTTL - time.Hour)
	st.ActionLastSeen[a.ID] = st.ActionPeakAt[a.ID].Add(3 * time.Hour)
	snap.Clients = nil
	st, d = actionCycle(st, snap, nil, nil, true)
	if st.Actions[a.ID] != "P1" || len(d.ResolvedActionIDs) != 0 {
		t.Fatalf("offline TTL measured from peak: %+v", d)
	}
	st.ActionLastSeen[a.ID] = time.Now().Add(-offlineFindingTTL - time.Minute)
	_, d = actionCycle(st, snap, nil, nil, true)
	if !slices.Equal(d.ResolvedActionIDs, []string{a.ID}) {
		t.Fatalf("expired last observation: %+v", d)
	}
}

// TestLegacyActionAssetTimestamps checks that the old host list survives a load and save.
func TestLegacyActionAssetTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	const id = "act:vlan-egress:lab"
	const raw = `{"scoring_version":2,"actions":{"act:vlan-egress:lab":"P2"},"action_assets":{"act:vlan-egress:lab":["Guest"]},"action_last_seen":{"act:vlan-egress:lab":"2026-01-01T00:00:00Z"}}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	prev, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	seen := prev.ActionLastSeen[id]
	if seen.IsZero() || !prev.ActionAssets[id]["guest"].Equal(seen) {
		t.Fatalf("migrated asset timestamps = %v", prev.ActionAssets)
	}
	next := BuildStateWithPrev(prev, &unifi.Snapshot{}, Report{}, config.NetworkConfig{}, nil)
	next.ActionAssets[id]["guest"] = next.UpdatedAt
	if !prev.ActionAssets[id]["guest"].Equal(seen) {
		t.Fatal("updating the next baseline changed the previous observation")
	}
	if err := SaveState(path, next); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(path)
	if err != nil || !maps.Equal(loaded.ActionAssets[id], next.ActionAssets[id]) {
		t.Fatalf("reloaded asset timestamps: state=%v err=%v", loaded, err)
	}
}

func TestNetworkActionProtectedAssets(t *testing.T) {
	const id = "act:vlan-ingress:lab"
	cl := unifi.Client{MAC: "02:00:00:00:00:0a"}
	gw := unifi.Device{ID: "Gateway"}
	snap := &unifi.Snapshot{Devices: []unifi.Device{gw}, Clients: []unifi.Client{cl}}
	a := ActionAlert{ID: id, Priority: "P2", AffectedAssets: []string{strings.ToUpper(cl.MAC), gw.ID}}
	st, _ := actionCycle(nil, snap, []ActionAlert{a}, nil, true)
	seen := st.ActionLastSeen[id]
	snap.Clients = nil
	st, d := actionCycle(st, snap, nil, nil, true)
	if len(d.ResolvedActionIDs) != 0 || st.Actions[id] != "P2" || !st.ActionLastSeen[id].Equal(seen) || !maps.Equal(st.ActionAssets[id], map[string]time.Time{cl.MAC: seen}) {
		t.Fatalf("offline protected host: %+v, state = %+v", d, st)
	}
	snap.Clients = []unifi.Client{cl}
	st, d = actionCycle(st, snap, nil, map[string]struct{}{}, true)
	if len(d.ResolvedActionIDs) != 0 || !st.CarriedActions[id] {
		t.Fatalf("unprobed protected host: %+v, state = %+v", d, st)
	}
	st, d = actionCycle(st, snap, nil, map[string]struct{}{cl.MAC: {}}, true)
	if !slices.Equal(d.ResolvedActionIDs, []string{id}) || len(st.ActionAssets) != 0 {
		t.Fatalf("fixed network control: %+v, assets = %v", d, st.ActionAssets)
	}
}

func TestPartialNetworkActionObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		guest := unifi.Client{MAC: "02:00:00:00:00:0a"}
		const stableIP = "2001:db8:abcd::1"
		stable := unifi.Client{IPv6: []string{stableIP}}
		const id = "act:vlan-egress:lab"
		action := ActionAlert{ID: id, Priority: "P2", AffectedAssets: []string{guest.MAC, stableIP, "switch"}}
		snap := &unifi.Snapshot{Clients: []unifi.Client{guest, stable}, Devices: []unifi.Device{{ID: "switch"}}}
		st, _ := actionCycle(nil, snap, []ActionAlert{action}, nil, true)
		seen := st.ActionLastSeen[id]
		snap.Clients = []unifi.Client{stable}
		probed := map[string]struct{}{stableIP: {}}
		action.AffectedAssets = []string{stableIP}
		for day := 1; day <= 8; day++ {
			time.Sleep(24 * time.Hour)
			st, _ = actionCycle(st, snap, []ActionAlert{action}, probed, true)
			want := map[string]time.Time{stableIP: time.Now().UTC()}
			if day <= 7 {
				want[guest.MAC] = seen
			}
			if !maps.Equal(st.ActionAssets[id], want) {
				t.Fatalf("day %d: assets=%v want=%v", day, st.ActionAssets[id], want)
			}
			if day == 7 {
				missing, d := actionCycle(st, snap, nil, probed, true)
				if len(d.ResolvedActionIDs) != 0 || !maps.Equal(missing.ActionAssets[id], map[string]time.Time{guest.MAC: seen}) {
					t.Fatalf("missing action at TTL: assets=%v diff=%+v", missing.ActionAssets[id], d)
				}
			}
		}
		st, d := actionCycle(st, snap, nil, probed, true)
		if !slices.Equal(d.ResolvedActionIDs, []string{id}) || len(st.ActionAssets) != 0 {
			t.Fatalf("fixed control: assets=%v diff=%+v", st.ActionAssets, d)
		}
		_, d = actionCycle(st, snap, []ActionAlert{action}, probed, true)
		if len(d.NewActions) != 1 || d.NewActions[0].ID != id {
			t.Fatalf("regressed control: %+v", d)
		}
	})
}

func TestWANActionsAcrossDualStackDisconnect(t *testing.T) {
	cl := unifi.Client{MAC: "02:00:00:00:00:0a", IP: "192.0.2.10", IPv6: []string{"2001:db8::a"}}
	pf := unifi.PortForward{ID: "https", Enabled: true, FwdIP: cl.IP, Proto: "tcp", DstPort: "443"}
	rule := unifi.FirewallPolicy{Name: "v6", Enabled: true, Action: "ALLOW", IPVersion: "ipv6", Protocol: "tcp",
		Source: unifi.PolicyEndpoint{ZoneName: "External"}, Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: cl.IPv6, Ports: []int{443}}}
	snap := &unifi.Snapshot{Clients: []unifi.Client{cl}, PortForwards: []unifi.PortForward{pf}, FirewallPolicies: []unifi.FirewallPolicy{rule},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true}}
	bundle := ActionAlert{ID: "act:wan-service:" + cl.MAC + ":tcp/443", Priority: "P2"}
	routed := ActionAlert{ID: "act:gateway-routed:v6", Priority: "P2", AffectedAssets: []string{
		"child:" + cl.MAC + ":zigbee2mqtt:item-1", "managed:" + cl.IPv6[0], "server",
	}}
	fallback := ActionAlert{ID: "act:wan-pf:https", Priority: "P2"}
	online := []ActionAlert{bundle, routed}
	st, _ := actionCycle(nil, snap, online, nil, true)
	seen := st.ActionLastSeen[routed.ID]
	if !maps.Equal(st.ActionAssets[routed.ID], map[string]time.Time{cl.MAC: seen, cl.IPv6[0]: seen}) {
		t.Fatalf("protected clients = %v", st.ActionAssets[routed.ID])
	}
	snap.FirewallPolicies[0].Action = "BLOCK"
	for _, probed := range []map[string]struct{}{activeClientHostSet(snap), {}} {
		_, d := actionCycle(st, snap, []ActionAlert{bundle}, probed, true)
		if !slices.Equal(d.ResolvedActionIDs, []string{routed.ID}) {
			t.Fatalf("blocked gateway policy: resolved=%v", d.ResolvedActionIDs)
		}
	}
	snap.FirewallPolicies[0].Action = "ALLOW"
	snap.Clients = nil
	st, d := actionCycle(st, snap, []ActionAlert{fallback}, nil, true)
	if len(st.Actions) != 2 || st.Actions[bundle.ID] != "P2" || st.Actions[routed.ID] != "P2" ||
		len(d.NewActions)+len(d.EscalatedActions)+len(d.ResolvedActionIDs) != 0 {
		t.Fatalf("disconnect: %+v, actions=%v", d, st.Actions)
	}
	snap.Clients = []unifi.Client{cl}
	_, d = actionCycle(st, snap, online, nil, true)
	if len(d.NewActions)+len(d.EscalatedActions)+len(d.ResolvedActionIDs) != 0 {
		t.Fatalf("reconnect: %+v", d)
	}
	snap.Clients, snap.PortForwards = nil, nil
	st, d = actionCycle(st, snap, nil, nil, true)
	if st.Actions[bundle.ID] != "P2" || len(d.ResolvedActionIDs) != 0 {
		t.Fatalf("remaining IPv6 publication: %+v", d)
	}
	snap.FirewallPolicies[0].Destination.IPs = []string{"2001:db8::b"}
	st, d = actionCycle(st, snap, nil, nil, true)
	if !slices.Equal(d.ResolvedActionIDs, []string{bundle.ID}) || len(st.KnownClientIPs) != 0 {
		t.Fatalf("last matching publication removed: %+v, owners=%v", d, st.KnownClientIPs)
	}
	snap.FirewallPolicies = nil
	_, d = actionCycle(st, snap, nil, nil, true)
	if !slices.Equal(d.ResolvedActionIDs, []string{routed.ID}) {
		t.Fatalf("gateway policy deleted while client offline: %+v", d)
	}
}

// TestCarriedWANBundleForwardAlerts checks which forwards a retained bundle can cover.
func TestCarriedWANBundleForwardAlerts(t *testing.T) {
	cl := unifi.Client{MAC: "02:00:00:00:00:0a", IPv6: []string{"2001:db8::a"}}
	bundle := ActionAlert{ID: "act:wan-service:" + cl.MAC + ":tcp/443", Priority: "P3"}
	for _, tc := range []struct {
		name, ruleID, ruleName, key, priority string
		duplicate, alert                      bool
	}{
		{"opened forward", "pf", "", "pf", "P2", false, true},
		{"unique name", "", "web", "web", "P3", false, false},
		{"socket", "", "", cl.IPv6[0] + ":tcp/443", "P3", false, false},
		{"ambiguous name", "", "web", "web", "P3", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pf := unifi.PortForward{ID: tc.ruleID, Name: tc.ruleName, Enabled: true, FwdIP: "2001:0db8:0000:0000:0000:0000:0000:000a", Proto: "tcp", DstPort: "443", Src: "2001:db8::1"}
			snap := &unifi.Snapshot{Clients: []unifi.Client{cl}, PortForwards: []unifi.PortForward{pf}}
			if tc.duplicate {
				snap.PortForwards = append(snap.PortForwards, unifi.PortForward{Enabled: true, Name: "WEB", FwdIP: "192.0.2.99", Proto: "tcp", DstPort: "80"})
			}
			st, _ := actionCycle(nil, snap, []ActionAlert{bundle}, nil, true)
			snap.Clients = nil
			if tc.priority == "P2" {
				snap.PortForwards[0].Src = "any"
			}
			fallback := ActionAlert{ID: "act:wan-pf:" + tc.key, Priority: tc.priority}
			st, d := actionCycle(st, snap, []ActionAlert{fallback}, nil, true)
			if st.Actions[bundle.ID] != "P3" || (st.Actions[fallback.ID] != "") != tc.alert || len(d.ResolvedActionIDs)+len(d.EscalatedActions) != 0 {
				t.Fatalf("disconnect: actions=%v diff=%+v", st.Actions, d)
			}
			if tc.alert {
				if len(d.NewActions) != 1 || d.NewActions[0].ID != fallback.ID || d.NewActions[0].Priority != tc.priority {
					t.Fatalf("missing fallback alert: %+v", d)
				}
				return
			}
			if len(d.NewActions) != 0 {
				t.Fatalf("unchanged forward alerted on disconnect: %+v", d)
			}
			snap.Clients = []unifi.Client{cl}
			_, d = actionCycle(st, snap, []ActionAlert{bundle}, nil, true)
			if len(d.NewActions)+len(d.EscalatedActions)+len(d.ResolvedActionIDs) != 0 {
				t.Fatalf("unchanged forward alerted on reconnect: %+v", d)
			}
		})
	}
}

func TestWANBackendOwners(t *testing.T) {
	cl := unifi.Client{MAC: "02-00-00-00-00-0A", IPv6: []string{"2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4", "2001:db8::5"}}
	phone := unifi.Client{MAC: "02:00:00:00:00:0b", IPv6: []string{"2001:db8::b"}}
	snap := &unifi.Snapshot{Clients: []unifi.Client{cl, phone},
		PortForwards: []unifi.PortForward{{FwdIP: cl.IPv6[0]}}, DynamicMappings: []unifi.DynamicPortMapping{{InternalIP: cl.IPv6[1]}},
		ProxyRoutes: []unifi.ProxyRoute{{BackendIP: cl.IPv6[2], PublicExposed: true}, {BackendIP: phone.IPv6[0]}}, PublishedTunnels: []unifi.PublishedTunnel{{BackendIP: cl.IPv6[3]}}}
	want := map[string]string{}
	for _, ip := range cl.IPv6[:4] {
		want[ip] = "02:00:00:00:00:0a"
	}
	st := BuildStateWithPrev(&State{KnownClientIPs: map[string]string{"2001:db8::abcd": phone.MAC}}, snap, Report{}, config.NetworkConfig{}, nil)
	if !maps.Equal(st.KnownClientIPs, want) {
		t.Fatalf("configured backends: %v", st.KnownClientIPs)
	}
	a := ActionAlert{ID: "act:wan-service:" + cl.IPv6[4] + ":tcp/443", Priority: "P2"}
	snap.Clients[1].IPv6 = []string{"2001:db8::c"}
	st, _ = actionCycle(st, snap, []ActionAlert{a}, nil, true)
	want[cl.IPv6[4]] = "02:00:00:00:00:0a"
	if !maps.Equal(st.KnownClientIPs, want) {
		t.Fatalf("backends and active service: %v", st.KnownClientIPs)
	}
	snap.PortForwards, snap.DynamicMappings, snap.ProxyRoutes, snap.PublishedTunnels = nil, nil, nil, nil
	st, _ = actionCycle(st, snap, nil, nil, true)
	if len(st.KnownClientIPs) != 0 {
		t.Fatalf("removed publications retained owners: %v", st.KnownClientIPs)
	}
}

func TestOfflineWANBundleRequiresPublicSocket(t *testing.T) {
	const ip = "192.0.2.10"
	a := ActionAlert{ID: "act:wan-service:" + ip + ":tcp/443", Priority: "P2"}
	prev, _ := actionCycle(nil, &unifi.Snapshot{}, []ActionAlert{a}, nil, true)
	now := time.Now()
	for _, tc := range []struct {
		name string
		snap unifi.Snapshot
		keep bool
	}{
		{"dynamic mapping", unifi.Snapshot{DynamicMappings: []unifi.DynamicPortMapping{{InternalIP: ip, IntPort: 443, Transport: "tcp"}}}, true},
		{"expired mapping", unifi.Snapshot{CollectedAt: now, DynamicMappings: []unifi.DynamicPortMapping{{InternalIP: ip, IntPort: 443, Transport: "tcp", ExpiresAt: &now}}}, false},
		{"public proxy", unifi.Snapshot{ProxyRoutes: []unifi.ProxyRoute{{PublicExposed: true, BackendIP: ip, BackendPort: 443}}}, true},
		{"private proxy", unifi.Snapshot{ProxyRoutes: []unifi.ProxyRoute{{BackendIP: ip, BackendPort: 443}}}, false},
		{"tunnel", unifi.Snapshot{PublishedTunnels: []unifi.PublishedTunnel{{BackendIP: ip, BackendPort: 443}}}, true},
		{"other port", unifi.Snapshot{PublishedTunnels: []unifi.PublishedTunnel{{BackendIP: ip, BackendPort: 80}}}, false},
		{"other transport", unifi.Snapshot{PortForwards: []unifi.PortForward{{Enabled: true, Proto: "udp", FwdIP: ip, FwdPort: "443"}}}, false},
		{"disabled forward", unifi.Snapshot{PortForwards: []unifi.PortForward{{Proto: "tcp", FwdIP: ip, FwdPort: "443"}}}, false},
	} {
		st, d := actionCycle(prev, &tc.snap, nil, nil, true)
		if (st.Actions[a.ID] != "") != tc.keep || slices.Contains(d.ResolvedActionIDs, a.ID) == tc.keep {
			t.Errorf("%s: actions=%v resolved=%v", tc.name, st.Actions, d.ResolvedActionIDs)
		}
	}
}

func TestInfrastructureAndPatchActionResolution(t *testing.T) {
	snap := &unifi.Snapshot{Devices: []unifi.Device{{ID: "Gateway", MAC: "02-00-00-00-00-0A", IP: "2001:db8::A"}}}
	const patch = "act:patch:CVE-1:02:00:00:00:00:0a"
	ids := []string{"act:check:admin:gateway:80", "act:service:02-00-00-00-00-0a:tcp/22", "act:service:2001:db8::a:udp/53"}
	current := []ActionAlert{{ID: patch, Priority: "P1"}}
	for _, id := range ids {
		current = append(current, ActionAlert{ID: id, Priority: "P2"})
	}
	st, _ := actionCycle(nil, snap, current, nil, true)
	seen := time.Now().Add(-time.Hour)
	st.ActionLastSeen[patch] = seen
	st, d := actionCycle(st, snap, nil, map[string]struct{}{}, true)
	if !slices.Equal(d.ResolvedActionIDs, ids) || st.Actions[patch] != "P1" || !st.ActionLastSeen[patch].Equal(seen) {
		t.Fatalf("brief banner miss: %+v, seen = %v", d, st.ActionLastSeen)
	}
	st, d = actionCycle(st, snap, current[:1], nil, true)
	if len(d.NewActions)+len(d.EscalatedActions) != 0 {
		t.Fatalf("returning banner alerted: %+v", d)
	}
	seen = time.Now().Add(-offlineFindingTTL - time.Hour)
	st.ActionLastSeen[patch] = seen
	st.CarriedActions = map[string]bool{patch: true}
	st, d = actionCycle(st, snap, nil, nil, false)
	if len(d.ResolvedActionIDs) != 0 || st.Actions[patch] != "P1" || !st.CarriedActions[patch] || !st.ActionLastSeen[patch].Equal(seen) {
		t.Fatalf("cache outage: %+v, state = %+v", d, st)
	}
	st.ActionLastSeen[patch] = time.Now().Add(-transientPatchActionGrace - time.Minute)
	_, d = actionCycle(st, snap, nil, map[string]struct{}{}, true)
	if !slices.Equal(d.ResolvedActionIDs, []string{patch}) {
		t.Fatalf("patched infrastructure = %+v", d)
	}
}

func TestWANServiceActionIdentity(t *testing.T) {
	cl := unifi.Client{MAC: "02:00:00:00:00:0a", IPv6: []string{"2001:DB8::A"}}
	online := &unifi.Snapshot{Clients: []unifi.Client{cl}}
	offline := &unifi.Snapshot{}
	const suffix = ":tcp/443"
	ipID := "act:wan-service:" + strings.ToLower(cl.IPv6[0]) + suffix
	macID := "act:wan-service:" + cl.MAC + suffix
	a := ActionAlert{ID: ipID, Priority: "P2"}
	st, _ := actionCycle(nil, offline, []ActionAlert{a}, nil, true)
	seen := st.ActionLastSeen[ipID]
	for _, step := range []struct {
		snap *unifi.Snapshot
		id   string
	}{{online, macID}, {offline, ipID}, {online, macID}} {
		a.ID, a.Priority = step.id, "P4"
		var d Diff
		st, d = actionCycle(st, step.snap, []ActionAlert{a}, nil, true)
		if len(d.NewActions)+len(d.ResolvedActionIDs)+len(d.EscalatedActions) != 0 || len(st.Actions) != 1 ||
			st.Actions[macID] != "P2" || !st.ActionPeakAt[macID].Equal(seen) || !st.ActionLastSeen[macID].After(seen) || st.KnownClientIPs["2001:db8::a"] != cl.MAC {
			t.Fatalf("observed %s: %+v, state = %+v", step.id, d, st)
		}
	}
	_, d := actionCycle(st, &unifi.Snapshot{}, nil, nil, true)
	if !slices.Equal(d.ResolvedActionIDs, []string{macID}) {
		t.Fatalf("removed forward = %+v", d)
	}
	online.Clients[0].MAC = "02:00:00:00:00:0b"
	a.ID = ipID
	_, d = actionCycle(st, online, []ActionAlert{a}, nil, true)
	if len(d.NewActions) != 1 || d.NewActions[0].ID != ipID || !slices.Equal(d.ResolvedActionIDs, []string{macID}) {
		t.Fatalf("IP action for a reassigned address = %+v", d)
	}
	a.ID = "act:wan-service:" + online.Clients[0].MAC + suffix
	st, d = actionCycle(st, online, []ActionAlert{a}, nil, true)
	if !slices.Equal(d.ResolvedActionIDs, []string{macID}) || len(d.NewActions) != 1 || d.NewActions[0].ID != a.ID || st.KnownClientIPs["2001:db8::a"] != online.Clients[0].MAC {
		t.Fatalf("reassigned forward = %+v, state = %+v", d, st)
	}
}
