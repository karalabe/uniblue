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

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

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
