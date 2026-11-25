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

// TestTransitEvaluationCatchesPartiallyBlockedPortRange verifies that when a
// gateway blocks the first port of an allowed port range (e.g., blocks 8000,
// allows 8000-8010), EvaluateIsolation still detects the remaining permitted
// ports as a violation instead of misreporting blocked-ok.
func TestTransitEvaluationCatchesPartiallyBlockedPortRange(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks: []unifi.Network{
			{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "10.0.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-iot", Name: "IoT", VLAN: "30", Subnet: "10.0.30.1/24", Purpose: "corporate", ZoneName: "IoT", IsolationEnabled: true},
		},
		Zones: []unifi.FirewallZone{
			{ID: "z-int", Name: "Internal", NetworkIDs: []string{"net-lan"}},
			{ID: "z-iot", Name: "IoT", NetworkIDs: []string{"net-iot"}},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-block-first", Index: 10, Name: "Block 8000", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{8000}},
			},
			{
				ID: "p-allow-range", Index: 20, Name: "Allow 8000-8010", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, PortRanges: []unifi.PortRange{{Start: 8000, End: 8010}}},
			},
			{
				ID: "p-block-rest", Index: 30, Name: "Block IoT to Internal", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	mat, _, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{
		TrustedVLANs:  []string{"LAN"},
		IsolatedVLANs: []string{"IoT"},
	})
	foundViolation := false
	for _, c := range mat.Cells {
		if c.DestFunction == "trusted-lan-transit" && c.SourceNetwork == "IoT" && c.DestNetwork == "LAN" && c.IPFamily == "ipv4" {
			if c.Verdict != IsolationViolation {
				t.Fatalf("expected violation for partially-blocked range 8000-8010, got %+v", c)
			}
			if c.Port <= 8000 || c.Port > 8010 {
				t.Fatalf("expected violation on open port in 8001-8010, got port=%d (%+v)", c.Port, c)
			}
			foundViolation = true
		}
	}
	if !foundViolation {
		t.Fatalf("missing IoT -> LAN transit cell, got %+v", mat.Cells)
	}
}

// TestTransitEvaluationCatchesL3SwitchACLException verifies that when an L3
// switch explicitly allows a specific port before denying everything else,
// EvaluateIsolation inspects switch ACL ALLOW rules and reports a violation
// instead of false blocked-ok.
func TestTransitEvaluationCatchesL3SwitchACLException(t *testing.T) {
	const swMAC = "bb:00:00:00:00:10"
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm"},
			{Name: "Core L3 Switch", MAC: swMAC, IP: "10.0.1.2", Model: "USW-Pro-24", Type: "usw"},
		},
		Networks: []unifi.Network{
			{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "10.0.1.1/24", Purpose: "corporate", ZoneName: "Internal", RouterDeviceMAC: swMAC},
			{ID: "net-iot", Name: "IoT", VLAN: "30", Subnet: "10.0.30.1/24", Purpose: "corporate", ZoneName: "IoT", IsolationEnabled: true, RouterDeviceMAC: swMAC},
		},
		Zones: []unifi.FirewallZone{
			{ID: "z-int", Name: "Internal", NetworkIDs: []string{"net-lan"}},
			{ID: "z-iot", Name: "IoT", NetworkIDs: []string{"net-iot"}},
		},
		SwitchACLs: []unifi.SwitchACL{
			{
				ID: "acl-allow-8443", Index: 10, Name: "Allow IoT to LAN 8443", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				DeviceMACs:  []string{swMAC},
				Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{8443}},
			},
			{
				ID: "acl-deny-all", Index: 20, Name: "Deny IoT to LAN", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
				DeviceMACs:  []string{swMAC},
				Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
		SwitchACLCoverage: &unifi.SwitchACLCoverage{Status: "complete"},
		Visibility:        &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	mat, _, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{
		TrustedVLANs:  []string{"LAN"},
		IsolatedVLANs: []string{"IoT"},
	})
	foundViolation := false
	for _, c := range mat.Cells {
		if c.DestFunction == "trusted-lan-transit" && c.SourceNetwork == "IoT" && c.DestNetwork == "LAN" {
			if c.Verdict != IsolationViolation || c.Port != 8443 || c.DecisiveRuleID != "acl-allow-8443" {
				t.Fatalf("expected L3 switch ACL exception violation on port 8443, got %+v", c)
			}
			foundViolation = true
		}
	}
	if !foundViolation {
		t.Fatalf("missing L3 switch transit cell, got %+v", mat.Cells)
	}
}

// TestRoleScopedApprovalDoesNotHideUnrelatedTransitViolation verifies that an
// approved workflow scoped to dest_role="ups" never suppresses an unrelated
// guest-to-printer transit violation AND resolves the UPS host so the UPS
// workflow itself evaluates cleanly instead of staying unknown.
func TestRoleScopedApprovalDoesNotHideUnrelatedTransitViolation(t *testing.T) {
	printer := unifi.Client{MAC: "00:11:22:33:44:50", IP: "10.0.1.50", Name: "Office Printer", Hostname: "office-printer", NetworkID: "net-lan", NetworkName: "LAN"}
	ups := unifi.Client{MAC: "00:11:22:33:44:60", IP: "10.0.1.60", Name: "Rack UPS", Hostname: "rack-ups", NetworkID: "net-lan", NetworkName: "LAN"}

	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks: []unifi.Network{
			{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "10.0.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-guest", Name: "Guest", VLAN: "40", Subnet: "10.0.40.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		Zones: []unifi.FirewallZone{
			{ID: "z-int", Name: "Internal", NetworkIDs: []string{"net-lan"}},
			{ID: "z-guest", Name: "Hotspot", NetworkIDs: []string{"net-guest"}},
		},
		Clients: []unifi.Client{printer, ups},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-allow-printer", Index: 10, Name: "Allow Guest to Printer 3493", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"10.0.1.50"}, Ports: []int{3493}},
			},
			{
				ID: "p-allow-ups", Index: 15, Name: "Allow Guest to UPS 3493", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"10.0.1.60"}, Ports: []int{3493}},
			},
			{
				ID: "p-deny-rest", Index: 20, Name: "Deny Guest to Internal", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	rawFindings := []checks.Finding{
		{CheckID: "UB-0041", Title: "IPP Printer Exposed", Client: printer, Port: 631},
	}

	mat, _, _ := EvaluateIsolation(snap, rawFindings, config.NetworkConfig{
		TrustedVLANs: []string{"LAN"},
		IsolationPolicy: config.IsolationIntent{
			GuestVLANs: []string{"Guest"},
			ApprovedPaths: []config.ApprovedPath{
				{
					Name:       "UPS monitoring",
					SourceZone: "Hotspot",
					DestZone:   "Internal",
					DestRole:   "ups",
					Function:   "ups-monitoring",
					Transport:  "tcp",
					Port:       3493,
				},
			},
		},
	})

	var transitCell *IsolationCell
	var upsCell *IsolationCell
	for i := range mat.Cells {
		c := &mat.Cells[i]
		if c.DestFunction == "trusted-lan-transit" && c.SourceNetwork == "Guest" && c.DestNetwork == "LAN" {
			transitCell = c
		}
		if c.DestFunction == "ups-monitoring" {
			upsCell = c
		}
	}
	if transitCell == nil || transitCell.Verdict != IsolationViolation || transitCell.DestIP != "10.0.1.50" {
		t.Fatalf("expected Guest -> LAN transit violation on printer 10.0.1.50 (not hidden by UPS approval), got %+v (all cells=%+v)", transitCell, mat.Cells)
	}
	if upsCell == nil || upsCell.Verdict != IsolationApproved || upsCell.DestIP != "10.0.1.60" {
		t.Fatalf("expected UPS monitoring workflow to resolve Rack UPS (10.0.1.60) as approved (not unknown), got %+v", upsCell)
	}
}
