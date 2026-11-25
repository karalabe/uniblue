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

// TestPartialHostApprovalDoesNotHideUnapprovedScope verifies that approving a
// single destination IP never hides unapproved hosts allowed by a wider range,
// CIDR, or multi-IP firewall rule, and only yields blocked-ok when the entire
// permitted scope is approved.
func TestPartialHostApprovalDoesNotHideUnapprovedScope(t *testing.T) {
	run := func(name string, dstIPs []string, wantVerdict IsolationVerdict) {
		t.Run(name, func(t *testing.T) {
			snap := &unifi.Snapshot{
				Site: "default",
				Devices: []unifi.Device{
					{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm"},
				},
				Networks: []unifi.Network{
					{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "10.0.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
					{ID: "net-guest", Name: "Guest", VLAN: "40", Subnet: "10.0.40.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
				},
				FirewallPolicies: []unifi.FirewallPolicy{
					{
						ID: "p-allow", Index: 10, Name: "Allow Guest Batch", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
						Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
						Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: dstIPs, Ports: []int{8443}},
					},
					{
						ID: "p-deny", Index: 20, Name: "Deny Guest to Internal", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
						Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
						Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
					},
				},
				Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
			}
			mat, _, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{
				TrustedVLANs: []string{"LAN"},
				IsolationPolicy: config.IsolationIntent{
					GuestVLANs: []string{"Guest"},
					ApprovedPaths: []config.ApprovedPath{
						{Name: "Single App", SourceZone: "Hotspot", DestZone: "Internal", DestIP: "10.0.1.10", Transport: "tcp", Port: 8443},
					},
				},
			})
			var cell *IsolationCell
			for i := range mat.Cells {
				if mat.Cells[i].DestFunction == "trusted-lan-transit" && mat.Cells[i].SourceNetwork == "Guest" && mat.Cells[i].DestNetwork == "LAN" {
					cell = &mat.Cells[i]
				}
			}
			if cell == nil || cell.Verdict != wantVerdict {
				t.Fatalf("got transit cell %+v, want verdict %q", cell, wantVerdict)
			}
			if wantVerdict == IsolationViolation && cell.DestIP == "10.0.1.10" {
				t.Fatalf("expected violation to cite an unapproved host, not approved 10.0.1.10: %+v", cell)
			}
		})
	}

	run("range_10_hosts_only_first_approved", []string{"10.0.1.10-10.0.1.19"}, IsolationViolation)
	run("cidr_16_hosts_only_one_approved", []string{"10.0.1.0/28"}, IsolationViolation)
	run("explicit_list_10_hosts_only_first_approved", []string{
		"10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.13", "10.0.1.14",
		"10.0.1.15", "10.0.1.16", "10.0.1.17", "10.0.1.18", "10.0.1.19",
	}, IsolationViolation)
	run("single_approved_host_only", []string{"10.0.1.10"}, IsolationBlockedOK)
}

// TestCUPSPrintServerDoesNotMatchUPSRoleApproval verifies that word-boundary
// role matching prevents "cups-printserver" (and CUPS finding titles) from
// qualifying for a UPS-only ApprovedPath exception.
func TestCUPSPrintServerDoesNotMatchUPSRoleApproval(t *testing.T) {
	cupsHost := unifi.Client{
		MAC: "00:11:22:33:44:70", IP: "10.0.1.70",
		Name: "CUPS Print Server", Hostname: "cups-printserver",
		NetworkID: "net-lan", NetworkName: "LAN",
	}
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks: []unifi.Network{
			{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "10.0.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-guest", Name: "Guest", VLAN: "40", Subnet: "10.0.40.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		Clients: []unifi.Client{cupsHost},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-allow-cups", Index: 10, Name: "Allow Guest to CUPS 3493", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"10.0.1.70"}, Ports: []int{3493}},
			},
			{
				ID: "p-deny", Index: 20, Name: "Deny Guest to Internal", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}
	rawFindings := []checks.Finding{
		{CheckID: "UB-0041", Title: "CUPS Admin Interface Exposed", Client: cupsHost, Port: 631},
	}

	mat, _, _ := EvaluateIsolation(snap, rawFindings, config.NetworkConfig{
		TrustedVLANs: []string{"LAN"},
		IsolationPolicy: config.IsolationIntent{
			GuestVLANs: []string{"Guest"},
			ApprovedPaths: []config.ApprovedPath{
				{Name: "UPS monitoring", SourceZone: "Hotspot", DestZone: "Internal", DestRole: "ups", Function: "ups-monitoring", Transport: "tcp", Port: 3493},
			},
		},
	})

	var transitCell *IsolationCell
	for i := range mat.Cells {
		c := &mat.Cells[i]
		if c.DestFunction == "ups-monitoring" && c.DestIP == "10.0.1.70" {
			t.Fatalf("cups-printserver must not match UPS-only approval, got %+v", c)
		}
		if c.DestFunction == "trusted-lan-transit" && c.SourceNetwork == "Guest" && c.DestNetwork == "LAN" {
			transitCell = c
		}
	}
	if transitCell == nil || transitCell.Verdict != IsolationViolation {
		t.Fatalf("expected transit violation for cups-printserver (not suppressed by UPS approval), got %+v", transitCell)
	}
}

// TestIPv6GatewayAdminEvaluatedOnDualStackGuest verifies that a dual-stack
// guest network evaluates both IPv4 and IPv6 gateway administration boundaries
// and flags an explicit IPv6 HTTPS allowance to the gateway.
func TestIPv6GatewayAdminEvaluatedOnDualStackGuest(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks: []unifi.Network{
			{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "10.0.1.1/24", IPv6Subnet: "2001:db8:1::1/64", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-guest", Name: "Guest", VLAN: "40", Subnet: "10.0.40.1/24", IPv6Subnet: "2001:db8:40::1/64", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-v4-block-gw", Index: 10, Name: "Block Guest IPv4 GW Admin", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, Ports: []int{443, 22, 80, 8443}},
			},
			{
				ID: "p-v6-allow-gw", Index: 15, Name: "Allow Guest IPv6 GW HTTPS", Enabled: true, Action: "ALLOW", IPVersion: "ipv6", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, Ports: []int{443}},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	mat, findings, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{
		TrustedVLANs: []string{"LAN"},
		IsolationPolicy: config.IsolationIntent{
			GuestVLANs: []string{"Guest"},
		},
	})

	var v4Cell, v6Cell *IsolationCell
	for i := range mat.Cells {
		c := &mat.Cells[i]
		if c.DestFunction == "gateway-admin" && c.SourceNetwork == "Guest" {
			if c.IPFamily == "ipv4" {
				v4Cell = c
			}
			if c.IPFamily == "ipv6" {
				v6Cell = c
			}
		}
	}
	if v4Cell == nil || v4Cell.Verdict != IsolationBlockedOK {
		t.Fatalf("expected IPv4 gateway-admin cell blocked-ok, got %+v", v4Cell)
	}
	if v6Cell == nil || v6Cell.Verdict != IsolationViolation || v6Cell.Port != 443 || v6Cell.DecisiveRuleName != "Allow Guest IPv6 GW HTTPS" {
		t.Fatalf("expected IPv6 gateway-admin cell violation on TCP 443, got %+v", v6Cell)
	}
	foundV6Finding := false
	for _, f := range findings {
		if f.CheckID == "UB-UNIFI-ISO-GW-ADMIN" && f.Property == "isolation-gw-admin-guest-ipv6" {
			foundV6Finding = true
		}
	}
	if !foundV6Finding {
		t.Fatalf("expected IPv6 UB-UNIFI-ISO-GW-ADMIN finding, got %+v", findings)
	}
}

// TestHostSpecificRuleAlertsOnlyOwningVLANInSharedZone verifies that a
// host-specific ALLOW rule in a zone shared by multiple VLANs triggers a
// transit violation only for the VLAN that actually owns the host IP (both on
// the destination side and on the source side).
func TestHostSpecificRuleAlertsOnlyOwningVLANInSharedZone(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.10.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks: []unifi.Network{
			{ID: "net-a", Name: "TrustedA", VLAN: "10", Subnet: "10.0.10.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-b", Name: "TrustedB", VLAN: "20", Subnet: "10.0.20.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-g1", Name: "GuestA", VLAN: "30", Subnet: "10.0.30.1/24", Purpose: "guest", ZoneName: "Untrusted", IsolationEnabled: true},
			{ID: "net-g2", Name: "IoTB", VLAN: "40", Subnet: "10.0.40.1/24", Purpose: "corporate", ZoneName: "Untrusted", IsolationEnabled: true},
		},
		Clients: []unifi.Client{
			{MAC: "02:00:00:00:00:10", IP: "10.0.10.50", Name: "app-a", NetworkID: "net-a", NetworkName: "TrustedA"},
			{MAC: "02:00:00:00:00:20", IP: "10.0.20.50", Name: "app-b", NetworkID: "net-b", NetworkName: "TrustedB"},
			{MAC: "02:00:00:00:00:30", IP: "10.0.30.25", Name: "guest-laptop", NetworkID: "net-g1", NetworkName: "GuestA"},
			{MAC: "02:00:00:00:00:40", IP: "10.0.40.25", Name: "iot-sensor", NetworkID: "net-g2", NetworkName: "IoTB"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-host-only", Index: 10, Name: "Allow Single GuestA Host to Single TrustedA Host", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Untrusted", IPs: []string{"10.0.30.25"}, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"10.0.10.50"}, Ports: []int{8443}},
			},
			{
				ID: "p-deny-rest", Index: 20, Name: "Deny Untrusted to Internal", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Untrusted", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	mat, findings, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{
		TrustedVLANs:  []string{"TrustedA", "TrustedB"},
		IsolatedVLANs: []string{"GuestA", "IoTB"},
	})

	verdicts := make(map[string]IsolationVerdict)
	for _, c := range mat.Cells {
		if c.DestFunction == "trusted-lan-transit" && c.IPFamily == "ipv4" {
			verdicts[c.SourceNetwork+"->"+c.DestNetwork] = c.Verdict
		}
	}
	if verdicts["GuestA->TrustedA"] != IsolationViolation {
		t.Fatalf("expected GuestA->TrustedA violation, got %+v", verdicts)
	}
	for _, cleanPair := range []string{"GuestA->TrustedB", "IoTB->TrustedA", "IoTB->TrustedB"} {
		if verdicts[cleanPair] != IsolationBlockedOK {
			t.Fatalf("expected %s to be blocked-ok (host belongs to another VLAN), got %q (all=%+v)", cleanPair, verdicts[cleanPair], verdicts)
		}
	}
	transitFindings := 0
	for _, f := range findings {
		if f.CheckID == "UB-UNIFI-ISO-TRUSTED-TRANSIT" {
			transitFindings++
			if f.Property != "isolation-transit-guesta-trusteda-ipv4" {
				t.Fatalf("unexpected transit finding on unrelated VLAN: %+v", f)
			}
		}
	}
	if transitFindings != 1 {
		t.Fatalf("expected exactly 1 transit finding (GuestA->TrustedA only), got %d (%+v)", transitFindings, findings)
	}
}
