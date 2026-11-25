// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"fmt"
	"testing"
	"time"

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

// TestProtocolCoversNegatedCompositeDoesNotShadowWANAllow verifies that an
// earlier negated BLOCK (NOT tcp) never shadows a later composite ALLOW
// (tcp_udp), raising CRITICAL UB-UNIFI-FW-WAN-LAN, and validates protocolCovers
// across concrete, composite, and negated selectors.
func TestProtocolCoversNegatedCompositeDoesNotShadowWANAllow(t *testing.T) {
	cases := []struct {
		ep   string
		eNeg bool
		tp   string
		tNeg bool
		want bool
	}{
		{"tcp", true, "tcp_udp", false, false},
		{"tcp", true, "tcp/udp", false, false},
		{"tcp", true, "all", false, false},
		{"tcp", true, "any", false, false},
		{"tcp", true, "", false, false},
		{"tcp", true, "tcp", true, false},
		{"tcp", true, "udp", true, false},
		{"tcp", true, "tcp", false, false},
		{"tcp", true, "udp", false, true},
		{"tcp", true, "icmp", false, true},
		{"tcp_udp", true, "tcp", false, false},
		{"tcp_udp", true, "udp", false, false},
		{"tcp_udp", true, "icmp", false, true},
	}
	for _, tc := range cases {
		if got := protocolCovers(tc.ep, tc.eNeg, tc.tp, tc.tNeg); got != tc.want {
			t.Fatalf("protocolCovers(%q, %v, %q, %v) = %v, want %v", tc.ep, tc.eNeg, tc.tp, tc.tNeg, got, tc.want)
		}
	}

	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-block-not-tcp", Index: 1, Name: "Block Non-TCP from WAN", Enabled: true, Action: "BLOCK", Origin: "USER_DEFINED",
				Protocol: "tcp", ProtocolNegated: true,
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
			{
				ID: "p-allow-tcp-udp", Index: 2, Name: "Allow WAN TCP/UDP", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
				Protocol:    "tcp_udp",
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
	}

	fwFindings := auditFirewallPolicies(snap)
	if len(fwFindings) != 1 || fwFindings[0].CheckID != "UB-UNIFI-FW-WAN-LAN" || fwFindings[0].EffectiveSeverity != checks.SeverityCritical {
		t.Fatalf("expected CRITICAL UB-UNIFI-FW-WAN-LAN when BLOCK NOT tcp precedes ALLOW tcp_udp, got %+v", fwFindings)
	}
}

// TestNegatedTargetAllowWithUnparseableSelectorReturnsUnknown verifies that a
// negated-target ALLOW with an unparseable IP selector (such as a malformed CIDR
// or unresolved group name) produces IsolationUnknown rather than false
// blocked-ok on both Gateway firewall policies and L3 switch ACLs.
func TestNegatedTargetAllowWithUnparseableSelectorReturnsUnknown(t *testing.T) {
	t.Run("gateway_malformed_cidr", func(t *testing.T) {
		snap := &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
			},
			Networks: []unifi.Network{
				{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
				{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "192.168.50.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
			},
			FirewallPolicies: []unifi.FirewallPolicy{
				{
					ID: "p-allow-bad-neg", Index: 10, Name: "Allow SSH Except Bad CIDR", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.0/33"}, NegateTarget: true, Ports: []int{22}},
				},
				{
					ID: "p-block-all", Index: 20, Name: "Block Guest to Internal", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			},
			Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}
		mat, _, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{TrustedVLANs: []string{"LAN"}, IsolatedVLANs: []string{"Guest"}})
		var cell *IsolationCell
		for i := range mat.Cells {
			if mat.Cells[i].DestFunction == "trusted-lan-transit" && mat.Cells[i].IPFamily == "ipv4" {
				cell = &mat.Cells[i]
			}
		}
		if cell == nil || cell.Verdict != IsolationUnknown {
			t.Fatalf("expected IsolationUnknown for negated-target ALLOW with malformed CIDR, got %+v", cell)
		}
	})

	t.Run("gateway_mixed_parseable_and_unparseable", func(t *testing.T) {
		snap := &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
			},
			Networks: []unifi.Network{
				{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
				{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "192.168.50.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
			},
			FirewallPolicies: []unifi.FirewallPolicy{
				{
					ID: "p-allow-mixed-neg", Index: 10, Name: "Allow SSH Except Gateway and Group", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.1", "UnresolvedGroup"}, NegateTarget: true, Ports: []int{22}},
				},
				{
					ID: "p-block-all", Index: 20, Name: "Block Guest to Internal", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			},
			Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}
		mat, _, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{TrustedVLANs: []string{"LAN"}, IsolatedVLANs: []string{"Guest"}})
		var cell *IsolationCell
		for i := range mat.Cells {
			if mat.Cells[i].DestFunction == "trusted-lan-transit" && mat.Cells[i].IPFamily == "ipv4" {
				cell = &mat.Cells[i]
			}
		}
		if cell == nil || cell.Verdict != IsolationUnknown {
			t.Fatalf("expected IsolationUnknown for mixed parseable/unparseable negated target, got %+v", cell)
		}
	})

	t.Run("l3_switch_acl_malformed_cidr", func(t *testing.T) {
		const swMAC = "bb:00:00:00:00:33"
		snap := &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
				{Name: "Core L3 Switch", MAC: swMAC, IP: "192.168.1.2", Model: "USW-Pro-24", Type: "usw"},
			},
			Networks: []unifi.Network{
				{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal", RouterDeviceMAC: swMAC},
				{ID: "net-iot", Name: "IoT", VLAN: "30", Subnet: "192.168.30.1/24", Purpose: "corporate", ZoneName: "IoT", IsolationEnabled: true, RouterDeviceMAC: swMAC},
			},
			SwitchACLs: []unifi.SwitchACL{
				{
					ID: "acl-allow-bad-neg", Index: 10, Name: "Allow SSH Except Bad CIDR", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
					DeviceMACs:  []string{swMAC},
					Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.0/33"}, NegateTarget: true, Ports: []int{22}},
				},
				{
					ID: "acl-block-all", Index: 20, Name: "Block IoT to Internal", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
					DeviceMACs:  []string{swMAC},
					Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			},
			SwitchACLCoverage: &unifi.SwitchACLCoverage{Status: "complete"},
			Visibility:        &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}
		mat, _, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{TrustedVLANs: []string{"LAN"}, IsolatedVLANs: []string{"IoT"}})
		var cell *IsolationCell
		for i := range mat.Cells {
			if mat.Cells[i].DestFunction == "trusted-lan-transit" && mat.Cells[i].IPFamily == "ipv4" {
				cell = &mat.Cells[i]
			}
		}
		if cell == nil || cell.Verdict != IsolationUnknown {
			t.Fatalf("expected IsolationUnknown for L3 switch ACL negated-target ALLOW with malformed CIDR, got %+v", cell)
		}
	})
}

// TestFunctionOnlyApprovedPathDoesNotHideZoneWideAllow verifies that an
// ApprovedPath specifying only Function (with empty DestIP and DestRole)
// requires a matching destination client role and never suppresses a zone-wide
// ALLOW as blocked-ok.
func TestFunctionOnlyApprovedPathDoesNotHideZoneWideAllow(t *testing.T) {
	printer := unifi.Client{MAC: "02:11:22:33:44:50", IP: "192.168.1.50", Name: "Office Printer", Hostname: "office-printer", NetworkID: "net-lan", NetworkName: "LAN"}
	workstation := unifi.Client{MAC: "02:11:22:33:44:20", IP: "192.168.1.20", Name: "Dev Laptop", Hostname: "dev-laptop", NetworkID: "net-lan", NetworkName: "LAN"}

	makeSnap := func(allowDst unifi.PolicyEndpoint) *unifi.Snapshot {
		return &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
			},
			Networks: []unifi.Network{
				{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
				{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "192.168.50.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
			},
			Clients: []unifi.Client{printer, workstation},
			FirewallPolicies: []unifi.FirewallPolicy{
				{
					ID: "p-allow-631", Index: 10, Name: "Allow Guest Printing", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
					Destination: allowDst,
				},
				{
					ID: "p-block-all", Index: 20, Name: "Block Guest to Internal", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			},
			Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}
	}

	netCfg := config.NetworkConfig{
		TrustedVLANs: []string{"LAN"},
		IsolationPolicy: config.IsolationIntent{
			GuestVLANs: []string{"Guest"},
			ApprovedPaths: []config.ApprovedPath{
				{
					Name:       "Guest Printing",
					SourceZone: "Hotspot",
					DestZone:   "Internal",
					Function:   "ipps-printing",
					Transport:  "tcp",
					Port:       631,
				},
			},
		},
	}

	// Zone-wide ALLOW Hotspot->Internal tcp/631 MUST report a transit violation.
	matWide, _, _ := EvaluateIsolation(makeSnap(unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{631}}), nil, netCfg)
	var wideCell *IsolationCell
	for i := range matWide.Cells {
		if matWide.Cells[i].DestFunction == "trusted-lan-transit" && matWide.Cells[i].IPFamily == "ipv4" {
			wideCell = &matWide.Cells[i]
		}
	}
	if wideCell == nil || wideCell.Verdict != IsolationViolation {
		t.Fatalf("expected zone-wide ALLOW tcp/631 not to be hidden by function-only ApprovedPath, got %+v", wideCell)
	}
	if wideCell.DestIP == printer.IP {
		t.Fatalf("expected violation to cite a non-printer host, not printer %s: %+v", printer.IP, wideCell)
	}

	// Printer-scoped ALLOW Hotspot->192.168.1.50 tcp/631 IS approved (blocked-ok).
	matScoped, _, _ := EvaluateIsolation(makeSnap(unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{printer.IP}, Ports: []int{631}}), nil, netCfg)
	var scopedCell *IsolationCell
	for i := range matScoped.Cells {
		if matScoped.Cells[i].DestFunction == "trusted-lan-transit" && matScoped.Cells[i].IPFamily == "ipv4" {
			scopedCell = &matScoped.Cells[i]
		}
	}
	if scopedCell == nil || scopedCell.Verdict != IsolationBlockedOK {
		t.Fatalf("expected printer-only ALLOW tcp/631 to be approved as blocked-ok, got %+v", scopedCell)
	}
}

// TestSubnetlessNetworkExcludedRealClientsNoSyntheticViolation verifies that
// when a destination network has no configured subnet but has active clients
// all covered by a negated-target ALLOW exclusion, EvaluateIsolation returns
// blocked-ok instead of synthesizing an out-of-network boundary IP violation.
func TestSubnetlessNetworkExcludedRealClientsNoSyntheticViolation(t *testing.T) {
	makeSnap := func(clients []unifi.Client) *unifi.Snapshot {
		return &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
			},
			Networks: []unifi.Network{
				{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "", Purpose: "corporate", ZoneName: "Internal"},
				{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "192.168.50.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
			},
			Clients: clients,
			FirewallPolicies: []unifi.FirewallPolicy{
				{
					ID: "p-allow-except", Index: 10, Name: "Allow SSH Except 192.168.1.0/24", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.0/24"}, NegateTarget: true, Ports: []int{22}},
				},
				{
					ID: "p-block-all", Index: 20, Name: "Block Guest to Internal", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			},
			Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}
	}

	netCfg := config.NetworkConfig{TrustedVLANs: []string{"LAN"}, IsolatedVLANs: []string{"Guest"}}

	// All real clients on subnet-less LAN fall inside 192.168.1.0/24 -> blocked-ok.
	snapCovered := makeSnap([]unifi.Client{
		{MAC: "02:aa:00:00:00:05", IP: "192.168.1.5", Name: "host-a", NetworkID: "net-lan", NetworkName: "LAN"},
		{MAC: "02:aa:00:00:00:06", IP: "192.168.1.6", Name: "host-b", NetworkID: "net-lan", NetworkName: "LAN"},
	})
	matCovered, _, _ := EvaluateIsolation(snapCovered, nil, netCfg)
	var cellCovered *IsolationCell
	for i := range matCovered.Cells {
		if matCovered.Cells[i].DestFunction == "trusted-lan-transit" && matCovered.Cells[i].IPFamily == "ipv4" {
			cellCovered = &matCovered.Cells[i]
		}
	}
	if cellCovered == nil || cellCovered.Verdict != IsolationBlockedOK {
		t.Fatalf("expected blocked-ok when all real clients on subnet-less LAN are excluded, got %+v", cellCovered)
	}

	// Adding a real client outside 192.168.1.0/24 on LAN must still detect the violation.
	snapOutside := makeSnap([]unifi.Client{
		{MAC: "02:aa:00:00:00:05", IP: "192.168.1.5", Name: "host-a", NetworkID: "net-lan", NetworkName: "LAN"},
		{MAC: "02:aa:00:00:00:10", IP: "192.168.2.10", Name: "host-c", NetworkID: "net-lan", NetworkName: "LAN"},
	})
	matOutside, _, _ := EvaluateIsolation(snapOutside, nil, netCfg)
	var cellOutside *IsolationCell
	for i := range matOutside.Cells {
		if matOutside.Cells[i].DestFunction == "trusted-lan-transit" && matOutside.Cells[i].IPFamily == "ipv4" {
			cellOutside = &matOutside.Cells[i]
		}
	}
	if cellOutside == nil || cellOutside.Verdict != IsolationViolation || cellOutside.DestIP != "192.168.2.10" {
		t.Fatalf("expected real violation to 192.168.2.10 on subnet-less LAN, got %+v", cellOutside)
	}
}

// TestTransitBoundaryProbePerformanceManyDenyPorts verifies that evaluating
// 25 multi-port BLOCK policies (16 ports each) plus 25 source-scoped any-port
// ALLOW policies across 3x3 dual-stack networks completes well under 100ms
// without sacrificing violation accuracy.
func TestTransitBoundaryProbePerformanceManyDenyPorts(t *testing.T) {
	networks := []unifi.Network{
		{ID: "net-t1", Name: "Trusted1", VLAN: "10", Subnet: "10.10.0.1/24", IPv6Subnet: "2001:db8:10::1/64", Purpose: "corporate", ZoneName: "Internal"},
		{ID: "net-t2", Name: "Trusted2", VLAN: "11", Subnet: "10.11.0.1/24", IPv6Subnet: "2001:db8:11::1/64", Purpose: "corporate", ZoneName: "Internal"},
		{ID: "net-t3", Name: "Trusted3", VLAN: "12", Subnet: "10.12.0.1/24", IPv6Subnet: "2001:db8:12::1/64", Purpose: "corporate", ZoneName: "Internal"},
		{ID: "net-u1", Name: "Untrusted1", VLAN: "20", Subnet: "10.20.0.1/24", IPv6Subnet: "2001:db8:20::1/64", Purpose: "corporate", ZoneName: "IoT", IsolationEnabled: true},
		{ID: "net-u2", Name: "Untrusted2", VLAN: "21", Subnet: "10.21.0.1/24", IPv6Subnet: "2001:db8:21::1/64", Purpose: "corporate", ZoneName: "IoT", IsolationEnabled: true},
		{ID: "net-u3", Name: "Untrusted3", VLAN: "22", Subnet: "10.22.0.1/24", IPv6Subnet: "2001:db8:22::1/64", Purpose: "corporate", ZoneName: "IoT", IsolationEnabled: true},
	}

	var policies []unifi.FirewallPolicy
	idx := 1
	// 25 BLOCK policies of 16 ports each (400 blocked ports total).
	for b := 0; b < 25; b++ {
		ports := make([]int, 0, 16)
		base := 1000 + b*20
		for p := 0; p < 16; p++ {
			ports = append(ports, base+p)
		}
		policies = append(policies, unifi.FirewallPolicy{
			ID: fmt.Sprintf("p-block-%d", b), Index: idx, Name: fmt.Sprintf("Block Batch %d", b),
			Enabled: true, Action: "BLOCK", IPVersion: "both", Protocol: "tcp_udp",
			Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
			Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: ports},
		})
		idx++
	}
	// Shadowing broad BLOCK so all probes across all 25 ALLOW rules execute to completion.
	policies = append(policies, unifi.FirewallPolicy{
		ID: "p-block-all", Index: idx, Name: "Block All IoT to Internal",
		Enabled: true, Action: "BLOCK", IPVersion: "both", Protocol: "all",
		Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
	})
	idx++
	// 25 source-scoped any-port ALLOW policies across the 3 untrusted networks.
	for a := 0; a < 25; a++ {
		vlan := 20 + (a % 3)
		host := 10 + a
		policies = append(policies, unifi.FirewallPolicy{
			ID: fmt.Sprintf("p-allow-%d", a), Index: idx, Name: fmt.Sprintf("Allow Host %d", a),
			Enabled: true, Action: "ALLOW", IPVersion: "both", Protocol: "all",
			Source: unifi.PolicyEndpoint{
				ZoneName: "IoT",
				IPs:      []string{fmt.Sprintf("10.%d.0.%d", vlan, host), fmt.Sprintf("2001:db8:%d::%x", vlan, host)},
				AnyPort:  true,
			},
			Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
		})
		idx++
	}

	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.10.0.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks:         networks,
		FirewallPolicies: policies,
		Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}
	netCfg := config.NetworkConfig{
		TrustedVLANs:  []string{"Trusted1", "Trusted2", "Trusted3"},
		IsolatedVLANs: []string{"Untrusted1", "Untrusted2", "Untrusted3"},
	}

	start := time.Now()
	mat, _, _ := EvaluateIsolation(snap, nil, netCfg)
	elapsed := time.Since(start)
	if elapsed >= 100*time.Millisecond {
		t.Fatalf("EvaluateIsolation took %v on 25x16 BLOCK + 25 ALLOW across 3x3 dual-stack networks, want < 100ms", elapsed)
	}
	transitCount := 0
	for _, c := range mat.Cells {
		if c.DestFunction == "trusted-lan-transit" {
			transitCount++
			if c.Verdict != IsolationBlockedOK {
				t.Fatalf("expected shadowed transit cell blocked-ok, got %+v", c)
			}
		}
	}
	if transitCount != 18 {
		t.Fatalf("expected 18 transit cells (3x3 dual-stack), got %d", transitCount)
	}
}

// TestPartialPortRangeApprovalAndPartialSourceBlockNeverHideAccess verifies:
// (1) approving one port inside an allowed port range does not hide the other
//     permitted ports (including across a synthetic sweep of controller port
//     range representations);
// (2) an earlier block on one source IP or MAC does not hide a neighbor source
//     permitted by a later allow rule (both on transit and gateway-admin paths);
// (3) when an allow rule's uncovered equivalence space exceeds the exact
//     verification cap, UniBlue returns IsolationUnknown rather than false
//     blocked-ok.
func TestPartialPortRangeApprovalAndPartialSourceBlockNeverHideAccess(t *testing.T) {
	baseSnap := func(policies []unifi.FirewallPolicy) *unifi.Snapshot {
		return &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm"},
			},
			Networks: []unifi.Network{
				{ID: "net-office", Name: "Office", VLAN: "1", Subnet: "10.0.1.0/24", ZoneName: "Internal"},
				{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "10.0.50.0/24", ZoneName: "Guest", IsolationEnabled: true},
			},
			Clients: []unifi.Client{
				{MAC: "02:00:00:50:00:10", Name: "guest-1", IP: "10.0.50.10", NetworkID: "net-guest", NetworkName: "Guest"},
				{MAC: "02:00:00:50:00:11", Name: "guest-2", IP: "10.0.50.11", NetworkID: "net-guest", NetworkName: "Guest"},
				{MAC: "02:00:00:01:00:20", Name: "office-srv", IP: "10.0.1.20", NetworkID: "net-office", NetworkName: "Office"},
			},
			FirewallPolicies: policies,
			Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}
	}

	findTransit := func(mat *IsolationMatrix) *IsolationCell {
		for i := range mat.Cells {
			c := &mat.Cells[i]
			if c.DestFunction == "trusted-lan-transit" && c.SourceNetwork == "Guest" && c.DestNetwork == "Office" && c.IPFamily == "ipv4" {
				return c
			}
		}
		return nil
	}

	// 1. Rule permits 17 TCP ports (8000-8016) on 10.0.1.20; operator approved
	// only 8000. The remaining 16 ports must produce IsolationViolation.
	t.Run("partial_port_range_approval_catches_unapproved_ports", func(t *testing.T) {
		snap := baseSnap([]unifi.FirewallPolicy{
			{
				ID: "p-range", Index: 10, Name: "Allow Range 8000-8016", Enabled: true,
				Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source: unifi.PolicyEndpoint{ZoneName: "Guest", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{
					ZoneName:   "Internal",
					IPs:        []string{"10.0.1.20"},
					PortRanges: []unifi.PortRange{{Start: 8000, End: 8016}},
				},
			},
			{
				ID: "p-deny", Index: 100, Name: "Block Guest -> Internal", Enabled: true,
				Action: "BLOCK", IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Guest", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		})
		netCfg := config.NetworkConfig{
			TrustedVLANs:  []string{"Office"},
			IsolatedVLANs: []string{"Guest"},
			IsolationPolicy: config.IsolationIntent{
				ApprovedPaths: []config.ApprovedPath{
					{SourceZone: "Guest", DestZone: "Internal", DestIP: "10.0.1.20", Transport: "tcp", Port: 8000},
				},
			},
		}
		mat, _, _ := EvaluateIsolation(snap, nil, netCfg)
		cell := findTransit(mat)
		if cell == nil || cell.Verdict != IsolationViolation || cell.Port < 8001 || cell.Port > 8016 {
			t.Fatalf("expected IsolationViolation on unapproved port in 8001..8016, got %+v", cell)
		}
	})

	// 2. Synthetic sweep across port-range + partial-approval + partial-block
	// combinations: whenever any unapproved port remains allowed, verdict must
	// be IsolationViolation; when every port is approved or earlier-blocked,
	// verdict must be IsolationBlockedOK.
	t.Run("port_range_synthetic_sweep", func(t *testing.T) {
		type sweepCase struct {
			name        string
			allowRanges []unifi.PortRange
			blockRanges []unifi.PortRange
			approved    []int
			want        IsolationVerdict
		}
		cases := []sweepCase{
			{
				name:        "first_of_17_approved",
				allowRanges: []unifi.PortRange{{Start: 8000, End: 8016}},
				approved:    []int{8000},
				want:        IsolationViolation,
			},
			{
				name:        "last_of_17_approved",
				allowRanges: []unifi.PortRange{{Start: 8000, End: 8016}},
				approved:    []int{8016},
				want:        IsolationViolation,
			},
			{
				name:        "ends_approved_middle_open",
				allowRanges: []unifi.PortRange{{Start: 8000, End: 8016}},
				approved:    []int{8000, 8016},
				want:        IsolationViolation,
			},
			{
				name:        "first_approved_rest_blocked_except_last",
				allowRanges: []unifi.PortRange{{Start: 8000, End: 8016}},
				blockRanges: []unifi.PortRange{{Start: 8001, End: 8015}},
				approved:    []int{8000},
				want:        IsolationViolation,
			},
			{
				name:        "first_approved_rest_fully_blocked",
				allowRanges: []unifi.PortRange{{Start: 8000, End: 8016}},
				blockRanges: []unifi.PortRange{{Start: 8001, End: 8016}},
				approved:    []int{8000},
				want:        IsolationBlockedOK,
			},
			{
				name:        "all_3_ports_individually_approved",
				allowRanges: []unifi.PortRange{{Start: 9000, End: 9002}},
				approved:    []int{9000, 9001, 9002},
				want:        IsolationBlockedOK,
			},
		}
		for _, tc := range cases {
			var pols []unifi.FirewallPolicy
			if len(tc.blockRanges) > 0 {
				pols = append(pols, unifi.FirewallPolicy{
					ID: "p-blk-sub", Index: 5, Name: "Block Subrange", Enabled: true,
					Action: "BLOCK", IPVersion: "ipv4", Protocol: "tcp",
					Source: unifi.PolicyEndpoint{ZoneName: "Guest", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{
						ZoneName:   "Internal",
						IPs:        []string{"10.0.1.20"},
						PortRanges: tc.blockRanges,
					},
				})
			}
			pols = append(pols,
				unifi.FirewallPolicy{
					ID: "p-allow", Index: 10, Name: "Allow Range", Enabled: true,
					Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
					Source: unifi.PolicyEndpoint{ZoneName: "Guest", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{
						ZoneName:   "Internal",
						IPs:        []string{"10.0.1.20"},
						PortRanges: tc.allowRanges,
					},
				},
				unifi.FirewallPolicy{
					ID: "p-deny", Index: 100, Name: "Block Default", Enabled: true,
					Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Guest", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			)
			var aps []config.ApprovedPath
			for _, p := range tc.approved {
				aps = append(aps, config.ApprovedPath{
					SourceZone: "Guest", DestZone: "Internal", DestIP: "10.0.1.20", Transport: "tcp", Port: p,
				})
			}
			mat, _, _ := EvaluateIsolation(baseSnap(pols), nil, config.NetworkConfig{
				TrustedVLANs:    []string{"Office"},
				IsolatedVLANs:   []string{"Guest"},
				IsolationPolicy: config.IsolationIntent{ApprovedPaths: aps},
			})
			cell := findTransit(mat)
			if cell == nil || cell.Verdict != tc.want {
				t.Fatalf("%s: verdict=%v, want %v (cell=%+v)", tc.name, cell.Verdict, tc.want, cell)
			}
		}
	})

	// 3. Earlier rule denies guest-1 (10.0.50.10); later rule allows guest-1
	// and neighbor guest-2 (10.0.50.11) to reach Office service 10.0.1.20:8443.
	// UniBlue must catch guest-2's access instead of reporting blocked-ok.
	for _, tc := range []struct {
		name      string
		allowSrc  unifi.PolicyEndpoint
		blockSrc  unifi.PolicyEndpoint
		wantState IsolationVerdict
	}{
		{
			name:     "block_first_client_allow_both_explicit_ips",
			blockSrc: unifi.PolicyEndpoint{ZoneName: "Guest", IPs: []string{"10.0.50.10"}, AnyPort: true},
			allowSrc: unifi.PolicyEndpoint{ZoneName: "Guest", IPs: []string{"10.0.50.10", "10.0.50.11"}, AnyPort: true},
		},
		{
			name:     "block_first_client_allow_range_covering_neighbor",
			blockSrc: unifi.PolicyEndpoint{ZoneName: "Guest", IPs: []string{"10.0.50.10"}, AnyPort: true},
			allowSrc: unifi.PolicyEndpoint{ZoneName: "Guest", IPs: []string{"10.0.50.10-10.0.50.11"}, AnyPort: true},
		},
		{
			name:     "block_first_client_allow_any_guest",
			blockSrc: unifi.PolicyEndpoint{ZoneName: "Guest", IPs: []string{"10.0.50.10"}, AnyPort: true},
			allowSrc: unifi.PolicyEndpoint{ZoneName: "Guest", AnyTarget: true, AnyPort: true},
		},
		{
			name:     "block_first_mac_allow_any_guest",
			blockSrc: unifi.PolicyEndpoint{ZoneName: "Guest", MACs: []string{"02:00:00:50:00:10"}, AnyPort: true},
			allowSrc: unifi.PolicyEndpoint{ZoneName: "Guest", AnyTarget: true, AnyPort: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := baseSnap([]unifi.FirewallPolicy{
				{
					ID: "p-block-one", Index: 10, Name: "Block Guest 1", Enabled: true,
					Action: "BLOCK", IPVersion: "ipv4", Protocol: "tcp",
					Source:      tc.blockSrc,
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"10.0.1.20"}, Ports: []int{8443}},
				},
				{
					ID: "p-allow-both", Index: 20, Name: "Allow Guests to Office", Enabled: true,
					Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
					Source:      tc.allowSrc,
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"10.0.1.20"}, Ports: []int{8443}},
				},
				{
					ID: "p-deny-rest", Index: 100, Name: "Block Guest -> Internal", Enabled: true,
					Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Guest", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			})
			mat, _, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{
				TrustedVLANs:  []string{"Office"},
				IsolatedVLANs: []string{"Guest"},
			})
			cell := findTransit(mat)
			if cell == nil || cell.Verdict != IsolationViolation || cell.DecisiveRuleID != "p-allow-both" {
				t.Fatalf("%s: expected IsolationViolation via p-allow-both, got %+v", tc.name, cell)
			}
		})
	}

	// 4. Same source-masking check on Gateway Admin boundary: blocking guest-1
	// from Gateway HTTPS must not hide guest-2 allowed by a subsequent rule.
	t.Run("gateway_admin_block_one_source_does_not_hide_neighbor", func(t *testing.T) {
		snap := baseSnap([]unifi.FirewallPolicy{
			{
				ID: "p-gw-block-one", Index: 10, Name: "Block Guest 1 -> GW", Enabled: true,
				Action: "BLOCK", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Guest", IPs: []string{"10.0.50.10"}, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, Ports: []int{443}},
			},
			{
				ID: "p-gw-allow-both", Index: 20, Name: "Allow Guests -> GW HTTPS", Enabled: true,
				Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Guest", IPs: []string{"10.0.50.10-10.0.50.11"}, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, Ports: []int{443}},
			},
			{
				ID: "p-gw-deny", Index: 100, Name: "Block Guest -> GW", Enabled: true,
				Action: "BLOCK", IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Guest", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, AnyPort: true},
			},
		})
		mat, _, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{
			TrustedVLANs:  []string{"Office"},
			IsolatedVLANs: []string{"Guest"},
		})
		var gwCell *IsolationCell
		for i := range mat.Cells {
			c := &mat.Cells[i]
			if c.DestFunction == "gateway-admin" && c.SourceNetwork == "Guest" && c.IPFamily == "ipv4" {
				gwCell = c
				break
			}
		}
		if gwCell == nil || gwCell.Verdict != IsolationViolation || gwCell.DecisiveRuleID != "p-gw-allow-both" {
			t.Fatalf("expected gateway-admin IsolationViolation via p-gw-allow-both, got %+v", gwCell)
		}
	})

	// 5. Differential oracle over 500 synthetic policies combining partial
	// source/dest/port blocks, allow port ranges, and partial approvals:
	// zero false blocked-ok and zero false violations.
	t.Run("differential_oracle_500_synthetic_policies", func(t *testing.T) {
		var seed uint64 = 0x5eed1234abcd9876
		nextInt := func(n int) int {
			seed = seed*6364136223846793005 + 1442695040888963407
			return int((seed >> 33) % uint64(n))
		}
		srcPool := []string{"10.0.50.10", "10.0.50.11", "10.0.50.12", "10.0.50.13"}
		dstPool := []string{"10.0.1.20", "10.0.1.21", "10.0.1.22", "10.0.1.23"}
		pickIPSel := func(pool []string) ([]string, bool) {
			switch nextInt(5) {
			case 0:
				return nil, true // AnyTarget
			case 1:
				return []string{pool[nextInt(len(pool))]}, false
			case 2:
				a := nextInt(len(pool))
				b := nextInt(len(pool))
				if a > b {
					a, b = b, a
				}
				return []string{pool[a] + "-" + pool[b]}, false
			case 3:
				a := nextInt(len(pool))
				b := nextInt(len(pool))
				return []string{pool[a], pool[b]}, false
			default:
				return []string{pool[nextInt(len(pool))]}, false
			}
		}
		pickPortEP := func(base unifi.PolicyEndpoint) unifi.PolicyEndpoint {
			switch nextInt(4) {
			case 0:
				p := 8000 + nextInt(17)
				base.Ports = []int{p}
			case 1:
				a := 8000 + nextInt(17)
				b := 8000 + nextInt(17)
				if a > b {
					a, b = b, a
				}
				base.PortRanges = []unifi.PortRange{{Start: a, End: b}}
			case 2:
				a := 8000 + nextInt(10)
				base.PortRanges = []unifi.PortRange{{Start: a, End: a + 5}}
				base.Ports = []int{8016}
			default:
				base.Ports = []int{8000 + nextInt(17), 8000 + nextInt(17)}
			}
			return base
		}

		for trial := 0; trial < 500; trial++ {
			var pols []unifi.FirewallPolicy
			// 0..2 earlier partial BLOCK rules.
			numBlocks := nextInt(3)
			for b := 0; b < numBlocks; b++ {
				sIPs, sAny := pickIPSel(srcPool)
				dIPs, dAny := pickIPSel(dstPool)
				srcEP := unifi.PolicyEndpoint{ZoneName: "Guest", IPs: sIPs, AnyTarget: sAny, AnyPort: true}
				dstEP := pickPortEP(unifi.PolicyEndpoint{ZoneName: "Internal", IPs: dIPs, AnyTarget: dAny})
				if nextInt(6) == 0 && !sAny {
					srcEP.NegateTarget = true
				}
				if nextInt(6) == 0 && !dAny {
					dstEP.NegateTarget = true
				}
				pols = append(pols, unifi.FirewallPolicy{
					ID: fmt.Sprintf("blk-%d-%d", trial, b), Index: 10 + b, Name: "Block", Enabled: true,
					Action: "BLOCK", IPVersion: "ipv4", Protocol: "tcp",
					Source: srcEP, Destination: dstEP,
				})
			}
			// 1 ALLOW rule scoped to srcPool/dstPool and ports in 8000..8016.
			sIPs, sAny := pickIPSel(srcPool)
			if sAny {
				sIPs = []string{"10.0.50.10-10.0.50.13"}
			}
			dIPs, dAny := pickIPSel(dstPool)
			if dAny {
				dIPs = []string{"10.0.1.20-10.0.1.23"}
			}
			allowDst := pickPortEP(unifi.PolicyEndpoint{ZoneName: "Internal", IPs: dIPs})
			pols = append(pols,
				unifi.FirewallPolicy{
					ID: fmt.Sprintf("allow-%d", trial), Index: 50, Name: "Allow", Enabled: true,
					Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "Guest", IPs: sIPs, AnyPort: true},
					Destination: allowDst,
				},
				unifi.FirewallPolicy{
					ID: "deny-all", Index: 100, Name: "Block Rest", Enabled: true,
					Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Guest", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			)

			// 0..2 partial ApprovedPath entries.
			var aps []config.ApprovedPath
			for a := 0; a < nextInt(3); a++ {
				aps = append(aps, config.ApprovedPath{
					SourceZone: "Guest",
					DestZone:   "Internal",
					DestIP:     dstPool[nextInt(len(dstPool))],
					Transport:  "tcp",
					Port:       8000 + nextInt(17),
				})
			}

			snap := baseSnap(pols)
			netCfg := config.NetworkConfig{
				TrustedVLANs:    []string{"Office"},
				IsolatedVLANs:   []string{"Guest"},
				IsolationPolicy: config.IsolationIntent{ApprovedPaths: aps},
			}

			// Brute-force oracle over every (src, dst, port) in the finite rule domain.
			oracleAllowed := false
			for _, sip := range srcPool {
				for _, dip := range dstPool {
					for port := 8000; port <= 8016; port++ {
						if isTransitProbeApproved(snap, nil, aps, "Guest", "Guest", snap.Networks[0], dip, "tcp", port, "ipv4") {
							continue
						}
						dec := evaluateGatewayPolicies(pols, pathQuery{
							srcZone: "Guest", srcNetID: "net-guest", srcNetName: "Guest", srcIP: sip,
							dstZone: "Internal", dstNetID: "net-office", dstNetName: "Office", dstIP: dip,
							proto: "tcp", port: port, ipFamily: "ipv4", state: "new",
						})
						if dec.action == "allow" {
							oracleAllowed = true
							break
						}
					}
					if oracleAllowed {
						break
					}
				}
				if oracleAllowed {
					break
				}
			}

			mat, _, _ := EvaluateIsolation(snap, nil, netCfg)
			cell := findTransit(mat)
			want := IsolationBlockedOK
			if oracleAllowed {
				want = IsolationViolation
			}
			if cell == nil || cell.Verdict != want {
				t.Fatalf("trial %d: EvaluateIsolation verdict=%v, brute-force oracle wants %v (cell=%+v, aps=%+v)", trial, cell.Verdict, want, cell, aps)
			}
		}
	})
}
