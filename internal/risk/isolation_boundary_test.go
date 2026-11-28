// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
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
			{Name: "Gateway", MAC: "AA:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm"},
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
			checkOracleTransit(t, snap, c, "aa:00:00:00:00:01")
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
	const swMAC = "BB:00:00:00:00:10"
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "AA:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm"},
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
		Visibility:        &unifi.SiteVisibility{GatewayPoliciesAvailable: true, SwitchACLsAvailable: true},
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
			checkOracleTransit(t, snap, c, strings.ToLower(swMAC))
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
			Visibility:        &unifi.SiteVisibility{GatewayPoliciesAvailable: true, SwitchACLsAvailable: true},
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
//
//	permitted ports (including across a synthetic sweep of controller port
//	range representations);
//
// (2) an earlier block on one source IP or MAC does not hide a neighbor source
//
//	permitted by a later allow rule (both on transit and gateway-admin paths);
//
// (3) when an allow rule's uncovered equivalence space exceeds the exact
//
//	verification cap, UniBlue returns IsolationUnknown rather than false
//	blocked-ok.
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

// TestControllerPortFilterDoesNotBlockAllTraffic verifies end-to-end from a
// real UniFi Integration v1 ACL wire payload (PORTS with portFilter:[443])
// through unifi.Controller.FetchSnapshot into risk.Evaluate that blocking a
// single destination port does not certify full inter-VLAN transit isolation.
func TestControllerPortFilterDoesNotBlockAllTraffic(t *testing.T) {
	const base = "/proxy/network/integration/v1/sites"
	const sensorID = "6673035e-23a8-40cf-8a61-0127d0de3a44"
	empty := `{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}`
	page := func(n int, rows string) string {
		return fmt.Sprintf(`{"offset":0,"limit":200,"count":%d,"totalCount":%d,"data":%s}`, n, n, rows)
	}
	site := base + "/site-1/"
	data := map[string]string{
		base:                            page(1, `[{"id":"site-1","name":"Default","internalReference":"default"}]`),
		site + "clients":                empty,
		site + "devices":                page(1, `[{"id":"switch-a","name":"Switch","macAddress":"00:00:5e:00:53:01","model":"USW"}]`),
		site + "networks":               page(2, `[{"id":"`+sensorID+`","name":"Sensors","vlanId":20,"isolationEnabled":true,"zoneId":"z-hot","routerDeviceMac":"00:00:5e:00:53:01","subnet":"198.51.100.1/24"},{"id":"office","name":"Office","vlanId":10,"zoneId":"z-lan","routerDeviceMac":"00:00:5e:00:53:01","subnet":"192.0.2.1/24"}]`),
		site + "firewall/zones":         page(2, `[{"id":"z-hot","name":"Hotspot","networkIds":["`+sensorID+`"]},{"id":"z-lan","name":"Internal","networkIds":["office"]}]`),
		site + "firewall/policies":      empty,
		site + "traffic-matching-lists": empty,
		site + "acl-rules":              page(1, `[{"type":"IPV4","id":"ba6d1f92-4920-479d-84a7-81c1f3876665","index":1,"name":"Block one management port","action":"BLOCK","enabled":true,"metadata":{"origin":"USER_DEFINED"},"sourceFilter":{"type":"NETWORKS","networkIds":["`+sensorID+`"]},"destinationFilter":{"type":"PORTS","portFilter":[443]}}]`),
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := data[strings.TrimSuffix(r.URL.Path, "/")]; ok {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ctrl, err := unifi.New(config.UniFiConfig{URL: srv.URL, Site: "default", APIKey: "test-only", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctrl.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap, err := ctrl.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.SwitchACLs) != 1 || snap.SwitchACLCoverage.Status != "complete" {
		t.Fatalf("ACL fixture not loaded: %+v", snap.SwitchACLCoverage)
	}

	rep := Evaluate(snap, nil, config.NetworkConfig{TrustedVLANs: []string{"Office"}, IsolatedVLANs: []string{"Sensors"}})
	for _, cell := range rep.Isolation.Cells {
		if cell.SourceNetwork == "Sensors" && cell.DestNetwork == "Office" && cell.DestFunction == "trusted-lan-transit" && cell.IPFamily == "ipv4" {
			if cell.Verdict != IsolationViolation {
				t.Fatalf("only port 443 is denied; controller -> report returned %s, enforcer=%s, rule=%s, ACL coverage=%s", cell.Verdict, cell.Enforcer, cell.DecisiveRuleName, snap.SwitchACLCoverage.Status)
			}
			return
		}
	}
	t.Fatal("no transit cell found")
}

// checkOracleTransit compares a concrete client pair with the service witness
// found by the matrix's network-wide search on the same uniform boundary.
func checkOracleTransit(t *testing.T, snap *unifi.Snapshot, want IsolationCell, mac string) {
	t.Helper()
	o := NewOracle(snap, config.NetworkConfig{})
	src := Position{NetworkID: "net-iot", IP: "10.0.30.42"}
	dst := unifi.Client{NetworkName: "LAN", IP: "10.0.1.42"}
	for _, got := range []IsolationCell{o.Service(src, dst, want.Transport, want.Port, want.IPFamily), o.AnyPort(src, dst, want.IPFamily)} {
		if got.Effective != want.Effective || got.Verdict != want.Verdict || got.DecisiveRuleID != want.DecisiveRuleID ||
			got.PathKind != want.PathKind || got.Enforcer != want.Enforcer || !slices.Equal(got.EnforcerMACs, want.EnforcerMACs) ||
			!slices.Equal(got.EnforcerMACs, []string{mac}) {
			t.Fatalf("Oracle returned %+v for matrix witness %+v", got, want)
		}
	}
	if got := o.Service(src, dst, "udp", want.Port, want.IPFamily); got.Verdict != IsolationBlockedOK {
		t.Fatalf("TCP witness also allowed UDP: %+v", got)
	}
}

// TestOraclePeerParity checks both physical isolation and a directional ACL
// exception against the pair represented in the containment matrix.
func TestOraclePeerParity(t *testing.T) {
	for _, medium := range []string{"switch ACL", "isolated ports", "same AP", "cross AP", "mixed"} {
		t.Run(medium, func(t *testing.T) {
			s := wiredPeerSite(2)
			s.Networks[0].IsolationEnabled = true
			s.Networks[0].ZoneName = "Cameras"
			a, b := &s.Clients[0], &s.Clients[1]
			sw := s.Devices[0].MAC
			kind, mac, verdict := "wired-same-vlan", sw, IsolationBlockedOK
			switch medium {
			case "switch ACL":
				verdict = IsolationViolation
				any := unifi.PolicyEndpoint{AnyTarget: true, AnyPort: true}
				s.SwitchACLs = []unifi.SwitchACL{
					{ID: "exception", Enabled: true, Action: "ALLOW", Protocol: "tcp", Source: unifi.PolicyEndpoint{MACs: []string{a.MAC}, AnyPort: true}, Destination: unifi.PolicyEndpoint{AnyTarget: true, Ports: []int{8443}}},
					{ID: "block", Index: 1, Enabled: true, Action: "BLOCK", Source: any, Destination: any},
				}
			case "isolated ports":
				for i := range s.Devices[0].Ports {
					s.Devices[0].Ports[i].Isolation = true
				}
			default:
				ap1, ap2 := "02:00:00:00:01:af", "02:00:00:00:01:bf"
				s.Devices = append(s.Devices, unifi.Device{Type: "uap", MAC: ap1, UplinkMAC: sw, UplinkPort: 1},
					unifi.Device{Type: "uap", MAC: ap2, UplinkMAC: sw, UplinkPort: 2})
				s.WLANs = []unifi.WLANConfig{{Name: "Patio", NetworkName: "Cameras", Enabled: true, L2Isolation: true}}
				b.IsWired, b.APMAC, b.ESSID = false, ap2, "Patio"
				switch medium {
				case "same AP":
					a.IsWired, a.APMAC, a.ESSID = false, strings.ToUpper(ap2), "Patio"
					kind, mac = "same-ap-wifi", ap2
				case "cross AP":
					a.IsWired, a.APMAC, a.ESSID = false, ap1, "Patio"
					kind, verdict = "cross-ap-wifi", IsolationViolation
				case "mixed":
					kind, verdict = "mixed-same-vlan", IsolationViolation
				}
			}
			matrix, _, _ := EvaluateIsolation(s, nil, config.NetworkConfig{})
			o := NewOracle(s, config.NetworkConfig{})
			src := PositionForClient(*a)
			for _, got := range []IsolationCell{o.Service(src, *b, "tcp", 8443, "ipv4"), o.AnyPort(src, *b, "ipv4")} {
				if got.PathKind != kind || got.Verdict != verdict || !slices.Equal(got.EnforcerMACs, []string{mac}) ||
					!slices.ContainsFunc(matrix.Cells, func(c IsolationCell) bool {
						return c.PathKind == got.PathKind && (c.IPFamily == "both" || c.IPFamily == got.IPFamily) &&
							c.Effective == got.Effective && c.Verdict == got.Verdict && c.DecisiveRuleID == got.DecisiveRuleID &&
							c.Enforcer == got.Enforcer && slices.Equal(c.EnforcerMACs, got.EnforcerMACs)
					}) {
					t.Fatalf("missing matching matrix decision for %+v", got)
				}
			}
			if medium == "isolated ports" {
				// Partial wired client structs hydrate cleanly (even without IsWired or SwitchMAC),
				// while a caller-supplied switch port is preserved over inventory.
				for _, partial := range []unifi.Client{
					{MAC: b.MAC, IsWired: true},
					{MAC: b.MAC, IsWired: true, SwitchMAC: b.SwitchMAC},
					{MAC: b.MAC, SwitchMAC: b.SwitchMAC},
					{MAC: b.MAC, SwitchPort: b.SwitchPort},
				} {
					if got := o.Service(src, partial, "tcp", 8443, "ipv4"); got.Verdict != IsolationBlockedOK {
						t.Fatalf("partial wired dst %+v lost switch port isolation: %+v", partial, got)
					}
				}
				overridePort := unifi.Client{MAC: b.MAC, IsWired: true, SwitchMAC: b.SwitchMAC, SwitchPort: 99}
				if got := o.Service(src, overridePort, "tcp", 8443, "ipv4"); got.Verdict == IsolationBlockedOK {
					t.Fatalf("caller-supplied switch port was overwritten by inventory: %+v", got)
				}
				// Shared fe80:: addresses across VLANs must resolve by VLAN scope in either inventory order.
				b.IPv6 = []string{"fe80::42"}
				other := unifi.Client{MAC: "02:00:00:00:00:99", NetworkID: "other", NetworkName: "Other", IPv6: []string{"fe80::42"}, IsWired: true, SwitchMAC: "02:00:00:00:00:dd", SwitchPort: 9}
				for _, clients := range [][]unifi.Client{append(slices.Clone(s.Clients), other), append([]unifi.Client{other}, s.Clients...)} {
					scoped := *s
					scoped.Clients = clients
					if got := NewOracle(&scoped, config.NetworkConfig{}).Service(src, unifi.Client{NetworkName: b.NetworkName, IPv6: []string{"fe80::42"}}, "tcp", 8443, "ipv6"); got.PathKind != "wired-same-vlan" || got.Verdict != IsolationBlockedOK {
						t.Fatalf("VLAN-scoped link-local lookup selected wrong client: %+v", got)
					}
				}
			}
			if medium == "switch ACL" {
				for _, got := range []IsolationCell{o.Service(src, *b, "udp", 8443, "ipv4"), o.AnyPort(PositionForClient(*b), *a, "ipv4")} {
					if got.DecisiveRuleID != "block" {
						t.Fatalf("directional TCP exception leaked: %+v", got)
					}
				}
				// Unresolved L3 router or External zone + Internet toggle must not override same-switch L2 ACLs.
				inetOn := true
				s.Networks[0].RouterUnresolved = true
				s.Networks[0].ZoneName = "External"
				s.Networks[0].InternetAccessEnabled = &inetOn
				so := NewOracle(s, config.NetworkConfig{})
				if got := so.Service(src, *b, "udp", 8443, "ipv4"); got.DecisiveRuleID != "block" {
					t.Fatalf("unresolved L3 router or External zone overrode known L2 switch ACL decision: %+v", got)
				}
				if got := so.AnyPort(PositionForClient(*b), *a, "ipv4"); got.DecisiveRuleID != "block" {
					t.Fatalf("External zone overrode AnyPort L2 switch ACL block: %+v", got)
				}
			}
		})
	}
}

// TestOracleInternet resolves publications by backend address and service. The
// earlier External deny shadows the allow for one port in the same range.
func TestOracleInternet(t *testing.T) {
	dst := unifi.Client{IP: "192.0.2.10", IPv6: []string{"2001:db8::10"}, NetworkID: "lan"}
	block, allow := zoneRule(1, "External", "Internal", "BLOCK", "tcp"), zoneRule(2, "External", "Internal", "ALLOW", "tcp")
	block.Destination.AnyPort, block.Destination.Ports = false, []int{8444}
	allow.Destination = unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{dst.IP}, PortRanges: []unifi.PortRange{{Start: 8443, End: 8444}}}
	restricted := "198.51.100.0/24"
	allow.Source = unifi.PolicyEndpoint{ZoneName: "External", NetworkIDs: []string{"wan2"}, IPs: []string{restricted}, Ports: []int{50000}}
	taken := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	s := &unifi.Snapshot{
		CollectedAt: taken,
		Networks: []unifi.Network{{ID: "lan", Name: "Office", ZoneName: "Internal", RouterDeviceMAC: "02:00:00:00:00:aa"},
			{ID: "wan1", Name: "Primary", Purpose: "wan"}, {ID: "wan2", Name: "Backup", Purpose: "wan2"}},
		Devices: []unifi.Device{{Type: "ugw", Name: "Gateway", MAC: "02:00:00:00:00:BB"}},
		PortForwards: []unifi.PortForward{
			{ID: "open", Enabled: true, FwdIP: dst.IP, FwdPort: "443", DstPort: "10443", Proto: "tcp"},
			{ID: "restricted", Enabled: true, FwdIP: dst.IP, DstPort: "443", Proto: "tcp", Src: restricted},
			{ID: "unresolved", Enabled: true, FwdIP: dst.IP, FwdPort: "443", Proto: "tcp", SourceUnknown: true},
		},
		DynamicMappings: []unifi.DynamicPortMapping{
			{Protocol: "pcp", Transport: "udp", ExtPort: 1053, InternalIP: dst.IP, IntPort: 53},
			{Protocol: "upnp", Transport: "udp", ExtPort: 2053, InternalIP: dst.IP, IntPort: 53, ExpiresAt: &taken},
		},
		PublishedTunnels: []unifi.PublishedTunnel{{Provider: "tunnel", Hostname: "web.example", BackendIP: dst.IPv6[0], BackendPort: 443}},
		ProxyRoutes: []unifi.ProxyRoute{{Hostname: "proxy.example", PublicExposed: true, BackendIP: dst.IPv6[0], BackendPort: 443},
			{Hostname: "private.example", BackendIP: dst.IPv6[0], BackendPort: 443}},
		FirewallPolicies: []unifi.FirewallPolicy{allow, block},
	}
	o := NewOracle(s, config.NetworkConfig{})
	fw := o.Internet(dst, "tcp", 8443, "ipv4")
	if len(fw) != 1 || fw[0].DecisiveRuleID != allow.ID || fw[0].Effective != "allow" || fw[0].SourceNetwork != "Backup" || !slices.Equal(fw[0].EnforcerMACs, []string{"02:00:00:00:00:bb"}) {
		t.Fatalf("External firewall decision: %+v", fw)
	}
	forwards := o.Internet(dst, "tcp", 443, "ipv4")
	if len(forwards) != 3 || forwards[0].DecisiveRuleID != "open" || forwards[0].Effective != "allow" ||
		forwards[1].Effective != "allow" || forwards[1].SourceNetwork != restricted ||
		forwards[2].Verdict != IsolationUnknown || forwards[2].MissingInput == "" {
		t.Fatalf("WAN forward scope: %+v", forwards)
	}
	web := o.Internet(dst, "tcp", 443, "ipv6")
	if len(web) != 2 || web[0].DecisiveRuleName != "web.example" || web[1].DecisiveRuleName != "proxy.example" {
		t.Fatalf("owner publications: %+v", web)
	}
	if maps := o.Internet(dst, "udp", 53, "ipv4"); len(maps) != 1 || maps[0].DecisiveRuleName != "pcp" {
		t.Fatalf("active leases: %+v", maps)
	}
	for _, q := range []struct {
		proto string
		port  int
		fam   string
	}{
		{"tcp", 10443, "ipv4"}, {"udp", 443, "ipv4"}, {"udp", 443, "ipv6"}, {"tcp", 8444, "ipv4"},
	} {
		if cells := o.Internet(dst, q.proto, q.port, q.fam); len(cells) != 0 {
			t.Fatalf("%+v matched %+v", q, cells)
		}
	}

	// Finding-shaped dst (MAC, IPv6-in-IP, or IPv6-only) hydrates full addresses from inventory,
	// and missing visibility feeds emit explicit unknown cells instead of empty slices.
	s.Clients = []unifi.Client{
		{MAC: "02:00:00:00:00:10", IP: dst.IP, IPv6: dst.IPv6, NetworkID: "lan"},
		{MAC: "02:00:00:00:00:11", IP: "2001:db8::11", NetworkID: "lan"},
	}
	s.PublishedTunnels = append(s.PublishedTunnels, unifi.PublishedTunnel{Provider: "tunnel", Hostname: "v6only.example", BackendIP: "2001:db8::11", BackendPort: 443})
	o = NewOracle(s, config.NetworkConfig{})
	if got := o.Internet(unifi.Client{MAC: "02:00:00:00:00:10"}, "tcp", 443, "ipv6"); len(got) != 2 {
		t.Fatalf("hydrated finding dst missed IPv6 publications: %+v", got)
	}
	if got := o.Internet(unifi.Client{MAC: "02:00:00:00:00:11"}, "tcp", 443, "ipv6"); len(got) != 1 || got[0].DecisiveRuleName != "v6only.example" {
		t.Fatalf("MAC-only dst missed IPv6 address stored in Client.IP: %+v", got)
	}
	for _, partial := range []unifi.Client{{IP: dst.IPv6[0], NetworkID: "lan"}, {IPv6: dst.IPv6, NetworkID: "lan"}} {
		if got := o.Internet(partial, "tcp", 443, "ipv4"); len(got) != 3 {
			t.Fatalf("IPv6-identified dst %+v missed IPv4 forwards: %+v", partial, got)
		}
	}
	// Multi-WAN scoped allow keeps distinct WAN cells; unscoped allow deduplicates as "Internet"
	// only when all uplinks permit, preserving the permitting WAN when another uplink is blocked.
	dualAllow := zoneRule(3, "External", "Internal", "ALLOW", "tcp")
	dualAllow.ID = "dual-allow"
	dualAllow.Source = unifi.PolicyEndpoint{ZoneName: "External", NetworkIDs: []string{"wan1", "wan2"}, AnyPort: true}
	dualAllow.Destination = unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{dst.IP}, Ports: []int{9443}}
	unscopedAllow := zoneRule(4, "External", "Internal", "ALLOW", "tcp")
	unscopedAllow.ID = "unscoped-allow"
	unscopedAllow.Destination = unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{dst.IP}, Ports: []int{9444}}
	blockWan1 := zoneRule(5, "External", "Internal", "BLOCK", "tcp")
	blockWan1.ID = "block-wan1"
	blockWan1.Source = unifi.PolicyEndpoint{ZoneName: "External", NetworkIDs: []string{"wan1"}, AnyPort: true}
	blockWan1.Destination = unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{dst.IP}, Ports: []int{9445}}
	partialAllow := zoneRule(6, "External", "Internal", "ALLOW", "tcp")
	partialAllow.ID = "partial-allow"
	partialAllow.Destination = unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{dst.IP}, Ports: []int{9445}}
	multiWAN := &unifi.Snapshot{
		Networks:         s.Networks,
		Devices:          s.Devices,
		FirewallPolicies: []unifi.FirewallPolicy{dualAllow, unscopedAllow, blockWan1, partialAllow},
		Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
	}
	mo := NewOracle(multiWAN, config.NetworkConfig{})
	if got := mo.Internet(dst, "tcp", 9443, "ipv4"); len(got) != 2 {
		t.Fatalf("dual-WAN scoped rule should keep 2 cells, got %+v", got)
	}
	if got := mo.Internet(dst, "tcp", 9444, "ipv4"); len(got) != 1 || got[0].SourceNetwork != "Internet" {
		t.Fatalf("unscoped External rule should deduplicate as Internet, got %+v", got)
	}
	if got := mo.Internet(dst, "tcp", 9445, "ipv4"); len(got) != 1 || got[0].SourceNetwork != "Backup" {
		t.Fatalf("partial multi-WAN allow must keep permitting interface name, got %+v", got)
	}
	// Concrete External destination honors InternetAccessEnabled, gateway enforcement
	// even on switch-routed VLANs, and does not substitute 1.1.1.1 or drop WAN-subnet IPs.
	inetOff, inetOn := false, true
	blockDNS := zoneRule(1, "Internal", "External", "BLOCK", "all")
	blockDNS.Destination = unifi.PolicyEndpoint{ZoneName: "External", IPs: []string{"8.8.8.8"}, AnyPort: true}
	allowExt := zoneRule(2, "Internal", "External", "ALLOW", "all")
	extSnap := &unifi.Snapshot{
		Networks: []unifi.Network{
			{ID: "lan", Name: "Office", ZoneName: "Internal", Subnet: "192.0.2.0/24", InternetAccessEnabled: &inetOff},
			{ID: "hot", Name: "Guest", ZoneName: "Hotspot", Subnet: "198.51.100.0/24", RouterDeviceMAC: "02:00:00:00:00:aa", InternetAccessEnabled: &inetOn},
			{ID: "wan1", Name: "Primary", ZoneName: "External", Purpose: "wan", Subnet: "8.8.8.0/24"},
		},
		Devices:          s.Devices,
		FirewallPolicies: []unifi.FirewallPolicy{blockDNS, allowExt},
		Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
	}
	eo := NewOracle(extSnap, config.NetworkConfig{})
	if got := eo.AnyPort(Position{NetworkID: "lan", IP: dst.IP}, unifi.Client{IP: "8.8.8.8", NetworkID: "wan1"}, "ipv4"); got.Effective != "deny" {
		t.Fatalf("InternetAccessEnabled=false must deny External egress, got %+v", got)
	}
	if got := eo.Service(Position{NetworkID: "hot", IP: "198.51.100.10"}, unifi.Client{IP: "8.8.8.8", NetworkID: "wan1"}, "tcp", 443, "ipv4"); got.Effective != "allow" || !slices.Equal(got.EnforcerMACs, []string{"02:00:00:00:00:bb"}) {
		t.Fatalf("switch-routed Hotspot External egress must use gateway and InternetAccessEnabled=true, got %+v", got)
	}
	// External ingress into a switch-routed VLAN enforces gateway rules across Service and AnyPort,
	// and non-routable link-local or loopback addresses cannot receive direct WAN-routed traffic.
	extAllowHot := zoneRule(3, "External", "Hotspot", "ALLOW", "tcp")
	extAllowHot.Destination.AnyPort, extAllowHot.Destination.Ports = false, []int{8443}
	extSnap.FirewallPolicies = append(extSnap.FirewallPolicies, extAllowHot, zoneRule(4, "External", "Hotspot", "BLOCK", "all"))
	eo = NewOracle(extSnap, config.NetworkConfig{})
	wan, guest := Position{Zone: "External", IP: "203.0.113.42"}, unifi.Client{IP: "198.51.100.10", NetworkID: "hot"}
	if got := eo.Service(wan, guest, "tcp", 443, "ipv4"); got.Effective != "deny" {
		t.Fatalf("External ingress into switch-routed VLAN bypassed gateway block: %+v", got)
	}
	if got := eo.AnyPort(wan, guest, "ipv4"); got.Effective != "allow" || got.Port != 8443 {
		t.Fatalf("External ingress into switch-routed VLAN missed gateway allow: %+v", got)
	}
	if got := eo.AnyPort(Position{Zone: "External"}, guest, "ipv4"); got.Effective != "allow" || got.Port != 8443 {
		t.Fatalf("External zone ingress without fixed IP missed gateway allow: %+v", got)
	}
	llGuest := unifi.Client{NetworkID: "hot", IPv6: []string{"fe80::1234"}}
	if got := eo.Internet(llGuest, "tcp", 8443, "ipv6"); len(got) != 0 {
		t.Fatalf("link-local IPv6 backend must not match direct WAN ingress: %+v", got)
	}
	if got := eo.Service(wan, llGuest, "tcp", 8443, "ipv6"); got.Effective != "deny" {
		t.Fatalf("Service must deny direct WAN path to link-local IPv6: %+v", got)
	}
	if got := eo.AnyPort(wan, llGuest, "ipv6"); got.Effective != "deny" {
		t.Fatalf("AnyPort must deny direct WAN path to link-local IPv6: %+v", got)
	}
	if got := eo.Service(Position{Zone: "External", IP: "fe80::1"}, guest, "tcp", 8443, "ipv6"); got.Effective != "deny" {
		t.Fatalf("Service must deny non-routable link-local External source: %+v", got)
	}
	if got := eo.Internet(unifi.Client{NetworkID: "hot", IP: "127.0.0.1"}, "tcp", 8443, "ipv4"); len(got) != 0 {
		t.Fatalf("IPv4 loopback backend must not match direct WAN ingress: %+v", got)
	}
	if got := eo.Internet(unifi.Client{NetworkID: "hot", IPv6: []string{"::1"}}, "tcp", 8443, "ipv6"); len(got) != 0 {
		t.Fatalf("IPv6 loopback backend must not match direct WAN ingress: %+v", got)
	}
	// WAN NAT rules to non-routable backends, loopback-only External source rules,
	// WAN uplink queries with narrow uplink subnets, and cross-VLAN IP lookups stay sound.
	loopbackAllow := zoneRule(3, "External", "Hotspot", "ALLOW", "tcp")
	loopbackAllow.Source = unifi.PolicyEndpoint{ZoneName: "External", IPs: []string{"127.0.0.2"}, AnyPort: true}
	loopbackAllow.Destination.AnyPort, loopbackAllow.Destination.Ports = false, []int{9443}
	remoteAllow := zoneRule(4, "External", "Hotspot", "ALLOW", "tcp")
	remoteAllow.Source = unifi.PolicyEndpoint{ZoneName: "External", IPs: []string{"198.51.100.7"}, AnyPort: true}
	remoteAllow.Destination.AnyPort, remoteAllow.Destination.Ports = false, []int{9444}
	wanEdgeSnap := &unifi.Snapshot{
		Networks: []unifi.Network{
			{ID: "hot", Name: "Guest", ZoneName: "Hotspot", Subnet: "198.51.100.0/24"},
			{ID: "wan-p", Name: "Primary", Purpose: "wan", Subnet: "203.0.113.0/30"},
			{ID: "other", Name: "Other", ZoneName: "Internal", Subnet: "192.0.2.0/24"},
		},
		Clients: []unifi.Client{{MAC: "02:00:00:00:00:aa", IP: "198.51.100.10", NetworkID: "other"}},
		Devices: s.Devices,
		PortForwards: []unifi.PortForward{
			{ID: "ll-pf", Enabled: true, FwdIP: "169.254.7.12", FwdPort: "443", DstPort: "443", Proto: "tcp"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{loopbackAllow, remoteAllow, zoneRule(5, "External", "Hotspot", "BLOCK", "all")},
		Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
	}
	wo := NewOracle(wanEdgeSnap, config.NetworkConfig{})
	if got := wo.Internet(unifi.Client{NetworkID: "hot", IP: "169.254.7.12"}, "tcp", 443, "ipv4"); len(got) != 0 {
		t.Fatalf("WAN port forward to link-local IPv4 must be ignored: %+v", got)
	}
	if got := wo.Internet(guest, "tcp", 9443, "ipv4"); len(got) != 0 {
		t.Fatalf("loopback-only External allow must not permit WAN ingress: %+v", got)
	}
	if got := wo.Service(Position{NetworkID: "wan-p"}, guest, "tcp", 9443, "ipv4"); got.Effective != "deny" {
		t.Fatalf("loopback-only External allow must not permit Service: %+v", got)
	}
	if got := wo.Service(Position{NetworkID: "wan-p"}, guest, "tcp", 9444, "ipv4"); got.Effective != "allow" {
		t.Fatalf("WAN uplink without ZoneName and narrow /30 must still find remote External allow: %+v", got)
	}
	if got := wo.AnyPort(Position{NetworkID: "wan-p"}, guest, "ipv4"); got.Effective != "allow" || got.Port != 9444 {
		t.Fatalf("AnyPort from WAN uplink with narrow /30 missed remote External allow: %+v", got)
	}
	if hydrated := wo.inventoryClient(unifi.Client{IP: "198.51.100.10", NetworkID: "hot"}); hydrated.MAC != "" {
		t.Fatalf("VLAN-scoped IP lookup copied MAC from another VLAN: %+v", hydrated)
	}
	// Unresolved switch router on a VLAN must not cause Internet Egress containment to skip UDP probes.
	extSnap.Networks[1].RouterUnresolved = true
	extSnap.FirewallPolicies = []unifi.FirewallPolicy{
		zoneRule(1, "Hotspot", "External", "ALLOW", "udp"),
		zoneRule(2, "Hotspot", "External", "BLOCK", "all"),
	}
	extMatrix, _, _ := EvaluateIsolation(extSnap, nil, config.NetworkConfig{IsolationPolicy: config.IsolationIntent{NoInternetVLANs: []string{"Guest"}}})
	if len(extMatrix.Containment) == 0 || extMatrix.Containment[0].InternetEgress.State == "blocked" {
		t.Fatalf("unresolved router must not hide UDP internet egress allow: %+v", extMatrix.Containment)
	}
	// Concurrent IPv6 hydration must not race on caller-owned slice backing arrays.
	sharedIPv6 := make([]string, 0, 2)
	callerDst := unifi.Client{IP: dst.IPv6[0], IPv6: sharedIPv6, NetworkID: "lan"}
	done := make(chan struct{}, 2)
	for range 2 {
		go func() {
			_ = o.Internet(callerDst, "tcp", 443, "ipv4")
			done <- struct{}{}
		}()
	}
	<-done
	<-done
	missingSnap := &unifi.Snapshot{
		Networks:   []unifi.Network{{ID: "lan", Name: "Office", ZoneName: "Internal"}},
		Devices:    s.Devices,
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: false, PortForwardsAvailable: false},
	}
	missCells := NewOracle(missingSnap, config.NetworkConfig{}).Internet(dst, "tcp", 443, "ipv4")
	if len(missCells) < 2 || missCells[0].Verdict != IsolationUnknown || missCells[1].Verdict != IsolationUnknown {
		t.Fatalf("missing feeds must produce unknown cells, got %+v", missCells)
	}
	// Missing WAN inventory leaves WAN-scoped NetworkIDs unresolved (unknown), never hard-mismatched.
	noWANSnap := &unifi.Snapshot{
		Networks:         []unifi.Network{{ID: "lan", Name: "Office", ZoneName: "Internal"}},
		Devices:          s.Devices,
		FirewallPolicies: []unifi.FirewallPolicy{allow},
		Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
	}
	if got := NewOracle(noWANSnap, config.NetworkConfig{}).Internet(dst, "tcp", 8443, "ipv4"); len(got) != 1 || got[0].Verdict != IsolationUnknown {
		t.Fatalf("WAN-scoped rule without WAN inventory must resolve unknown, got %+v", got)
	}
}

// mixedRoutingSite places a gateway-routed LAN behind a switch-routed source.
// An empty action represents a controller feed that could not be collected.
func mixedRoutingSite(switchAction, gatewayAction string) *unifi.Snapshot {
	const sw = "00:00:5e:00:53:01"
	s := &unifi.Snapshot{
		Devices: []unifi.Device{
			{Name: "Switch", MAC: sw, Type: "usw"},
			{Name: "Gateway", MAC: "00:00:5e:00:53:02", Type: "ugw"},
		},
		Networks: []unifi.Network{
			{ID: "s", Name: "Sensors", ZoneName: "Hotspot", Subnet: "198.51.100.1/24", RouterDeviceMAC: sw},
			{ID: "o", Name: "Office", ZoneName: "Internal", Subnet: "192.0.2.1/24"},
		},
		Zones:      []unifi.FirewallZone{{Name: "Hotspot"}, {Name: "Internal"}},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: gatewayAction != "", SwitchACLsAvailable: switchAction != ""},
	}
	any := unifi.PolicyEndpoint{AnyTarget: true, AnyPort: true}
	if gatewayAction != "" {
		s.FirewallPolicies = []unifi.FirewallPolicy{{ID: "gw-rule", Name: "Gateway policy", Enabled: true, Action: gatewayAction, Source: any, Destination: any}}
	}
	if switchAction != "" {
		s.SwitchACLCoverage = &unifi.SwitchACLCoverage{Status: "complete"}
		s.SwitchACLs = []unifi.SwitchACL{{ID: "sw-rule", Name: "Switch policy", Enabled: true, Action: switchAction, DeviceMACs: []string{sw}, Source: any, Destination: any}}
	}
	return s
}

// TestMixedRoutingDecisions checks per-packet and whole-boundary decisions,
// including attribution when a missing feed precedes a mandatory block.
func TestMixedRoutingDecisions(t *testing.T) {
	for _, tt := range []struct {
		sw, gw            string
		want, id, missing string
	}{
		{"ALLOW", "BLOCK", "deny", "gw-rule", ""},
		{"BLOCK", "ALLOW", "deny", "sw-rule", ""},
		{"ALLOW", "ALLOW", "allow", "", ""},
		{"ALLOW", "", "unknown", "", "Gateway firewall policy telemetry is unavailable"},
		{"", "BLOCK", "deny", "gw-rule", ""},
		{"", "ALLOW", "unknown", "", "Switch ACL unavailable"},
	} {
		t.Run(tt.sw+"/"+tt.gw, func(t *testing.T) {
			s := mixedRoutingSite(tt.sw, tt.gw)
			o := NewOracle(s, config.NetworkConfig{})
			for _, pair := range [][2]string{{"s", "o"}, {"o", "s"}} {
				src, dst := Position{NetworkID: pair[0]}, unifi.Client{NetworkID: pair[1]}
				for _, got := range []IsolationCell{o.Service(src, dst, "tcp", 443, "ipv4"), o.AnyPort(src, dst, "ipv4")} {
					if got.Effective != tt.want || !strings.Contains(got.MissingInput, tt.missing) {
						t.Fatalf("%v: got %+v, want %s %s", pair, got, tt.want, tt.missing)
					}
					switch tt.want {
					case "deny":
						device := s.Devices[0]
						if tt.id == "gw-rule" {
							device = s.Devices[1]
						}
						if got.Verdict != IsolationBlockedOK || got.DecisiveRuleID != tt.id || got.DecisiveRuleName != device.Name+" policy" ||
							got.DecisiveReason == "" || !strings.HasPrefix(got.Enforcer, device.Name+" (") || !slices.Equal(got.EnforcerMACs, []string{device.MAC}) {
							t.Fatalf("lost denying rule or owner: %+v", got)
						}
					case "allow":
						if !slices.Equal(got.EnforcerMACs, []string{s.Devices[0].MAC, s.Devices[1].MAC}) {
							t.Fatalf("missing mandatory enforcer: %+v", got)
						}
					}
				}
			}
		})
	}
}

// TestMixedRoutingPacketPartitions requires a single packet to pass both sets
// of rules, including narrow exceptions away from the baseline probes.
func TestMixedRoutingPacketPartitions(t *testing.T) {
	s := mixedRoutingSite("ALLOW", "ALLOW")
	sw, gw := &s.SwitchACLs[0], &s.FirewallPolicies[0]
	sw.Protocol, gw.Protocol = "tcp", "tcp"
	sw.Source = unifi.PolicyEndpoint{IPs: []string{"198.51.100.77"}, AnyPort: true}
	sw.Destination = unifi.PolicyEndpoint{AnyTarget: true, Ports: []int{8443}}
	gw.Source = unifi.PolicyEndpoint{AnyTarget: true, Ports: []int{62000}}
	gw.Destination = unifi.PolicyEndpoint{AnyTarget: true, Ports: []int{8443}}
	any := unifi.PolicyEndpoint{AnyTarget: true, AnyPort: true}
	s.SwitchACLs = append(s.SwitchACLs, unifi.SwitchACL{Enabled: true, Index: 1, Action: "BLOCK", Source: any, Destination: any})
	src, dst := Position{NetworkID: "s"}, unifi.Client{NetworkID: "o", IP: "192.0.2.22"}
	check := func(want string) {
		t.Helper()
		o := NewOracle(s, config.NetworkConfig{})
		for _, c := range []IsolationCell{o.Service(src, dst, "tcp", 8443, "ipv4"), o.AnyPort(src, dst, "ipv4"),
			o.evaluateBoundary(nil, config.IsolationIntent{}, s.Networks[0], s.Networks[1], "Hotspot", "Internal", "ipv4", "deny", nil)} {
			if c.Effective != want || (want == "allow" && c.Port != 8443) {
				t.Fatalf("want %s on the joint packet partition, got %+v", want, c)
			}
		}
	}
	check("allow")
	s.SwitchACLs[0].Destination.Ports = []int{8444}
	check("deny")
	s.SwitchACLCoverage.Status = "partial"
	check("unknown")
}

// TestCrossSwitchRouting requires a block on a mandatory endpoint switch or
// explicit knowledge of the transit route before deciding a cross-switch path.
func TestCrossSwitchRouting(t *testing.T) {
	s := mixedRoutingSite("ALLOW", "BLOCK")
	dstMAC := "00:00:5e:00:53:03"
	s.Networks[1].RouterDeviceMAC = dstMAC
	s.SwitchACLs = append(s.SwitchACLs, unifi.SwitchACL{ID: "dst-block", Enabled: true, Action: "BLOCK", DeviceMACs: []string{dstMAC},
		Source: s.SwitchACLs[0].Source, Destination: s.SwitchACLs[0].Destination})
	check := func(want string, macs []string, missing string) {
		t.Helper()
		o := NewOracle(s, config.NetworkConfig{})
		src, dst := Position{NetworkID: "s"}, unifi.Client{NetworkID: "o"}
		for _, c := range []IsolationCell{o.Service(src, dst, "tcp", 443, "ipv4"), o.AnyPort(src, dst, "ipv4")} {
			if c.Effective != want || !slices.Equal(c.EnforcerMACs, macs) || !strings.Contains(c.MissingInput, missing) || (want == "deny" && c.DecisiveRuleID != "dst-block") {
				t.Fatalf("want %s %v %q, got %+v", want, macs, missing, c)
			}
		}
	}
	check("deny", []string{dstMAC}, "")
	s.Networks[0].RouterUnresolved = true
	check("unknown", nil, "Switch routing owner")
	s.Networks[0].RouterUnresolved = false
	s.SwitchACLs[1].Action = "ALLOW"
	check("unknown", nil, "transit route")
}

// TestMixedRoutingTelemetryLoss checks every combination of omitted feeds and
// collection metadata. The remaining evidence cannot establish a new block.
func TestMixedRoutingTelemetryLoss(t *testing.T) {
	for mask := range 32 {
		s := mixedRoutingSite("ALLOW", "ALLOW")
		s.WLANs = []unifi.WLANConfig{{Name: "Sensors", NetworkName: "Sensors", Enabled: true}}
		s.Visibility.WLANsAvailable = true
		if mask&1 != 0 {
			s.FirewallPolicies, s.Visibility.GatewayPoliciesAvailable = nil, false
		}
		if mask&2 != 0 {
			s.SwitchACLs, s.SwitchACLCoverage, s.Visibility.SwitchACLsAvailable = nil, nil, false
		}
		if mask&4 != 0 {
			s.WLANs, s.Visibility.WLANsAvailable = nil, false
		}
		if mask&8 != 0 {
			s.Visibility = &unifi.SiteVisibility{}
		}
		if mask&16 != 0 {
			s.Visibility = nil
		}
		want := "allow"
		if mask&3 != 0 || (mask&8 != 0 && s.Visibility != nil) {
			want = "unknown"
		}
		o := NewOracle(s, config.NetworkConfig{})
		src, dst := Position{NetworkID: "s"}, unifi.Client{NetworkID: "o"}
		for _, c := range []IsolationCell{o.Service(src, dst, "tcp", 443, "ipv4"), o.AnyPort(src, dst, "ipv4")} {
			if c.Effective != want {
				t.Fatalf("omission mask %05b: want %s, got %+v", mask, want, c)
			}
		}
	}
}

// TestCompromisedEnforcers checks two independent denials and an immutable base scenario.
func TestCompromisedEnforcers(t *testing.T) {
	const gw, sw, ap = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"
	any := unifi.PolicyEndpoint{AnyTarget: true, AnyPort: true}
	s := &unifi.Snapshot{
		Devices:          []unifi.Device{{MAC: gw, Type: "udm"}, {MAC: sw, Type: "usw", Ports: []unifi.SwitchPort{{PortIdx: 1, Isolation: true}, {PortIdx: 2, Isolation: true}}}},
		Networks:         []unifi.Network{{ID: "a", Name: "a", ZoneName: "A", RouterDeviceMAC: sw}, {ID: "b", Name: "b", ZoneName: "B"}},
		WLANs:            []unifi.WLANConfig{{Name: "wifi", NetworkName: "a", Enabled: true, L2Isolation: true}},
		FirewallPolicies: []unifi.FirewallPolicy{{ID: "gateway", Enabled: true, Action: "BLOCK", Protocol: "all", Source: any, Destination: any}},
		SwitchACLs:       []unifi.SwitchACL{{ID: "switch", Enabled: true, Action: "BLOCK", DeviceMACs: []string{sw}, Source: any, Destination: any}},
	}
	base := NewOracle(s, config.NetworkConfig{})
	switchLost := base.WithCompromised("02-00-00-00-00-02")
	both := switchLost.WithCompromised(gw)
	for _, tc := range []struct {
		o          *Oracle
		want, rule string
	}{
		{both, "allow", ""}, {switchLost, "deny", "gateway"}, {base.WithCompromised(gw), "deny", "switch"}, {base, "deny", "switch"},
	} {
		c := tc.o.Service(Position{NetworkID: "a", IP: "192.0.2.1"}, unifi.Client{NetworkID: "b", IP: "198.51.100.2"}, "tcp", 443, "ipv4")
		if c.Effective != tc.want || c.DecisiveRuleID != tc.rule || tc.want == "allow" && c.DecisiveReason != "Enforcer compromised in what-if scenario" {
			t.Fatalf("want %s from %q, got %+v", tc.want, tc.rule, c)
		}
	}
	for _, tc := range []struct {
		mac string
		a   Position
		b   unifi.Client
	}{
		{ap, Position{NetworkID: "a", APMAC: ap, SSID: "wifi"}, unifi.Client{NetworkID: "a", APMAC: ap, ESSID: "wifi"}},
		{sw, Position{NetworkID: "a", IsWired: true, SwitchMAC: sw, SwitchPort: 1}, unifi.Client{NetworkID: "a", IsWired: true, SwitchMAC: sw, SwitchPort: 2}},
	} {
		if c := base.WithCompromised(tc.mac).Service(tc.a, tc.b, "tcp", 22, "ipv4"); c.Effective != "allow" {
			t.Fatal(c)
		}
		if c := base.Service(tc.a, tc.b, "tcp", 22, "ipv4"); c.Effective != "deny" {
			t.Fatal(c)
		}
	}
}

// TestIPv6AddressGroupIsolation checks both zone boundaries and the service
// query used by Blast Radius when an IPv6 address group precedes a blanket allow.
func TestIPv6AddressGroupIsolation(t *testing.T) {
	const pd = "2001:db8:20::/64"
	const ula = "fd00:20::/64"
	for _, tc := range []struct {
		name, primary     string
		prefixes, clients []string
		want              IsolationVerdict
	}{
		{name: "missing prefix", want: IsolationUnknown},
		{name: "only non-routable clients", clients: []string{"ff02::fb", "::1", "::", "fe80::2"}, want: IsolationUnknown},
		{name: "observed ULA client", clients: []string{"fe80::2", "fd00:20::2"}, want: IsolationBlockedOK},
		{name: "legacy prefix", primary: pd, want: IsolationBlockedOK},
		{name: "uncovered client outside configured ULA", primary: ula, clients: []string{"2001:db8:30::42"}, want: IsolationViolation},
		{name: "delegated and ULA", prefixes: []string{pd, ula}, want: IsolationBlockedOK},
		{name: "uncovered second prefix", primary: pd, prefixes: []string{pd, "2001:db8:30::/64"}, want: IsolationViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := unifi.Network{ID: "iot", Name: "IoT", ZoneName: "IoT", IPv6Subnet: tc.primary, IPv6Subnets: tc.prefixes}
			snap := &unifi.Snapshot{
				Networks:   []unifi.Network{src, {ID: "lan", Name: "Default", ZoneName: "Internal"}},
				Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
			}
			if len(tc.clients) > 0 {
				snap.Clients = []unifi.Client{{NetworkID: src.ID, IPv6: tc.clients}}
			}
			for _, zone := range []string{"Internal", "Gateway"} {
				block := unifi.FirewallPolicy{ID: "block-" + zone, Name: "Block IPv6 group", Enabled: true, Action: "BLOCK", IPVersion: "ipv6",
					Source:      unifi.PolicyEndpoint{ZoneName: src.ZoneName, AnyPort: true, IPs: []string{pd, "fc00::/7"}},
					Destination: unifi.PolicyEndpoint{ZoneName: zone, AnyPort: true, AnyTarget: true}}
				allow := block
				allow.ID, allow.Name, allow.Action, allow.Index = "allow-"+zone, "Allow All Traffic", "ALLOW", 1
				allow.Source = unifi.PolicyEndpoint{ZoneName: src.ZoneName, AnyPort: true, AnyTarget: true}
				snap.FirewallPolicies = append(snap.FirewallPolicies, block, allow)
			}
			cfg := config.NetworkConfig{TrustedVLANs: []string{"Default"}, IsolatedVLANs: []string{"IoT"}}
			matrix, findings, notes := EvaluateIsolation(snap, nil, cfg)
			for _, dst := range []string{"Default", "Gateway"} {
				i := slices.IndexFunc(matrix.Cells, func(c IsolationCell) bool {
					return c.SourceNetwork == src.Name && c.DestNetwork == dst && c.IPFamily == "ipv6" &&
						(c.DestFunction == "gateway-admin" || c.DestFunction == "trusted-lan-transit")
				})
				if i < 0 {
					t.Fatalf("missing IPv6 boundary to %s", dst)
				}
				if matrix.Cells[i].Verdict != tc.want {
					t.Fatalf("expected %s for %s, got %+v", tc.want, dst, matrix.Cells[i])
				}
				if tc.want == IsolationUnknown {
					detail := matrix.Cells[i].MissingInput
					if detail == "" || !slices.ContainsFunc(notes, func(n PostureNote) bool {
						return n.Title == "Isolation verdict unknown for IoT -> "+dst+" (IPV6)" && n.Severity == checks.SeverityLow && n.Detail == detail
					}) {
						t.Errorf("missing low-severity note for %s: %+v", dst, notes)
					}
				}
			}
			hasFinding := slices.ContainsFunc(findings, func(f checks.Finding) bool { return f.CheckID == "UB-UNIFI-ISO-GW-ADMIN" })
			if hasFinding != (tc.want == IsolationViolation) {
				t.Errorf("gateway admin finding = %v for %s", hasFinding, tc.want)
			}
			cell := NewOracle(snap, cfg).Service(Position{NetworkID: src.ID}, unifi.Client{NetworkID: GatewayNetworkID, IP: "2001:db8:1::1"}, "tcp", 443, "ipv6")
			if cell.Verdict != tc.want {
				t.Errorf("gateway service verdict = %s, want %s", cell.Verdict, tc.want)
			}
		})
	}
}

// TestSubnetlessIPv6ScopedAllow checks a non-baseline port so only the exact
// boundary search can discover the possibly permitted service.
func TestSubnetlessIPv6ScopedAllow(t *testing.T) {
	src := unifi.Network{ID: "s", Name: "Sensors", ZoneName: "IoT"}
	dst := unifi.Network{ID: "d", Name: "Default", ZoneName: "Internal"}
	for _, tc := range []struct {
		clientID string
		selector unifi.PolicyEndpoint
		want     IsolationVerdict
	}{
		{"", unifi.PolicyEndpoint{IPs: []string{"fd00::/8"}}, IsolationUnknown},
		{"", unifi.PolicyEndpoint{IPs: []string{"::/0"}}, IsolationViolation},
		{src.ID, unifi.PolicyEndpoint{IPs: []string{"fd00::/8"}}, IsolationViolation},
		{src.ID, unifi.PolicyEndpoint{IPs: []string{"2001:db8:20::50"}}, IsolationViolation},
		{"stale", unifi.PolicyEndpoint{IPs: []string{"fd00::/8"}}, IsolationUnknown},
		{"", unifi.PolicyEndpoint{NetworkIDs: []string{src.ID}}, IsolationViolation},
		{"", unifi.PolicyEndpoint{AnyTarget: true}, IsolationViolation},
	} {
		source := tc.selector
		source.ZoneName, source.AnyPort = src.ZoneName, true
		pol := unifi.FirewallPolicy{Enabled: true, Action: "ALLOW", Protocol: "tcp", IPVersion: "ipv6", Source: source,
			Destination: unifi.PolicyEndpoint{ZoneName: dst.ZoneName, AnyTarget: true, Ports: []int{9443}}}
		snap := &unifi.Snapshot{Networks: []unifi.Network{src, dst}, FirewallPolicies: []unifi.FirewallPolicy{pol}}
		if tc.clientID != "" {
			snap.Clients = []unifi.Client{{NetworkID: tc.clientID, NetworkName: src.Name, IPv6: []string{"2001:db8:30::2"}}}
		}
		o := NewOracle(snap, config.NetworkConfig{})
		cell := o.evaluateBoundary(nil, config.IsolationIntent{}, src, dst, src.ZoneName, dst.ZoneName, "ipv6", "deny", nil)
		if cell.Verdict != tc.want || cell.Port != 9443 {
			t.Fatalf("source %+v: expected %s on TCP 9443, got %+v", source, tc.want, cell)
		}
	}
}

// TestGatewayAdminTargets excludes multicast and service-specific destinations
// even when the policy itself explicitly names IPv6.
func TestGatewayAdminTargets(t *testing.T) {
	src := unifi.Network{ZoneName: "IoT"}
	for _, tc := range []struct {
		family, proto, target string
		port                  int
	}{
		{"ipv6", "udp", "ff02::fb", 5353}, {"ipv4", "udp", "224.0.0.251", 5353},
		{"ipv6", "udp", "2001:db8::2", 547}, {"ipv6", "icmpv6", "2001:db8::2", 0},
		{"ipv6", "tcp", "2001:db8::2", 5353}, {"ipv6", "tcp", "ff02::fb", 443},
		{"ipv6", "tcp", "::", 443}, {"ipv6", "tcp", "::1", 443},
		{"ipv4", "tcp", "255.255.255.255", 443},
	} {
		policies := []unifi.FirewallPolicy{{Enabled: true, Action: "ALLOW", IPVersion: tc.family, Protocol: tc.proto,
			Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", IPs: []string{tc.target}, Ports: []int{tc.port}}}}
		if got := allGatewayIPsForFamily(nil, "", tc.family, src, policies); !slices.Equal(got, []string{""}) {
			t.Errorf("%+v supplied a gateway admin target %v", tc, got)
		}
		if gatewayHasIPv6Context(nil, src, policies) {
			t.Errorf("%+v supplied IPv6 admin context", tc)
		}
	}
	src.IPv6Subnets = []string{"2001:db8:1::/64", "fd12:3456::7/64"}
	snap := &unifi.Snapshot{Networks: []unifi.Network{src, {IPv6Subnet: "fd00:2::1/64", RouterDeviceMAC: "02:00:00:00:00:02"}}}
	want := []string{"fd12:3456::7"}
	if got := allGatewayIPsForFamily(snap, "", "ipv6", src, nil); !slices.Equal(got, want) {
		t.Fatalf("gateway interface addresses = %v", got)
	}
	if got := NewOracle(snap, config.NetworkConfig{}).DeviceClient(unifi.Device{Type: "udm"}); !slices.Equal(got.IPv6, want) {
		t.Fatalf("gateway inventory addresses = %v", got.IPv6)
	}
	if sample := sampleNetworkIPForFamily(src, snap, "ipv6"); sample != "2001:db8:1::1" {
		t.Fatalf("delegated prefix sample = %q", sample)
	}
}

// TestExternalZoneSource checks the public source domain without a WAN inventory record.
func TestExternalZoneSource(t *testing.T) {
	dst := unifi.Network{ID: "lan", Name: "LAN", ZoneName: "Internal"}
	allow := zoneRule(1, "External", dst.ZoneName, "ALLOW", "tcp")
	allow.Source.AnyTarget, allow.Source.IPs = false, []string{"2001:db8:44::/64"}
	allow.Destination.AnyPort, allow.Destination.Ports = false, []int{9443}
	o := NewOracle(&unifi.Snapshot{Networks: []unifi.Network{dst}, FirewallPolicies: []unifi.FirewallPolicy{allow}}, config.NetworkConfig{})
	pos, host := Position{Zone: "External"}, unifi.Client{NetworkID: dst.ID, IP: "2001:db8::5"}
	for _, cell := range []IsolationCell{o.Service(pos, host, "tcp", 9443, "ipv6"), o.AnyPort(pos, host, "ipv6")} {
		if cell.Verdict != IsolationViolation || cell.DecisiveRuleID != allow.ID {
			t.Fatalf("External zone source: %+v", cell)
		}
	}
}

// TestGatewayAdminLinkLocalContext checks IPv6 exposure when the gateway's only
// inventoried address is IPv4 and the source VLAN has only a link-local IPv6 client.
func TestGatewayAdminLinkLocalContext(t *testing.T) {
	src := unifi.Network{ID: "guest", Name: "Guest", ZoneName: "Hotspot", Purpose: "guest"}
	block := zoneRule(0, src.ZoneName, "Gateway", "BLOCK", "tcp")
	block.IPVersion = "ipv4"
	allow := zoneRule(1, src.ZoneName, "Gateway", "ALLOW", "tcp")
	snap := &unifi.Snapshot{Networks: []unifi.Network{src}, Devices: []unifi.Device{{Type: "udm", IP: "192.0.2.1"}},
		Clients: []unifi.Client{{NetworkID: src.ID, IPv6: []string{"fe80::22"}}}, FirewallPolicies: []unifi.FirewallPolicy{block, allow}}
	cfg := config.NetworkConfig{IsolationPolicy: config.IsolationIntent{GuestVLANs: []string{src.Name}}}
	_, findings, _ := EvaluateIsolation(snap, nil, cfg)
	i := slices.IndexFunc(findings, func(f checks.Finding) bool {
		return f.CheckID == "UB-UNIFI-ISO-GW-ADMIN" && f.Property == "isolation-gw-admin-guest-ipv6"
	})
	if i < 0 || findings[i].Client.IP != "" {
		t.Fatalf("expected IPv6 finding without an invented gateway address: %+v", findings)
	}
	snap.FirewallPolicies[1].Destination.AnyTarget = false
	snap.FirewallPolicies[1].Destination.IPs = []string{"ff02::/16", "::1"}
	cell := NewOracle(snap, cfg).evaluateGatewayAdminBoundary([]string{""}, src, src.ZoneName, "ipv6")
	if cell.Verdict != IsolationBlockedOK {
		t.Fatalf("multicast and loopback admin targets: %+v", cell)
	}
}

// TestGatewayAdminSelectors checks the address evidence supplied by gateway policies.
func TestGatewayAdminSelectors(t *testing.T) {
	src := unifi.Network{ID: "guest", ZoneName: "Guest", Subnet: "192.0.2.1/24"}
	p := zoneRule(1, src.ZoneName, "Gateway", "ALLOW", "tcp")
	p.Source.AnyTarget = false
	for _, tc := range []struct {
		selector string
		want     bool
	}{
		{"fd00::/8", true}, {"2001:db8::50", true}, {"ff02::/16", false}, {"::1", false}, {"192.0.2.3", false},
	} {
		p.Source.IPs = []string{tc.selector}
		if got := gatewayHasIPv6Context(nil, src, []unifi.FirewallPolicy{p}); got != tc.want {
			t.Errorf("source %s gave IPv6 context %t, want %t", tc.selector, got, tc.want)
		}
		snap := &unifi.Snapshot{FirewallPolicies: []unifi.FirewallPolicy{p}}
		if got := siteHasIPv6Context(snap, src, unifi.Network{}, unifi.Client{}, false); got != tc.want {
			t.Errorf("dual-stack selector %s gave site IPv6 context %t, want %t", tc.selector, got, tc.want)
		}
	}
	p.Source.NetworkIDs, p.Source.IPs = []string{"other"}, []string{"fd00::/8"}
	if gatewayHasIPv6Context(nil, src, []unifi.FirewallPolicy{p}) {
		t.Fatal("another VLAN's rule supplied IPv6 gateway context")
	}
	p.Source.NetworkIDs = nil
	p.Source.IPs = []string{"ff02::fb"}
	observed := &unifi.Snapshot{Networks: []unifi.Network{src}, FirewallPolicies: []unifi.FirewallPolicy{p},
		Clients: []unifi.Client{{NetworkID: src.ID, IPv6: []string{"fd00::2"}}}}
	cell := NewOracle(observed, config.NetworkConfig{}).evaluateGatewayAdminBoundary([]string{"fd00::1"}, src, src.ZoneName, "ipv6")
	if cell.Verdict != IsolationBlockedOK {
		t.Fatalf("multicast source on a VLAN with an observed unicast client: %+v", cell)
	}
	p.Source.AnyTarget = true
	p.Destination.AnyTarget, p.Destination.IPs = false, []string{"192.0.2.255", "198.51.100.7", "203.0.113.3"}
	snap := &unifi.Snapshot{Networks: []unifi.Network{src, {Subnet: "198.51.100.5/30"}, {Subnet: "203.0.113.2/31"}}}
	want := []string{"192.0.2.1", "198.51.100.5", "203.0.113.3"}
	if got := allGatewayIPsForFamily(snap, "192.0.2.255", "ipv4", src, []unifi.FirewallPolicy{p}); !slices.Equal(got, want) {
		t.Fatalf("gateway addresses = %v, want %v", got, want)
	}
}

// TestExternalBaselinePolicy preserves the gateway decision for an unspecified WAN source.
func TestExternalBaselinePolicy(t *testing.T) {
	lan := unifi.Network{ID: "lan", Name: "LAN", ZoneName: "Internal"}
	host := unifi.Client{NetworkID: lan.ID, IP: "192.0.2.7"}
	snap := &unifi.Snapshot{Networks: []unifi.Network{lan}}
	query := func() IsolationCell {
		return NewOracle(snap, config.NetworkConfig{}).AnyPort(Position{Zone: "External"}, host, "ipv4")
	}
	if got := query(); got.Verdict != IsolationUnknown || got.MissingInput == "" {
		t.Fatalf("missing WAN policies: %+v", got)
	}
	block := zoneRule(0, "External", lan.ZoneName, "BLOCK", "all")
	snap.FirewallPolicies = []unifi.FirewallPolicy{block}
	if got := query(); got.Verdict != IsolationBlockedOK || got.DecisiveRuleName != block.Name {
		t.Fatalf("explicit WAN block: %+v", got)
	}
}

// TestIsolatedZonePrefixOrder requires explicit transit blocks for each source and destination prefix.
func TestIsolatedZonePrefixOrder(t *testing.T) {
	src := unifi.Network{ID: "s", Name: "Sensors", ZoneName: "IoT", IPv6Subnets: []string{"2001:db8:1::/64", "fd00:1::/64"}}
	dst := unifi.Network{ID: "d", Name: "LAN", ZoneName: "Internal", IPv6Subnets: []string{"2001:db8:2::/64", "fd00:2::/64"}}
	v4 := zoneRule(0, src.ZoneName, dst.ZoneName, "BLOCK", "all")
	v4.IPVersion = "ipv4"
	tcp := zoneRule(1, src.ZoneName, dst.ZoneName, "BLOCK", "tcp")
	tcp.IPVersion = "ipv6"
	dns := zoneRule(2, src.ZoneName, dst.ZoneName, "BLOCK", "udp")
	dns.IPVersion = "ipv6"
	for _, tc := range []struct {
		proto                 string
		sources, destinations []string
		want                  bool
	}{
		{"udp", src.IPv6Subnets[:1], nil, false},
		{"udp", nil, dst.IPv6Subnets[:1], false},
		{"tcp", nil, dst.IPv6Subnets[:1], false},
		{"udp", src.IPv6Subnets, dst.IPv6Subnets, true},
	} {
		snap := &unifi.Snapshot{Networks: []unifi.Network{src, dst}, FirewallPolicies: []unifi.FirewallPolicy{v4, tcp, dns}}
		for i := range snap.FirewallPolicies {
			p := &snap.FirewallPolicies[i]
			if p.Protocol == tc.proto {
				p.Source.AnyTarget, p.Source.IPs = tc.sources == nil, tc.sources
				p.Destination.AnyTarget, p.Destination.IPs = tc.destinations == nil, tc.destinations
			}
		}
		for range 2 {
			if got := IsolatedZones(snap)["iot"]; got != tc.want {
				t.Errorf("sources %v, destinations %v, first prefixes %s and %s: isolated = %t, want %t",
					tc.sources, tc.destinations, snap.Networks[0].IPv6Subnets[0], snap.Networks[1].IPv6Subnets[0], got, tc.want)
			}
			snap.Networks[0].IPv6Subnets = []string{src.IPv6Subnets[1], src.IPv6Subnets[0]}
			snap.Networks[1].IPv6Subnets = []string{dst.IPv6Subnets[1], dst.IPv6Subnets[0]}
		}
	}
}

// TestRoutedHostAliases keeps both routable addresses in the matrix and one report per affected service.
func TestRoutedHostAliases(t *testing.T) {
	guest := unifi.Network{ID: "guest", Name: "Guest", ZoneName: "Hotspot"}
	lan := unifi.Network{ID: "lan", Name: "LAN", ZoneName: "Internal"}
	bmc := unifi.Client{MAC: "02:00:00:00:00:01", Name: "Server-BMC", NetworkID: lan.ID,
		IPv6: []string{"fe80::2", "2001:db8::2", "fd00::2"}}
	printer := unifi.Client{MAC: "02:00:00:00:00:02", Name: "Printer", NetworkID: lan.ID,
		IPv6: []string{"fe80::3", "ff02::fb", "::", "::1", "2001:db8::3", "fd00::3"}}
	admin := zoneRule(0, guest.ZoneName, lan.ZoneName, "ALLOW", "tcp")
	admin.IPVersion = "ipv6"
	admin.Destination.AnyPort, admin.Destination.Ports = false, []int{80, 443}
	snap := &unifi.Snapshot{Networks: []unifi.Network{guest, lan}, Clients: []unifi.Client{bmc, printer},
		FirewallPolicies: []unifi.FirewallPolicy{admin}}
	cfg := config.NetworkConfig{IsolationPolicy: config.IsolationIntent{ApprovedPaths: []config.ApprovedPath{
		{SourceZone: guest.ZoneName, DestRole: "printer", Function: "printing", IPVersion: "ipv6", Port: 631},
		{SourceZone: guest.ZoneName, DestRole: "printer", Function: "monitoring", IPVersion: "ipv6", Port: 9100},
	}}}
	matrix, findings, notes := EvaluateIsolation(snap, nil, cfg)
	var bmcCells int
	for _, c := range matrix.Cells {
		if c.DestHost == bmc.Name || c.DestHost == printer.Name {
			if isNonRoutableIP(c.DestIP) {
				t.Fatalf("non-routable host target: %+v", c)
			}
			if c.DestHost == bmc.Name && c.IPFamily == "ipv6" && c.Port == 443 {
				bmcCells++
			}
		}
	}
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.CheckID == "UB-UNIFI-ISO-BMC-IPV6" || f.CheckID == "UB-UNIFI-ISO-PRINTER-ADMIN" {
			if seen[f.Key()] {
				t.Errorf("duplicate finding %s", f.Key())
			}
			seen[f.Key()] = true
		}
	}
	if bmcCells != 2 || len(seen) != 3 {
		t.Errorf("got %d IPv6 BMC cells and %d distinct host findings, want 2 and 3", bmcCells, len(seen))
	}
	for _, prefix := range []string{"Approved guest printing path blocked", "Approved workflow blocked"} {
		count := 0
		for _, n := range notes {
			if strings.HasPrefix(n.Title, prefix) {
				count++
				if strings.Contains(n.Detail, "fe80:") {
					t.Errorf("link-local recommendation: %s", n.Detail)
				}
			}
		}
		if count != 1 {
			t.Errorf("got %d %q notes, want 1", count, prefix)
		}
	}
}
