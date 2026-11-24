// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"strings"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

func boolPtr(b bool) *bool { return &b }

func TestIsolationUnavailableGatewayPoliciesMustYieldUnknown(t *testing.T) {
	// Critical safety invariant: when controller firewall policy telemetry is
	// unavailable (e.g. HTTP 403/404 or legacy API), UniBlue MUST NEVER invent
	// a passing "blocked-ok" verdict — every gateway-enforced cell must be unknown.
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.0.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks: []unifi.Network{
			{ID: "n-mgmt", Name: "OOB Management", VLAN: "90", Subnet: "10.0.90.1/24", ZoneName: "Management"},
			{ID: "n-guest", Name: "Guest", VLAN: "50", Subnet: "10.0.50.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		Clients: []unifi.Client{
			{MAC: "11:22:33:44:55:02", IP: "10.0.90.10", Name: "Server-01 BMC", NetworkName: "OOB Management", VLAN: "90"},
		},
		Visibility: &unifi.SiteVisibility{
			GatewayPoliciesAvailable: false,
			MissingFeeds:             []string{"firewall-policies (HTTP 403)"},
		},
	}

	mat, _, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{
		IsolationPolicy: config.IsolationIntent{
			ManagementVLANs: []string{"OOB Management"},
			GuestVLANs:      []string{"Guest"},
		},
	})
	if mat == nil || len(mat.Cells) == 0 {
		t.Fatal("expected isolation cells")
	}
	for _, cell := range mat.Cells {
		if cell.PathKind == "gateway-routed" || cell.PathKind == "gateway-local" {
			if cell.Verdict != IsolationUnknown || cell.Effective != "unknown" {
				t.Fatalf("gateway cell must be unknown when firewall policies are unavailable, got %+v", cell)
			}
		}
	}
}

func TestIsolationPolicyPrecedenceAndReturnStateHandling(t *testing.T) {
	// A preceding BLOCK rule must override a later ALLOW rule, an
	// ESTABLISHED/RELATED-only ALLOW rule must NOT permit NEW initiation, and
	// MatchReturnTraffic in the reverse direction allows established return traffic!
	policies := []unifi.FirewallPolicy{
		{
			ID:               "r-return",
			Name:             "Allow Established Return",
			Enabled:          true,
			Index:            1,
			Action:           "ALLOW",
			IPVersion:        "ipv4",
			Protocol:         "all",
			ConnectionStates: []string{"established", "related"},
			Source:           unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
			Destination:      unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
		},
		{
			ID:          "r-block-first",
			Name:        "Block Guest Admin",
			Enabled:     true,
			Index:       2,
			Action:      "BLOCK",
			IPVersion:   "ipv4",
			Protocol:    "tcp",
			Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
			Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"10.0.1.30"}, Ports: []int{443}},
		},
		{
			ID:          "r-allow-later",
			Name:        "Broad Later Allow",
			Enabled:     true,
			Index:       3,
			Action:      "ALLOW",
			IPVersion:   "ipv4",
			Protocol:    "tcp",
			Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
			Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"10.0.1.30"}, Ports: []int{443}},
		},
	}

	dec := evaluateGatewayPolicies(policies, pathQuery{
		srcZone:  "Hotspot",
		dstZone:  "Internal",
		dstIP:    "10.0.1.30",
		proto:    "tcp",
		port:     443,
		ipFamily: "ipv4",
		state:    "new",
	})
	if dec.action != "deny" || dec.ruleID != "r-block-first" {
		t.Fatalf("expected preceding BLOCK rule (ignoring ESTABLISHED-only rule) to win, got %+v", dec)
	}

	// Unsupported selector must yield unknown rather than silently matching or missing.
	unkDec := evaluateGatewayPolicies([]unifi.FirewallPolicy{{
		ID:          "r-opaque",
		Name:        "Region Filter Allow",
		Enabled:     true,
		Index:       1,
		Action:      "ALLOW",
		IPVersion:   "ipv4",
		Protocol:    "tcp",
		Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: false, UnsupportedSelector: `traffic filter type "REGION"`},
		Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
	}}, pathQuery{srcZone: "Hotspot", dstZone: "Internal", dstIP: "10.0.1.30", proto: "tcp", port: 443, ipFamily: "ipv4", state: "new"})
	if unkDec.action != "unknown" {
		t.Fatalf("expected opaque selector to yield unknown, got %+v", unkDec)
	}
}

func TestExtendedNetworkChecksPositiveAndCounterexamples(t *testing.T) {
	stale := time.Now().UTC().Add(-45 * 24 * time.Hour)
	snap := &unifi.Snapshot{
		Site: "default",
		Health: &unifi.SystemHealth{
			WANStatus: "ok",
			WANIP:     "100.64.12.5", // RFC 6598 CGNAT!
		},
		Devices: []unifi.Device{
			{
				Name: "Core Switch", MAC: "aa:00:00:00:00:01", IP: "10.0.0.1", Model: "USW-Pro", Type: "usw",
				Ports: []unifi.SwitchPort{{PortIdx: 24, Up: true, Enabled: true, NativeNetworkName: "Management"}},
			},
			{
				Name: "Garage Switch", MAC: "aa:00:00:00:00:02", IP: "10.0.0.2", Model: "USW-Lite", Type: "usw",
				UplinkMAC: "aa:00:00:00:00:01", UplinkPort: 24,
				Ports: []unifi.SwitchPort{{PortIdx: 1, Up: true, Enabled: true, IsUplink: true, NativeNetworkName: "IoT"}},
			},
		},
		Networks: []unifi.Network{
			{ID: "n1", Name: "CorpA", Subnet: "10.10.0.1/24", Purpose: "corporate", DHCPStart: "10.10.0.10", DHCPEnd: "10.10.0.29", ActiveLeases: 19},
			{ID: "n2", Name: "CorpB", Subnet: "10.10.0.128/25", Purpose: "corporate"},
		},
		PortForwards: []unifi.PortForward{
			{Name: "Web", Enabled: true, Proto: "tcp", DstPort: "443", FwdIP: "10.10.0.5", FwdPort: "443", Src: "any"},
		},
		DynamicMappings: []unifi.DynamicPortMapping{
			{Protocol: "upnp", Transport: "tcp", ExtPort: 8080, InternalIP: "10.10.0.50", IntPort: 8080, OwnerIP: "10.10.0.99"},
			{Protocol: "upnp", Transport: "udp", ExtPort: 3074, InternalIP: "10.10.0.60", IntPort: 3074, Approved: true},
		},
		ProxyRoutes: []unifi.ProxyRoute{
			{ProxyIP: "10.10.0.5", Hostname: "admin.example.test", PublicExposed: true, FrontendAuth: boolPtr(false), BackendIP: "10.10.0.6", BackendPort: 8080, AdminVHost: true},
		},
		PublishedTunnels: []unifi.PublishedTunnel{
			{Provider: "cloudflare-tunnel", Hostname: "proxmox.example.test", BackendIP: "10.10.0.7", BackendPort: 8006, AccessPolicy: "none", AdminEndpoint: true},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{ID: "icmp6-block", Name: "Drop All ICMPv6", Enabled: true, Action: "BLOCK", Protocol: "icmpv6", Source: unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true}, Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true}},
		},
		BackupStatus: &unifi.BackupStatus{LastBackupAt: &stale, BackupHealthy: true},
		Visibility:   &unifi.SiteVisibility{MissingFeeds: []string{"switch_acls", "flow_logs"}},
	}

	findings, notes := AnalyzeExtendedNetworkChecks(snap, config.NetworkConfig{})
	gotIDs := make(map[string]checks.Finding)
	for _, f := range findings {
		gotIDs[f.CheckID] = f
	}

	for _, want := range []string{
		"UB-UNIFI-DYNAMIC-NAT-MAPPING",
		"UB-UNIFI-PROXY-ADMIN-PUBLIC",
		"UB-UNIFI-TUNNEL-ADMIN-PUBLIC",
		"UB-UNIFI-OVERLAPPING-SUBNETS",
		"UB-UNIFI-NATIVE-VLAN-MISMATCH",
		"UB-UNIFI-IPV6-BLANKET-ICMPV6-BLOCK",
	} {
		if _, ok := gotIDs[want]; !ok {
			t.Fatalf("expected extended network finding %q, got %+v", want, gotIDs)
		}
	}
	if gotIDs["UB-UNIFI-DYNAMIC-NAT-MAPPING"].EffectiveSeverity != checks.SeverityHigh {
		t.Fatalf("third-party UPnP mapping should be High, got %v", gotIDs["UB-UNIFI-DYNAMIC-NAT-MAPPING"].EffectiveSeverity)
	}

	hasCGNAT, hasDHCP, hasBackup, hasVis := false, false, false, false
	for _, n := range notes {
		low := strings.ToLower(n.Title)
		if strings.Contains(low, "cgnat") {
			hasCGNAT = true
		}
		if strings.Contains(low, "dhcp pool") {
			hasDHCP = true
		}
		if strings.Contains(low, "backup") {
			hasBackup = true
		}
		if strings.Contains(low, "incomplete site telemetry") {
			hasVis = true
		}
	}
	if !hasCGNAT || !hasDHCP || !hasBackup || !hasVis {
		t.Fatalf("expected CGNAT (%v), DHCP (%v), backup (%v), visibility (%v) notes, got %+v", hasCGNAT, hasDHCP, hasBackup, hasVis, notes)
	}

	// Counterexample: authenticated tunnel + authenticated proxy + aligned native VLAN + disjoint subnets + healthy backup -> 0 findings & 0 bad notes!
	fresh := time.Now().UTC().Add(-2 * 24 * time.Hour)
	cleanSnap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{
				Name: "Core Switch", MAC: "aa:00:00:00:00:01", IP: "10.0.0.1", Model: "USW-Pro", Type: "usw",
				Ports: []unifi.SwitchPort{{PortIdx: 24, Up: true, Enabled: true, NativeNetworkID: "n1", NativeNetworkName: "CorpA"}},
			},
			{
				Name: "Garage Switch", MAC: "aa:00:00:00:00:02", IP: "10.0.0.2", Model: "USW-Lite", Type: "usw",
				UplinkMAC: "aa:00:00:00:00:01", UplinkPort: 24,
				Ports: []unifi.SwitchPort{{PortIdx: 1, Up: true, Enabled: true, IsUplink: true, NativeNetworkID: "n1", NativeNetworkName: "CorpA"}},
			},
		},
		Networks: []unifi.Network{
			{ID: "n1", Name: "CorpA", Subnet: "10.10.0.1/24", Purpose: "corporate", DHCPStart: "10.10.0.10", DHCPEnd: "10.10.0.200", ActiveLeases: 12},
			{ID: "n2", Name: "CorpB", Subnet: "10.20.0.1/24", Purpose: "corporate"},
		},
		ProxyRoutes: []unifi.ProxyRoute{
			{ProxyIP: "10.10.0.5", Hostname: "app.example.test", PublicExposed: true, FrontendAuth: boolPtr(true), BackendIP: "10.10.0.6", BackendPort: 8080, BackendAuth: boolPtr(true)},
		},
		PublishedTunnels: []unifi.PublishedTunnel{
			{Provider: "cloudflare-tunnel", Hostname: "admin.example.test", BackendIP: "10.10.0.7", BackendPort: 8006, AccessPolicy: "authenticated", AdminEndpoint: true},
		},
		BackupStatus: &unifi.BackupStatus{LastBackupAt: &fresh, LastRestoreTestAt: &fresh, BackupHealthy: true},
	}
	cleanFindings, cleanNotes := AnalyzeExtendedNetworkChecks(cleanSnap, config.NetworkConfig{})
	if len(cleanFindings) != 0 || len(cleanNotes) != 0 {
		t.Fatalf("expected 0 findings and 0 notes on clean counterexample snapshot, got findings=%+v notes=%+v", cleanFindings, cleanNotes)
	}
}
