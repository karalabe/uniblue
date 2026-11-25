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
	builtinrules "github.com/karalabe/uniblue/rules"
)

// TestExposureRulePortainerAndDstPortFallback verifies that ambiguous ports
// like TCP 9000 for Portainer/MinIO are NOT downgraded to info-level Ethereum
// P2P, and that WAN destination ports forwarded to non-standard internal
// ports (e.g. WAN 3389 -> 13389) are still classified as RDP exposure.
func TestExposureRulePortainerAndDstPortFallback(t *testing.T) {
	cls, err := LoadExposureClassifier(builtinrules.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadExposureClassifier: %v", err)
	}

	portainer := cls.Classify(unifi.PortForward{
		ID: "pf-1", Name: "Portainer", Enabled: true, Proto: "tcp",
		DstPort: "9000", FwdIP: "192.0.2.20", FwdPort: "9000", Src: "any",
	}, unifi.Client{IP: "192.0.2.20"})
	if portainer.Class == "expected-p2p" || portainer.Severity < checks.SeverityMedium {
		t.Fatalf("expected Portainer on 9000 not to be classified as safe expected-p2p, got %+v", portainer)
	}

	ethConsensus := cls.Classify(unifi.PortForward{
		ID: "pf-2", Name: "Lighthouse Beacon P2P", Enabled: true, Proto: "tcp_udp",
		DstPort: "9000", FwdIP: "192.0.2.21", FwdPort: "9000", Src: "any",
	}, unifi.Client{IP: "192.0.2.21"})
	if ethConsensus.Class != "expected-p2p" || ethConsensus.Severity != checks.SeverityInfo {
		t.Fatalf("expected named Ethereum consensus forward on 9000 to match expected-p2p, got %+v", ethConsensus)
	}

	rdpTranslated := cls.Classify(unifi.PortForward{
		ID: "pf-3", Name: "Office Jump", Enabled: true, Proto: "tcp",
		DstPort: "3389", FwdIP: "192.0.2.22", FwdPort: "13389", Src: "any",
	}, unifi.Client{IP: "192.0.2.22"})
	if rdpTranslated.Severity != checks.SeverityCritical || rdpTranslated.Class != "dangerous-remote" {
		t.Fatalf("expected WAN:3389 -> :13389 to match critical RDP exposure, got %+v", rdpTranslated)
	}
}

// TestIsolationMultiPortIPRangeUnresolvedZoneAndSameVLAN verifies multi-port
// transit probing, IP-range selectors, unresolved zone IDs, protocol negation,
// prefix-delegated IPv6 context, DestRole gating on ApprovedPaths, strict
// single-switch L2 port isolation, and isolatedZoneSet rejecting narrow
// ICMP-only blocks.
func TestIsolationMultiPortIPRangeUnresolvedZoneAndSameVLAN(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{
				Name: "Gateway", MAC: "02:aa:00:00:00:01", IP: "192.0.2.1", Model: "UDMPRO", Type: "udm",
			},
			{
				Name: "SwitchA", MAC: "02:aa:00:00:00:02", IP: "192.0.2.2", Model: "USW", Type: "usw",
				Ports: []unifi.SwitchPort{{PortIdx: 3, Enabled: true, Up: true, Isolation: true, MACTableCount: 1}},
			},
			{
				Name: "SwitchB", MAC: "02:aa:00:00:00:03", IP: "192.0.2.3", Model: "USW", Type: "usw",
				Ports: []unifi.SwitchPort{{PortIdx: 5, Enabled: true, Up: true, Isolation: true, MACTableCount: 1}},
			},
		},
		Networks: []unifi.Network{
			{ID: "net-lan", Name: "Main", VLAN: "1", Subnet: "192.0.2.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "198.51.100.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
			{ID: "net-iot", Name: "IoT", VLAN: "20", Subnet: "203.0.113.1/24", Purpose: "corporate", ZoneName: "IoTZone"},
		},
		Clients: []unifi.Client{
			// Prefix-delegated IPv6 client on Guest (no static IPv6Subnet on network).
			{MAC: "02:bb:00:00:00:01", IP: "198.51.100.10", IPv6: []string{"2001:db8:50::10"}, Name: "plug-a", NetworkID: "net-guest", NetworkName: "Guest", IsWired: true, SwitchMAC: "02:aa:00:00:00:02", SwitchPort: 3},
			{MAC: "02:bb:00:00:00:02", IP: "198.51.100.11", Name: "plug-b", NetworkID: "net-guest", NetworkName: "Guest", IsWired: true, SwitchMAC: "02:aa:00:00:00:03", SwitchPort: 5},
			{MAC: "02:bb:00:00:00:03", IP: "192.0.2.30", Name: "Server-BMC", NetworkID: "net-lan", NetworkName: "Main", IsWired: true},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			// Non-443 ALLOW rule (SSH 22 + RDP 3389) from Hotspot -> Internal must trigger violation.
			{
				ID: "p-ssh", Name: "Allow Guest SSH", Enabled: true, Index: 10, Action: "ALLOW",
				IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{22, 3389}},
			},
			// IP-range ALLOW to BMC (192.0.2.10-192.0.2.40) must match 192.0.2.30.
			{
				ID: "p-bmc-range", Name: "Allow Guest Range", Enabled: true, Index: 15, Action: "ALLOW",
				IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.0.2.10-192.0.2.40"}, Ports: []int{443}},
			},
			// Narrow ICMP-only BLOCK on IoTZone -> Internal must NOT mark IoTZone isolated.
			{
				ID: "p-iot-icmp", Name: "Block IoT ICMP", Enabled: true, Index: 20, Action: "BLOCK",
				IPVersion: "ipv4", Protocol: "icmp",
				Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	// IoTZone has only an ICMP BLOCK, so it must NOT be treated as isolated.
	isoZones := isolatedZoneSet(snap)
	if isoZones["iotzone"] {
		t.Fatalf("expected IoTZone with ICMP-only BLOCK not to be marked isolated, got %+v", isoZones)
	}

	netCfg := config.NetworkConfig{
		IsolationPolicy: config.IsolationIntent{
			GuestVLANs:               []string{"Guest"},
			RequireSameVLANIsolation: []string{"Guest"},
			// DestRole="printer" without Function must NOT approve BMC on TCP 443.
			ApprovedPaths: []config.ApprovedPath{
				{Name: "Printer HTTPS", SourceZone: "Hotspot", DestZone: "Internal", DestRole: "printer", Transport: "tcp", Port: 443},
			},
		},
	}
	mat, _, _ := EvaluateIsolation(snap, nil, netCfg)

	foundTransitViolation := false
	foundBMCRangeViolation := false
	foundIPv6Transit := false
	foundWiredUnknown := false
	for _, c := range mat.Cells {
		if c.DestFunction == "trusted-lan-transit" && c.IPFamily == "ipv4" && c.Verdict == IsolationViolation {
			foundTransitViolation = true
		}
		if c.DestFunction == "trusted-lan-transit" && c.IPFamily == "ipv6" {
			foundIPv6Transit = true
		}
		if c.DestFunction == "bmc-redfish-admin" && c.IPFamily == "ipv4" && c.Verdict == IsolationViolation {
			foundBMCRangeViolation = true
		}
		if c.PathKind == "wired-same-vlan" && c.Verdict == IsolationUnknown {
			foundWiredUnknown = true
		}
	}
	if !foundTransitViolation {
		t.Fatalf("expected non-443 ALLOW (TCP 22/3389) to trigger transit violation, got %+v", mat.Cells)
	}
	if !foundIPv6Transit {
		t.Fatalf("expected IPv6 transit cell from client PD IPv6 address, got %+v", mat.Cells)
	}
	if !foundBMCRangeViolation {
		t.Fatalf("expected IP-range ALLOW to flag BMC violation (and not be whitelisted by printer DestRole), got %+v", mat.Cells)
	}
	if !foundWiredUnknown {
		t.Fatalf("expected cross-switch wired same-VLAN cell to be unknown (not blocked-ok), got %+v", mat.Cells)
	}

	// Unresolved ZoneID yields unknown; negated UDP protocol matches TCP.
	unresDec := evaluateGatewayPolicies([]unifi.FirewallPolicy{
		{
			ID: "p-unres", Name: "Unresolved Zone Block", Enabled: true, Index: 1, Action: "BLOCK",
			Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
			Destination: unifi.PolicyEndpoint{ZoneID: "z-unknown", AnyTarget: true, AnyPort: true},
		},
	}, pathQuery{srcZone: "Hotspot", dstZone: "Internal", proto: "tcp", port: 443, ipFamily: "ipv4", state: "new"})
	if unresDec.action != "unknown" {
		t.Fatalf("expected unresolved zone ID to return unknown, got %+v", unresDec)
	}
	negDec := evaluateGatewayPolicies([]unifi.FirewallPolicy{
		{
			ID: "p-neg-proto", Name: "Allow Not-UDP", Enabled: true, Index: 1, Action: "ALLOW",
			Protocol: "udp", ProtocolNegated: true,
			Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
			Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
		},
	}, pathQuery{srcZone: "Hotspot", dstZone: "Internal", proto: "tcp", port: 443, ipFamily: "ipv4", state: "new"})
	if negDec.action != "allow" {
		t.Fatalf("expected negated UDP protocol policy to allow TCP, got %+v", negDec)
	}
}

// TestPortsExternalAPDownlinkMACFormatAndPostureDedupe verifies that an AP
// connected to an external switch does not trigger multi-MAC false positives,
// dash/bare config MACs match authorized devices, rogue wired APs are deduped,
// cloned-BSSID rogue APs are not suppressed, and BuildStateWithPrev carries
// forward offline trusted clients and retains max severity per key.
func TestPortsExternalAPDownlinkMACFormatAndPostureDedupe(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{
				Name: "Garage Switch", MAC: "02:aa:00:00:00:10", IP: "192.0.2.10", Model: "USW", Type: "usw",
				Ports: []unifi.SwitchPort{
					{PortIdx: 2, Enabled: true, Up: true, MACTableCount: 9, NativeNetworkName: "Main"},
					{PortIdx: 3, Enabled: true, Up: true, MACTableCount: 1, NativeNetworkName: "IoT", TaggedVLANMgmt: "block_all", PortSecurityEnabled: true},
				},
			},
			{
				Name: "Garage AP", MAC: "02:aa:00:00:00:11", IP: "192.0.2.11", Model: "U6-Mesh", Type: "uap",
				UplinkMAC: "02:aa:00:00:00:10", UplinkPort: 2,
			},
		},
		Networks: []unifi.Network{
			{ID: "n1", Name: "Main", VLAN: "1", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "n2", Name: "IoT", VLAN: "20", Purpose: "corporate", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		Clients: []unifi.Client{
			{MAC: "02:cc:00:00:00:01", IP: "192.0.2.50", Name: "Camera-1", NetworkName: "IoT", IsWired: true, SwitchMAC: "02:aa:00:00:00:10", SwitchPort: 3},
			{MAC: "02:dd:00:00:00:01", IP: "192.0.2.60", Name: "Travel-Router", NetworkName: "Main", IsWired: true},
		},
		WLANs: []unifi.WLANConfig{
			{ID: "w1", Name: "HomeWiFi", Enabled: true, Security: "wpapsk", WPAMode: "wpa2", NetworkName: "Main"},
			{ID: "w2", Name: "OpenGuest", Enabled: true, Security: "open", IsGuest: true, NetworkName: "IoT"},
			{ID: "w3", Name: "OpenStaff", Enabled: true, Security: "open", IsGuest: false, NetworkName: "Main"},
		},
		RogueAPs: []unifi.RogueAP{
			// Cloned BSSID flagged is_rogue=true must trigger evil twin.
			{BSSID: "02:aa:00:00:00:11", ESSID: "HomeWiFi", IsRogue: true},
			// Two observations of the same wired rogue AP must produce 1 finding.
			{BSSID: "02:dd:00:00:00:02", ESSID: "RogueNet", APMAC: "ap1", IsRogue: true},
			{BSSID: "02:dd:00:00:00:03", ESSID: "RogueNet", APMAC: "ap2", IsRogue: true},
		},
	}

	netCfg := config.NetworkConfig{
		ExternalDevices: []string{"02-AA-00-00-00-10"},
		PhysicalPorts: []config.PhysicalPortRule{
			{Device: "02AA00000010", Port: 3, Zone: "external", AllowedMACs: []string{"02-CC-00-00-00-01"}},
		},
	}

	rep := Evaluate(snap, nil, netCfg)
	rogueWiredCount := 0
	foundEvilTwin := false
	for _, f := range rep.Findings {
		if f.CheckID == "UB-UNIFI-PORT-EXT-MULTI-MAC" {
			t.Fatalf("unexpected multi-MAC finding on external switch port feeding UniFi AP: %+v", f)
		}
		if f.CheckID == "UB-UNIFI-PORT-UNAUTHORIZED-MAC" {
			t.Fatalf("unexpected unauthorized MAC finding when dash-formatted allowed_macs matches: %+v", f)
		}
		if f.CheckID == "UB-UNIFI-WIFI-ROGUE-WIRED-AP" {
			rogueWiredCount++
		}
		if f.CheckID == "UB-UNIFI-WIFI-EVIL-TWIN" {
			foundEvilTwin = true
		}
	}
	if !foundEvilTwin {
		t.Fatal("expected cloned-BSSID rogue AP (is_rogue=true) to raise UB-UNIFI-WIFI-EVIL-TWIN")
	}
	if rogueWiredCount != 1 {
		t.Fatalf("expected deduped rogue wired AP count=1, got %d", rogueWiredCount)
	}

	// BuildStateWithPrev carries forward offline trusted clients and offline host findings.
	prev := &State{
		TrustedClients: map[string]string{"02:ff:00:00:00:99": "offline-laptop"},
		Findings: map[string]checks.Severity{
			"UB-0001|02:ff:00:00:00:99|23": checks.SeverityHigh,
		},
	}
	next := BuildStateWithPrev(prev, snap, rep, netCfg, nil)
	if next.TrustedClients["02:ff:00:00:00:99"] != "offline-laptop" {
		t.Fatalf("expected offline trusted client to be carried forward, got %+v", next.TrustedClients)
	}
	if next.Findings["UB-0001|02:ff:00:00:00:99|23"] != checks.SeverityHigh {
		t.Fatalf("expected offline host finding to be carried forward, got %+v", next.Findings)
	}
}

// TestTransitProbeUnrestrictedNegatedAndExcludedCases verifies that transit
// evaluation catches unrestricted ALLOWs shadowed at 443, negated-port ALLOWs,
// negated-port BLOCKs followed by ALLOW, negated-target ALLOWs, and L3 switch
// ACL equivalents instead of reporting false blocked-ok.
func TestTransitProbeUnrestrictedNegatedAndExcludedCases(t *testing.T) {
	baseSnap := func(pols []unifi.FirewallPolicy) *unifi.Snapshot {
		return &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
			},
			Networks: []unifi.Network{
				{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
				{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "192.168.50.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
			},
			Zones: []unifi.FirewallZone{
				{ID: "z-int", Name: "Internal", NetworkIDs: []string{"net-lan"}},
				{ID: "z-guest", Name: "Hotspot", NetworkIDs: []string{"net-guest"}},
			},
			FirewallPolicies: pols,
			Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}
	}
	findTransitCell := func(t *testing.T, mat *IsolationMatrix, fam string) IsolationCell {
		t.Helper()
		for _, c := range mat.Cells {
			if c.DestFunction == "trusted-lan-transit" && c.IPFamily == fam {
				return c
			}
		}
		t.Fatalf("missing %s trusted-lan-transit cell in %+v", fam, mat.Cells)
		return IsolationCell{}
	}
	netCfg := config.NetworkConfig{TrustedVLANs: []string{"LAN"}, IsolatedVLANs: []string{"Guest"}}

	t.Run("block_80_443_then_allow_any", func(t *testing.T) {
		snap := baseSnap([]unifi.FirewallPolicy{
			{
				ID: "p-block-web", Index: 10, Name: "Block 80/443", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{80, 443}},
			},
			{
				ID: "p-allow-any", Index: 20, Name: "Allow TCP Any", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
			{
				ID: "p-block-all", Index: 30, Name: "Block Rest", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		})
		mat, _, _ := EvaluateIsolation(snap, nil, netCfg)
		cell := findTransitCell(t, mat, "ipv4")
		if cell.Verdict != IsolationViolation || cell.Port == 80 || cell.Port == 443 {
			t.Fatalf("expected violation on non-80/443 port, got %+v", cell)
		}
	})

	t.Run("block_2_to_65534_then_allow_any", func(t *testing.T) {
		snap := baseSnap([]unifi.FirewallPolicy{
			{
				ID: "p-block-mid", Index: 10, Name: "Block 2-65534", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, PortRanges: []unifi.PortRange{{Start: 2, End: 65534}}},
			},
			{
				ID: "p-allow-any", Index: 20, Name: "Allow TCP Any", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		})
		mat, _, _ := EvaluateIsolation(snap, nil, netCfg)
		cell := findTransitCell(t, mat, "ipv4")
		if cell.Verdict != IsolationViolation || (cell.Port != 1 && cell.Port != 65535) {
			t.Fatalf("expected violation on port 1 or 65535, got %+v", cell)
		}
	})

	t.Run("allow_negate_port_443", func(t *testing.T) {
		snap := baseSnap([]unifi.FirewallPolicy{
			{
				ID: "p-allow-not-443", Index: 10, Name: "Allow All Except 443", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{443}, NegatePort: true},
			},
			{
				ID: "p-block-all", Index: 20, Name: "Block Rest", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		})
		mat, _, _ := EvaluateIsolation(snap, nil, netCfg)
		cell := findTransitCell(t, mat, "ipv4")
		if cell.Verdict != IsolationViolation || cell.Port == 443 {
			t.Fatalf("expected violation on non-443 port for negated ALLOW, got %+v", cell)
		}
	})

	t.Run("block_all_except_8080_then_allow_all", func(t *testing.T) {
		snap := baseSnap([]unifi.FirewallPolicy{
			{
				ID: "p-block-not-8080", Index: 10, Name: "Block All Except 8080", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{8080}, NegatePort: true},
			},
			{
				ID: "p-allow-all", Index: 20, Name: "Allow All", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		})
		mat, _, _ := EvaluateIsolation(snap, nil, netCfg)
		cell := findTransitCell(t, mat, "ipv4")
		if cell.Verdict != IsolationViolation || cell.Port != 8080 {
			t.Fatalf("expected violation on port 8080 escaping negated BLOCK, got %+v", cell)
		}
	})

	t.Run("allow_negate_target_prefix", func(t *testing.T) {
		snap := baseSnap([]unifi.FirewallPolicy{
			{
				ID: "p-allow-not-cidr", Index: 10, Name: "Allow Except 192.168.1.0/28", Enabled: true, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.0/28"}, NegateTarget: true, Ports: []int{443}},
			},
			{
				ID: "p-block-all", Index: 20, Name: "Block Rest", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		})
		mat, _, _ := EvaluateIsolation(snap, nil, netCfg)
		cell := findTransitCell(t, mat, "ipv4")
		if cell.Verdict != IsolationViolation || cell.DestIP == "" || ipMatchesSelectorTri(cell.DestIP, "192.168.1.0/28") == matchYes {
			t.Fatalf("expected violation on dstNet IP outside 192.168.1.0/28, got %+v", cell)
		}
	})

	t.Run("l3_switch_acl_negated_block_and_negated_target", func(t *testing.T) {
		const swMAC = "bb:00:00:00:00:22"
		snap := &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
				{Name: "L3 Switch", MAC: swMAC, IP: "192.168.1.2", Model: "USW-Pro", Type: "usw"},
			},
			Networks: []unifi.Network{
				{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal", RouterDeviceMAC: swMAC},
				{ID: "net-iot", Name: "IoT", VLAN: "30", Subnet: "192.168.30.1/24", Purpose: "corporate", ZoneName: "IoT", IsolationEnabled: true, RouterDeviceMAC: swMAC},
			},
			SwitchACLs: []unifi.SwitchACL{
				{
					ID: "acl-block-not-8080", Index: 10, Name: "Block All Except 8080", Enabled: true, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
					DeviceMACs:  []string{swMAC},
					Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{8080}, NegatePort: true},
				},
			},
			SwitchACLCoverage: &unifi.SwitchACLCoverage{Status: "complete"},
			Visibility:        &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}
		mat, _, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{TrustedVLANs: []string{"LAN"}, IsolatedVLANs: []string{"IoT"}})
		cell := findTransitCell(t, mat, "ipv4")
		if cell.Verdict != IsolationViolation || cell.Port != 8080 {
			t.Fatalf("expected L3 switch ACL negated block to catch open port 8080, got %+v", cell)
		}
	})
}

// TestIsolatedZonePinholesAndLeakingCustomZones verifies that single-host
// pinholes do not misclassify an isolated custom zone as trusted, while custom
// zones with isolation leaks remain untrusted sources for transit and firewall
// leak audits without receiving the isolated-VLAN mitigation downgrade.
func TestIsolatedZonePinholesAndLeakingCustomZones(t *testing.T) {
	t.Run("single_ip_pinhole_stays_isolated", func(t *testing.T) {
		snap := &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
			},
			Networks: []unifi.Network{
				{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
				{ID: "net-iot", Name: "IoT", VLAN: "20", Subnet: "192.168.20.1/24", Purpose: "corporate", ZoneName: "IoTZone"},
			},
			Zones: []unifi.FirewallZone{
				{ID: "z-int", Name: "Internal", NetworkIDs: []string{"net-lan"}},
				{ID: "z-iot", Name: "IoTZone", NetworkIDs: []string{"net-iot"}},
			},
			Clients: []unifi.Client{
				{MAC: "cc:00:00:00:00:01", IP: "192.168.20.15", Name: "smart-plug", NetworkID: "net-iot", NetworkName: "IoT", VLAN: "20"},
			},
			FirewallPolicies: []unifi.FirewallPolicy{
				{
					ID: "p-pihole", Index: 10, Name: "Allow IoT DNS to Pi-hole", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
					IPVersion: "ipv4", Protocol: "udp",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.53"}, Ports: []int{53}},
				},
				{
					ID: "p-block-iot", Index: 200, Name: "Block IoT to Internal", Enabled: true, Action: "BLOCK", Origin: "USER_DEFINED",
					IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			},
			Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}

		trusted, isolated := resolveVLANTiers(snap, config.NetworkConfig{})
		if _, ok := isolated["iot"]; !ok {
			t.Fatalf("expected IoT with Pi-hole pinhole before BLOCK to be isolated, trusted=%v isolated=%v", trusted, isolated)
		}
		if _, ok := trusted["iot"]; ok {
			t.Fatalf("IoT with Pi-hole pinhole must NOT be classified trusted, trusted=%v", trusted)
		}

		raw := []checks.Finding{{CheckID: "UB-0001", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[0], Port: 23}}
		rep := Evaluate(snap, raw, config.NetworkConfig{})
		for _, f := range rep.Findings {
			if f.CheckID == "UB-0001" && f.EffectiveSeverity != checks.SeverityMedium {
				t.Fatalf("expected isolated IoT finding to downgrade High->Medium, got %v (%+v)", f.EffectiveSeverity, f.RiskReasons)
			}
		}
		// New IoT device must NOT trigger NewTrustedClients alert.
		diff := ComputeDiff(&State{TrustedClients: map[string]string{}}, snap, rep, config.NetworkConfig{})
		if len(diff.NewTrustedClients) != 0 {
			t.Fatalf("expected 0 NewTrustedClients for isolated IoT device, got %+v", diff.NewTrustedClients)
		}
		// Isolation matrix must retain IoT -> LAN transit cell.
		hasIoTCell := false
		for _, c := range rep.Isolation.Cells {
			if c.SourceNetwork == "IoT" && c.DestNetwork == "LAN" && c.DestFunction == "trusted-lan-transit" {
				hasIoTCell = true
			}
		}
		if !hasIoTCell {
			t.Fatalf("expected IoT -> LAN transit cell in isolation matrix, got %+v", rep.Isolation.Cells)
		}
	})

	t.Run("leaking_custom_zone_keeps_leak_audits_without_downgrade_or_trusted_bump", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			pols []unifi.FirewallPolicy
		}{
			{
				name: "icmp_block_then_allow_all",
				pols: []unifi.FirewallPolicy{
					{
						ID: "p-icmp", Index: 1, Name: "Block ICMP", Enabled: true, Action: "BLOCK", Origin: "USER_DEFINED",
						IPVersion: "both", Protocol: "icmp",
						Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
						Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
					},
					{
						ID: "p-allow", Index: 100, Name: "Allow All", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
						IPVersion: "both", Protocol: "all",
						Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
						Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
					},
				},
			},
			{
				name: "forgotten_allow_all_before_block",
				pols: []unifi.FirewallPolicy{
					{
						ID: "p-allow", Index: 10, Name: "Temp Allow All", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
						IPVersion: "both", Protocol: "all",
						Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
						Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
					},
					{
						ID: "p-block", Index: 200, Name: "Block IoT to Internal", Enabled: true, Action: "BLOCK", Origin: "USER_DEFINED",
						IPVersion: "both", Protocol: "all",
						Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
						Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
					},
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				snap := &unifi.Snapshot{
					Site: "default",
					Devices: []unifi.Device{
						{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
					},
					Networks: []unifi.Network{
						{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
						{ID: "net-iot", Name: "IoT", VLAN: "20", Subnet: "192.168.20.1/24", Purpose: "corporate", ZoneName: "IoTZone"},
					},
					Clients: []unifi.Client{
						{MAC: "cc:00:00:00:00:02", IP: "192.168.20.20", Name: "sensor-1", NetworkID: "net-iot", NetworkName: "IoT", VLAN: "20"},
					},
					FirewallPolicies: tc.pols,
					Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
				}

				raw := []checks.Finding{{CheckID: "UB-0001", BaseSeverity: checks.SeverityHigh, Client: snap.Clients[0], Port: 23}}
				rep := Evaluate(snap, raw, config.NetworkConfig{})

				var foundTransit, foundFWLeak bool
				for _, f := range rep.Findings {
					switch f.CheckID {
					case "UB-0001":
						if f.EffectiveSeverity != checks.SeverityHigh {
							t.Fatalf("leaking custom zone finding should stay at BaseSeverity High (neither downgraded nor trusted-bumped), got %v (%+v)", f.EffectiveSeverity, f.RiskReasons)
						}
					case "UB-UNIFI-ISO-TRUSTED-TRANSIT":
						foundTransit = true
					case "UB-UNIFI-FW-ISO-LEAK":
						foundFWLeak = true
					}
				}
				if !foundTransit {
					t.Fatalf("expected UB-UNIFI-ISO-TRUSTED-TRANSIT for leaking custom zone, got findings=%+v", rep.Findings)
				}
				if !foundFWLeak {
					t.Fatalf("expected UB-UNIFI-FW-ISO-LEAK for leaking custom zone, got findings=%+v", rep.Findings)
				}
			})
		}
	})

	t.Run("ipv4_only_block_with_open_ipv6_not_effectively_isolated", func(t *testing.T) {
		snap := &unifi.Snapshot{
			Site: "default",
			Networks: []unifi.Network{
				{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
				{ID: "net-iot", Name: "IoT", VLAN: "20", Subnet: "192.168.20.1/24", Purpose: "corporate", ZoneName: "IoTZone"},
			},
			FirewallPolicies: []unifi.FirewallPolicy{
				{
					ID: "p-block-v4", Index: 10, Name: "Block IPv4 Only", Enabled: true, Action: "BLOCK",
					IPVersion: "ipv4", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
				{
					ID: "p-allow-both", Index: 20, Name: "Allow All", Enabled: true, Action: "ALLOW",
					IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			},
		}
		if isolatedZoneSet(snap)["iotzone"] {
			t.Fatal("expected IPv4-only BLOCK followed by dual-stack ALLOW all not to mark IoTZone effectively isolated")
		}
	})
}

// TestIPv6TransitWithIPv4PinholeYieldsBlockedOK verifies that an IPv4-only
// pinhole on a dual-stack ("both") ALLOW rule evaluates to matchNo (not
// matchUnknown) for IPv6 transit probes, avoiding false unknown verdicts and
// low-severity unknown posture notes on dual-stack sites.
func TestIPv6TransitWithIPv4PinholeYieldsBlockedOK(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks: []unifi.Network{
			{ID: "net-lan", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "192.168.50.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		Clients: []unifi.Client{
			{MAC: "aa:11:22:33:44:01", IP: "192.168.1.40", Name: "Office Printer", NetworkID: "net-lan", NetworkName: "LAN"},
			{MAC: "aa:11:22:33:44:02", IP: "192.168.1.50", IPv6: []string{"2001:db8:1::50"}, Name: "LAN Phone", NetworkID: "net-lan", NetworkName: "LAN"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-print", Index: 10, Name: "Allow Guest to Printer IPv4", Enabled: true, Action: "ALLOW",
				IPVersion: "both", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.40"}, Ports: []int{631}},
			},
			{
				ID: "p-block", Index: 20, Name: "Block Guest to Internal", Enabled: true, Action: "BLOCK",
				IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	netCfg := config.NetworkConfig{
		TrustedVLANs: []string{"LAN"},
		IsolationPolicy: config.IsolationIntent{
			GuestVLANs: []string{"Guest"},
			ApprovedPaths: []config.ApprovedPath{
				{Name: "Guest Printing", SourceZone: "Hotspot", DestZone: "Internal", DestIP: "192.168.1.40", Transport: "tcp", Port: 631},
			},
		},
	}

	mat, _, notes := EvaluateIsolation(snap, nil, netCfg)
	var v4Verdict, v6Verdict IsolationVerdict
	for _, c := range mat.Cells {
		if c.DestFunction == "trusted-lan-transit" && c.SourceNetwork == "Guest" && c.DestNetwork == "LAN" {
			if c.IPFamily == "ipv4" {
				v4Verdict = c.Verdict
			}
			if c.IPFamily == "ipv6" {
				v6Verdict = c.Verdict
			}
		}
	}
	if v4Verdict != IsolationBlockedOK {
		t.Fatalf("expected IPv4 transit cell blocked-ok, got %q", v4Verdict)
	}
	if v6Verdict != IsolationBlockedOK {
		t.Fatalf("expected IPv6 transit cell blocked-ok (not unknown), got %q", v6Verdict)
	}
	for _, n := range notes {
		if strings.Contains(strings.ToLower(n.Title), "isolation verdict unknown") {
			t.Fatalf("unexpected unknown-verdict posture note on dual-stack site with IPv4-only pinhole: %+v", n)
		}
	}

	// Direct unit check: IPv4 selector with empty target IP on an IPv6 query returns matchNo.
	m, _ := matchesEndpoint(unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.40"}, Ports: []int{631}}, "Internal", "", "", "", "", 631, "ipv6")
	if m != matchNo {
		t.Fatalf("expected IPv4-only selector against IPv6 query to return matchNo, got %v", m)
	}
}

// TestOfflineHostCarryForwardStableKeysAndTTL verifies that host-scoped UniFi
// findings (port-forward targets, BMC isolation, BMC shared VLAN) and check
// findings do not re-alert across offline/online cycles, are not emitted in
// ResolvedKeys while the host is merely offline, and expire cleanly once
// offline past the staleness TTL.
func TestOfflineHostCarryForwardStableKeysAndTTL(t *testing.T) {
	netCfg := config.NetworkConfig{}
	nas := unifi.Client{MAC: "aa:bb:cc:00:00:01", IP: "192.168.1.20", Name: "nas-01", NetworkID: "net-lan", NetworkName: "Default", VLAN: "1", IsWired: true}
	bmc := unifi.Client{MAC: "aa:bb:cc:00:00:02", IP: "192.168.1.30", Name: "Server-BMC", NetworkID: "net-lan", NetworkName: "Default", VLAN: "1", IsWired: true}

	makeSnap := func(clients []unifi.Client, forwards []unifi.PortForward) *unifi.Snapshot {
		return &unifi.Snapshot{
			Site: "default",
			Devices: []unifi.Device{
				{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
			},
			Networks: []unifi.Network{
				{ID: "net-lan", Name: "Default", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
				{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "192.168.50.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
			},
			Clients:      clients,
			PortForwards: forwards,
			FirewallPolicies: []unifi.FirewallPolicy{
				{
					ID: "p-allow-bmc", Index: 10, Name: "Allow Guest to BMC", Enabled: true, Action: "ALLOW",
					IPVersion: "ipv4", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.30"}, Ports: []int{443}},
				},
				{
					ID: "p-block-rest", Index: 20, Name: "Block Guest", Enabled: true, Action: "BLOCK",
					IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
			},
			Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}
	}

	fwds := []unifi.PortForward{
		{ID: "pf-nas", Name: "Proxmox Admin", Enabled: true, Proto: "tcp", DstPort: "8006", FwdIP: "192.168.1.20", FwdPort: "8006", Src: "any"},
	}
	rawOnline := []checks.Finding{
		{CheckID: "UB-0001", BaseSeverity: checks.SeverityHigh, Client: nas, Port: 23},
	}

	// Cycle 1: both hosts online.
	snap1 := makeSnap([]unifi.Client{nas, bmc}, fwds)
	rep1 := Evaluate(snap1, rawOnline, netCfg)
	st1 := BuildStateWithPrev(nil, snap1, rep1, netCfg, nil)

	// Cycle 2: both hosts go offline (e.g., reboot); port forward still exists.
	snapOff := makeSnap(nil, fwds)
	repOff := Evaluate(snapOff, nil, netCfg)
	diffOff1 := ComputeDiff(st1, snapOff, repOff, netCfg)
	if len(diffOff1.NewFindings) != 0 || len(diffOff1.EscalatedFindings) != 0 {
		t.Fatalf("offline cycle must not raise new/escalated findings, got new=%+v esc=%+v", diffOff1.NewFindings, diffOff1.EscalatedFindings)
	}
	if len(diffOff1.ResolvedKeys) != 0 {
		t.Fatalf("offline carried-forward findings must not appear in ResolvedKeys, got %+v", diffOff1.ResolvedKeys)
	}
	st2 := BuildStateWithPrev(st1, snapOff, repOff, netCfg, nil)

	// Cycle 3: still offline; ResolvedKeys must remain empty across repeated cycles.
	diffOff2 := ComputeDiff(st2, snapOff, repOff, netCfg)
	if len(diffOff2.ResolvedKeys) != 0 || len(diffOff2.NewFindings) != 0 || len(diffOff2.EscalatedFindings) != 0 {
		t.Fatalf("repeated offline cycle must produce empty diff, got %+v", diffOff2)
	}
	st3 := BuildStateWithPrev(st2, snapOff, repOff, netCfg, nil)

	// Cycle 4: both hosts return online; zero new/escalated/trusted alerts.
	repBack := Evaluate(snap1, rawOnline, netCfg)
	diffBack := ComputeDiff(st3, snap1, repBack, netCfg)
	if len(diffBack.NewFindings) != 0 || len(diffBack.EscalatedFindings) != 0 || len(diffBack.NewTrustedClients) != 0 || len(diffBack.ResolvedKeys) != 0 {
		t.Fatalf("returning online hosts must not re-alert, got %+v", diffBack)
	}

	// Cycle 5: simulate hosts offline longer than offlineFindingTTL (8 days).
	aged := &State{
		UpdatedAt:       time.Now().UTC().Add(-8 * 24 * time.Hour),
		Findings:        make(map[string]checks.Severity, len(st3.Findings)),
		FindingLastSeen: make(map[string]time.Time, len(st3.FindingLastSeen)),
		TrustedClients:  st3.TrustedClients,
		PortForwards:    st3.PortForwards,
	}
	expiredAt := time.Now().UTC().Add(-8 * 24 * time.Hour)
	for k, sev := range st3.Findings {
		aged.Findings[k] = sev
		aged.FindingLastSeen[k] = expiredAt
	}
	diffExpired := ComputeDiff(aged, snapOff, repOff, netCfg)
	if len(diffExpired.ResolvedKeys) == 0 {
		t.Fatal("expected offline host findings past TTL to resolve once")
	}
	stExpired := BuildStateWithPrev(aged, snapOff, repOff, netCfg, nil)
	for _, k := range diffExpired.ResolvedKeys {
		if _, stillPresent := stExpired.Findings[k]; stillPresent {
			t.Fatalf("expected expired key %q to be pruned from state", k)
		}
	}
	// Subsequent offline cycle after expiration must report 0 resolved keys.
	diffAfterExpire := ComputeDiff(stExpired, snapOff, repOff, netCfg)
	if len(diffAfterExpire.ResolvedKeys) != 0 {
		t.Fatalf("expected 0 resolved keys after expiration pruning, got %+v", diffAfterExpire.ResolvedKeys)
	}

	// Disabling the port forward must immediately resolve UB-UNIFI-PORTFWD.
	snapNoFwd := makeSnap(nil, nil)
	repNoFwd := Evaluate(snapNoFwd, nil, netCfg)
	diffNoFwd := ComputeDiff(stExpired, snapNoFwd, repNoFwd, netCfg)
	foundFwdResolved := false
	for _, k := range diffNoFwd.ResolvedKeys {
		if strings.HasPrefix(k, "UB-UNIFI-PORTFWD|portfwd:pf-nas|") {
			foundFwdResolved = true
		}
	}
	if !foundFwdResolved {
		t.Fatalf("expected disabled port forward to resolve immediately, got %+v", diffNoFwd.ResolvedKeys)
	}
}

// TestExposureBenignRulesIgnoreWANPortAndFullRangeSeverity verifies that
// WAN-side DstPort fallback never downgrades internal services to benign
// expected-p2p/vpn-entrypoint rules, and that 1-65535 WAN firewall ALLOW
// policies receive Critical severity matching AnyPort rules.
func TestExposureBenignRulesIgnoreWANPortAndFullRangeSeverity(t *testing.T) {
	cls, err := LoadExposureClassifier(builtinrules.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadExposureClassifier: %v", err)
	}

	for _, pf := range []unifi.PortForward{
		{ID: "pf-jf", Name: "Jellyfin", Enabled: true, Proto: "tcp", DstPort: "4001", FwdIP: "192.168.1.30", FwdPort: "8096", Src: "any"},
		{ID: "pf-app", Name: "Web App", Enabled: true, Proto: "tcp", DstPort: "8333", FwdIP: "192.168.1.31", FwdPort: "8080", Src: "any"},
		{ID: "pf-https", Name: "Internal Portal", Enabled: true, Proto: "tcp", DstPort: "30303", FwdIP: "192.168.1.32", FwdPort: "8443", Src: "any"},
		{ID: "pf-udp", Name: "Custom UDP", Enabled: true, Proto: "udp", DstPort: "51820", FwdIP: "192.168.1.33", FwdPort: "8080", Src: "any"},
	} {
		got := cls.Classify(pf, unifi.Client{IP: pf.FwdIP})
		if got.Class != "unclassified-wan" || got.Severity != checks.SeverityMedium {
			t.Fatalf("forward %s (%s->%s) must stay unclassified-wan/medium, got %+v", pf.Name, pf.DstPort, pf.FwdPort, got)
		}
	}

	// True internal P2P / VPN ports remain benign info.
	for _, pf := range []unifi.PortForward{
		{ID: "pf-ipfs", Name: "IPFS", Enabled: true, Proto: "tcp", DstPort: "4001", FwdIP: "192.168.1.40", FwdPort: "4001", Src: "any"},
		{ID: "pf-wg", Name: "WireGuard", Enabled: true, Proto: "udp", DstPort: "51820", FwdIP: "192.168.1.41", FwdPort: "51820", Src: "any"},
	} {
		got := cls.Classify(pf, unifi.Client{IP: pf.FwdIP})
		if got.Severity != checks.SeverityInfo {
			t.Fatalf("legitimate forward %s (%s->%s) should stay info, got %+v", pf.Name, pf.DstPort, pf.FwdPort, got)
		}
	}

	// WAN->LAN and WAN->Gateway 1-65535 port ranges must be graded Critical.
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "fw-wan-lan-full", Name: "Full Range WAN to Host", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
				Protocol:    "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.20"}, PortRanges: []unifi.PortRange{{Start: 1, End: 65535}}},
			},
			{
				ID: "fw-wan-gw-full", Name: "Full Range WAN to Gateway", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
				Protocol:    "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, PortRanges: []unifi.PortRange{{Start: 1, End: 65535}}},
			},
		},
	}
	fwFindings := auditFirewallPolicies(snap)
	if len(fwFindings) != 2 {
		t.Fatalf("expected 2 WAN firewall findings, got %+v", fwFindings)
	}
	for _, f := range fwFindings {
		if f.EffectiveSeverity != checks.SeverityCritical {
			t.Fatalf("expected 1-65535 WAN policy %s to be Critical, got %v", f.CheckID, f.EffectiveSeverity)
		}
	}
}

// TestProtocolNegationInICMPv6CheckAndFirewallAudit verifies that negated
// protocols are honored by both the blanket ICMPv6 check and WAN firewall
// shadowing/evidence formatting.
func TestProtocolNegationInICMPv6CheckAndFirewallAudit(t *testing.T) {
	// BLOCK with Protocol="icmpv6", ProtocolNegated=true blocks everything EXCEPT ICMPv6.
	snapNegBlock := &unifi.Snapshot{
		Site: "default",
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-block-not-icmpv6", Index: 10, Name: "Block Non-ICMPv6", Enabled: true, Action: "BLOCK",
				Protocol: "icmpv6", ProtocolNegated: true,
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
	}
	extFindings, _ := AnalyzeExtendedNetworkChecks(snapNegBlock, config.NetworkConfig{})
	for _, f := range extFindings {
		if f.CheckID == "UB-UNIFI-IPV6-BLANKET-ICMPV6-BLOCK" {
			t.Fatalf("negated ICMPv6 block (everything except ICMPv6) must not raise blanket ICMPv6 finding: %+v", f)
		}
	}

	// Earlier ALLOW with Protocol="icmpv6", ProtocolNegated=true must NOT suppress a real ICMPv6 block.
	snapNegAllow := &unifi.Snapshot{
		Site: "default",
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-allow-not-icmpv6", Index: 5, Name: "Allow Non-ICMPv6", Enabled: true, Action: "ALLOW",
				Protocol: "icmpv6", ProtocolNegated: true,
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
			{
				ID: "p-block-icmpv6", Index: 10, Name: "Drop ICMPv6", Enabled: true, Action: "BLOCK",
				Protocol: "icmpv6",
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
	}
	extFindings2, _ := AnalyzeExtendedNetworkChecks(snapNegAllow, config.NetworkConfig{})
	foundICMPv6 := false
	for _, f := range extFindings2 {
		if f.CheckID == "UB-UNIFI-IPV6-BLANKET-ICMPV6-BLOCK" {
			foundICMPv6 = true
		}
	}
	if !foundICMPv6 {
		t.Fatalf("expected UB-UNIFI-IPV6-BLANKET-ICMPV6-BLOCK when earlier ALLOW negated ICMPv6, got %+v", extFindings2)
	}

	// BLOCK udp before ALLOW not-udp must NOT shadow ALLOW not-udp, and evidence must render "protocol=not udp".
	snapAudit := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-block-udp", Index: 10, Name: "Block WAN UDP", Enabled: true, Action: "BLOCK", Origin: "USER_DEFINED",
				Protocol:    "udp",
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
			{
				ID: "p-allow-not-udp", Index: 20, Name: "Allow WAN Not-UDP", Enabled: true, Action: "ALLOW", Origin: "USER_DEFINED",
				Protocol: "udp", ProtocolNegated: true,
				Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.168.1.20"}, Ports: []int{22}},
			},
		},
	}
	auditFindings := auditFirewallPolicies(snapAudit)
	if len(auditFindings) != 1 || auditFindings[0].CheckID != "UB-UNIFI-FW-WAN-LAN" {
		t.Fatalf("expected ALLOW not-udp after BLOCK udp not to be shadowed, got %+v", auditFindings)
	}
	if !strings.Contains(auditFindings[0].Evidence, "protocol=not udp") {
		t.Fatalf("expected evidence to format negated protocol as 'protocol=not udp', got %q", auditFindings[0].Evidence)
	}
}

// TestGatewayDNSDependencyPerVLANGatewayIP verifies that a gateway DNS ALLOW
// policy scoped to the guest VLAN's own gateway interface IP is recognized as
// approved rather than reported as a broken dependency.
func TestGatewayDNSDependencyPerVLANGatewayIP(t *testing.T) {
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
				ID: "p-guest-dns", Index: 10, Name: "Allow Guest VLAN Gateway DNS", Enabled: true, Action: "ALLOW",
				IPVersion: "ipv4", Protocol: "udp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", IPs: []string{"192.168.50.1"}, Ports: []int{53}},
			},
			{
				ID: "p-guest-gw-block", Index: 20, Name: "Block Guest to Gateway", Enabled: true, Action: "BLOCK",
				IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, AnyPort: true},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	mat, _, notes := EvaluateIsolation(snap, nil, config.NetworkConfig{
		IsolationPolicy: config.IsolationIntent{GuestVLANs: []string{"Guest"}},
	})
	foundDNSApproved := false
	for _, c := range mat.Cells {
		if c.DestFunction == "gateway-dns" && c.SourceNetwork == "Guest" {
			if c.Verdict != IsolationApproved {
				t.Fatalf("expected gateway-dns allowed on per-VLAN gateway IP 192.168.50.1 to be approved, got %+v", c)
			}
			foundDNSApproved = true
		}
	}
	if !foundDNSApproved {
		t.Fatalf("expected approved gateway-dns cell for Guest, got %+v", mat.Cells)
	}
	for _, n := range notes {
		if strings.Contains(n.Title, "gateway-dns") {
			t.Fatalf("unexpected broken gateway-dns note when VLAN gateway IP is permitted: %+v", n)
		}
	}
}
