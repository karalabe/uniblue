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
	builtinrules "github.com/karalabe/uniblue/rules"
)

// TestExposureRulePortainerAndDstPortFallback verifies that ambiguous ports
// like TCP 9000 for Portainer/MinIO are NOT downgraded to info-level Ethereum
// P2P (#70), and that WAN destination ports forwarded to non-standard internal
// ports (e.g. WAN 3389 -> 13389) are still classified as RDP exposure (#80).
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
// transit probing (#71), IP-range selectors (#79), unresolved zone IDs (#78),
// protocol negation (#4), prefix-delegated IPv6 context (#81), DestRole gating
// on ApprovedPaths (#82), strict single-switch L2 port isolation (#72), and
// isolatedZoneSet rejecting narrow ICMP-only blocks (#75).
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
			// Non-443 ALLOW rule (SSH 22 + RDP 3389) from Hotspot -> Internal must trigger violation (#71).
			{
				ID: "p-ssh", Name: "Allow Guest SSH", Enabled: true, Index: 10, Action: "ALLOW",
				IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{22, 3389}},
			},
			// IP-range ALLOW to BMC (192.0.2.10-192.0.2.40) must match 192.0.2.30 (#79).
			{
				ID: "p-bmc-range", Name: "Allow Guest Range", Enabled: true, Index: 15, Action: "ALLOW",
				IPVersion: "ipv4", Protocol: "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"192.0.2.10-192.0.2.40"}, Ports: []int{443}},
			},
			// Narrow ICMP-only BLOCK on IoTZone -> Internal must NOT mark IoTZone isolated (#75).
			{
				ID: "p-iot-icmp", Name: "Block IoT ICMP", Enabled: true, Index: 20, Action: "BLOCK",
				IPVersion: "ipv4", Protocol: "icmp",
				Source:      unifi.PolicyEndpoint{ZoneName: "IoTZone", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	// #75: IoTZone has only an ICMP BLOCK, so it must NOT be treated as isolated.
	isoZones := isolatedZoneSet(snap)
	if isoZones["iotzone"] {
		t.Fatalf("expected IoTZone with ICMP-only BLOCK not to be marked isolated, got %+v", isoZones)
	}

	netCfg := config.NetworkConfig{
		IsolationPolicy: config.IsolationIntent{
			GuestVLANs:               []string{"Guest"},
			RequireSameVLANIsolation: []string{"Guest"},
			// #82: DestRole="printer" without Function must NOT approve BMC on TCP 443.
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

	// #78 + #4: Unresolved ZoneID -> matchUnknown; negated UDP protocol matches TCP.
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
// connected to an external switch does not trigger multi-MAC false positives
// (#76), dash/bare config MACs match authorized devices (#77), rogue wired APs
// are deduped (#84), cloned-BSSID rogue APs are not suppressed (#83), and
// BuildStateWithPrev carries forward offline trusted clients & keeps max
// severity per key (#73, #74).
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
			// #83: Cloned BSSID flagged is_rogue=true must trigger evil twin.
			{BSSID: "02:aa:00:00:00:11", ESSID: "HomeWiFi", IsRogue: true},
			// #84: Two observations of the same wired rogue AP must produce 1 finding.
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

	// #74: BuildStateWithPrev carries forward offline trusted clients & offline host findings.
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
