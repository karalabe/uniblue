// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"strings"
	"testing"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

func TestSmartGuestVsIoTContainmentWithSharedHotspotZone(t *testing.T) {
	snap := &unifi.Snapshot{
		Networks: []unifi.Network{
			{ID: "net-def", Name: "Default", VLAN: "1", Purpose: "corporate", ZoneName: "Internal", Subnet: "10.0.0.1/16", InternetAccessEnabled: boolPtr(true)},
			{ID: "net-iot", Name: "Smart Devices", VLAN: "99", Purpose: "guest", ZoneName: "Hotspot", Subnet: "10.99.0.1/16", DomainName: "iot", InternetAccessEnabled: boolPtr(true)},
			{ID: "net-guest", Name: "Guest Devices", VLAN: "100", Purpose: "guest", ZoneName: "Hotspot", Subnet: "10.100.0.1/16", DomainName: "guest", InternetAccessEnabled: boolPtr(true)},
		},
		WLANs: []unifi.WLANConfig{
			{ID: "w-def", Name: "HomeWiFi", Enabled: true, Security: "wpapsk", NetworkName: "Default", L2Isolation: false, IsGuest: false},
			{ID: "w-iot", Name: "UPC029C724", Enabled: true, Security: "wpapsk", NetworkName: "Smart Devices", L2Isolation: true, IsGuest: false},
			{ID: "w-guest", Name: "UPC700343E", Enabled: true, Security: "wpapsk", NetworkName: "Guest Devices", L2Isolation: false, IsGuest: false},
		},
		Devices: []unifi.Device{
			{MAC: "aa:bb:cc:00:00:01", Name: "UDM Pro", Type: "udm", IP: "10.0.0.1"},
			{MAC: "aa:bb:cc:00:00:02", Name: "Core Switch", Type: "usw", Ports: []unifi.SwitchPort{
				{PortIdx: 9, Up: true, Isolation: false},
				{PortIdx: 10, Up: true, Isolation: false},
			}},
			{MAC: "aa:bb:cc:00:00:11", Name: "Downstairs AP", Type: "uap", UplinkMAC: "aa:bb:cc:00:00:02", UplinkPort: 9},
			{MAC: "aa:bb:cc:00:00:12", Name: "Upstairs AP", Type: "uap", UplinkMAC: "aa:bb:cc:00:00:02", UplinkPort: 10},
		},
		Clients: []unifi.Client{
			{MAC: "11:22:33:44:55:01", Name: "Galaxy-A12", IP: "10.100.1.10", NetworkName: "Guest Devices", APMAC: "aa:bb:cc:00:00:11"},
			{MAC: "11:22:33:44:55:02", Name: "Roomba", OUI: "iRobot", IP: "10.100.1.11", NetworkName: "Guest Devices", APMAC: "aa:bb:cc:00:00:12"},
		},
		KnownClients: []unifi.HistoricalClient{
			{MAC: "11:22:33:44:55:03", Name: "Visitor iPhone", Hostname: "iPhone", LastNetworkName: "Guest Devices"},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID: "p-postauth", Name: "Post-Authorization Restrictions", Enabled: true, Index: 30002,
				Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: false, AnyPort: true, IPs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}},
			},
			{
				ID: "p-hot-int", Name: "Block Hotspot to Internal", Enabled: true, Index: 2147483647,
				Action: "BLOCK", IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
			{
				ID: "p-hot-gw", Name: "Block Hotspot to Gateway", Enabled: true, Index: 2147483647,
				Action: "BLOCK", IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, AnyPort: true},
			},
			{
				ID: "p-hot-ext", Name: "Allow All Traffic", Enabled: true, Index: 2147483647,
				Action: "ALLOW", IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
			},
			{
				ID: "p-int-hot", Name: "Allow All Traffic", Enabled: true, Index: 2147483647,
				Action: "ALLOW", IPVersion: "both", Protocol: "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
			},
		},
		SwitchACLCoverage: &unifi.SwitchACLCoverage{Status: "complete"},
		Visibility: &unifi.SiteVisibility{
			GatewayPoliciesAvailable: true,
			SwitchACLsAvailable:      true,
			WLANsAvailable:           true,
		},
	}

	report := Evaluate(snap, nil, config.NetworkConfig{})
	if report.Isolation == nil {
		t.Fatal("expected non-nil IsolationMatrix")
	}

	byNet := make(map[string]NetworkContainment)
	for _, nc := range report.Isolation.Containment {
		byNet[nc.NetworkName] = nc
	}

	iot, ok := byNet["Smart Devices"]
	if !ok {
		t.Fatalf("missing containment for Smart Devices: %+v", report.Isolation.Containment)
	}
	if iot.Archetype != "iot" {
		t.Fatalf("Smart Devices archetype = %q, want iot (reason=%q)", iot.Archetype, iot.ArchetypeReason)
	}
	if iot.Peers.State != "partial" {
		t.Fatalf("Smart Devices peers = %+v, want partial (same-AP ok, cross-AP open)", iot.Peers)
	}
	if iot.LANEgress.State != "blocked" {
		t.Fatalf("Smart Devices LAN egress = %+v, want blocked", iot.LANEgress)
	}
	if iot.InternetEgress.State != "open" {
		t.Fatalf("Smart Devices internet egress = %+v, want open", iot.InternetEgress)
	}
	if iot.LANInbound.State != "open" {
		t.Fatalf("Smart Devices LAN inbound = %+v, want open", iot.LANInbound)
	}
	if len(iot.SharedZoneWith) != 1 || iot.SharedZoneWith[0] != "Guest Devices" {
		t.Fatalf("expected Smart Devices SharedZoneWith=[Guest Devices], got %v", iot.SharedZoneWith)
	}

	guest, ok := byNet["Guest Devices"]
	if !ok {
		t.Fatalf("missing containment for Guest Devices: %+v", report.Isolation.Containment)
	}
	if guest.Archetype != "guest" {
		t.Fatalf("Guest Devices archetype = %q, want guest (reason=%q)", guest.Archetype, guest.ArchetypeReason)
	}
	if guest.Peers.State != "open" {
		t.Fatalf("Guest Devices peers = %+v, want open (l2_isolation=false)", guest.Peers)
	}
	if guest.InternetEgress.State != "open" {
		t.Fatalf("Guest Devices internet egress = %+v, want open", guest.InternetEgress)
	}

	hasFinding := func(id, net string) bool {
		for _, f := range report.Findings {
			if f.CheckID == id && (net == "" || strings.EqualFold(f.Client.NetworkName, net)) {
				return true
			}
		}
		return false
	}
	if !hasFinding("UB-UNIFI-WIFI-NO-L2-ISOLATION", "Guest Devices") {
		t.Fatalf("expected UB-UNIFI-WIFI-NO-L2-ISOLATION for generic SSID name UPC700343E on isolated Guest Devices, got findings=%+v", report.Findings)
	}
	if !hasFinding("UB-UNIFI-ISO-IOT-INTERNET", "Smart Devices") {
		t.Fatalf("expected UB-UNIFI-ISO-IOT-INTERNET for Smart Devices, got findings=%+v", report.Findings)
	}
	if hasFinding("UB-UNIFI-ISO-IOT-INTERNET", "Guest Devices") || hasFinding("UB-UNIFI-ISO-INTERNET-LEAK", "Guest Devices") {
		t.Fatalf("Guest Devices must NOT be flagged for open internet: %+v", report.Findings)
	}
	if !hasFinding("UB-UNIFI-ISO-IOT-INBOUND", "Smart Devices") {
		t.Fatalf("expected UB-UNIFI-ISO-IOT-INBOUND for wide-open Internal -> Smart Devices")
	}
	if !hasFinding("UB-UNIFI-ISO-SAME-VLAN", "Smart Devices") {
		t.Fatalf("expected cross-AP UB-UNIFI-ISO-SAME-VLAN for Smart Devices across 2 APs with 0 switch ACLs")
	}

	foundSharedNote := false
	foundMisplacedNote := false
	for _, n := range report.PostureNotes {
		if strings.Contains(n.Title, "shares firewall zone") {
			foundSharedNote = true
		}
		if strings.Contains(n.Title, "Roomba") {
			foundMisplacedNote = true
		}
	}
	if !foundSharedNote {
		t.Fatalf("expected shared firewall zone posture note, got %+v", report.PostureNotes)
	}
	if !foundMisplacedNote {
		t.Fatalf("expected misplaced Roomba on Guest Devices posture note, got %+v", report.PostureNotes)
	}
}

func TestLockedDownIoTAndIPv6InternetInboundParityLeaks(t *testing.T) {
	t.Run("fully locked down IoT passes all 4 axes", func(t *testing.T) {
		snap := &unifi.Snapshot{
			Networks: []unifi.Network{
				{ID: "net-def", Name: "Default", VLAN: "1", Purpose: "corporate", ZoneName: "Internal", Subnet: "10.0.0.1/24"},
				{ID: "net-iot", Name: "IoT", VLAN: "30", Purpose: "corporate", ZoneName: "IoT", Subnet: "10.30.0.1/24", IsolationEnabled: true, InternetAccessEnabled: boolPtr(false)},
			},
			WLANs: []unifi.WLANConfig{
				{ID: "w-iot", Name: "IoT-WiFi", Enabled: true, Security: "wpapsk", NetworkName: "IoT", L2Isolation: true},
			},
			Devices: []unifi.Device{
				{MAC: "aa:bb:cc:00:00:01", Name: "UDM", Type: "udm", IP: "10.0.0.1"},
				{MAC: "aa:bb:cc:00:00:02", Name: "Switch", Type: "usw", Ports: []unifi.SwitchPort{
					{PortIdx: 5, Up: true, Isolation: true, MACTableCount: 1},
				}},
			},
			Clients: []unifi.Client{
				{MAC: "11:22:33:44:55:10", Name: "Daikin AC", IP: "10.30.0.20", NetworkName: "IoT", IsWired: true, SwitchMAC: "aa:bb:cc:00:00:02", SwitchPort: 5},
			},
			FirewallPolicies: []unifi.FirewallPolicy{
				{ID: "p1", Name: "Block IoT to Internal", Enabled: true, Index: 100, Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true}},
				{ID: "p2", Name: "Block IoT to Gateway", Enabled: true, Index: 101, Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, AnyPort: true}},
				{ID: "p3", Name: "Allow HA to IoT", Enabled: true, Index: 102, Action: "ALLOW", IPVersion: "both", Protocol: "tcp",
					Source:      unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: false, IPs: []string{"10.0.0.50"}, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: false, Ports: []int{80}}},
				{ID: "p4", Name: "Block Internal to IoT", Enabled: true, Index: 103, Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true}},
			},
			SwitchACLCoverage: &unifi.SwitchACLCoverage{Status: "complete"},
			Visibility:        &unifi.SiteVisibility{GatewayPoliciesAvailable: true, SwitchACLsAvailable: true, WLANsAvailable: true},
		}

		mat, findings, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{})
		if len(mat.Containment) != 1 {
			t.Fatalf("expected 1 containment entry, got %+v", mat.Containment)
		}
		nc := mat.Containment[0]
		if nc.Peers.State != "isolated" || nc.LANEgress.State != "blocked" || nc.InternetEgress.State != "blocked" || nc.LANInbound.State != "restricted" {
			t.Fatalf("unexpected locked-down IoT containment: %+v", nc)
		}
		for _, f := range findings {
			if strings.HasPrefix(f.CheckID, "UB-UNIFI-ISO-") {
				t.Fatalf("locked-down IoT should have zero isolation findings, got %+v", f)
			}
		}
	})

	t.Run("IPv4 blocked but IPv6 open fires high internet and inbound leak findings", func(t *testing.T) {
		snap := &unifi.Snapshot{
			Networks: []unifi.Network{
				{ID: "net-def", Name: "Default", VLAN: "1", Purpose: "corporate", ZoneName: "Internal", Subnet: "10.0.0.1/24", IPv6Subnet: "2001:db8:1::1/64"},
				{ID: "net-iot", Name: "IoT", VLAN: "30", Purpose: "corporate", ZoneName: "IoT", Subnet: "10.30.0.1/24", IPv6Subnet: "2001:db8:30::1/64", IsolationEnabled: true},
			},
			FirewallPolicies: []unifi.FirewallPolicy{
				{ID: "p-iot-int", Name: "Block IoT->Internal", Enabled: true, Index: 100, Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source: unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true}, Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true}},
				{ID: "p-iot-gw", Name: "Block IoT->GW", Enabled: true, Index: 101, Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source: unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true}, Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, AnyPort: true}},
				{ID: "p-ext-v4", Name: "Block IoT IPv4 Internet", Enabled: true, Index: 102, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
					Source: unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true}, Destination: unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true}},
				{ID: "p-ext-all", Name: "Allow All External", Enabled: true, Index: 200, Action: "ALLOW", IPVersion: "both", Protocol: "all",
					Source: unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true}, Destination: unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true}},
				{ID: "p-in-v4", Name: "Block Internal->IoT v4", Enabled: true, Index: 103, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all",
					Source: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true}, Destination: unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true}},
				{ID: "p-in-all", Name: "Allow Internal->IoT", Enabled: true, Index: 201, Action: "ALLOW", IPVersion: "both", Protocol: "all",
					Source: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true}, Destination: unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true}},
			},
			Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}

		mat, findings, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{})
		nc := mat.Containment[0]
		if nc.InternetEgress.State != "partial" {
			t.Fatalf("expected partial internet egress on IPv4-only block, got %+v", nc.InternetEgress)
		}
		if nc.LANInbound.State != "partial" {
			t.Fatalf("expected partial LAN inbound on IPv4-only block, got %+v", nc.LANInbound)
		}
		var sawInetLeak, sawInLeak bool
		for _, f := range findings {
			if f.CheckID == "UB-UNIFI-ISO-INTERNET-LEAK" && f.EffectiveSeverity == checks.SeverityHigh {
				sawInetLeak = true
			}
			if f.CheckID == "UB-UNIFI-ISO-INBOUND-LEAK" && f.EffectiveSeverity == checks.SeverityHigh {
				sawInLeak = true
			}
		}
		if !sawInetLeak || !sawInLeak {
			t.Fatalf("expected both High IPv6 leak findings, got %+v", findings)
		}
	})

	t.Run("subnet-scoped Isolated Networks rule resolves Cameras to BMC as blocked-ok and LAN egress as blocked", func(t *testing.T) {
		snap := &unifi.Snapshot{
			Networks: []unifi.Network{
				{ID: "net-srv", Name: "Servers", VLAN: "2", Purpose: "corporate", ZoneName: "Internal", Subnet: "10.2.0.1/16"},
				{ID: "net-cam", Name: "Cameras", VLAN: "3", Purpose: "corporate", ZoneName: "Cameras", Subnet: "10.3.0.1/16", IsolationEnabled: true, InternetAccessEnabled: boolPtr(false)},
			},
			Devices: []unifi.Device{
				{MAC: "aa:bb:cc:00:00:01", Name: "UDM Pro", Type: "udm", IP: "10.0.0.1"},
				{MAC: "aa:bb:cc:00:00:02", Name: "Switch", Type: "usw", Ports: []unifi.SwitchPort{
					{PortIdx: 1, Up: true, Isolation: true, MACTableCount: 1},
				}},
			},
			Clients: []unifi.Client{
				{MAC: "11:22:33:44:55:99", Name: "Unraid Management Console", IP: "10.2.0.5", NetworkName: "Servers", IsWired: true},
				{MAC: "11:22:33:44:55:88", Name: "Camera - Fence", IP: "10.3.0.46", NetworkName: "Cameras", IsWired: true, SwitchMAC: "aa:bb:cc:00:00:02", SwitchPort: 1},
			},
			FirewallPolicies: []unifi.FirewallPolicy{
				{
					ID: "p-iso", Name: "Isolated Networks", Enabled: true, Index: 30000, Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Cameras", IPs: []string{"10.3.0.0/16"}, AnyTarget: false, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
				{
					ID: "p-cam-int", Name: "Block All Traffic", Enabled: true, Index: 2147483647, Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Cameras", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
				},
				{
					ID: "p-cam-gw-dhcp", Name: "Allow DHCP & NTP", Enabled: true, Index: 10001, Action: "ALLOW", IPVersion: "both", Protocol: "udp",
					Source:      unifi.PolicyEndpoint{ZoneName: "Cameras", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, AnyPort: false, Ports: []int{67, 123, 10001}},
				},
				{
					ID: "p-cam-gw-blk", Name: "Block All Traffic", Enabled: true, Index: 10003, Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Cameras", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, AnyPort: true},
				},
				{
					ID: "p-int-cam", Name: "Block All Traffic", Enabled: true, Index: 2147483647, Action: "BLOCK", IPVersion: "both", Protocol: "all",
					Source:      unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
					Destination: unifi.PolicyEndpoint{ZoneName: "Cameras", AnyTarget: true, AnyPort: true},
				},
			},
			SwitchACLCoverage: &unifi.SwitchACLCoverage{Status: "complete"},
			Visibility:        &unifi.SiteVisibility{GatewayPoliciesAvailable: true, SwitchACLsAvailable: true},
		}

		mat, findings, notes := EvaluateIsolation(snap, nil, config.NetworkConfig{})
		if len(mat.Containment) != 1 {
			t.Fatalf("expected 1 containment entry, got %+v", mat.Containment)
		}
		nc := mat.Containment[0]
		if nc.Peers.State != "isolated" || nc.LANEgress.State != "blocked" || nc.InternetEgress.State != "blocked" || nc.LANInbound.State != "blocked" {
			t.Fatalf("expected all 4 Cameras containment axes green, got %+v", nc)
		}
		if mat.UnknownCount != 0 || mat.BrokenDepCount != 0 || mat.ViolationCount != 0 {
			t.Fatalf("expected 0 unknown/broken/violation cells for locked-down Cameras, got unknown=%d broken=%d viol=%d cells=%+v", mat.UnknownCount, mat.BrokenDepCount, mat.ViolationCount, mat.Cells)
		}
		if len(findings) != 0 || len(notes) != 0 {
			t.Fatalf("expected 0 findings and 0 notes, got findings=%+v notes=%+v", findings, notes)
		}

		// Turning off switch port isolation on the camera port MUST be detected
		// even when network-level IsolationEnabled ("Isolate Network") is true.
		snap.Devices[1].Ports[0].Isolation = false
		matOpen, findingsOpen, _ := EvaluateIsolation(snap, nil, config.NetworkConfig{})
		if matOpen.Containment[0].Peers.State != "open" {
			t.Fatalf("expected Peers=open when switch port isolation is off (despite IsolationEnabled=true), got %+v", matOpen.Containment[0].Peers)
		}
		foundWiredSameVLAN := false
		for _, f := range findingsOpen {
			if f.CheckID == "UB-UNIFI-ISO-SAME-VLAN" {
				foundWiredSameVLAN = true
				break
			}
		}
		if !foundWiredSameVLAN {
			t.Fatalf("expected UB-UNIFI-ISO-SAME-VLAN when wired camera port lacks isolation, got %+v", findingsOpen)
		}
	})
}
