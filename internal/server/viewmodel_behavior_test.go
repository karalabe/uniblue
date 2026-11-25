// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"strings"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/topology"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestSkippedHostAndZeroScannedAt verifies that skipped hosts carry
// Skipped/SkipReason and an Excluded/Skipped label without counting in
// Census.UnassessedCount, while a non-nil zero LastScannedAt still counts as
// unassessed.
func TestSkippedHostAndZeroScannedAt(t *testing.T) {
	now := time.Now().UTC()
	zeroTime := time.Time{}
	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "LAN", VLAN: "1", Subnet: "192.0.2.1/24", Purpose: "corporate", ZoneName: "Internal"},
		},
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.0.2.1", Model: "UDM-Pro", Type: "udm"},
		},
		Clients: []unifi.Client{
			{MAC: "11:11:11:11:00:01", IP: "192.0.2.10", Name: "excluded-box", NetworkName: "LAN"},
			{MAC: "11:11:11:11:00:02", IP: "192.0.2.11", Name: "zero-ts-box", NetworkName: "LAN"},
			{MAC: "11:11:11:11:00:03", IP: "192.0.2.12", Name: "scanned-box", NetworkName: "LAN"},
		},
	}
	clientViews := []ClientView{
		{Client: snap.Clients[0], Skipped: true, SkipReason: "IP excluded by network.exclude_ips"},
		{Client: snap.Clients[1], LastScannedAt: &zeroTime},
		{Client: snap.Clients[2], LastScannedAt: &now},
	}

	pm := BuildPresentationModel(snap, risk.Report{}, nil, clientViews, nil, nil, nil)

	excl := pm.Entities["host:11:11:11:11:00:01"]
	if excl == nil || !excl.Skipped || excl.SkipReason == "" || excl.StateLabel != "Excluded" {
		t.Fatalf("expected skipped host with Excluded label, got %+v", excl)
	}
	zeroEnt := pm.Entities["host:11:11:11:11:00:02"]
	if zeroEnt == nil || zeroEnt.State != VerdictUnknown || zeroEnt.ScannedAt != nil {
		t.Fatalf("expected zero LastScannedAt host to remain VerdictUnknown, got %+v", zeroEnt)
	}
	if pm.Census.UnassessedCount != 1 {
		t.Fatalf("expected UnassessedCount=1 (only zero-ts host, not skipped host), got %d", pm.Census.UnassessedCount)
	}
}

// TestUniFiDeviceFirmwareCVEsAttached verifies that exact and potential CVEs
// matched against UniFi gateway/switch/AP firmware attach to dev:<mac>
// entities, raise exposed reasons, enter the queue, and count in ExactCVEHosts.
func TestUniFiDeviceFirmwareCVEsAttached(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Core UDM", MAC: "aa:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm", Version: "4.0.6"},
		},
	}
	exact := []cve.ProductSummary{
		{
			Product:     cve.Product{HostIP: "10.0.1.1", Label: "UniFi UDM Pro Firmware", Version: "4.0.6"},
			Confidence:  cve.ConfidenceExact,
			TotalCVEs:   2,
			KEVCount:    1,
			MaxSeverity: checks.SeverityCritical,
			MaxCVSS:     9.8,
			TopCVEs:     []string{"CVE-2026-1000"},
		},
	}
	pot := []cve.ProductSummary{
		{
			Product:     cve.Product{HostIP: "10.0.1.1", Label: "UniFi Web UI"},
			Confidence:  cve.ConfidencePotential,
			TotalCVEs:   1,
			MaxSeverity: checks.SeverityMedium,
		},
	}

	pm := BuildPresentationModel(snap, risk.Report{}, nil, nil, exact, pot, nil)
	gw := pm.Entities["dev:aa:00:00:00:00:01"]
	if gw == nil || gw.State != VerdictExposed || gw.ExactCVECount != 2 || gw.PotCVECount != 1 {
		t.Fatalf("expected gateway dev entity to be Exposed with 2 exact and 1 potential CVE, got %+v", gw)
	}
	if pm.Census.ExactCVEHosts != 1 {
		t.Fatalf("expected Census.ExactCVEHosts=1 for gateway firmware CVE, got %d", pm.Census.ExactCVEHosts)
	}
	if len(pm.Queue) == 0 || pm.Queue[0].SubjectID != gw.ID {
		t.Fatalf("expected gateway CVE in fix-next queue, got %+v", pm.Queue)
	}
	if strings.HasPrefix(pm.Headline, "All clear") {
		t.Fatalf("headline must not say All clear with gateway CVE: %q", pm.Headline)
	}
}

// TestUnauthorizedMACPortFindingResolutionAndFallback verifies that
// UB-UNIFI-PORT-UNAUTHORIZED-MAC resolves the switch port via SwitchMAC/Property
// or peer lists, attaches to both the switch port and intruding host without
// double-counting queue items or Census.ExposedCount, and falls back instead of
// silently dropping when the port entity is absent.
func TestUnauthorizedMACPortFindingResolutionAndFallback(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.1.1", Model: "UDM-Pro", Type: "udm"},
			{Name: "Office Switch", MAC: "aa:00:00:00:00:02", IP: "10.0.1.2", Model: "USW-8", Type: "usw"},
		},
		Clients: []unifi.Client{
			{MAC: "66:66:66:66:66:66", IP: "10.0.1.66", Name: "Rogue Laptop", NetworkName: "LAN", IsWired: true, SwitchMAC: "aa:00:00:00:00:02", SwitchPort: 3},
		},
	}
	clientViews := []ClientView{
		{Client: snap.Clients[0], LastScannedAt: &now},
	}
	report := risk.Report{
		SwitchPorts: []risk.SwitchDeviceView{
			{
				Name: "Office Switch",
				MAC:  "aa:00:00:00:00:02",
				Ports: []risk.SwitchPortView{
					{
						PortIdx:    3,
						Zone:       "internal",
						State:      "active",
						NativeVLAN: "LAN",
						Peers:      []risk.PortPeer{{Kind: "client", MAC: "66:66:66:66:66:66", IP: "10.0.1.66", Name: "Rogue Laptop"}},
					},
				},
			},
		},
		Findings: []checks.Finding{
			{
				CheckID:           "UB-UNIFI-PORT-UNAUTHORIZED-MAC",
				Title:             "Unauthorized Device Connected to Office Switch Port 3",
				Property:          "port:aa:00:00:00:00:02/3",
				EffectiveSeverity: checks.SeverityCritical,
				Client: unifi.Client{
					MAC:        "66:66:66:66:66:66",
					IP:         "10.0.1.66",
					Name:       "Rogue Laptop",
					SwitchMAC:  "aa:00:00:00:00:02",
					SwitchPort: 3,
				},
				Port: 3,
			},
			// Missing port entity must fall back to gateway rather than drop silently.
			{
				CheckID:           "UB-UNIFI-PORT-STP-BLOCKED",
				Title:             "Switch Port Blocked by Spanning Tree (Missing Switch Port 9)",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{MAC: "cc:cc:cc:cc:cc:cc", IP: "10.0.1.99"},
				Port:              9,
			},
		},
	}

	pm := BuildPresentationModel(snap, report, nil, clientViews, nil, nil, nil)

	portEnt := pm.Entities["port:aa:00:00:00:00:02/3"]
	if portEnt == nil || portEnt.State != VerdictExposed || portEnt.MaxSeverity != "critical" {
		t.Fatalf("expected switch port entity to be Exposed/critical, got %+v", portEnt)
	}
	hostEnt := pm.Entities["host:66:66:66:66:66:66"]
	if hostEnt == nil || hostEnt.State != VerdictExposed || hostEnt.MaxSeverity != "critical" {
		t.Fatalf("expected intruding host entity to be Exposed/critical, got %+v", hostEnt)
	}
	if len(hostEnt.Reasons) != 1 || !hostEnt.Reasons[0].Secondary {
		t.Fatalf("expected secondary reason on host when primary port owns finding, got %+v", hostEnt.Reasons)
	}
	unauthQueueItems := 0
	for _, q := range pm.Queue {
		if q.ReasonRef == "UB-UNIFI-PORT-UNAUTHORIZED-MAC" {
			unauthQueueItems++
		}
	}
	if unauthQueueItems != 1 {
		t.Fatalf("expected exactly 1 queue item for UB-UNIFI-PORT-UNAUTHORIZED-MAC, got %d: %+v", unauthQueueItems, pm.Queue)
	}
	gwEnt := pm.Entities["dev:aa:00:00:00:00:01"]
	if gwEnt == nil || gwEnt.State != VerdictExposed {
		t.Fatalf("expected unattached port finding to fall back to gateway, got %+v", gwEnt)
	}
	// Two findings total (unauthorized MAC on port + STP fallback on gateway) -> ExposedCount == 2, not 3.
	if pm.Census.ExposedCount != 2 {
		t.Fatalf("expected Census.ExposedCount=2 (no port+host double count), got %d", pm.Census.ExposedCount)
	}
}

// TestUnscannedHostWithPlacementReviewStaysUnknown verifies that an unscanned
// host with heuristic Review reasons (such as VLAN placement advice) remains
// VerdictUnknown, preserves its review reasons, and still counts in
// Census.UnassessedCount.
func TestUnscannedHostWithPlacementReviewStaysUnknown(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "LAN", VLAN: "1", Subnet: "192.0.2.1/24", Purpose: "corporate", ZoneName: "Internal"},
		},
		Clients: []unifi.Client{
			{MAC: "22:22:22:22:22:01", IP: "192.0.2.50", Name: "Porch Cam", NetworkName: "LAN"},
		},
	}
	topo := &topology.Model{
		VLANs: []topology.VLANGroup{
			{
				Name: "LAN",
				Clients: []topology.ClientNode{
					{
						Name:            "Porch Cam",
						IP:              "192.0.2.50",
						MAC:             "22:22:22:22:22:01",
						Placement:       topology.PlacementIsolate,
						PlacementReason: "camera on flat trusted LAN",
					},
				},
			},
		},
	}
	clientViews := []ClientView{
		{Client: snap.Clients[0], Class: classify.Result{Category: classify.CategoryCamera, Role: "Camera"}, LastScannedAt: nil},
	}

	pm := BuildPresentationModel(snap, risk.Report{}, topo, clientViews, nil, nil, nil)
	cam := pm.Entities["host:22:22:22:22:22:01"]
	if cam == nil || cam.State != VerdictUnknown {
		t.Fatalf("expected unscanned host with placement review to stay VerdictUnknown, got %+v", cam)
	}
	if len(cam.Reasons) != 1 || cam.Reasons[0].Ref != "VLAN-PLACEMENT" {
		t.Fatalf("expected placement review reason to be preserved, got %+v", cam.Reasons)
	}
	if pm.Census.UnassessedCount != 1 {
		t.Fatalf("expected Census.UnassessedCount=1, got %d", pm.Census.UnassessedCount)
	}
}

// TestUnassignedNetworkHostsAppearInLogicalLanes verifies that hosts with empty
// or unresolved NetworkName appear inside the Unassigned logical lane instead
// of vanishing from Devices & Wi-Fi.
func TestUnassignedNetworkHostsAppearInLogicalLanes(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "LAN", VLAN: "1", Subnet: "192.0.2.1/24", Purpose: "corporate", ZoneName: "Internal"},
		},
		Clients: []unifi.Client{
			{MAC: "33:33:33:33:33:01", IP: "192.0.2.10", Name: "lan-host", NetworkName: "LAN"},
			{MAC: "33:33:33:33:33:02", IP: "10.99.0.5", Name: "mystery-host", NetworkName: ""},
		},
	}
	classes := map[string]classify.Result{}
	topo := topology.Build(snap, classes, config.NetworkConfig{})
	clientViews := []ClientView{
		{Client: snap.Clients[0], LastScannedAt: &now},
		{Client: snap.Clients[1], LastScannedAt: &now},
	}

	pm := BuildPresentationModel(snap, risk.Report{}, topo, clientViews, nil, nil, nil)
	totalInLanes := 0
	unassignedFound := 0
	for _, lane := range pm.Logical {
		totalInLanes += lane.TotalHosts
		if strings.EqualFold(lane.Name, "Unassigned") {
			unassignedFound++
			if lane.TotalHosts != 1 {
				t.Fatalf("expected 1 host in Unassigned lane, got %+v", lane)
			}
		}
	}
	if totalInLanes != 2 || unassignedFound != 1 {
		t.Fatalf("expected 2 total hosts across lanes with 1 Unassigned lane, got total=%d unassignedLanes=%d lanes=%+v", totalInLanes, unassignedFound, pm.Logical)
	}
}

// TestHostScopedUniFiFindingsAttachToHostNotGateway verifies that host-scoped
// UB-UNIFI-* findings (rogue wired AP, public admin tunnel/proxy, dynamic NAT
// mapping) attach to the concrete host entity instead of the gateway.
func TestHostScopedUniFiFindingsAttachToHostNotGateway(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		Clients: []unifi.Client{
			{MAC: "44:44:44:44:44:77", IP: "192.168.1.77", Name: "lab-box", NetworkName: "LAN", IsWired: true},
		},
	}
	clientViews := []ClientView{
		{Client: snap.Clients[0], LastScannedAt: &now},
	}
	report := risk.Report{
		Findings: []checks.Finding{
			{
				CheckID:           "UB-UNIFI-WIFI-ROGUE-WIRED-AP",
				Title:             "Unauthorized Wireless AP Connected to Wired LAN (lab-box)",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            snap.Clients[0],
			},
			{
				CheckID:           "UB-UNIFI-TUNNEL-ADMIN-PUBLIC",
				Title:             "Outbound Tunnel Publishes Internal Admin Endpoint",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{IP: "192.168.1.77", Name: "admin.example"},
				Port:              8443,
			},
			{
				CheckID:           "UB-UNIFI-SSH-PASSWORD",
				Title:             "UniFi Device SSH Enabled with Password Authentication",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Name: "Gateway"},
			},
		},
	}

	pm := BuildPresentationModel(snap, report, nil, clientViews, nil, nil, nil)
	host := pm.Entities["host:44:44:44:44:44:77"]
	if host == nil || host.State != VerdictExposed || len(host.Reasons) != 2 {
		t.Fatalf("expected 2 host-scoped UB-UNIFI-* reasons on host, got %+v", host)
	}
	gw := pm.Entities["dev:aa:00:00:00:00:01"]
	if gw == nil || len(gw.Reasons) != 1 || gw.Reasons[0].Ref != "UB-UNIFI-SSH-PASSWORD" {
		t.Fatalf("expected only site-scoped SSH finding on gateway, got %+v", gw)
	}
}

// TestMultipleGatewayReasonsEmitSeparateQueueItems verifies that each distinct
// exposed gateway/controller reason emits its own controller queue item.
func TestMultipleGatewayReasonsEmitSeparateQueueItems(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
		},
	}
	gwClient := unifi.Client{MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Name: "Gateway"}
	report := risk.Report{
		Findings: []checks.Finding{
			{CheckID: "UB-UNIFI-WIFI-OPEN", Title: "Unencrypted Wi-Fi (Guest)", EffectiveSeverity: checks.SeverityCritical, Client: gwClient},
			{CheckID: "UB-UNIFI-SSH-PASSWORD", Title: "SSH Password Auth Enabled", EffectiveSeverity: checks.SeverityHigh, Client: gwClient},
			{CheckID: "UB-UNIFI-UPNP-ENABLED", Title: "Gateway UPnP Enabled", EffectiveSeverity: checks.SeverityHigh, Client: gwClient},
		},
	}

	pm := BuildPresentationModel(snap, report, nil, nil, nil, nil, nil)
	ctrlCount := 0
	for _, q := range pm.Queue {
		if q.Category == "controller" {
			ctrlCount++
		}
	}
	if ctrlCount != 3 {
		t.Fatalf("expected 3 controller queue items for 3 gateway findings, got %d: %+v", ctrlCount, pm.Queue)
	}
}

// TestMissingWANTelemetryEmitsUnknownCoverageFlow verifies that missing
// firewall-policy and port-forward feeds emit an Unknown coverage WANFlow and
// report the exact missing feed count in PresentationModel.Headline.
func TestMissingWANTelemetryEmitsUnknownCoverageFlow(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "USG-3P", Type: "ugw"},
		},
		Visibility: &unifi.SiteVisibility{
			GatewayPoliciesAvailable: false,
			PortForwardsAvailable:    false,
			MissingFeeds:             []string{"firewall-policies", "port-forwards"},
		},
	}

	pm := BuildPresentationModel(snap, risk.Report{}, nil, nil, nil, nil, nil)
	foundCov := false
	for _, wf := range pm.WANFlows {
		if wf.Kind == "coverage" && wf.State == VerdictUnknown {
			foundCov = true
		}
	}
	if !foundCov {
		t.Fatalf("expected Unknown coverage WANFlow when firewall/port-forward feeds are missing, got %+v", pm.WANFlows)
	}
	if pm.Headline != "Coverage incomplete: 2 WAN telemetry feeds unavailable." {
		t.Fatalf("expected exact 2 missing WAN telemetry feeds headline, got %q", pm.Headline)
	}
}

// TestWidePortRangeForwardMarksServiceWAN verifies that a port-range forward
// wider than 64 ports marks matching open TCP ports as "wan" and adds a concise
// UDP range chip when no concrete UDP service inside a wide UDP forward was observed.
func TestWidePortRangeForwardMarksServiceWAN(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "LAN", VLAN: "1", Subnet: "192.168.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
		},
		Clients: []unifi.Client{
			{MAC: "55:55:55:55:55:10", IP: "192.168.1.10", Name: "app-srv", NetworkName: "LAN"},
		},
	}
	clientViews := []ClientView{
		{Client: snap.Clients[0], OpenPorts: []int{8080}, LastScannedAt: &now},
	}
	report := risk.Report{
		WANSurface: []risk.ExposureAssessment{
			{
				Forward: unifi.PortForward{
					ID: "pf-wide", Name: "Wide Range", Enabled: true, Proto: "tcp",
					DstPort: "8000-9000", FwdIP: "192.168.1.10", FwdPort: "8000-9000", Src: "any",
				},
				Client:   snap.Clients[0],
				Severity: checks.SeverityCritical,
			},
			{
				Forward: unifi.PortForward{
					ID: "pf-udp-wide", Name: "RTP UDP Range", Enabled: true, Proto: "udp",
					DstPort: "10000-20000", FwdIP: "192.168.1.10", FwdPort: "10000-20000", Src: "any",
				},
				Client:   snap.Clients[0],
				Severity: checks.SeverityHigh,
			},
		},
	}

	pm := BuildPresentationModel(snap, report, nil, clientViews, nil, nil, nil)
	ent := pm.Entities["host:55:55:55:55:55:10"]
	if ent == nil || len(ent.Services) != 2 {
		t.Fatalf("expected TCP 8080 + wide UDP range chip (2 services), got %+v", ent)
	}
	var sawTCP, sawWideUDP bool
	for _, svc := range ent.Services {
		if svc.Port == 8080 && svc.Proto == "tcp" && svc.Reachable == "wan" {
			sawTCP = true
		}
		if svc.Proto == "udp" && svc.Reachable == "wan" && svc.Label == "UDP :10000-20000" {
			sawWideUDP = true
		}
	}
	if !sawTCP || !sawWideUDP {
		t.Fatalf("expected wan TCP :8080 and wan UDP :10000-20000 chips, got %+v", ent.Services)
	}
}

// TestFirewallPolicyWANFlowRoutingAndHostResolution verifies that
// UB-UNIFI-FW-ISO-LEAK does not appear in WANFlows, while UB-UNIFI-FW-WAN-LAN
// sets TargetIP, resolves TargetID to the concrete IPv4/IPv6 host entity, and
// does not double-count the finding across two queue items or Census.ExposedCount.
func TestFirewallPolicyWANFlowRoutingAndHostResolution(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "192.168.1.1", Model: "UDM-Pro", Type: "udm"},
		},
		Clients: []unifi.Client{
			{MAC: "55:55:55:55:55:20", IP: "192.168.1.20", IPv6: []string{"2001:db8::20"}, Name: "Dev Laptop", NetworkName: "LAN"},
		},
	}
	clientViews := []ClientView{
		{Client: snap.Clients[0], LastScannedAt: &now},
	}
	report := risk.Report{
		Findings: []checks.Finding{
			{
				CheckID:           "UB-UNIFI-FW-ISO-LEAK",
				Title:             "Broad Isolated-to-Internal Firewall Policy (Guest Leak)",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{MAC: "fw:p1", IP: "192.168.1.1", Name: "Guest Leak", NetworkName: "Hotspot -> Internal"},
			},
			{
				CheckID:           "UB-UNIFI-FW-WAN-LAN",
				Title:             "WAN-to-LAN Firewall Policy Allows Inbound Traffic (IPv6 Pinhole)",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{MAC: "fw:p2", IP: "2001:db8::20", Name: "IPv6 Pinhole", NetworkName: "External -> Internal"},
			},
		},
	}

	pm := BuildPresentationModel(snap, report, nil, clientViews, nil, nil, nil)
	if len(pm.WANFlows) != 1 {
		t.Fatalf("expected only 1 WANFlow (WAN-LAN, not ISO-LEAK), got %+v", pm.WANFlows)
	}
	wf := pm.WANFlows[0]
	if wf.TargetID != "host:55:55:55:55:55:20" || wf.TargetIP != "2001:db8::20" || wf.TargetName != "Dev Laptop" {
		t.Fatalf("expected WAN-LAN WANFlow to target Dev Laptop, got %+v", wf)
	}
	laptop := pm.Entities["host:55:55:55:55:55:20"]
	if laptop == nil || laptop.State != VerdictExposed {
		t.Fatalf("expected IPv6-pinholed host to be Exposed, got %+v", laptop)
	}
	if len(laptop.Reasons) != 1 || !laptop.Reasons[0].Secondary {
		t.Fatalf("expected secondary reason on host for WAN-LAN rule already represented in WANFlows, got %+v", laptop.Reasons)
	}
	wanQueueItems := 0
	for _, q := range pm.Queue {
		if q.ReasonRef == "UB-UNIFI-FW-WAN-LAN" {
			wanQueueItems++
		}
	}
	if wanQueueItems != 1 {
		t.Fatalf("expected exactly 1 queue item for UB-UNIFI-FW-WAN-LAN, got %d: %+v", wanQueueItems, pm.Queue)
	}
}

// TestHeadlineNotAllClearWhenUnassessedOrUnexpectedWAN verifies that
// PresentationModel.Headline never says "All clear" when hosts are unassessed
// or when an unexpected WAN port forward is present.
func TestHeadlineNotAllClearWhenUnassessedOrUnexpectedWAN(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{MAC: "77:77:77:77:77:01", IP: "192.168.1.10", Name: "rdp-box", NetworkName: "LAN"},
		},
	}

	// Case 1: unassessed host with empty queue.
	pmUnassessed := BuildPresentationModel(snap, risk.Report{}, nil, []ClientView{{Client: snap.Clients[0]}}, nil, nil, nil)
	if strings.HasPrefix(pmUnassessed.Headline, "All clear") {
		t.Fatalf("headline must not say All clear while hosts are unassessed: %q", pmUnassessed.Headline)
	}

	// Case 2: scanned clean host with critical RDP WAN forward.
	repWAN := risk.Report{
		WANSurface: []risk.ExposureAssessment{
			{
				Forward:  unifi.PortForward{ID: "pf-rdp", Name: "RDP", Enabled: true, Proto: "tcp", DstPort: "3389", FwdIP: "192.168.1.10", FwdPort: "3389", Src: "any"},
				Client:   snap.Clients[0],
				Severity: checks.SeverityCritical,
			},
		},
	}
	pmWAN := BuildPresentationModel(snap, repWAN, nil, []ClientView{{Client: snap.Clients[0], LastScannedAt: &now}}, nil, nil, nil)
	if strings.HasPrefix(pmWAN.Headline, "All clear") {
		t.Fatalf("headline must not say All clear with unexpected WAN forward: %q", pmWAN.Headline)
	}
}

// TestPlacementLookupFallsBackToMACForIPv6OnlyHost verifies that a host without
// an IPv4 address still receives its placement review via placementByMAC.
func TestPlacementLookupFallsBackToMACForIPv6OnlyHost(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{MAC: "88:88:88:88:88:01", IP: "", IPv6: []string{"2001:db8::99"}, Name: "IPv6 Cam", NetworkName: "LAN"},
		},
	}
	topo := &topology.Model{
		VLANs: []topology.VLANGroup{
			{
				Name: "LAN",
				Clients: []topology.ClientNode{
					{Name: "IPv6 Cam", IP: "", MAC: "88:88:88:88:88:01", Placement: topology.PlacementIsolate, PlacementReason: "camera on trusted LAN"},
				},
			},
		},
	}
	clientViews := []ClientView{
		{Client: snap.Clients[0], LastScannedAt: &now},
	}

	pm := BuildPresentationModel(snap, risk.Report{}, topo, clientViews, nil, nil, nil)
	cam := pm.Entities["host:88:88:88:88:88:01"]
	if cam == nil || len(cam.Reasons) != 1 || cam.Reasons[0].Ref != "VLAN-PLACEMENT" {
		t.Fatalf("expected IPv6-only host to get placement review via MAC fallback, got %+v", cam)
	}
}

// TestUnusedPortsCountedOnceWithoutDoubleCounting verifies that indoor ports
// zoned "unused" are aggregated once per switch without creating duplicate
// per-port queue items or mislabeling indoor unused ports as external even when
// the upstream risk finding title contains "External".
func TestUnusedPortsCountedOnceWithoutDoubleCounting(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Closet Switch", MAC: "aa:00:00:00:00:05", IP: "192.168.1.5", Model: "USW-8", Type: "usw"},
		},
	}
	report := risk.Report{
		SwitchPorts: []risk.SwitchDeviceView{
			{
				Name:           "Closet Switch",
				MAC:            "aa:00:00:00:00:05",
				ExternalDevice: false,
				Ports: []risk.SwitchPortView{
					{PortIdx: 5, Zone: "unused", State: "inactive_enabled", TaggedPolicy: "all"},
					{PortIdx: 6, Zone: "unused", State: "inactive_enabled", TaggedPolicy: "all"},
				},
			},
		},
		Findings: []checks.Finding{
			{
				CheckID:           "UB-UNIFI-PORT-EXT-UNUSED-OPEN",
				Title:             "Unused External Switch Ports Left Enabled (Closet Switch: 2 port(s))",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{MAC: "aa:00:00:00:00:05", IP: "192.168.1.5", Name: "Closet Switch"},
				Port:              5,
			},
		},
	}

	pm := BuildPresentationModel(snap, report, nil, nil, nil, nil, nil)
	perimItems := 0
	for _, q := range pm.Queue {
		if q.Category == "perimeter" {
			perimItems++
			if strings.Contains(strings.ToLower(q.Sentence), "external") {
				t.Fatalf("indoor unused-only switch must not say external in queue sentence: %q", q.Sentence)
			}
		}
	}
	if perimItems != 1 {
		t.Fatalf("expected exactly 1 perimeter queue item for 2 unused ports, got %d: %+v", perimItems, pm.Queue)
	}
	if pm.Census.ExposedCount != 1 {
		t.Fatalf("expected Census.ExposedCount=1 for single switch unused-ports rollup, got %d", pm.Census.ExposedCount)
	}
}

// TestQueueSentenceReportsActualCheckFindingCount verifies that when a host has
// both exact CVEs and check findings, the queue sentence reports the real
// check-finding count rather than hard-coded "0 check findings".
func TestQueueSentenceReportsActualCheckFindingCount(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{MAC: "99:99:99:99:99:01", IP: "192.168.1.30", Name: "media-box", NetworkName: "LAN"},
		},
	}
	clientViews := []ClientView{
		{Client: snap.Clients[0], OpenPorts: []int{5900, 23}, LastScannedAt: &now},
	}
	exact := []cve.ProductSummary{
		{
			Product:     cve.Product{HostIP: "192.168.1.30", Label: "OpenSSH", Version: "8.9p1"},
			Confidence:  cve.ConfidenceExact,
			TotalCVEs:   2,
			MaxSeverity: checks.SeverityCritical,
			MaxCVSS:     9.8,
			TopCVEs:     []string{"CVE-2026-2000"},
		},
	}
	report := risk.Report{
		Findings: []checks.Finding{
			{CheckID: "UB-0002", Title: "Open VNC", EffectiveSeverity: checks.SeverityHigh, Client: snap.Clients[0], Port: 5900},
			{CheckID: "UB-0009", Title: "TLS 1.0", EffectiveSeverity: checks.SeverityMedium, Client: snap.Clients[0], Port: 23},
		},
	}

	pm := BuildPresentationModel(snap, report, nil, clientViews, exact, nil, nil)
	if len(pm.Queue) != 1 || !strings.Contains(pm.Queue[0].Sentence, "2 check findings") {
		t.Fatalf("expected queue sentence to report 2 check findings, got %+v", pm.Queue)
	}
}

// TestUDPForwardServiceChipsAreDeterministicallySorted verifies that UDP
// forward service chips are appended in sorted port order across rebuilds.
func TestUDPForwardServiceChipsAreDeterministicallySorted(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.40", Name: "game-box", NetworkName: "LAN"},
		},
	}
	clientViews := []ClientView{
		{Client: snap.Clients[0], LastScannedAt: &now},
	}
	report := risk.Report{
		WANSurface: []risk.ExposureAssessment{
			{
				Forward:  unifi.PortForward{ID: "pf-udp", Name: "Game UDP", Enabled: true, Proto: "udp", DstPort: "27015-27030", FwdIP: "192.168.1.40", FwdPort: "27015-27030", Src: "any"},
				Client:   snap.Clients[0],
				Severity: checks.SeverityMedium,
			},
		},
	}

	for run := 0; run < 10; run++ {
		pm := BuildPresentationModel(snap, report, nil, clientViews, nil, nil, nil)
		ent := pm.Entities["host:aa:bb:cc:dd:ee:01"]
		if ent == nil || len(ent.Services) != 16 {
			t.Fatalf("expected 16 UDP services, got %+v", ent)
		}
		for i := 1; i < len(ent.Services); i++ {
			if ent.Services[i].Port <= ent.Services[i-1].Port {
				t.Fatalf("UDP services not sorted on run %d: %+v", run, ent.Services)
			}
		}
	}
}

// TestServiceChipKeepsHighestSeverityLabel verifies that a later lower-severity
// finding on the same port never overwrites the higher-severity service chip label.
func TestServiceChipKeepsHighestSeverityLabel(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Clients: []unifi.Client{
			{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.1.41", Name: "rack-bmc", NetworkName: "LAN"},
		},
	}
	clientViews := []ClientView{
		{Client: snap.Clients[0], OpenPorts: []int{443}, LastScannedAt: &now},
	}
	report := risk.Report{
		Findings: []checks.Finding{
			{CheckID: "UB-2026-0002", Title: "iDRAC Exposed", EffectiveSeverity: checks.SeverityCritical, Client: snap.Clients[0], Port: 443},
			{CheckID: "UB-0009", Title: "TLS 1.0/1.1", EffectiveSeverity: checks.SeverityMedium, Client: snap.Clients[0], Port: 443},
			{CheckID: "UB-0042", Title: "HTTPS Observed", ClaimKind: checks.ClaimServiceObserved, EffectiveSeverity: checks.SeverityInfo, Client: snap.Clients[0], Port: 443},
		},
	}

	pm := BuildPresentationModel(snap, report, nil, clientViews, nil, nil, nil)
	ent := pm.Entities["host:aa:bb:cc:dd:ee:02"]
	if ent == nil || len(ent.Services) != 1 {
		t.Fatalf("expected 1 service on port 443, got %+v", ent)
	}
	if ent.Services[0].Label != "iDRAC/iLO :443" || ent.Services[0].Severity != "critical" {
		t.Fatalf("expected highest-severity chip label iDRAC/iLO :443 (critical), got %+v", ent.Services[0])
	}
}

// TestNetIsolatedHonorsTopologyIsolatedVLANs verifies that corporate VLANs
// marked isolated via network.isolated_vlans or custom isolated zones in
// topology.Model label host services as "vlan-only" rather than "lan".
func TestNetIsolatedHonorsTopologyIsolatedVLANs(t *testing.T) {
	now := time.Now().UTC()
	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n-iot", Name: "IoT", VLAN: "30", Subnet: "192.168.30.1/24", Purpose: "corporate", ZoneName: "CustomIoT", IsolationEnabled: false},
		},
		Clients: []unifi.Client{
			{MAC: "aa:bb:cc:dd:ee:03", IP: "192.168.30.10", Name: "smart-plug", NetworkName: "IoT"},
		},
	}
	topo := topology.Build(snap, nil, config.NetworkConfig{IsolatedVLANs: []string{"IoT"}})
	clientViews := []ClientView{
		{Client: snap.Clients[0], OpenPorts: []int{80}, LastScannedAt: &now},
	}

	pm := BuildPresentationModel(snap, risk.Report{}, topo, clientViews, nil, nil, nil)
	ent := pm.Entities["host:aa:bb:cc:dd:ee:03"]
	if ent == nil || len(ent.Services) != 1 || ent.Services[0].Reachable != "vlan-only" {
		t.Fatalf("expected service on config-isolated IoT VLAN to be vlan-only, got %+v", ent)
	}
}

// TestDashboardHTMLInvariants verifies UI/JS invariants in index.html including
// auth sign-in flow, initial splash gating, progress-tick view transitions,
// indoor vs outdoor port separation, reason_ref matching, Devices CVE filter
// accuracy, safe hash decoding, zero inline handlers, and typography rules.
func TestDashboardHTMLInvariants(t *testing.T) {
	html := string(dashboardHTML)

	// Checking indicator must derive from state.scanning / scan_progress.initial, not unassessed > 0.
	if strings.Contains(html, "Boolean(state.scanning || unassessed > 0)") {
		t.Fatal("index.html must not derive checking from unassessed > 0")
	}
	if !strings.Contains(html, "Boolean(state.scanning || (state.scan_progress && state.scan_progress.initial))") {
		t.Fatal("index.html must derive checking from state.scanning || scan_progress.initial")
	}

	// Initial splash must only activate when scan_progress.initial is true (not on targeted rescans).
	if !strings.Contains(html, "function isInitialScanActive() {\n  if (!state || isStaticMode) return false;\n  const hasBaseline = Boolean(state.last_full_scan_at && !String(state.last_full_scan_at).startsWith(\"0001-\"));\n  if (hasBaseline) return false;\n  return Boolean(state.scan_progress && state.scan_progress.initial);\n}") {
		t.Fatal("isInitialScanActive must gate strictly on scan_progress.initial")
	}

	// Safety Features must handle absent/null settings as Unknown rather than green Off.
	if !strings.Contains(html, "const hasSettings = rawSettings != null") || !strings.Contains(html, `!hasSettings ? "Unknown"`) {
		t.Fatal("index.html must render Unknown when unifi_posture.settings is absent/null")
	}

	// DOM patching must preserve focus/details state, skip scan_progress tab rebuilds
	// while a tab view is already active, and render when exiting the initial splash.
	if !strings.Contains(html, "function patchContainerHTML(") || !strings.Contains(html, "if (progressOnly && !hadSplash && hasActiveView) return;") {
		t.Fatal("index.html must preserve focus/details state and render full view when transitioning out of splash")
	}

	// Token sign-in overlay must post to /api/auth on HTTP 401.
	for _, needle := range []string{`id="auth-overlay"`, `id="auth-form"`, `fetch("/api/auth"`, `r.status === 401`} {
		if !strings.Contains(html, needle) {
			t.Fatalf("index.html missing API token auth flow marker %q", needle)
		}
	}

	// Devices tab Security updates filter must count host entities with CVEs.
	if !strings.Contains(html, "const hostCVECount = allHosts.filter(e => e.exact_cve_count > 0).length;") ||
		!strings.Contains(html, "Security updates (${hostCVECount})") {
		t.Fatal("index.html must count host entities for Devices tab Security updates filter")
	}

	// Indoor switch port alerts must stay separate from outdoor cable alerts,
	// match reasons by reason_ref, and exclude secondary reasons from hero host counts.
	for _, needle := range []string{"Indoor Switch Port Alerts", "function matchQueueReason(", "function hasPrimaryExposedReason(", "Unused indoor switch ports are still active"} {
		if !strings.Contains(html, needle) {
			t.Fatalf("index.html missing indoor/dedupe/reason_ref marker %q", needle)
		}
	}

	// Unknown WAN coverage must not display Front door locked.
	if !strings.Contains(html, `"Coverage unknown"`) || !strings.Contains(html, "wanCoverageUnknown") {
		t.Fatal("index.html must handle unknown WAN coverage without claiming Front door locked")
	}

	// Splash must not appear when no scan runs, and last_scan_error must show Retry now banner.
	if strings.Contains(html, "|| (state.view?.census?.unassessed_count || 0) > 0") {
		t.Fatal("isInitialScanActive must not lock splash on unassessed_count when no scan runs")
	}
	if !strings.Contains(html, "state?.last_scan_error") || !strings.Contains(html, "Retry now") {
		t.Fatal("index.html must display last_scan_error with a Retry now button")
	}

	// Wi-Fi security badges must handle WEP, open, WPA1, WPA3, and disabled SSIDs.
	for _, needle := range []string{"function wifiSecurityBadge(", `"Legacy (WEP)"`, `"Legacy (WPA1)"`, "w.enabled === false", ">Disabled<"} {
		if !strings.Contains(html, needle) {
			t.Fatalf("index.html missing Wi-Fi security marker %q", needle)
		}
	}

	// fmtTime must include date for static exports or non-today timestamps.
	if !strings.Contains(html, "isStaticMode || !sameDay") || !strings.Contains(html, "toLocaleDateString") {
		t.Fatal("fmtTime must include date for static snapshots and non-today timestamps")
	}

	// Friendly reason keys must match Go CheckIDs.
	if strings.Contains(html, `"UB-UNIFI-UPNP":`) || strings.Contains(html, `"UB-UNIFI-PORT-EXT-OPEN":`) {
		t.Fatal("index.html still contains mismatched UB-UNIFI-UPNP or UB-UNIFI-PORT-EXT-OPEN keys")
	}
	if !strings.Contains(html, `"UB-UNIFI-UPNP-ENABLED":`) || !strings.Contains(html, `"UB-UNIFI-PORT-EXT-UNRESTRICTED":`) {
		t.Fatal("index.html missing UB-UNIFI-UPNP-ENABLED or UB-UNIFI-PORT-EXT-UNRESTRICTED keys")
	}

	// Filter changes must call syncHash(false) (history.replaceState).
	for _, fn := range []string{"function setPortFilter(", "function setDeviceFilter(", "function setActivityFilter("} {
		if !strings.Contains(html, fn) {
			t.Fatalf("index.html missing filter history helper %q", fn)
		}
	}

	// decodeURIComponent in hash parsing must be wrapped in try/catch.
	if !strings.Contains(html, "try {\n      ent = decodeURIComponent(") {
		t.Fatal("index.html must wrap decodeURIComponent in try/catch when parsing location.hash")
	}

	// Zero inline onclick= handlers; use delegated data-entity-id / data-action listeners.
	if strings.Contains(html, "onclick=") {
		t.Fatal("index.html must not contain inline onclick= handlers")
	}
	if !strings.Contains(html, `closest("[data-action]")`) || !strings.Contains(html, `closest("[data-entity-id]")`) {
		t.Fatal("index.html missing delegated data-action / data-entity-id click handler")
	}

	// triggerRescan must send X-UniBlue-Request, check resp.ok, and surface errors via toast.
	for _, needle := range []string{`"X-UniBlue-Request": "1"`, "if (!resp.ok)", "Rescan request failed"} {
		if !strings.Contains(html, needle) {
			t.Fatalf("triggerRescan missing %q", needle)
		}
	}

	// SSE EventSource error handler must recreate on CLOSED with backoff and track sseDisconnected.
	for _, needle := range []string{"EventSource.CLOSED", "scheduleSSEReconnect()", "sseDisconnected"} {
		if !strings.Contains(html, needle) {
			t.Fatalf("SSE reconnect handler missing %q", needle)
		}
	}

	// Typography constraint: no en-dash or em-dash characters anywhere in index.html.
	if strings.ContainsAny(html, "\u2013\u2014") {
		t.Fatal("index.html must not contain en-dash or em-dash characters")
	}
}

// TestIPv6OnlyHostReceivesAdvisoriesAndClassification verifies that an
// IPv6-only client (Client.IP == "", Client.IPv6 populated) gets its exact and
// potential CVE advisories and profile services attached in BuildPresentationModel.
func TestIPv6OnlyHostReceivesAdvisoriesAndClassification(t *testing.T) {
	now := time.Now().UTC()
	v6Client := unifi.Client{
		MAC:         "00:17:88:aa:bb:99",
		IPv6:        []string{"fd00:30::99"},
		Name:        "hue-bridge",
		NetworkName: "IoT",
	}
	snap := &unifi.Snapshot{
		Site:    "default",
		Clients: []unifi.Client{v6Client},
	}
	clientViews := []ClientView{
		{
			Client:        v6Client,
			Class:         classify.Result{Category: classify.CategoryIoT, Role: "Philips Hue Bridge", Confidence: classify.ConfidenceHigh},
			LastScannedAt: &now,
		},
	}
	exact := []cve.ProductSummary{
		{
			Product:     cve.Product{HostIP: "fd00:30::99", Label: "Nginx", Version: "1.24.0"},
			Confidence:  cve.ConfidenceExact,
			TotalCVEs:   2,
			MaxSeverity: checks.SeverityHigh,
			MaxCVSS:     8.1,
			TopCVEs:     []string{"CVE-2026-9999"},
		},
	}
	profiles := []probe.HostProfile{
		{
			Client: v6Client,
			Services: []probe.Service{
				{Port: 443, Transport: "tcp", Protocol: "https", AddressFamily: "ipv6"},
			},
		},
	}

	pm := BuildPresentationModel(snap, risk.Report{}, nil, clientViews, exact, nil, profiles)
	ent := pm.Entities["host:00:17:88:aa:bb:99"]
	if ent == nil {
		t.Fatalf("missing IPv6-only host entity in presentation model")
	}
	if ent.Subtitle != "Philips Hue Bridge" {
		t.Fatalf("expected role Philips Hue Bridge, got %q", ent.Subtitle)
	}
	if ent.ExactCVECount != 2 || len(ent.ExactCVEs) != 1 {
		t.Fatalf("expected IPv6-only host to receive 2 exact CVEs, got count=%d list=%+v", ent.ExactCVECount, ent.ExactCVEs)
	}
}
