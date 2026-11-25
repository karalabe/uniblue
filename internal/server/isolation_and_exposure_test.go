// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	builtinchecks "github.com/karalabe/uniblue/checks"
	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/topology"
	"github.com/karalabe/uniblue/internal/unifi"
)

func runFullPipelineForTest(t *testing.T, snap *unifi.Snapshot, profiles []probe.HostProfile, netCfg config.NetworkConfig, extraChecks []*checks.Check) (risk.Report, *PresentationModel) {
	t.Helper()
	list := extraChecks
	if len(list) == 0 {
		all, err := checks.LoadFromFS(builtinchecks.BuiltinFS)
		if err != nil {
			t.Fatalf("LoadFromFS: %v", err)
		}
		// Keep default fixture tests strictly offline (observe checks only) so
		// RFC1918 fixture IPs never send packets onto the test runner's LAN.
		for _, c := range all {
			if c.Probe.Type == "observe" {
				list = append(list, c)
			}
		}
	}
	runner := checks.NewRunner(list, 2)
	rawFindings := runner.RunAll(context.Background(), profiles)
	rawFindings = append(rawFindings, checks.FindingsFromProfiles(profiles, rawFindings)...)
	report := risk.Evaluate(snap, rawFindings, netCfg)

	cls, err := classify.Load(classifydata.BuiltinFS, nil)
	if err != nil {
		t.Fatalf("classify.Load: %v", err)
	}
	classes := cls.ClassifyAll(snap, profiles)
	topo := topology.Build(snap, classes, netCfg)

	profByIP := make(map[string]probe.HostProfile, len(profiles))
	for _, p := range profiles {
		profByIP[p.Client.IP] = p
	}
	now := time.Now().UTC()
	var clientViews []ClientView
	for _, cl := range snap.Clients {
		cv := ClientView{
			Client:      cl,
			Class:       classes[cl.IP],
			MaxSeverity: "clean",
		}
		if hp, ok := profByIP[cl.IP]; ok {
			cv.OpenPorts = hp.OpenPorts
			ts := now
			cv.LastScannedAt = &ts
		}
		clientViews = append(clientViews, cv)
	}
	pm := BuildPresentationModel(snap, report, topo, clientViews, nil, nil, profiles)
	return report, pm
}

// TestGuestApprovedIPPSPrintingAdminBlocked verifies that an approved guest
// IPPS printing path (TCP 631) stays out of the action queue when printer web
// administration (TCP 80/443) is blocked, and flags admin access if opened.
func TestGuestApprovedIPPSPrintingAdminBlocked(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.0.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks: []unifi.Network{
			{ID: "net-main", Name: "Trusted", VLAN: "1", Subnet: "10.0.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "10.0.50.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		Clients: []unifi.Client{
			{MAC: "11:22:33:44:55:01", IP: "10.0.1.30", Name: "Office Printer", NetworkName: "Trusted", VLAN: "1", IsWired: true},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID:          "pol-guest-ipps",
				Name:        "Allow Guest IPPS Printing",
				Enabled:     true,
				Index:       1,
				Action:      "ALLOW",
				Origin:      "USER_DEFINED",
				IPVersion:   "ipv4",
				Protocol:    "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", IPs: []string{"10.0.1.30"}, Ports: []int{631}},
			},
			{
				ID:          "pol-guest-deny",
				Name:        "Block Guest to Internal",
				Enabled:     true,
				Index:       2,
				Action:      "BLOCK",
				Origin:      "USER_DEFINED",
				IPVersion:   "ipv4",
				Protocol:    "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
			},
		},
	}

	netCfg := config.NetworkConfig{
		IsolationPolicy: config.IsolationIntent{
			GuestVLANs: []string{"Guest"},
			ApprovedPaths: []config.ApprovedPath{
				{
					Name:       "Guest IPPS Printing",
					SourceZone: "Hotspot",
					DestRole:   "printer",
					DestIP:     "10.0.1.30",
					Function:   "ipps-printing",
					Transport:  "tcp",
					Port:       631,
					IPVersion:  "ipv4",
				},
			},
		},
	}

	now := time.Now().UTC()
	profiles := []probe.HostProfile{
		{
			Client:    snap.Clients[0],
			OpenPorts: []int{631, 443},
			MDNSServices: []probe.MDNSService{
				{Type: "_ipps._tcp", Instance: "Office Printer", Port: 631, ObserverVLAN: "Guest", Reflected: true},
			},
			ScannedAt: now,
		},
	}

	report, pm := runFullPipelineForTest(t, snap, profiles, netCfg, nil)
	if report.Isolation == nil {
		t.Fatal("expected IsolationMatrix to be populated")
	}
	foundApprovedPrint := false
	foundBlockedAdmin := false
	for _, cell := range report.Isolation.Cells {
		if cell.DestFunction == "ipps-printing" && cell.Verdict == risk.IsolationApproved {
			foundApprovedPrint = true
		}
		if cell.DestFunction == "printer-admin" && cell.Port == 443 && cell.Verdict == risk.IsolationBlockedOK {
			foundBlockedAdmin = true
		}
	}
	if !foundApprovedPrint {
		t.Fatalf("expected approved ipps-printing cell, got cells=%+v", report.Isolation.Cells)
	}
	if !foundBlockedAdmin {
		t.Fatalf("expected blocked-ok printer-admin cell, got cells=%+v", report.Isolation.Cells)
	}
	if len(pm.Queue) != 0 {
		t.Fatalf("expected action queue to be completely clear for approved guest printing, got %+v", pm.Queue)
	}

	// Counterexample: if the guest rule also allows TCP 443 (printer admin), UniBlue flags it.
	snap.FirewallPolicies[0].Destination.Ports = []int{631, 443}
	reportBad, pmBad := runFullPipelineForTest(t, snap, profiles, netCfg, nil)
	if reportBad.Isolation.ViolationCount == 0 || len(pmBad.Queue) == 0 {
		t.Fatalf("expected violation and action queue item when guest can reach printer admin :443, got iso=%+v queue=%+v", reportBad.Isolation, pmBad.Queue)
	}
}

// TestBMCRedfishGuestIPv4DeniedIPv6Allowed verifies that Redfish ServiceRoot is
// recorded as service-observed inventory while an IPv6 guest-to-BMC firewall rule
// is flagged separately from blocked IPv4 access, naming the decisive rule.
func TestBMCRedfishGuestIPv4DeniedIPv6Allowed(t *testing.T) {
	// Spin up a local Redfish ServiceRoot HTTP mock to test UB-0020 end-to-end.
	redfishSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/redfish/v1") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"@odata.type":"#ServiceRoot.v1_15_0.ServiceRoot","Id":"RootService","RedfishVersion":"1.15.0"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer redfishSrv.Close()

	host, portStr, _ := net.SplitHostPort(redfishSrv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Load real UB-0020 and adapt its port strictly to the local mock server port.
	allChecks, err := checks.LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatalf("LoadFromFS: %v", err)
	}
	var redfishCheck *checks.Check
	for _, c := range allChecks {
		if c.ID == "UB-0020" {
			cp := *c
			cp.Preconditions.PortsAny = []int{port}
			cp.Probe.Scheme = "http"
			redfishCheck = &cp
			break
		}
	}
	if redfishCheck == nil {
		t.Fatal("UB-0020 not found in embedded checks")
	}

	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.0.1", Model: "UDM-Pro", Type: "udm"},
		},
		Networks: []unifi.Network{
			{ID: "net-mgmt", Name: "OOB Management", VLAN: "90", Subnet: "10.0.90.1/24", IPv6Subnet: "2001:db8:90::/64", Purpose: "corporate", ZoneName: "Management"},
			{ID: "net-guest", Name: "Guest", VLAN: "50", Subnet: "10.0.50.1/24", IPv6Subnet: "2001:db8:50::/64", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		Clients: []unifi.Client{
			{MAC: "11:22:33:44:55:02", IP: host, IPv6: []string{"2001:db8:90::10"}, Name: "Server-01 BMC", NetworkName: "OOB Management", VLAN: "90", IsWired: true},
		},
		FirewallPolicies: []unifi.FirewallPolicy{
			{
				ID:          "pol-guest-v4-deny",
				Name:        "Deny Guest IPv4 to Management",
				Enabled:     true,
				Index:       1,
				Action:      "BLOCK",
				Origin:      "USER_DEFINED",
				IPVersion:   "ipv4",
				Protocol:    "all",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Management", AnyTarget: true, AnyPort: true},
			},
			{
				ID:          "pol-guest-v6-leak",
				Name:        "Legacy IPv6 Allow BMC",
				Enabled:     true,
				Index:       2,
				Action:      "ALLOW",
				Origin:      "USER_DEFINED",
				IPVersion:   "ipv6",
				Protocol:    "tcp",
				Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
				Destination: unifi.PolicyEndpoint{ZoneName: "Management", IPs: []string{"2001:db8:90::10"}, Ports: []int{port}},
			},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}

	netCfg := config.NetworkConfig{
		IsolationPolicy: config.IsolationIntent{
			ManagementVLANs: []string{"OOB Management"},
			GuestVLANs:      []string{"Guest"},
		},
	}

	now := time.Now().UTC()
	profiles := []probe.HostProfile{
		{
			Client:    snap.Clients[0],
			OpenPorts: []int{port},
			ScannedAt: now,
		},
	}

	report, pm := runFullPipelineForTest(t, snap, profiles, netCfg, []*checks.Check{redfishCheck})

	// 1. Redfish check must match as service-observed inventory (Info).
	foundRedfish := false
	foundIPv6Finding := false
	for _, f := range report.Findings {
		if f.CheckID == "UB-0020" {
			foundRedfish = true
			if f.ClaimKind != checks.ClaimServiceObserved || f.EffectiveSeverity != checks.SeverityInfo {
				t.Fatalf("expected UB-0020 to be service-observed Info, got claim=%q sev=%v", f.ClaimKind, f.EffectiveSeverity)
			}
		}
		if f.CheckID == "UB-UNIFI-ISO-BMC-IPV6" {
			foundIPv6Finding = true
			if !strings.Contains(f.Evidence, "Legacy IPv6 Allow BMC") || !strings.Contains(f.Evidence, "2001:db8:90::10") || !strings.Contains(f.Evidence, "ipv6") {
				t.Fatalf("IPv6 BMC isolation finding must name the decisive IPv6 rule and BMC IPv6 address, got %q", f.Evidence)
			}
		}
	}
	if !foundRedfish {
		t.Fatal("expected UB-0020 to identify Redfish ServiceRoot")
	}
	if !foundIPv6Finding {
		t.Fatalf("expected UB-UNIFI-ISO-BMC-IPV6 finding, got %+v", report.Findings)
	}

	// 2. Verify IsolationMatrix separates IPv4 (blocked-ok) from IPv6 (violation naming the rule).
	v4Blocked, v6Violation := false, false
	for _, cell := range report.Isolation.Cells {
		if cell.DestFunction == "bmc-redfish-admin" && cell.IPFamily == "ipv4" && cell.Verdict == risk.IsolationBlockedOK {
			v4Blocked = true
		}
		if cell.DestFunction == "bmc-redfish-admin" && cell.IPFamily == "ipv6" && cell.Verdict == risk.IsolationViolation && cell.DecisiveRuleName == "Legacy IPv6 Allow BMC" {
			v6Violation = true
		}
	}
	if !v4Blocked || !v6Violation {
		t.Fatalf("expected IPv4 blocked-ok (%v) and IPv6 violation (%v), cells=%+v", v4Blocked, v6Violation, report.Isolation.Cells)
	}

	// 2b. Verify an IPv6 rule scoped to a different IPv6 address does not match this BMC.
	snap.FirewallPolicies[1].Destination.IPs = []string{"2001:db8:90::99"}
	repOther, pmOther := runFullPipelineForTest(t, snap, profiles, netCfg, []*checks.Check{redfishCheck})
	if repOther.Isolation.ViolationCount != 0 || len(pmOther.Queue) != 0 {
		t.Fatalf("IPv6 rule for unrelated address must not trigger BMC violation, got iso=%+v queue=%+v", repOther.Isolation, pmOther.Queue)
	}

	// 3. Counterexample: disabling the IPv6 leak leaves the isolated Redfish BMC as clean inventory with an empty queue.
	snap.FirewallPolicies[1].Enabled = false
	_, pmClean := runFullPipelineForTest(t, snap, profiles, netCfg, []*checks.Check{redfishCheck})
	if len(pmClean.Queue) != 0 {
		t.Fatalf("expected isolated Redfish BMC with IPv4+IPv6 denied to leave action queue clear, got %+v", pmClean.Queue)
	}
	bmcEnt := pmClean.Entities["host:11:22:33:44:55:02"]
	if bmcEnt == nil || !bmcEnt.IsBMC || bmcEnt.State != VerdictOK {
		t.Fatalf("expected isolated Redfish BMC entity to be IsBMC=true & VerdictOK, got %+v", bmcEnt)
	}
	_ = pm
}

// TestUDPForwardDoesNotPromoteTCPAdminOnSamePort verifies that a UDP WAN port
// forward never escalates an internal TCP service sharing the same port number.
func TestUDPForwardDoesNotPromoteTCPAdminOnSamePort(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "n1", Name: "IoT", VLAN: "20", Subnet: "10.0.20.1/24", Purpose: "guest", ZoneName: "Hotspot", IsolationEnabled: true},
		},
		Clients: []unifi.Client{
			{MAC: "11:22:33:44:55:03", IP: "10.0.20.15", Name: "game-box", NetworkName: "IoT", VLAN: "20", IsWired: true},
		},
		PortForwards: []unifi.PortForward{
			{ID: "pf-udp", Name: "UDP Game Port", Enabled: true, Proto: "udp", DstPort: "27015", FwdIP: "10.0.20.15", FwdPort: "27015", Src: "any"},
		},
	}

	rawFindings := []checks.Finding{
		{
			CheckID:      "UB-0040",
			Title:        "Internal TCP Admin Panel",
			Category:     "unauth-control",
			ClaimKind:    checks.ClaimConfirmedPermission,
			Transport:    "tcp",
			BaseSeverity: checks.SeverityMedium,
			Client:       snap.Clients[0],
			Port:         27015,
		},
	}

	report := risk.Evaluate(snap, rawFindings, config.NetworkConfig{})
	var tcpFinding *checks.Finding
	for i := range report.Findings {
		if report.Findings[i].CheckID == "UB-0040" {
			tcpFinding = &report.Findings[i]
			break
		}
	}
	if tcpFinding == nil {
		t.Fatal("expected UB-0040 finding in report")
	}
	// Because the forward is UDP-only, a TCP finding on an isolated IoT VLAN must not become WAN-Critical.
	if tcpFinding.EffectiveSeverity == checks.SeverityCritical {
		t.Fatalf("UDP game forward must NOT promote TCP admin finding on port 27015 to Critical: %+v", tcpFinding)
	}
	for _, r := range tcpFinding.RiskReasons {
		if strings.Contains(strings.ToLower(r), "wan") {
			t.Fatalf("UDP forward must not attach WAN reason to TCP service: %v", tcpFinding.RiskReasons)
		}
	}

	// Verify PresentationModel marks TCP 27015 as vlan-only (not wan) and UDP 27015 as wan.
	now := time.Now().UTC()
	cv := []ClientView{{Client: snap.Clients[0], OpenPorts: []int{27015}, LastScannedAt: &now}}
	pm := BuildPresentationModel(snap, report, nil, cv, nil, nil, []probe.HostProfile{{Client: snap.Clients[0], OpenPorts: []int{27015}, ScannedAt: now}})
	ent := pm.Entities["host:11:22:33:44:55:03"]
	if ent == nil {
		t.Fatal("expected host entity")
	}
	tcpReach, udpReach := "", ""
	for _, svc := range ent.Services {
		if svc.Port == 27015 && svc.Proto == "tcp" {
			tcpReach = svc.Reachable
		}
		if svc.Port == 27015 && svc.Proto == "udp" {
			udpReach = svc.Reachable
		}
	}
	if tcpReach == "wan" {
		t.Fatalf("TCP 27015 must NOT be marked WAN reachable from a UDP-only forward; got %+v", ent.Services)
	}
	if udpReach != "wan" {
		t.Fatalf("UDP 27015 should be marked WAN reachable; got %+v", ent.Services)
	}

	// Counterexample: changing the forward to TCP escalates TCP 27015 to Critical,
	// even when an earlier source-restricted TCP forward appears first.
	snap.PortForwards = []unifi.PortForward{
		{ID: "pf-tcp-restricted", Name: "TCP Admin Restricted", Enabled: true, Proto: "tcp", DstPort: "27015", FwdIP: "10.0.20.15", FwdPort: "27015", Src: "203.0.113.5/32"},
		{ID: "pf-tcp-open", Name: "TCP Admin Open", Enabled: true, Proto: "tcp", DstPort: "27015", FwdIP: "10.0.20.15", FwdPort: "27015", Src: "any"},
	}
	repTCP := risk.Evaluate(snap, rawFindings, config.NetworkConfig{})
	foundTCP := false
	for _, f := range repTCP.Findings {
		if f.CheckID == "UB-0040" {
			foundTCP = true
			if f.EffectiveSeverity != checks.SeverityCritical {
				t.Fatalf("later unrestricted TCP forward must escalate TCP finding to Critical even after restricted forward, got %v", f.EffectiveSeverity)
			}
		}
	}
	if !foundTCP {
		t.Fatal("expected UB-0040 in repTCP")
	}
}

// TestNVRChildCameraPrivatePoE verifies that an NVR-reported private-PoE camera
// appears as a child entity with recorder-supplied identity, direct LAN reachability
// marked unknown, and zero spurious direct-LAN exposures.
func TestNVRChildCameraPrivatePoE(t *testing.T) {
	nvrInventoryJSON := `{
		"parent_ip": "10.0.30.10",
		"parent_mac": "11:22:33:44:55:04",
		"parent_role": "nvr",
		"devices": [
			{
				"id": "poe-ch1",
				"name": "Driveway PoE Camera",
				"vendor": "Reolink",
				"model": "RLC-810A",
				"firmware": "v3.1.0.956",
				"private_address": "172.16.25.2",
				"capabilities": ["video", "rtsp"]
			}
		]
	}`

	children, err := probe.ParseBridgeInventory([]byte(nvrInventoryJSON), probe.BridgeInventorySpec{
		Format: "nvr",
	})
	if err != nil {
		t.Fatalf("ParseBridgeInventory: %v", err)
	}
	if len(children) != 1 || children[0].IdentitySource != "recorder-inventory" || children[0].DirectLANReachability != "unknown" {
		t.Fatalf("unexpected parsed NVR child camera: %+v", children)
	}

	snap := &unifi.Snapshot{
		Site: "default",
		Networks: []unifi.Network{
			{ID: "net-cam", Name: "Cameras", VLAN: "30", Subnet: "10.0.30.1/24", ZoneName: "Camera", IsolationEnabled: true},
		},
		Clients: []unifi.Client{
			{MAC: "11:22:33:44:55:04", IP: "10.0.30.10", Name: "Main NVR", NetworkName: "Cameras", VLAN: "30", IsWired: true},
		},
	}
	now := time.Now().UTC()
	profiles := []probe.HostProfile{
		{Client: snap.Clients[0], OpenPorts: []int{443}, ScannedAt: now},
	}
	probe.AttachBridgeChildren(profiles, children)

	_, pm := runFullPipelineForTest(t, snap, profiles, config.NetworkConfig{}, nil)
	nvrEnt := pm.Entities["host:11:22:33:44:55:04"]
	if nvrEnt == nil || len(nvrEnt.ChildIDs) != 1 {
		t.Fatalf("expected NVR entity to own 1 child camera, got %+v", nvrEnt)
	}
	childEnt := pm.Entities[nvrEnt.ChildIDs[0]]
	if childEnt == nil {
		t.Fatalf("child entity %q missing from PresentationModel", nvrEnt.ChildIDs[0])
	}
	if childEnt.Kind != "child" || childEnt.ParentID != nvrEnt.ID ||
		childEnt.IdentitySource != "recorder-inventory" ||
		childEnt.Model != "RLC-810A" || childEnt.Firmware != "v3.1.0.956" ||
		childEnt.DirectLANReachability != "unknown" || childEnt.State != VerdictUnknown {
		t.Fatalf("unexpected child camera entity: %+v", childEnt)
	}
	// NVR private-PoE child must not generate a false direct-LAN exposure in the action queue.
	if len(pm.Queue) != 0 {
		t.Fatalf("private PoE child camera must not claim direct LAN exposure in queue: %+v", pm.Queue)
	}
}

// TestOmittedSwitchACLYieldsUnknownIsolationVerdict verifies that L3 switch-routed
// and wired same-VLAN cells remain unknown when switch ACL telemetry is omitted,
// and resolve once complete switch ACLs are provided.
func TestOmittedSwitchACLYieldsUnknownIsolationVerdict(t *testing.T) {
	snap := &unifi.Snapshot{
		Site: "default",
		Devices: []unifi.Device{
			{Name: "Gateway", MAC: "aa:00:00:00:00:01", IP: "10.0.0.1", Model: "UDM-Pro", Type: "udm"},
			{Name: "Core L3 Switch", MAC: "aa:00:00:00:00:02", IP: "10.0.0.2", Model: "USW-Pro-24", Type: "usw"},
		},
		Networks: []unifi.Network{
			{ID: "net-trusted", Name: "Trusted", VLAN: "1", Subnet: "10.0.1.1/24", Purpose: "corporate", ZoneName: "Internal"},
			{ID: "net-iot", Name: "IoT", VLAN: "20", Subnet: "10.0.20.1/24", Purpose: "corporate", ZoneName: "Hotspot", IsolationEnabled: true, RouterDeviceMAC: "aa:00:00:00:00:02"},
		},
		Clients: []unifi.Client{
			{MAC: "11:22:33:44:55:10", IP: "10.0.20.10", Name: "sensor-a", NetworkName: "IoT", VLAN: "20", IsWired: true, SwitchMAC: "aa:00:00:00:00:02", SwitchPort: 3},
			{MAC: "11:22:33:44:55:11", IP: "10.0.20.11", Name: "sensor-b", NetworkName: "IoT", VLAN: "20", IsWired: true, SwitchMAC: "aa:00:00:00:00:02", SwitchPort: 4},
		},
		SwitchACLCoverage: &unifi.SwitchACLCoverage{
			Status: "unavailable",
			Reason: "controller API does not expose switch ACLs on this site",
		},
	}

	netCfg := config.NetworkConfig{
		IsolationPolicy: config.IsolationIntent{
			RequireSameVLANIsolation: []string{"IoT"},
		},
	}

	report := risk.Evaluate(snap, nil, netCfg)
	if report.Isolation == nil || report.Isolation.UnknownCount == 0 {
		t.Fatalf("expected unknown isolation cells when switch ACL is omitted, got %+v", report.Isolation)
	}
	foundL3Unknown := false
	foundL2Unknown := false
	for _, cell := range report.Isolation.Cells {
		if cell.PathKind == "switch-routed" && cell.Verdict == risk.IsolationUnknown && strings.Contains(cell.MissingInput, "Switch ACL unavailable") {
			foundL3Unknown = true
		}
		if cell.PathKind == "wired-same-vlan" && cell.Verdict == risk.IsolationUnknown && strings.Contains(cell.MissingInput, "Switch ACL unavailable") {
			foundL2Unknown = true
		}
	}
	if !foundL3Unknown || !foundL2Unknown {
		t.Fatalf("expected both L3 switch-routed (%v) and wired same-VLAN (%v) verdicts to be unknown with missing evidence, cells=%+v", foundL3Unknown, foundL2Unknown, report.Isolation.Cells)
	}

	// Counterexample: when the controller supplies complete switch ACLs, both the L3
	// switch-routed cell and the L2 wired-same-vlan cell remain present.
	snap.SwitchACLCoverage = &unifi.SwitchACLCoverage{Status: "complete"}
	snap.SwitchACLs = []unifi.SwitchACL{
		{
			ID:          "acl-1",
			Name:        "Block IoT to Trusted on L3 Switch",
			Enabled:     true,
			Index:       1,
			Action:      "BLOCK",
			IPVersion:   "ipv4",
			Protocol:    "all",
			DeviceMACs:  []string{"aa:00:00:00:00:02"},
			Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyTarget: true, AnyPort: true},
			Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, AnyPort: true},
		},
		{
			ID:          "acl-2",
			Name:        "Block IoT Same-VLAN L2 Peers",
			Enabled:     true,
			Index:       2,
			Action:      "BLOCK",
			IPVersion:   "ipv4",
			Protocol:    "all",
			DeviceMACs:  []string{"aa:00:00:00:00:02"},
			NetworkIDs:  []string{"net-iot"},
			Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", NetworkIDs: []string{"net-iot"}, AnyPort: true},
			Destination: unifi.PolicyEndpoint{ZoneName: "Hotspot", NetworkIDs: []string{"net-iot"}, AnyPort: true},
		},
	}
	repComplete := risk.Evaluate(snap, nil, netCfg)
	resolvedL3, resolvedL2 := false, false
	for _, cell := range repComplete.Isolation.Cells {
		if cell.PathKind == "switch-routed" && cell.Verdict == risk.IsolationBlockedOK && cell.DecisiveRuleName == "Block IoT to Trusted on L3 Switch" {
			resolvedL3 = true
		}
		if cell.PathKind == "wired-same-vlan" && cell.Verdict == risk.IsolationBlockedOK && cell.DecisiveRuleName == "Block IoT Same-VLAN L2 Peers" {
			resolvedL2 = true
		}
	}
	if !resolvedL3 || !resolvedL2 {
		t.Fatalf("expected BOTH L3 switch-routed (%v) and L2 wired-same-vlan (%v) cells to resolve to blocked-ok once switch ACLs are provided, got %+v", resolvedL3, resolvedL2, repComplete.Isolation.Cells)
	}
}
