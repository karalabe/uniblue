// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	embedded "github.com/karalabe/uniblue/checks"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

func coverageSite() (*unifi.Snapshot, config.NetworkConfig) {
	snap := &unifi.Snapshot{
		Site: "example",
		Networks: []unifi.Network{
			{ID: "g", Name: "Guest", ZoneName: "Hotspot", Purpose: "guest", IsolationEnabled: true, Subnet: "198.51.100.1/24"},
			{ID: "o", Name: "Office", ZoneName: "Internal", Purpose: "corporate", Subnet: "192.0.2.1/24"},
		},
		Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
	}
	cfg := config.NetworkConfig{TrustedVLANs: []string{"Office"}, IsolatedVLANs: []string{"Guest"}}
	return snap, cfg
}

func protocolRule(action, proto string, negated bool, index int) unifi.FirewallPolicy {
	return unifi.FirewallPolicy{
		ID: action + proto, Name: action + " " + proto, Index: index, Enabled: true, Action: action,
		Protocol: proto, ProtocolNegated: negated, IPVersion: "ipv4",
		Source:      unifi.PolicyEndpoint{ZoneName: "Hotspot", AnyPort: true, AnyTarget: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "Internal", AnyPort: true, AnyTarget: true},
	}
}

func coverageCell(t *testing.T, snap *unifi.Snapshot, cfg config.NetworkConfig, fn string) risk.IsolationCell {
	t.Helper()
	m, _, _ := risk.EvaluateIsolation(snap, nil, cfg)
	for _, cell := range m.Cells {
		if cell.SourceNetwork == "Guest" && cell.DestNetwork == "Office" && cell.DestFunction == fn && cell.IPFamily == "ipv4" {
			return cell
		}
	}
	t.Fatalf("missing %s cell", fn)
	return risk.IsolationCell{}
}

func TestProtocolCoverage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []unifi.FirewallPolicy
		want  risk.IsolationVerdict
	}{
		{"explicit ICMP", []unifi.FirewallPolicy{protocolRule("ALLOW", "icmp", false, 1)}, risk.IsolationViolation},
		{"complement of TCP and UDP", []unifi.FirewallPolicy{protocolRule("ALLOW", "tcp_udp", true, 1)}, risk.IsolationViolation},
		{"broad allow after transport-specific deny", []unifi.FirewallPolicy{protocolRule("BLOCK", "tcp_udp", false, 0), protocolRule("ALLOW", "all", false, 1)}, risk.IsolationViolation},
		{"ICMP blocked, other protocols permitted", []unifi.FirewallPolicy{protocolRule("BLOCK", "icmp", false, 0), protocolRule("ALLOW", "tcp_udp", true, 1)}, risk.IsolationViolation},
		{"earlier blanket block", []unifi.FirewallPolicy{protocolRule("BLOCK", "all", false, 0), protocolRule("ALLOW", "tcp_udp", true, 1)}, risk.IsolationBlockedOK},
		{"all concrete witnesses blocked leaving residual class", []unifi.FirewallPolicy{
			protocolRule("BLOCK", "tcp_udp", false, 0),
			protocolRule("BLOCK", "icmp", false, 1),
			protocolRule("BLOCK", "gre", false, 2),
			protocolRule("BLOCK", "esp", false, 3),
			protocolRule("BLOCK", "ah", false, 4),
			protocolRule("BLOCK", "sctp", false, 5),
			protocolRule("ALLOW", "all", false, 6),
		}, risk.IsolationUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap, cfg := coverageSite()
			snap.FirewallPolicies = tc.rules
			got := coverageCell(t, snap, cfg, "trusted-lan-transit")
			if got.Verdict != tc.want {
				t.Errorf("want %s, got %s (%s)", tc.want, got.Verdict, got.DecisiveRuleName)
			}
		})
	}
}

func TestProtocolCoverageIPv6(t *testing.T) {
	v6Rule := func(action, proto string, negated bool, index int) unifi.FirewallPolicy {
		p := protocolRule(action, proto, negated, index)
		p.IPVersion = "ipv6"
		return p
	}
	v6Cell := func(t *testing.T, rules []unifi.FirewallPolicy) risk.IsolationCell {
		t.Helper()
		snap, cfg := coverageSite()
		snap.Networks[0].IPv6Subnet = "2001:db8:100::/64"
		snap.Networks[1].IPv6Subnet = "2001:db8:200::/64"
		snap.FirewallPolicies = rules
		m, _, _ := risk.EvaluateIsolation(snap, nil, cfg)
		for _, cell := range m.Cells {
			if cell.SourceNetwork == "Guest" && cell.DestNetwork == "Office" && cell.DestFunction == "trusted-lan-transit" && cell.IPFamily == "ipv6" {
				return cell
			}
		}
		t.Fatal("missing ipv6 trusted-lan-transit cell")
		return risk.IsolationCell{}
	}

	for _, tc := range []struct {
		name          string
		rules         []unifi.FirewallPolicy
		want          risk.IsolationVerdict
		wantTransport string
	}{
		{
			name:          "deny tcp_udp then allow all catches icmpv6",
			rules:         []unifi.FirewallPolicy{v6Rule("BLOCK", "tcp_udp", false, 0), v6Rule("ALLOW", "all", false, 1)},
			want:          risk.IsolationViolation,
			wantTransport: "icmpv6",
		},
		{
			name:          "negated tcp_udp allow catches icmpv6",
			rules:         []unifi.FirewallPolicy{v6Rule("ALLOW", "tcp_udp", true, 1)},
			want:          risk.IsolationViolation,
			wantTransport: "icmpv6",
		},
		{
			name:  "earlier blanket block produces blocked-ok",
			rules: []unifi.FirewallPolicy{v6Rule("BLOCK", "all", false, 0), v6Rule("ALLOW", "tcp_udp", true, 1)},
			want:  risk.IsolationBlockedOK,
		},
		{
			name: "all concrete v6 witnesses blocked leaving residual class",
			rules: []unifi.FirewallPolicy{
				v6Rule("BLOCK", "tcp_udp", false, 0),
				v6Rule("BLOCK", "icmpv6", false, 1),
				v6Rule("BLOCK", "gre", false, 2),
				v6Rule("BLOCK", "esp", false, 3),
				v6Rule("BLOCK", "ah", false, 4),
				v6Rule("BLOCK", "sctp", false, 5),
				v6Rule("ALLOW", "all", false, 6),
			},
			want: risk.IsolationUnknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := v6Cell(t, tc.rules)
			if got.Verdict != tc.want {
				t.Fatalf("want %s, got %s (%+v)", tc.want, got.Verdict, got)
			}
			if tc.wantTransport != "" && got.Transport != tc.wantTransport {
				t.Fatalf("want transport %q, got %q (%+v)", tc.wantTransport, got.Transport, got)
			}
		})
	}
}

func TestSwitchProtocolComplement(t *testing.T) {
	snap, cfg := coverageSite()
	snap.Networks[0].RouterDeviceMAC = "00:00:5e:00:53:01"
	snap.SwitchACLCoverage = &unifi.SwitchACLCoverage{Status: "complete"}
	// Switch routing defaults to allow. These denies leave ICMP blocked but
	// permit other protocols such as GRE, even without an explicit ALLOW.
	for i, proto := range []string{"tcp_udp", "icmp"} {
		p := protocolRule("BLOCK", proto, false, i)
		snap.SwitchACLs = append(snap.SwitchACLs, unifi.SwitchACL{
			Index: i, Enabled: true, Name: p.Name, Action: p.Action, Protocol: p.Protocol,
			Source: p.Source, Destination: p.Destination, IPVersion: p.IPVersion,
		})
	}
	got := coverageCell(t, snap, cfg, "trusted-lan-transit")
	if got.Verdict != risk.IsolationViolation || got.Port != 0 || got.Transport == "icmp" {
		t.Fatalf("unexpected switch forwarding verdict: %+v", got)
	}
}

func TestMissingDestinationRole(t *testing.T) {
	// The operator approved one device role inside a larger zone.
	for _, action := range []string{"BLOCK", "ALLOW"} {
		t.Run(action, func(t *testing.T) {
			snap, cfg := coverageSite()
			snap.Clients = []unifi.Client{{Name: "office-printer", IP: "192.0.2.11", MAC: "00:00:5e:00:53:11", NetworkID: "o", NetworkName: "Office"}}
			cfg.IsolationPolicy.ApprovedPaths = []config.ApprovedPath{{SourceZone: "Hotspot", DestZone: "Internal", DestRole: "ups", Function: "ups-monitor", Transport: "tcp", Port: 3493}}
			pol := protocolRule(action, "tcp", false, 1)
			pol.Destination.AnyPort = false
			pol.Destination.Ports = []int{3493}
			snap.FirewallPolicies = []unifi.FirewallPolicy{pol}
			got := coverageCell(t, snap, cfg, "ups-monitor")
			if got.Verdict != risk.IsolationUnknown || got.DestIP != "" || !strings.Contains(got.MissingInput, "ups") || strings.Contains(got.RecommendedFix, "Allow Guest") {
				t.Errorf("unresolved UPS: %+v", got)
			}
			snap.Clients[0].Name = "rack-ups"
			want := risk.IsolationApproved
			if action == "BLOCK" {
				want = risk.IsolationBrokenDependency
			}
			if got := coverageCell(t, snap, cfg, "ups-monitor"); got.Verdict != want || got.DestIP != snap.Clients[0].IP {
				t.Errorf("known UPS: %+v, want %s", got, want)
			}
		})
	}
}

func TestFindingWANAttribution(t *testing.T) {
	all, err := checks.LoadFromFS(embedded.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	var hap *checks.Check
	for _, chk := range all {
		if chk.ID == "UB-2026-0022" {
			hap = chk
			break
		}
	}
	if hap == nil {
		t.Fatal("missing HomeKit rule")
	}
	cl := unifi.Client{Name: "dual-stack accessory", IP: "192.0.2.10", IPv6: []string{"2001:db8::10"}, MAC: "00:00:5e:00:53:10"}
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			addr := cl.IP
			if family == "ipv6" {
				addr = cl.IPv6[0]
			}
			hp := probe.HostProfile{Client: cl, MDNSServices: []probe.MDNSService{{
				Type: "_hap._tcp", TXT: []string{"sf=1"}, Port: 8080, Transport: "tcp", AddressFamily: family, TargetIPs: []string{addr}, ResponderIP: addr,
			}}}
			// Neither a paired advertisement nor an unrelated UDP service on
			// the same port contributes evidence to this TCP finding.
			hp.MDNSServices = append(hp.MDNSServices, probe.MDNSService{
				Type: "_hap._tcp", TXT: []string{"sf=0"}, Port: 8080, Transport: "tcp", TargetIPs: []string{cl.IP},
			})
			hp.Services = []probe.Service{{Protocol: "other", Transport: "udp", Port: 8080, AddressFamily: "ipv4"}}
			raw := checks.NewRunner([]*checks.Check{hap}, 1).RunHost(context.Background(), hp)
			if len(raw) != 1 {
				t.Fatalf("expected one advertisement, got %d", len(raw))
			}
			if raw[0].Transport != "tcp" || !slices.Equal(raw[0].ObservedIPs, []string{addr}) {
				t.Fatalf("observed endpoint = %s %v, want tcp %s", raw[0].Transport, raw[0].ObservedIPs, addr)
			}
			snap := &unifi.Snapshot{Clients: []unifi.Client{cl}, PortForwards: []unifi.PortForward{
				{Name: "IPv4-only web", Enabled: true, Proto: "tcp", DstPort: "8080", FwdPort: "8080", FwdIP: cl.IP},
			}}
			report := risk.Evaluate(snap, raw, config.NetworkConfig{})
			for _, f := range report.Findings {
				if f.CheckID == hap.ID {
					hasWAN := strings.Contains(strings.Join(f.RiskReasons, " "), "WAN")
					if hasWAN != (family == "ipv4") || (f.EffectiveSeverity == checks.SeverityCritical) != hasWAN {
						t.Errorf("%s advertisement: severity %s, reasons %v", family, f.EffectiveSeverity, f.RiskReasons)
					}
					return
				}
			}
			t.Fatal("missing scored finding")
		})
	}
}

func TestUnresolvedAndLegacyFindingAddresses(t *testing.T) {
	client := unifi.Client{IP: "192.0.2.1"}
	for _, tc := range []struct {
		name    string
		finding checks.Finding
		want    []string
	}{
		{"legacy single address", checks.Finding{Client: client}, []string{client.IP}},
		{"explicitly unresolved", checks.Finding{Client: client, ObservedIPs: []string{}}, nil},
		{"legacy dual stack", checks.Finding{Client: unifi.Client{IP: client.IP, IPv6: []string{"2001:db8::1"}}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.finding)
			if err != nil {
				t.Fatal(err)
			}
			var decoded checks.Finding
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if got := decoded.EndpointIPs(); !slices.Equal(got, tc.want) {
				t.Errorf("endpoint IPs after JSON round trip = %v, want %v", got, tc.want)
			}
		})
	}
}
