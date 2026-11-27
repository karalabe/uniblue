// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestControllerPolicyParity follows a policy through site discovery, inventory,
// normalization and Evaluate for both gateway and switch enforcement.
func TestControllerPolicyParity(t *testing.T) {
	const mac = "02:00:00:00:00:01"
	for _, router := range []string{"gateway", "switch"} {
		t.Run(router, func(t *testing.T) {
			legacy := map[string]string{
				"stat/sta": "[]", "rest/portforward": "[]", "rest/firewallgroup": "[]",
				"stat/device":      `[{"_id":"oid-sw","external_id":"dev-sw","device_id":"device-local","mac":"` + mac + `","type":"usw","name":"Switch"}]`,
				"rest/networkconf": `[{"_id":"oid-iot","external_id":"net-iot","name":"IoT","purpose":"corporate","ip_subnet":"192.0.2.1/24","network_isolation_enabled":true,"gateway_type":"` + router + `","gateway_device":"device-local","firewall_zone_id":"oid-z1"},{"_id":"oid-lan","external_id":"net-lan","name":"LAN","purpose":"corporate","ip_subnet":"198.51.100.1/24","firewall_zone_id":"oid-z2"}]`,
			}
			v1 := map[string]string{
				"clients": "[]", "devices": `[{"id":"dev-sw","macAddress":"` + mac + `","model":"USW","name":"Switch"}]`,
				"networks":               `[{"id":"net-iot","name":"IoT","zoneId":"z1","management":"GATEWAY"},{"id":"net-lan","name":"LAN","zoneId":"z2","management":"GATEWAY"}]`,
				"traffic-matching-lists": "[]",
				"firewall/zones":         `[{"id":"z1","name":"IoT","networkIds":["net-iot"]},{"id":"z2","name":"Internal","networkIds":["net-lan"]}]`,
				"firewall/policies":      `[{"id":"policy","name":"Transit","index":0,"action":{"type":"ALLOW"},"enabled":true,"ipProtocolScope":{"ipVersion":"IPV4"},"source":{"zoneId":"z1"},"destination":{"zoneId":"z2"}}]`,
				"acl-rules":              `[{"id":"acl","name":"Transit ACL","enabled":true,"index":0,"type":"IPV4","action":"ALLOW","enforcingDeviceFilter":{"type":"DEVICES","deviceIds":["dev-sw"]},"sourceFilter":{"type":"NETWORKS","networkIds":["net-iot"]},"destinationFilter":{"type":"NETWORKS","networkIds":["net-lan"]}}]`,
			}
			if router == "switch" {
				v1["networks"] = strings.Replace(v1["networks"], `"management":"GATEWAY"`, `"management":"SWITCH","deviceId":"dev-sw"`, 1)
			}
			v2 := map[string]string{
				"firewall/zone":     `[{"_id":"oid-z1","external_id":"z1","name":"IoT","network_ids":["oid-iot"]},{"_id":"oid-z2","external_id":"z2","name":"Internal","network_ids":["oid-lan"]}]`,
				"firewall-policies": `[{"_id":"oid-policy","name":"Transit","enabled":true,"index":0,"predefined":false,"action":"ALLOW","ip_version":"IPV4","protocol":"all","connection_state_type":"ALL","source":{"zone_id":"oid-z1","matching_target":"ANY","port_matching_type":"ANY"},"destination":{"zone_id":"oid-z2","matching_target":"ANY","port_matching_type":"ANY"}}]`,
				"acl-rules":         `[{"_id":"oid-acl","name":"Transit ACL","enabled":true,"acl_index":0,"type":"IPV4","action":"ALLOW","ip_acl_protocol":"ALL","specific_enforcers":["` + mac + `"],"traffic_source":{"type":"NETWORK","network_ids":["oid-iot"]},"traffic_destination":{"type":"NETWORK","network_ids":["oid-lan"]}}]`,
			}
			const v1root = "/proxy/network/integration/v1/sites"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := r.URL.Path
				switch path {
				case "/api/auth/login":
					http.SetCookie(w, &http.Cookie{Name: "session", Value: "test", Path: "/"})
					w.Header().Set("X-CSRF-Token", "test")
					return
				case "/proxy/network/api/self/sites":
					fmt.Fprint(w, `{"meta":{"rc":"ok"},"data":[{"name":"lab","desc":"Lab Site","external_id":"site"}]}`)
					return
				case v1root:
					fmt.Fprint(w, `{"offset":0,"count":1,"totalCount":1,"data":[{"id":"site","name":"Lab Site","internalReference":"lab"}]}`)
					return
				}
				if data, ok := legacy[strings.TrimPrefix(path, "/proxy/network/api/s/lab/")]; ok {
					fmt.Fprintf(w, `{"data":%s,"meta":{"rc":"ok"}}`, data)
					return
				}
				if path == v1root+"/site/networks/net-iot" {
					fmt.Fprint(w, `{"id":"net-iot","mdnsForwardingEnabled":true,"dhcpGuarding":{"trustedDhcpServerIpAddresses":["192.0.2.1"]},"ipv4Configuration":{"hostIpAddress":"192.0.2.1","prefixLength":24,"dhcpConfiguration":{"dnsServerIpAddressesOverride":["192.0.2.2"]}}}`)
					return
				}
				if data, ok := v1[strings.TrimPrefix(path, v1root+"/site/")]; ok {
					if r.Header.Get("X-API-Key") == "" {
						t.Error("missing key")
					}
					var rows []json.RawMessage
					if err := json.Unmarshal([]byte(data), &rows); err != nil {
						t.Error(err)
					}
					fmt.Fprintf(w, `{"offset":0,"count":%d,"totalCount":%d,"data":%s}`, len(rows), len(rows), data)
					return
				}
				if data, ok := v2[strings.TrimPrefix(path, "/proxy/network/v2/api/site/lab/")]; ok {
					if _, e := r.Cookie("session"); e != nil || r.Header.Get("X-CSRF-Token") != "test" {
						t.Error("missing cookie or CSRF")
					}
					fmt.Fprint(w, data)
					return
				}
				http.NotFound(w, r)
			}))
			defer server.Close()
			for _, mode := range []string{"key", "session"} {
				cfg := config.UniFiConfig{URL: server.URL, Site: "Lab Site", Username: "viewer", Password: "fixture"}
				if mode == "key" {
					cfg.APIKey = "fixture"
				}
				c, err := unifi.New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				s, err := c.FetchSnapshot(context.Background())
				if err != nil {
					t.Fatal(mode, err)
				}
				if !s.Visibility.GatewayPoliciesAvailable || s.SwitchACLCoverage.Status != "complete" || len(s.FirewallPolicies) != 1 || len(s.SwitchACLs) != 1 || s.FirewallPolicies[0].Index != 0 || s.Networks[0].ZoneName != "IoT" {
					t.Fatalf("%s incomplete snapshot: %+v", mode, s.Visibility)
				}
				if mode == "key" {
					n := s.Networks[0]
					if n.MDNSReflectorEnabled == nil || !*n.MDNSReflectorEnabled || n.DHCPGuardEnabled == nil || !*n.DHCPGuardEnabled || len(n.DNSServers) != 1 || n.DNSServers[0] != "192.0.2.2" {
						t.Fatal("network detail was not retained")
					}
				}
				report := Evaluate(s, nil, config.NetworkConfig{TrustedVLANs: []string{"LAN"}, IsolatedVLANs: []string{"IoT"}})
				found := false
				for _, cell := range report.Isolation.Cells {
					if cell.SourceNetwork == "IoT" && cell.DestNetwork == "LAN" && cell.IPFamily == "ipv4" && cell.DestFunction == "trusted-lan-transit" {
						want := "Transit"
						if router == "switch" {
							want = "Transit ACL"
						}
						if cell.Verdict != IsolationViolation || cell.DecisiveRuleName != want {
							t.Fatalf("%s: unexpected verdict: %+v", mode, cell)
						}
						found = true
					}
				}
				if !found {
					t.Fatal(mode, "missing transit cell")
				}
			}
		})
	}
}

// TestACLClassAndCompoundTargets checks hardware precedence and three-valued conjunction.
func TestACLClassAndCompoundTargets(t *testing.T) {
	any := unifi.PolicyEndpoint{AnyTarget: true, AnyPort: true}
	acls := []unifi.SwitchACL{{Enabled: true, RuleType: "IPV4", Index: 0, Action: "ALLOW", Source: any, Destination: any}, {Enabled: true, RuleType: "MAC", Index: 12, Action: "BLOCK", Source: any, Destination: any}}
	if got := evaluateSwitchACLs(orderedSwitchACLs(acls), "", pathQuery{ipFamily: "ipv4"}); got.action != "deny" {
		t.Fatal(got)
	}
	ep := unifi.PolicyEndpoint{AnyPort: true, IPs: []string{"192.0.2.4"}, MACs: []string{"02:00:00:00:00:01"}, NetworkIDs: []string{"iot"}}
	for _, tc := range []struct {
		net, ip, mac string
		want         triMatch
	}{
		{"iot", "192.0.2.4", "02:00:00:00:00:01", matchYes}, {"iot", "192.0.2.5", "02:00:00:00:00:01", matchNo}, {"iot", "192.0.2.4", "", matchUnknown}, {"other", "192.0.2.4", "", matchNo},
	} {
		got, _ := matchesEndpoint(ep, "", tc.net, "", tc.ip, tc.mac, 443, "ipv4")
		if got != tc.want {
			t.Errorf("%+v: %v", tc, got)
		}
	}
	for _, p := range []unifi.FirewallPolicy{{Schedule: "CUSTOM"}, {UnsupportedReason: "IPsec"}} {
		p.Action = "ALLOW"
		p.Enabled = true
		p.MatchReturnTraffic = true
		p.Source = any
		p.Destination = any
		if d := evaluateGatewayPolicies([]unifi.FirewallPolicy{p}, pathQuery{state: "established"}); d.action != "unknown" {
			t.Fatal(d)
		}
	}

	// Conflicting ALLOW and BLOCK rules sharing the exact same Index must yield
	// unknown regardless of response order, including through public Evaluate().
	tieAllow := unifi.FirewallPolicy{ID: "a", Name: "Allow", Enabled: true, Index: 100, Action: "ALLOW", IPVersion: "ipv4", Protocol: "all", Source: any, Destination: any}
	tieBlock := unifi.FirewallPolicy{ID: "b", Name: "Block", Enabled: true, Index: 100, Action: "BLOCK", IPVersion: "ipv4", Protocol: "all", Source: any, Destination: any}
	for _, order := range [][]unifi.FirewallPolicy{{tieAllow, tieBlock}, {tieBlock, tieAllow}} {
		if d := evaluateGatewayPolicies(order, pathQuery{ipFamily: "ipv4", state: "new", proto: "tcp", port: 443}); d.action != "unknown" {
			t.Fatalf("expected ambiguous same-index tie to return unknown, got %+v", d)
		}
	}
	port8443 := unifi.PolicyEndpoint{ZoneName: "Internal", AnyTarget: true, Ports: []int{8443}}
	iotSrc := unifi.PolicyEndpoint{ZoneName: "IoT", AnyTarget: true, AnyPort: true}
	tieAllow8443 := unifi.FirewallPolicy{ID: "a8443", Name: "Allow 8443", Enabled: true, Index: 7, Action: "ALLOW", IPVersion: "ipv4", Protocol: "tcp", Source: iotSrc, Destination: port8443}
	tieBlock8443 := unifi.FirewallPolicy{ID: "b8443", Name: "Block 8443", Enabled: true, Index: 7, Action: "BLOCK", IPVersion: "ipv4", Protocol: "tcp", Source: iotSrc, Destination: port8443}
	for _, order := range [][]unifi.FirewallPolicy{{tieAllow8443, tieBlock8443}, {tieBlock8443, tieAllow8443}} {
		rep := Evaluate(&unifi.Snapshot{
			Networks: []unifi.Network{
				{ID: "n-iot", Name: "IoT", Subnet: "192.0.2.1/24", IsolationEnabled: true, ZoneName: "IoT"},
				{ID: "n-lan", Name: "LAN", Subnet: "198.51.100.1/24", ZoneName: "Internal"},
			},
			FirewallPolicies: order,
			Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true},
		}, nil, config.NetworkConfig{TrustedVLANs: []string{"LAN"}, IsolatedVLANs: []string{"IoT"}})
		found := false
		for _, cell := range rep.Isolation.Cells {
			if cell.SourceNetwork == "IoT" && cell.DestNetwork == "LAN" && cell.IPFamily == "ipv4" && cell.DestFunction == "trusted-lan-transit" {
				found = true
				if cell.Verdict != IsolationUnknown {
					t.Fatalf("expected public Evaluate boundary tie (first=%s) to return unknown, got %+v", order[0].Action, cell)
				}
			}
		}
		if !found {
			t.Fatal("missing IoT -> LAN transit cell for boundary tie test")
		}
	}

	// Firewall exposure audit must skip RESPOND_ONLY rules and unavailable feeds,
	// while still auditing partially evaluated inbound ALLOW rules as High.
	extSrc := unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true}
	gwDst := unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, AnyPort: true}
	respOnly := unifi.FirewallPolicy{ID: "r1", Name: "Allow Return", Enabled: true, Index: 1, Action: "ALLOW", Origin: "USER_DEFINED", ConnectionStates: []string{"established", "related"}, Source: extSrc, Destination: gwDst}
	if fs := auditFirewallPolicies(&unifi.Snapshot{FirewallPolicies: []unifi.FirewallPolicy{respOnly}, Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true}}); len(fs) != 0 {
		t.Fatalf("expected RESPOND_ONLY rule to emit no WAN-GW finding, got %+v", fs)
	}
	partialAllow := unifi.FirewallPolicy{ID: "r2", Name: "IPsec SSH", Enabled: true, Index: 2, Action: "ALLOW", Origin: "USER_DEFINED", UnsupportedReason: "ipsecFilter", Source: extSrc, Destination: gwDst}
	if fs := auditFirewallPolicies(&unifi.Snapshot{FirewallPolicies: []unifi.FirewallPolicy{partialAllow}, Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: false}}); len(fs) != 0 {
		t.Fatalf("expected unavailable policy feed to emit no audit finding, got %+v", fs)
	}
	if fs := auditFirewallPolicies(&unifi.Snapshot{FirewallPolicies: []unifi.FirewallPolicy{partialAllow}, Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true}}); len(fs) != 1 || fs[0].EffectiveSeverity != checks.SeverityHigh {
		t.Fatalf("expected partially evaluated WAN-GW ALLOW to remain audited at high severity, got %+v", fs)
	}

	// Port forward with unresolved source must still bump severity (at least as restricted).
	scored := scoreFinding(
		checks.Finding{BaseSeverity: checks.SeverityMedium, Port: 443, Transport: "tcp"},
		[]unifi.PortForward{{Name: "Web", Enabled: true, Proto: "tcp", DstPort: "443", FwdPort: "443", FwdIP: "192.0.2.10", SourceUnknown: true}}, nil,
	)
	if scored.EffectiveSeverity != checks.SeverityHigh {
		t.Fatalf("expected unresolved WAN forward to bump medium -> high, got %s (%v)", scored.EffectiveSeverity, scored.RiskReasons)
	}
}
