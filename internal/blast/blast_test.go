// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

func network(id string) unifi.Network { return unifi.Network{ID: id, Name: id, ZoneName: id} }
func client(id, ip, net string) unifi.Client {
	return unifi.Client{ID: id, Name: id, IP: ip, NetworkID: net, NetworkName: net}
}
func allow(src, dst string) unifi.FirewallPolicy {
	return unifi.FirewallPolicy{ID: src + "-" + dst, Name: "Allow " + src + " to " + dst, Enabled: true, Protocol: "all", Action: "ALLOW", IPVersion: "both", Source: unifi.PolicyEndpoint{ZoneName: src, AnyTarget: true, AnyPort: true}, Destination: unifi.PolicyEndpoint{ZoneName: dst, AnyTarget: true, AnyPort: true}}
}
func observed(in *Input, cl unifi.Client, port int, effect checks.GrantEffect) {
	id := string(effect) + "-" + cl.ID
	in.Checks = append(in.Checks, &checks.Check{ID: id, Grants: []checks.GrantSpec{{Effect: effect, Basis: checks.BasisImplied}}})
	in.Findings = append(in.Findings, checks.Finding{CheckID: id, Client: cl, Port: port, Transport: "tcp", ObservedIPs: []string{cl.IP}})
}

func exposure(t *testing.T, r Report, e Entry, asset, effect string) Exposure {
	t.Helper()
	for _, x := range r.Exposures {
		if x.Entry == e && x.Asset == asset && x.Consequence == effect {
			return x
		}
	}
	t.Fatalf("missing %s/%s/%s in %+v", e, asset, effect, r.Exposures)
	return Exposure{}
}
func action(t *testing.T, r Report, id string) Action {
	t.Helper()
	for _, a := range r.Actions {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("missing %s in %+v", id, r.Actions)
	return Action{}
}

// TestPublishedPivotAndPlatformControl follows a public backend through its controller to an offline server and VM.
func TestPublishedPivotAndPlatformControl(t *testing.T) {
	proxy := client("automation", "192.0.2.10", "apps")
	bmc := client("bmc", "198.51.100.7", "management")
	auth := false
	s := &unifi.Snapshot{Clients: []unifi.Client{proxy, bmc}, Networks: []unifi.Network{network("apps"), network("management")},
		FirewallPolicies: []unifi.FirewallPolicy{allow("apps", "management")},
		ProxyRoutes:      []unifi.ProxyRoute{{Hostname: "automation.example", BackendIP: proxy.IP, BackendPort: 1880, PublicExposed: true, FrontendAuth: &auth}}}
	in := Input{Snapshot: s, Assets: map[string]classify.AssetProfile{"automation": {Tier: classify.TierHigh}, "bmc": {Tier: classify.TierCrown, Manages: []string{"server"}}, "server": {Tier: classify.TierCrown, Hosts: []string{"guest-vm"}}, "guest-vm": {Tier: classify.TierHigh}},
		Profiles: []probe.HostProfile{{Client: bmc, OpenPorts: []int{623}, Children: []probe.ChildDevice{{ID: "console", Name: "Remote console"}}}}}
	observed(&in, proxy, 1880, checks.GrantPivot)
	observed(&in, bmc, 443, checks.GrantControl)
	r := Evaluate(in)
	for _, h := range []string{"bmc", "server", "guest-vm", "child:bmc:console"} {
		x := exposure(t, r, Internet, h, "control")
		if x.State != "exposed" || (h != "child:bmc:console" && x.Priority != P1) {
			t.Fatal(x)
		}
	}
	// Protecting the frontend leaves the listener published but qualifies downstream access.
	auth = true
	if x := exposure(t, Evaluate(in), Internet, "server", "control"); x.Difficulty != DifficultyModerate || x.Lane != LaneVerify {
		t.Fatal(x)
	}
	in.Assets["bmc"] = classify.AssetProfile{Tier: classify.TierCrown}
	if x := exposure(t, Evaluate(in), Internet, "managed:bmc", "control"); !strings.Contains(x.Name, "Unidentified server") {
		t.Fatal(x)
	}
}

// TestAssumedBreachBoundaryAndApprovedPath checks that moving through a second interface retains the original audience.
func TestAssumedBreachBoundaryAndApprovedPath(t *testing.T) {
	sensor := client("sensor", "192.0.2.5", "iot")
	bridge := client("bridge", "198.51.100.5", "devices")
	second := bridge
	second.IP = "203.0.113.5"
	second.NetworkName = "inside"
	second.NetworkID = "inside"
	nas := client("files", "192.0.2.100", "storage")
	s := &unifi.Snapshot{Networks: []unifi.Network{network("iot"), network("devices"), network("inside"), network("storage")}, Clients: []unifi.Client{sensor, bridge, second, nas},
		FirewallPolicies: []unifi.FirewallPolicy{allow("iot", "devices"), allow("inside", "storage")}}
	in := Input{Snapshot: s, Assets: map[string]classify.AssetProfile{"files": {Tier: classify.TierCrown}}, NetCfg: config.NetworkConfig{IsolationPolicy: config.IsolationIntent{ApprovedPaths: []config.ApprovedPath{{Name: "Bridge updates", SourceZone: "iot", DestIP: bridge.IP, Port: 80, Transport: "tcp"}}}}}
	observed(&in, bridge, 80, checks.GrantPivot)
	observed(&in, nas, 443, checks.GrantRead)
	r := Evaluate(in)
	x := exposure(t, r, AssumeBreach, "files", "read")
	if x.State != "exposed" || x.Lane != LaneReduceExposure {
		t.Fatal(x)
	}
	a := action(t, r, "act:vlan-egress:iot->devices")
	if a.Lane != LaneReduceExposure || !slices.Contains(a.BreaksApproved, "Bridge updates") {
		t.Fatal(a)
	}
	// Independent network positions must not be joined by device name.
	s.Clients[2].ID = "different-bridge"
	r = Evaluate(in)
	for _, x := range r.Exposures {
		if x.Entry == AssumeBreach && x.Asset == "files" && x.Consequence == "read" && x.State == "exposed" {
			t.Fatal(x)
		}
	}
}

// TestOutdoorPortMembershipAndRecorder separates native camera access from the removable trunk tags.
func TestOutdoorPortMembershipAndRecorder(t *testing.T) {
	nvr := client("Protect", "198.51.100.8", "recorders")
	s := &unifi.Snapshot{Clients: []unifi.Client{nvr}, Networks: []unifi.Network{network("cameras"), network("recorders"), network("office"), network("guests")},
		FirewallPolicies: []unifi.FirewallPolicy{allow("cameras", "recorders")},
		Devices:          []unifi.Device{{MAC: "02:00:00:00:00:10", Name: "Garden", Ports: []unifi.SwitchPort{{PortIdx: 3, Enabled: true, TaggedNetworkIDs: []string{"office"}}}}}}
	in := Input{Snapshot: s, SwitchPorts: []risk.SwitchDeviceView{{MAC: s.Devices[0].MAC, Name: "Garden", Ports: []risk.SwitchPortView{{PortIdx: 3, Zone: "external_uplink", Enabled: true, NativeVLAN: "cameras", TaggedPolicy: "custom", PortSecurity: true}}}}}
	r := Evaluate(in)
	x := exposure(t, r, Physical, "Protect", "network access")
	if x.State != "no-known-path" || x.Lane != LaneReduceExposure {
		t.Fatal(x)
	}
	a := action(t, r, "act:port-ext:"+s.Devices[0].MAC+":3")
	if !strings.Contains(a.Reason, "MAC pinning") {
		t.Fatal(a)
	}
	if a := action(t, r, "act:port-tags:"+s.Devices[0].MAC+":3"); a.HighestTierReduced != "" {
		t.Fatal("removing tags received credit for the native camera path", a)
	}
	// Only the recorded custom member may contribute traffic.
	s.FirewallPolicies = []unifi.FirewallPolicy{allow("guests", "recorders")}
	if x := exposure(t, Evaluate(in), Physical, "Protect", "network access"); x.State != "contained" {
		t.Fatal(x)
	}
}

// TestParallelFamiliesAndStableQueue checks that independent publications retain one service exposure.
func TestParallelFamiliesAndStableQueue(t *testing.T) {
	cl := client("web", "192.0.2.2", "web")
	cl.IPv6 = []string{"2001:db8::2"}
	s := &unifi.Snapshot{Clients: []unifi.Client{cl}, Networks: []unifi.Network{network("web")}, Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
		PortForwards: []unifi.PortForward{{ID: "v4", Enabled: true, Proto: "tcp", FwdIP: cl.IP, FwdPort: "8443", IPVersion: "ipv4"}, {ID: "v6", Enabled: true, Proto: "tcp", FwdIP: cl.IPv6[0], FwdPort: "8443", IPVersion: "ipv6"}}}
	in := Input{Snapshot: s}
	before, _ := json.Marshal(s)
	r := Evaluate(in)
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("evaluation changed snapshot")
	}
	both := action(t, r, "act:wan-service:web:tcp/8443")
	if both.PairsByTier != [5]int{0, 1, 0, 0, 0} || both.HighestTierReduced != P2 {
		t.Fatal(both)
	}
	for _, id := range []string{"v4", "v6"} {
		if a := action(t, r, "act:wan-pf:"+id); a.HighestTierReduced != "" {
			t.Fatal(a)
		}
	}
	slices.Reverse(s.PortForwards)
	if other := Evaluate(in); !reflect.DeepEqual(r, other) {
		t.Fatal("queue changed when forwards were reordered")
	}
	// With distinct bindings, a finding on IPv4 cannot describe its IPv6 sibling.
	in.Snapshot.PortForwards = in.Snapshot.PortForwards[:1]
	in.Assets = map[string]classify.AssetProfile{"web": {Tier: classify.TierCrown}}
	observed(&in, cl, 8443, checks.GrantControl)
	for _, x := range Evaluate(in).Exposures {
		if x.Entry == Internet && x.Consequence == "control" {
			t.Fatal(x)
		}
	}
}

// TestMissingEnforcementAndVersionEvidence keeps absent policy and ambiguous patches in the verification lane.
func TestMissingEnforcementAndVersionEvidence(t *testing.T) {
	cl := client("storage", "198.51.100.1", "storage")
	iot := client("plug", "192.0.2.2", "iot")
	s := &unifi.Snapshot{Networks: []unifi.Network{network("iot"), network("storage")}, Clients: []unifi.Client{iot, cl}, Visibility: &unifi.SiteVisibility{PortForwardsAvailable: true}}
	in := Input{Snapshot: s}
	for _, kind := range []string{"firewall", "switch", "router"} {
		switch kind {
		case "switch":
			s.Networks[0].RouterDeviceMAC = "02:00:00:00:00:10"
			s.Networks[1].RouterDeviceMAC = s.Networks[0].RouterDeviceMAC
			s.Visibility.GatewayPoliciesAvailable = true
		case "router":
			s.Networks[0].RouterUnresolved = true
		}
		r := Evaluate(in)
		if x := exposure(t, r, AssumeBreach, "storage", "network access"); x.State != "unknown" || x.Lane != LaneVerify {
			t.Fatal(kind, x)
		}
		if !slices.ContainsFunc(r.Actions, func(a Action) bool { return a.Lane == LaneVerify && strings.Contains(a.ID, kind) }) {
			t.Fatal(kind, r.Actions)
		}
	}
	s.PortForwards = []unifi.PortForward{{ID: "public", Enabled: true, FwdIP: cl.IP, FwdPort: "443", Proto: "tcp"}}
	m := cve.Match{Record: cve.Record{ID: "CVE-example", AttackVector: "N", KEV: true}, Product: cve.Product{HostIP: cl.IP, Ports: []cve.EndpointPort{{Port: 443, Transport: "tcp"}}}, Confidence: cve.ConfidenceVersionAmbiguous}
	in.CVEMatches = []cve.Match{m}
	r := Evaluate(in)
	if x := exposure(t, r, Internet, "storage", m.Record.ID); x.Lane != LaneVerify || x.Difficulty != DifficultyModerate {
		t.Fatal(x)
	}
	in.CVEMatches[0].Confidence = cve.ConfidenceExact
	if x := exposure(t, Evaluate(in), Internet, "storage", m.Record.ID); x.Difficulty != DifficultyTrivial || x.Lane != LaneFixNow {
		t.Fatal(x)
	}
}

// TestCloudPolicyAndObservation distinguishes hosts on the same VLAN with different rules or vendor traffic.
func TestCloudPolicyAndObservation(t *testing.T) {
	a := client("local", "192.0.2.1", "iot")
	b := client("possible", "192.0.2.2", "iot")
	c := client("observed", "192.0.2.3", "iot")
	block := allow("iot", "External")
	block.Action = "BLOCK"
	block.Source.AnyTarget = false
	block.Source.IPs = []string{a.IP}
	block.Index = 1
	open := allow("iot", "External")
	open.Index = 2
	s := &unifi.Snapshot{Networks: []unifi.Network{network("iot")}, Clients: []unifi.Client{a, b, c}, FirewallPolicies: []unifi.FirewallPolicy{block, open}}
	in := Input{Snapshot: s, Profiles: []probe.HostProfile{{Client: b, OutboundDependencies: []probe.OutboundDependency{{Category: "firmware-updates", Source: "device-config"}}}, {Client: c, OutboundDependencies: []probe.OutboundDependency{{Category: "vendor-control", Source: "zeek"}}}}}
	r := Evaluate(in)
	got := map[string]string{}
	for _, e := range r.Cloud {
		got[e.Asset] = e.State
	}
	if !reflect.DeepEqual(got, map[string]string{"local": localOnly, "possible": cloudCapable, "observed": cloudConnected}) {
		t.Fatal(got)
	}
	a.IPv6 = []string{"2001:db8::1"}
	s.Clients[0] = a
	if e := Evaluate(in).Cloud[0]; e.Asset != "local" || e.State != cloudCapable {
		t.Fatal("IPv6 exception lost", e)
	}
}

// TestPriorityTableAndImpactCap checks every table axis and the per-tier cap on distinct improvements.
func TestPriorityTableAndImpactCap(t *testing.T) {
	values := []classify.AssetTier{classify.TierCrown, classify.TierHigh, classify.TierMedium, classify.TierLow, classify.TierDisposable}
	audiences := []EntryAudience{AudienceInternetAny, AudienceInternetRestricted, AudiencePhysical, AudienceGuestOrUntrusted, AudienceAssumeBreach, AudienceTrustedLAN}
	for i, a := range audiences {
		for j, d := range difficulties {
			for k, v := range values {
				p := PriorityFor(a, d, v)
				if p < P1 || p > P5 || i > 0 && p < PriorityFor(audiences[i-1], d, v) || j > 0 && p < PriorityFor(a, difficulties[j-1], v) || k > 0 && p < PriorityFor(a, d, values[k-1]) {
					t.Fatalf("%s %s %s -> %s", a, d, v, p)
				}
			}
		}
	}
	highest, counts := impact([]Priority{P1, P4, P4, P4, P4, P4}, []Priority{P2, "", "", "", "", ""})
	if highest != P1 || counts != [5]int{1, 0, 0, 3, 0} {
		t.Fatal(highest, counts)
	}
}

// TestWirelessAndExternalScopes keeps the audience distinct from an IP family
// or a device label, including when no active service probe was run.
func TestWirelessAndExternalScopes(t *testing.T) {
	cl := client("recorder", "192.0.2.8", "storage")
	rule := allow("External", "storage")
	rule.Source.AnyTarget = false
	rule.Source.IPs = []string{"198.51.100.0/24"}
	rule.Destination.AnyPort = false
	rule.Destination.Ports = []int{443, 8443}
	s := &unifi.Snapshot{Networks: []unifi.Network{network("visitors"), network("storage")}, Clients: []unifi.Client{cl},
		FirewallPolicies: []unifi.FirewallPolicy{rule, allow("visitors", "storage")}, WLANs: []unifi.WLANConfig{{Name: "Lobby", NetworkID: "visitors", Security: "open", Enabled: true}},
		DynamicMappings: []unifi.DynamicPortMapping{{Protocol: "pcp", Transport: "udp", ExtPort: 5300, InternalIP: cl.IP, IntPort: 53}}}
	in := Input{Snapshot: s, Assets: map[string]classify.AssetProfile{cl.ID: {Tier: classify.TierCrown}}}
	r := Evaluate(in)
	for _, port := range []string{"443", "8443"} {
		if x := exposure(t, r, InternetSource, cl.ID, "public access to tcp/"+port); x.Priority != P1 {
			t.Fatal(x)
		}
	}
	if x := exposure(t, r, Internet, cl.ID, "public access to udp/53"); x.Priority != P1 {
		t.Fatal(x)
	}
	if x := exposure(t, r, WiFi, cl.ID, "network access"); x.State != "no-known-path" {
		t.Fatal(x)
	}
	s.Clients[0].Name = "Another label"
	s.WLANs[0].Name = "Another SSID"
	other := Evaluate(in)
	if len(other.Exposures) != len(r.Exposures) {
		t.Fatal("relabeling changed exposure count")
	}
	for i, x := range other.Exposures {
		before := r.Exposures[i]
		x.Name = before.Name
		if x != before {
			t.Fatal("relabeling changed an assessment", before, x)
		}
	}
	for i, a := range other.Actions {
		if a.ID != r.Actions[i].ID || a.PairsByTier != r.Actions[i].PairsByTier {
			t.Fatal("relabeling changed priority", a)
		}
	}
}

// TestGreedyComplementaryCuts verifies that neither unbundled parallel cut
// claims arbitrary credit on its own, while a bundle covering both earns credit.
func TestGreedyComplementaryCuts(t *testing.T) {
	g := graph{ids: map[fact]int{}, actionIDs: map[string]int{}, assets: map[string]asset{"device": {name: "device", profile: classify.AssetProfile{Tier: classify.TierCrown}}}, actions: []candidate{{}}}
	for i, s := range starts {
		g.roots[i] = g.node(root(s.entry))
	}
	for _, id := range []string{"b", "a"} {
		cut := g.action(id, id, "", LaneFixNow, 1)
		g.link(root(Internet), fact{consequence, "device", "control"}, trivial, cut, 0)
	}
	got := g.rank(g.solve(nil))
	if len(got) != 2 || got[0].HighestTierReduced != "" || got[1].HighestTierReduced != "" {
		t.Fatalf("parallel cuts must not claim fake standalone credit: %+v", got)
	}
	bundle := g.action("both", "both", "", LaneFixNow, 2)
	for i := range g.edges[g.roots[0]] {
		g.edges[g.roots[0]][i].bundle = bundle
	}
	got = g.rank(g.solve(nil))
	if got[0].ID != "both" || got[0].HighestTierReduced != P1 || got[0].PairsByTier[0] != 1 {
		t.Fatalf("bundle covering both routes should win with P1: %+v", got)
	}
}

// TestAutoPortForwardAndScopedPolicyPorts verifies that UniFi's auto-generated
// "Allow Port Forward" policy does not steal credit from closing the forward,
// and that ports from an External rule for one zone do not bleed onto other hosts.
func TestAutoPortForwardAndScopedPolicyPorts(t *testing.T) {
	web := client("web", "192.0.2.10", "servers")
	gw := unifi.Device{ID: "gw", Name: "Gateway", MAC: "02:00:00:00:00:01", IP: "192.0.2.1", Type: "udm"}
	autoPF := unifi.FirewallPolicy{
		ID: "sys-pf", Name: "Allow Port Forward Web", Origin: "SYSTEM_DEFINED", Enabled: true, Action: "ALLOW",
		Protocol: "tcp", IPVersion: "ipv4",
		Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "servers", IPs: []string{web.IP}, Ports: []int{8443}},
	}
	gwAny := unifi.FirewallPolicy{
		ID: "gw-any", Name: "Allow Gateway", Origin: "USER_DEFINED", Enabled: true, Action: "ALLOW",
		Protocol: "all", IPVersion: "ipv4",
		Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, AnyPort: true},
	}
	otherPort := unifi.FirewallPolicy{
		ID: "wg", Name: "Allow WG", Origin: "USER_DEFINED", Enabled: true, Action: "ALLOW",
		Protocol: "udp", IPVersion: "ipv4",
		Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "servers", IPs: []string{web.IP}, Ports: []int{51820}},
	}
	s := &unifi.Snapshot{
		Networks:         []unifi.Network{network("servers")},
		Clients:          []unifi.Client{web},
		Devices:          []unifi.Device{gw},
		FirewallPolicies: []unifi.FirewallPolicy{autoPF, gwAny, otherPort},
		PortForwards:     []unifi.PortForward{{ID: "pf-web", Name: "Web", Enabled: true, Proto: "tcp", FwdIP: web.IP, FwdPort: "8443", IPVersion: "ipv4"}},
		Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
	}
	r := Evaluate(Input{Snapshot: s, Assets: map[string]classify.AssetProfile{"web": {Tier: classify.TierCrown}, "02:00:00:00:00:01": {Tier: classify.TierCrown}}})
	pf := action(t, r, "act:wan-pf:pf-web")
	if pf.HighestTierReduced != P1 {
		t.Fatalf("closing single port forward should earn P1 without auto-policy double counting: %+v", pf)
	}
	for _, x := range r.Exposures {
		if x.Asset == "02:00:00:00:00:01" && strings.Contains(x.Consequence, "51820") {
			t.Fatalf("unrelated policy port bled onto gateway: %+v", x)
		}
	}
}

// TestUnknownRouteBlocksCreditAndMissingEvidenceNeverContains verifies that:
// 1) closing IPv4 earns zero credit while IPv6 remains unknown;
// 2) UPnP without leases, unknown outdoor native VLAN, and duplicate IPs never claim "contained".
func TestUnknownRouteBlocksCreditAndMissingEvidenceNeverContains(t *testing.T) {
	// 1. Dual-stack NAS: IPv4 port forward + IPv6 unknown selector.
	nas := client("nas", "192.0.2.20", "storage")
	nas.IPv6 = []string{"2001:db8::20"}
	v6Unknown := unifi.FirewallPolicy{
		ID: "v6-unk", Name: "V6 Custom", Enabled: true, Action: "ALLOW", Protocol: "tcp", IPVersion: "ipv6",
		Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true, UnsupportedSelector: "region"},
		Destination: unifi.PolicyEndpoint{ZoneName: "storage", AnyTarget: true, Ports: []int{443}},
	}
	s := &unifi.Snapshot{
		Networks:         []unifi.Network{network("storage")},
		Clients:          []unifi.Client{nas},
		FirewallPolicies: []unifi.FirewallPolicy{v6Unknown},
		PortForwards:     []unifi.PortForward{{ID: "pf-v4", Name: "NAS v4", Enabled: true, Proto: "tcp", FwdIP: nas.IP, FwdPort: "443", IPVersion: "ipv4"}},
		Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
	}
	in := Input{Snapshot: s, Assets: map[string]classify.AssetProfile{"nas": {Tier: classify.TierCrown}}}
	observed(&in, nas, 443, checks.GrantControl)
	in.Findings[0].ObservedIPs = []string{nas.IP, nas.IPv6[0]}
	r := Evaluate(in)
	if pf := action(t, r, "act:wan-pf:pf-v4"); pf.HighestTierReduced != "" {
		t.Fatalf("IPv4 cut must not earn credit while IPv6 is unknown: %+v", pf)
	}

	// 2. UPnP enabled without lease data must not claim "contained".
	sUPnP := &unifi.Snapshot{
		Networks:         []unifi.Network{network("storage")},
		Clients:          []unifi.Client{client("nas", "192.0.2.20", "storage")},
		SecuritySettings: &unifi.SiteSecuritySettings{UPnPEnabled: true},
		Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
	}
	rUPnP := Evaluate(Input{Snapshot: sUPnP, Profiles: []probe.HostProfile{{Client: sUPnP.Clients[0], OpenPorts: []int{443}}}})
	if x := exposure(t, rUPnP, Internet, "nas", "network access"); x.State != "unknown" {
		t.Fatalf("UPnP without leases should yield unknown, got %+v", x)
	}

	// 3. Outdoor port with unknown native VLAN must not claim "contained" from Physical.
	sPhys := &unifi.Snapshot{
		Networks: []unifi.Network{network("storage")},
		Clients:  []unifi.Client{client("nas", "192.0.2.20", "storage")},
		Devices:  []unifi.Device{{MAC: "02:00:00:00:00:10", Name: "Switch", Ports: []unifi.SwitchPort{{PortIdx: 1, Enabled: true}}}},
	}
	rPhys := Evaluate(Input{
		Snapshot:    sPhys,
		SwitchPorts: []risk.SwitchDeviceView{{MAC: "02:00:00:00:00:10", Name: "Switch", Ports: []risk.SwitchPortView{{PortIdx: 1, Zone: "external", Enabled: true}}}},
	})
	if x := exposure(t, rPhys, Physical, "nas", "network access"); x.State != "unknown" {
		t.Fatalf("unknown outdoor native VLAN should yield unknown, got %+v", x)
	}

	// 4. Duplicate IP across two inventory clients must yield unknown + Verify, never "contained".
	dupA := client("host-a", "192.0.2.50", "storage")
	dupB := client("host-b", "192.0.2.50", "storage")
	sDup := &unifi.Snapshot{
		Networks:     []unifi.Network{network("storage")},
		Clients:      []unifi.Client{dupA, dupB},
		PortForwards: []unifi.PortForward{{ID: "pf-dup", Name: "Dup", Enabled: true, Proto: "tcp", FwdIP: "192.0.2.50", FwdPort: "443"}},
		Visibility:   &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
	}
	rDup := Evaluate(Input{Snapshot: sDup, Profiles: []probe.HostProfile{{Client: dupA, OpenPorts: []int{443}}}})
	if x := exposure(t, rDup, Internet, "host-a", "network access"); x.State != "unknown" {
		t.Fatalf("duplicate IP target should yield unknown, got %+v", x)
	}
}

// TestMultiVLANIngressBundle verifies that two open untrusted VLANs targeting
// the same destination VLAN produce an honest combined ingress bundle while
// neither individual egress cut claims fake standalone credit.
func TestMultiVLANIngressBundle(t *testing.T) {
	iot := client("plug", "192.0.2.5", "iot")
	cam := client("cam", "192.0.2.6", "cameras")
	srv := client("srv", "198.51.100.10", "servers")
	s := &unifi.Snapshot{
		Networks:         []unifi.Network{network("iot"), network("cameras"), network("servers")},
		Clients:          []unifi.Client{iot, cam, srv},
		FirewallPolicies: []unifi.FirewallPolicy{allow("iot", "servers"), allow("cameras", "servers")},
	}
	in := Input{
		Snapshot: s,
		NetCfg:   config.NetworkConfig{IsolationPolicy: config.IsolationIntent{IoTVLANs: []string{"iot"}, CameraVLANs: []string{"cameras"}}},
		Assets:   map[string]classify.AssetProfile{"srv": {Tier: classify.TierCrown}},
	}
	r := Evaluate(in)
	bundle := action(t, r, "act:vlan-ingress:servers")
	if bundle.HighestTierReduced != P3 || !strings.Contains(bundle.Title, "cameras") || !strings.Contains(bundle.Title, "iot") {
		t.Fatalf("combined ingress bundle should win P3 and name source networks: %+v", bundle)
	}
	for _, id := range []string{"act:vlan-egress:iot->servers", "act:vlan-egress:cameras->servers"} {
		if a := action(t, r, id); a.HighestTierReduced != "" {
			t.Fatalf("single-VLAN cut %s should not claim credit while other VLAN stays open: %+v", id, a)
		}
	}
}

// TestShadowedWANRuleAndCacheDeterminism verifies that:
// 1) a later WAN allow rule shadowing behind an earlier allow denies standalone credit to the first rule;
// 2) MAC-filtered cross-VLAN rules stay deterministic when another client lacks a MAC;
// 3) negated destination selectors keep eligible hosts; and local-only ambiguous CVEs stay excluded.
func TestShadowedWANRuleAndCacheDeterminism(t *testing.T) {
	// 1. Two overlapping WAN allow rules on udp/51820: closing only the first earns 0 credit.
	gw := unifi.Device{ID: "gw", Name: "Gateway", MAC: "02:00:00:00:00:01", IP: "192.0.2.1", Type: "udm"}
	first := unifi.FirewallPolicy{
		ID: "r1", Name: "First Allow", Origin: "USER_DEFINED", Enabled: true, Action: "ALLOW", Index: 100,
		Protocol: "udp", IPVersion: "ipv4",
		Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, Ports: []int{51820}},
	}
	second := unifi.FirewallPolicy{
		ID: "r2", Name: "Allow WG", Origin: "USER_DEFINED", Enabled: true, Action: "ALLOW", Index: 200,
		Protocol: "udp", IPVersion: "ipv4",
		Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, Ports: []int{51820}},
	}
	s := &unifi.Snapshot{
		Devices:          []unifi.Device{gw},
		FirewallPolicies: []unifi.FirewallPolicy{first, second},
		Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
	}
	r := Evaluate(Input{Snapshot: s, Assets: map[string]classify.AssetProfile{"02:00:00:00:00:01": {Tier: classify.TierCrown}}})
	if a := action(t, r, "act:gateway-local:r1"); a.HighestTierReduced != "" {
		t.Fatalf("shadowing rule r1 must not earn credit while r2 stays open: %+v", a)
	}
	if b := action(t, r, "act:wan-service:02:00:00:00:00:01:udp/51820"); b.HighestTierReduced != P1 {
		t.Fatalf("combined WAN service bundle should earn P1: %+v", b)
	}

	// 2. MAC-filtered rule with both a MAC-only guest client and an open SSID must never flip to contained.
	guestMAC := unifi.Client{ID: "gmac", Name: "GuestPhone", MAC: "02:00:00:00:00:99", NetworkID: "guest", NetworkName: "guest"}
	srv := client("srv", "198.51.100.10", "servers")
	allowMAC := unifi.FirewallPolicy{
		ID: "allow-mac", Name: "Allow Guest MAC", Enabled: true, Action: "ALLOW", Index: 10, Protocol: "all", IPVersion: "both",
		Source:      unifi.PolicyEndpoint{ZoneName: "guest", MACs: []string{"02:00:00:00:00:aa"}, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "servers", AnyTarget: true, AnyPort: true},
	}
	blockRest := allow("guest", "servers")
	blockRest.Action = "BLOCK"
	blockRest.Index = 20
	sMAC := &unifi.Snapshot{
		Networks:         []unifi.Network{network("guest"), network("servers")},
		Clients:          []unifi.Client{guestMAC, srv},
		WLANs:            []unifi.WLANConfig{{Name: "OpenGuest", NetworkID: "guest", Security: "open", Enabled: true}},
		FirewallPolicies: []unifi.FirewallPolicy{allowMAC, blockRest},
	}
	for range 5 {
		if x := exposure(t, Evaluate(Input{Snapshot: sMAC}), WiFi, "srv", "network access"); x.State == "contained" {
			t.Fatalf("open WiFi entrant must not reuse known-MAC client deny: %+v", x)
		}
	}

	// 3. Negated destination selector keeps eligible host, and local-only ambiguous CVE is ignored.
	eligible := client("eligible", "192.0.2.30", "servers")
	neg := unifi.FirewallPolicy{
		ID: "neg", Name: "Allow Except One", Enabled: true, Action: "ALLOW", Protocol: "tcp", IPVersion: "ipv4",
		Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "servers", IPs: []string{"192.0.2.99"}, NegateTarget: true, Ports: []int{8443}},
	}
	sNeg := &unifi.Snapshot{
		Networks:         []unifi.Network{network("servers")},
		Clients:          []unifi.Client{eligible},
		FirewallPolicies: []unifi.FirewallPolicy{neg},
		Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
	}
	inNeg := Input{
		Snapshot: sNeg,
		CVEMatches: []cve.Match{{
			Record:     cve.Record{ID: "CVE-2026-LOCAL", AttackVector: "L", Severity: checks.SeverityCritical},
			Product:    cve.Product{HostIP: eligible.IP, Ports: []cve.EndpointPort{{Port: 8443, Transport: "tcp"}}},
			Confidence: cve.ConfidenceVersionAmbiguous,
		}},
	}
	rNeg := Evaluate(inNeg)
	if x := exposure(t, rNeg, Internet, "eligible", "public access to tcp/8443"); x.State != "exposed" {
		t.Fatalf("negated selector should expose eligible host: %+v", x)
	}
	for _, x := range rNeg.Exposures {
		if x.Consequence == "CVE-2026-LOCAL" {
			t.Fatalf("local-only ambiguous CVE leaked into blast report: %+v", x)
		}
	}

	// 4. Dual-family gateway rule on an IPv4-only gateway with site IPv6 context merges into one action.
	gwV4 := unifi.Device{ID: "gw", Name: "Gateway", MAC: "02:00:00:00:00:01", IP: "192.0.2.1", Type: "udm"}
	wgBoth := unifi.FirewallPolicy{
		ID: "wg-both", Name: "Allow WG", Origin: "USER_DEFINED", Enabled: true, Action: "ALLOW",
		Protocol: "udp", IPVersion: "both",
		Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "Gateway", AnyTarget: true, Ports: []int{51820}},
	}
	v6Context := unifi.FirewallPolicy{
		ID: "v6-ctx", Name: "Block V6", Enabled: true, Action: "BLOCK", Protocol: "all", IPVersion: "ipv6",
		Source:      unifi.PolicyEndpoint{ZoneName: "External", AnyTarget: true, AnyPort: true},
		Destination: unifi.PolicyEndpoint{ZoneName: "servers", AnyTarget: true, AnyPort: true},
	}
	rGW := Evaluate(Input{
		Snapshot: &unifi.Snapshot{
			Devices:          []unifi.Device{gwV4},
			FirewallPolicies: []unifi.FirewallPolicy{wgBoth, v6Context},
			Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true},
		},
		Assets: map[string]classify.AssetProfile{"02:00:00:00:00:01": {Tier: classify.TierCrown}},
	})
	matches := 0
	for _, a := range rGW.Actions {
		if strings.HasSuffix(a.ID, ":wg-both") {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("expected single merged action for wg-both, got %d in %+v", matches, rGW.Actions)
	}
}

// TestInfraCompromiseScopes separates the uplink, the subtree and the controller host.
func TestInfraCompromiseScopes(t *testing.T) {
	const gw, sw, ap = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"
	phone := client("phone", "192.0.2.3", "iot")
	phone.APMAC, phone.ESSID = ap, "wifi"
	desk := client("desk", "198.51.100.2", "private")
	desk.IsWired, desk.SwitchMAC, desk.SwitchPort = true, gw, 2
	parentPort := unifi.SwitchPort{PortIdx: 1, Enabled: true, NativeNetworkID: "lan", TaggedVLANMgmt: "custom", ExcludedNetworkIDs: []string{"private"}}
	s := &unifi.Snapshot{Devices: []unifi.Device{
		{MAC: gw, Type: "udm", Name: "Console", Ports: []unifi.SwitchPort{parentPort}},
		{MAC: sw, Type: "usw", Name: "Core", UplinkMAC: gw, UplinkPort: 1, Ports: []unifi.SwitchPort{parentPort}},
		{MAC: ap, Type: "uap", Name: "Office AP", UplinkMAC: sw, UplinkPort: 1},
	}, Clients: []unifi.Client{phone, desk}, Networks: []unifi.Network{network("iot"), network("lan"), network("private")},
		WLANs: []unifi.WLANConfig{{Enabled: true, Name: "wifi", NetworkID: "iot", Security: "wpapsk", WPAMode: "wpa3", L2Isolation: true}}}
	s.Networks[0].RouterDeviceMAC = sw
	in := Input{Snapshot: s, Profiles: []probe.HostProfile{{Client: phone, Services: []probe.Service{{Protocol: "ssh", Port: 22}}}, {Client: desk, OpenPorts: []int{80}}}}
	run := func(target string) InfraReport {
		t.Helper()
		r, err := EvaluateInfraCompromise(in, target)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := run("Office AP")
	if r.UplinkUnknown || !slices.Equal(r.UplinkVLANs, []string{"iot", "lan"}) || !slices.Equal(r.Clients, []string{"phone"}) ||
		len(r.Legs) != 1 || r.Legs[0].Reachability != "allow" || r.Legs[0].Confidentiality != conditional || !strings.Contains(r.Legs[0].Wireless, "WPA3-SAE") {
		t.Fatal(r)
	}
	s.Devices[1].Ports[0].TaggedVLANUnknown = true
	r = run(ap)
	if !r.UplinkUnknown || !slices.Equal(r.UplinkVLANs, []string{"lan"}) {
		t.Fatal(r)
	}
	r = run(sw)
	if !slices.Equal(r.Downstream, []string{"Office AP"}) || !slices.Equal(r.RoutedVLANs, []string{"iot"}) || !slices.Equal(r.Ports, []int{1}) || !slices.Equal(r.Clients, []string{"phone"}) {
		t.Fatal(r)
	}
	any := unifi.PolicyEndpoint{AnyTarget: true, AnyPort: true}
	s.SwitchACLs = []unifi.SwitchACL{{Enabled: true, Action: "BLOCK", DeviceMACs: []string{sw}, Source: any, Destination: any}}
	s.Health = &unifi.SystemHealth{VPNConnections: []unifi.VPNConnection{{Name: "Remote access", Type: "wireguard"}}}
	// Integrated console hosts the controller, so losing it owns all managed switches/APs too.
	r = run(gw)
	if r.HostedOn != "Console" || len(r.Manages) != 2 || !slices.Equal(r.RoutedVLANs, []string{"iot", "lan", "private"}) {
		t.Fatal(r)
	}
	if !slices.ContainsFunc(r.Legs, func(l TransportSurvival) bool { return l.To == "phone" && l.Reachability == "allow" }) ||
		!slices.ContainsFunc(r.Legs, func(l TransportSurvival) bool {
			return l.Protocol == "wireguard" && l.Confidentiality == exposed && l.Integrity == exposed
		}) {
		t.Fatalf("console reachability or VPN termination lost: %+v", r.Legs)
	}
	r = run("controller")
	if r.HostedOn != "Console" || !slices.Equal(r.Manages, []string{"Console", "Core", "Office AP"}) || !slices.Contains(r.Clients, "desk") {
		t.Fatal(r)
	}
	// Separate UXG gateway (not hosting controller): intact switch ACL still blocks phone!
	s.Devices[0].Type = "uxg"
	s.Devices = append(s.Devices, unifi.Device{Type: "uck", Name: "Cloud Key", MAC: "02:00:00:00:00:04"})
	if r = run(gw); r.HostedOn != "" || len(r.Manages) != 0 || !slices.Equal(r.RoutedVLANs, []string{"lan", "private"}) {
		t.Fatal(r)
	}
	if !slices.ContainsFunc(r.Legs, func(l TransportSurvival) bool { return l.To == "phone" && l.Reachability == "deny" }) {
		t.Fatalf("standalone gateway compromise should still respect intact L3 switch ACL: %+v", r.Legs)
	}
	if r = run("Cloud Key"); r.HostedOn != "Cloud Key" || len(r.Manages) != 3 || !slices.Contains(r.Manages, "Console") {
		t.Fatal(r)
	}
}

// TestTransportDisclosure verifies the actual serialized verdict for every protected class.
func TestTransportDisclosure(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		banner   probe.HTTPBanner
		class    string
		verdict  TransportVerdict
	}{
		{"ssh", probe.HTTPBanner{}, "e2e", conditional},
		{"wireguard", probe.HTTPBanner{}, "e2e", resilient},
		{"matter", probe.HTTPBanner{}, "e2e", resilient},
		{"hap", probe.HTTPBanner{}, "e2e", resilient},
		{"esphome-noise", probe.HTTPBanner{}, "e2e", resilient},
		{"https", probe.HTTPBanner{TLSVerified: true}, "tls-ca", resilient},
		{"https", probe.HTTPBanner{TLSSelfSigned: true}, "tls-unverifiable", conditional},
		{"https", probe.HTTPBanner{TLSExpired: true}, "tls-unverifiable", conditional},
		{"https", probe.HTTPBanner{}, "tls-unverifiable", conditional},
		{"ftp", probe.HTTPBanner{}, "cleartext-auth", exposed},
		{"dns", probe.HTTPBanner{}, "cleartext-noauth", exposed},
		{"smb", probe.HTTPBanner{}, "unknown", unverified},
	} {
		l := assessTransport(probe.Service{Protocol: tc.protocol}, tc.banner)
		if l.Class != tc.class || l.Confidentiality != tc.verdict || l.Integrity != tc.verdict || l.Availability != exposed {
			t.Fatal(l)
		}
		if l.Confidentiality != resilient {
			continue
		}
		raw, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"confidentiality", "integrity"} {
			var v struct {
				Verdict    string
				BlindSpots []string `json:"blind_spots"`
			}
			if err = json.Unmarshal(fields[field], &v); err != nil {
				t.Fatal(err)
			}
			want := []string{"unsigned firmware", "check TLS certificates", "first SSH connection", "DHCP option 121", "UDP services, and IPv6", "WPA3-SAE"}
			if v.Verdict != "resilient (observed inbound surfaces)" || len(v.BlindSpots) != len(want) {
				t.Fatal(v)
			}
			for i, w := range want {
				if !strings.Contains(v.BlindSpots[i], w) {
					t.Fatalf("missing %q: %+v", w, v)
				}
			}
		}
	}
}
