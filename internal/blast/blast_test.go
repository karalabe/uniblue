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
	"strconv"
	"strings"
	"testing"

	builtinchecks "github.com/karalabe/uniblue/checks"
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
	in := Input{Snapshot: s, Assets: map[string]classify.AssetProfile{"files": {Tier: classify.TierCrown}}, NetCfg: config.NetworkConfig{IsolationPolicy: config.IsolationIntent{IoTVLANs: []string{"iot"}, ApprovedPaths: []config.ApprovedPath{{Name: "Bridge updates", SourceZone: "iot", DestIP: bridge.IP, Port: 80, Transport: "tcp"}}}}}
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
	in := Input{Snapshot: s, NetCfg: config.NetworkConfig{IsolationPolicy: config.IsolationIntent{IoTVLANs: []string{"iot"}}}}
	observed(&in, cl, 5900, checks.GrantControl)
	in.Findings = append(in.Findings, checks.Finding{Client: cl, CheckID: "NERVA-SSH-WEAK-KEX", Port: 22, BaseSeverity: checks.SeverityMedium})
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
		if !slices.ContainsFunc(r.Simulation.Edges, func(e SimEdge) bool {
			return e.From == iot.ID && e.To == cl.ID && e.Tier == "unknown" && len(e.CutIDs) == 0
		}) {
			t.Fatalf("%s telemetry gap missing from the map: %+v", kind, r.Simulation.Edges)
		}
		if !slices.ContainsFunc(r.Simulation.Edges, func(e SimEdge) bool {
			return e.From == iot.ID && e.To == cl.ID && e.Tier == "unknown-takeover" && slices.Contains(e.CutIDs, "act:check:control-storage:storage:5900")
		}) {
			t.Fatal("missing unknown takeover", kind)
		}
		if !slices.ContainsFunc(r.Simulation.Edges, func(e SimEdge) bool {
			return e.From == iot.ID && e.To == cl.ID && e.Tier == "unknown-likely" && slices.Contains(e.CutIDs, "act:check:NERVA-SSH-WEAK-KEX:storage:tcp/22")
		}) {
			t.Fatal("missing unverified weak SSH path", kind)
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
	in := Input{Snapshot: s, NetCfg: config.NetworkConfig{IsolationPolicy: config.IsolationIntent{IoTVLANs: []string{"iot"}}}, Profiles: []probe.HostProfile{{Client: b, OutboundDependencies: []probe.OutboundDependency{{Category: "firmware-updates", Source: "device-config"}}}, {Client: c, OutboundDependencies: []probe.OutboundDependency{{Category: "vendor-control", Source: "zeek"}}}}}
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

// TestSimulationEgressCuts checks which VLAN controls can close a multi-homed client's egress.
func TestSimulationEgressCuts(t *testing.T) {
	in := Input{Snapshot: &unifi.Snapshot{
		Networks:         []unifi.Network{network("iot"), network("sensors")},
		Clients:          []unifi.Client{client("bridge", "192.0.2.1", "iot"), client("bridge", "198.51.100.1", "sensors")},
		FirewallPolicies: []unifi.FirewallPolicy{allow("iot", "External")},
	}, NetCfg: config.NetworkConfig{IsolationPolicy: config.IsolationIntent{IoTVLANs: []string{"iot", "sensors"}}}}
	check := func(want ...string) {
		t.Helper()
		if got := Evaluate(in).Simulation.Nodes[0].EgressCutIDs; !slices.Equal(got, want) {
			t.Fatalf("got egress cuts %v, want %v", got, want)
		}
	}
	check() // The missing sensors policy leaves this attachment's egress unknown.
	in.Snapshot.FirewallPolicies = append(in.Snapshot.FirewallPolicies, allow("sensors", "External"))
	check("act:vlan-egress:iot->internet", "act:vlan-egress:sensors->internet")
	in.Snapshot.FirewallPolicies[1].Action = "BLOCK"
	check("act:vlan-egress:iot->internet")
}

// TestCloudEgressVelocityTieBreak keeps equally effective outbound controls in their usual order.
func TestCloudEgressVelocityTieBreak(t *testing.T) {
	a, b := client("alpha", "192.0.2.1", "a"), client("beta", "198.51.100.1", "b")
	vendor := []probe.OutboundDependency{{Category: "vendor-control", Source: "zeek"}}
	in := Input{Snapshot: &unifi.Snapshot{
		Networks: []unifi.Network{network("a"), network("b")}, Clients: []unifi.Client{a, b},
		FirewallPolicies: []unifi.FirewallPolicy{allow("a", "External"), allow("b", "External")},
	}, NetCfg: config.NetworkConfig{IsolationPolicy: config.IsolationIntent{IoTVLANs: []string{"a", "b"}}}, Profiles: []probe.HostProfile{{Client: a, OutboundDependencies: vendor}, {Client: b, OutboundDependencies: vendor}},
		TargetSignals: []TargetSignal{{Asset: b.IP, Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}}}}
	var ranked []Action
	for _, a := range Evaluate(in).Actions {
		if strings.HasSuffix(a.ID, "->internet") {
			ranked = append(ranked, a)
		}
	}
	if len(ranked) != 2 || ranked[0].ID != "act:vlan-egress:a->internet" || !ranked[1].HighProfile || ranked[0].HighestTierReduced != ranked[1].HighestTierReduced {
		t.Fatalf("unexpected egress ranking: %+v", ranked)
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

// TestTargetVelocityPriorityAndTieBreak verifies the target velocity rules:
// +1 step on any-source internet reach (not P1, not version-matched KEV), no
// cross-port bleed, no boost on source-restricted WAN or KEV, no discount for
// unknown/opaque IoT velocity, and upward tie-break on equal untrusted-LAN
// actions.
func TestTargetVelocityPriorityAndTieBreak(t *testing.T) {
	web := client("web", "192.0.2.10", "lan")
	web.MAC = "02:00:00:00:01:10"
	iot := client("iot", "192.0.2.20", "lan")
	iot.MAC = "02:00:00:00:01:20"
	aHost := client("alpha", "192.0.2.30", "lan")
	aHost.MAC = "02:00:00:00:01:30"
	bHost := client("beta", "192.0.2.31", "lan")
	bHost.MAC = "02:00:00:00:01:31"

	snap := &unifi.Snapshot{
		Networks: []unifi.Network{network("lan"), network("guest")},
		Clients:  []unifi.Client{web, iot, aHost, bHost},
		WLANs:    []unifi.WLANConfig{{Enabled: true, Name: "Guest", NetworkID: "guest", Security: "open"}},
		FirewallPolicies: []unifi.FirewallPolicy{
			allow("guest", "lan"),
		},
		PortForwards: []unifi.PortForward{
			{ID: "pf-443", Name: "HTTPS", Enabled: true, Proto: "tcp", DstPort: "443", FwdIP: web.IP, FwdPort: "443", Src: "any"},
			{ID: "pf-8080", Name: "AltHTTP", Enabled: true, Proto: "tcp", DstPort: "8080", FwdIP: web.IP, FwdPort: "8080", Src: "any"},
			{ID: "pf-restr", Name: "Restricted", Enabled: true, Proto: "tcp", DstPort: "8443", FwdIP: web.IP, FwdPort: "8443", Src: "198.51.100.1"},
			{ID: "pf-iot", Name: "IoT", Enabled: true, Proto: "tcp", DstPort: "9000", FwdIP: iot.IP, FwdPort: "9000", Src: "any"},
		},
	}
	in := Input{
		Snapshot: snap,
		Assets: map[string]classify.AssetProfile{
			web.MAC:   {Tier: classify.TierMedium},
			iot.MAC:   {Tier: classify.TierMedium},
			aHost.MAC: {Tier: classify.TierMedium},
			bHost.MAC: {Tier: classify.TierMedium},
		},
		CVEMatches: []cve.Match{
			{
				Confidence: cve.ConfidenceExact,
				Record: cve.Record{
					ID:                 "CVE-2025-9999",
					Severity:           checks.SeverityHigh,
					AttackVector:       "N",
					PrivilegesRequired: "L",
					KEV:                true,
				},
				Product: cve.Product{
					Label:          "WebApp",
					HostIP:         web.IP,
					HighConfidence: true,
					Ports:          []cve.EndpointPort{{Transport: "tcp", Port: 443}},
				},
			},
		},
		TargetSignals: []TargetSignal{
			{Asset: web.IP, Proto: "tcp", Port: 443, Product: "Nginx", Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}},
			{Asset: web.IP, Proto: "tcp", Port: 8443, Product: "Nginx", Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}},
			{Asset: iot.IP, Proto: "tcp", Port: 9000, Product: "UnknownIoT", Velocity: cve.TargetVelocity{Class: cve.VelocityUnknown}},
			{Asset: bHost.IP, Proto: "tcp", Port: 8000, Product: "PopularApp", Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}},
		},
	}
	// Attach equal unauthenticated service checks to alpha and beta so untrusted
	// Wi-Fi reaches both at equal priority; beta's high-profile signal must win
	// the tie-break despite sorting after alpha by ID.
	observed(&in, aHost, 8000, checks.GrantControl)
	observed(&in, bHost, 8000, checks.GrantControl)

	r := Evaluate(in)

	// 1. Public tcp/443 on TierMedium promotes P2 -> P1 with HighProfile=true.
	pub443 := exposure(t, r, Internet, web.MAC, "public access to tcp/443")
	if pub443.Priority != P1 || !pub443.HighProfile {
		t.Fatalf("expected tcp/443 promoted to P1 + HighProfile, got %+v", pub443)
	}
	// 2. Unrelated tcp/8080 on the same host does NOT inherit tcp/443 signal.
	pub8080 := exposure(t, r, Internet, web.MAC, "public access to tcp/8080")
	if pub8080.Priority != P2 || pub8080.HighProfile {
		t.Fatalf("expected tcp/8080 to stay P2 without HighProfile bleed, got %+v", pub8080)
	}
	// 3. Source-restricted tcp/8443 must NOT receive a priority boost (stays P2, not P1).
	restr := exposure(t, r, InternetSource, web.MAC, "public access to tcp/8443")
	if restr.Priority != P2 || !restr.HighProfile {
		t.Fatalf("expected source-restricted tcp/8443 to stay P2 (no priority boost), got %+v", restr)
	}
	// 4. Version-matched KEV (moderate difficulty on TierMedium = P3) must NOT double-stack.
	kevExp := exposure(t, r, Internet, web.MAC, "CVE-2025-9999")
	if kevExp.Priority != P3 {
		t.Fatalf("expected KEV fact not to double-stack target velocity (want P3), got %+v", kevExp)
	}
	// 5. VelocityUnknown on opaque IoT must NOT discount below base P2.
	iotExp := exposure(t, r, Internet, iot.MAC, "public access to tcp/9000")
	if iotExp.Priority != P2 || iotExp.HighProfile {
		t.Fatalf("expected VelocityUnknown IoT to stay P2 without discount, got %+v", iotExp)
	}
	// 6. On equal untrusted-LAN check actions, beta (HighProfile) must outrank alpha.
	idxA, idxB := -1, -1
	for i, a := range r.Actions {
		if strings.Contains(a.ID, aHost.MAC) {
			idxA = i
		}
		if strings.Contains(a.ID, bHost.MAC) {
			idxB = i
		}
	}
	if idxA < 0 || idxB < 0 || idxB > idxA {
		t.Fatalf("expected high-profile beta action before alpha (idxB=%d, idxA=%d): %+v", idxB, idxA, r.Actions)
	}
	if !r.Actions[idxB].HighProfile || r.Actions[idxA].HighProfile {
		t.Fatalf("expected HighProfile flag only on beta action: beta=%+v alpha=%+v", r.Actions[idxB], r.Actions[idxA])
	}

	// 7. Cross-port consequence bleed check: private high-profile tcp/443 and
	// public port-forwarded non-high-profile tcp/8080 both grant "control".
	// Internet "control" must stay P2 (NOT promoted to P1) with HighProfile=false.
	dual := client("dual", "192.0.2.40", "lan")
	dual.MAC = "02:00:00:00:01:40"
	inDual := Input{
		Snapshot: &unifi.Snapshot{
			Networks: []unifi.Network{network("lan")},
			Clients:  []unifi.Client{dual},
			PortForwards: []unifi.PortForward{
				{ID: "pf-dual", Name: "Alt8080", Enabled: true, Proto: "tcp", DstPort: "8080", FwdIP: dual.IP, FwdPort: "8080", Src: "any"},
			},
		},
		Assets: map[string]classify.AssetProfile{dual.MAC: {Tier: classify.TierMedium}},
		Checks: []*checks.Check{
			{ID: "CHK-443", Grants: []checks.GrantSpec{{Effect: checks.GrantControl, Basis: checks.BasisImplied}}},
			{ID: "CHK-8080", Grants: []checks.GrantSpec{{Effect: checks.GrantControl, Basis: checks.BasisImplied}}},
		},
		Findings: []checks.Finding{
			{CheckID: "CHK-443", Client: dual, Port: 443, Transport: "tcp", ObservedIPs: []string{dual.IP}},
			{CheckID: "CHK-8080", Client: dual, Port: 8080, Transport: "tcp", ObservedIPs: []string{dual.IP}},
		},
		TargetSignals: []TargetSignal{
			{Asset: dual.IP, Proto: "tcp", Port: 443, Product: "PrivateHP", Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}},
		},
	}
	rDual := Evaluate(inDual)
	ctrlExp := exposure(t, rDual, Internet, dual.MAC, "control")
	if ctrlExp.Priority != P2 || ctrlExp.HighProfile {
		t.Fatalf("private tcp/443 signal must not promote public tcp/8080 control (want P2, HighProfile=false), got %+v", ctrlExp)
	}

	// 8. Trusted-LAN-only actions must NOT reverse order on target velocity tie-break.
	tA := client("t-alpha", "192.0.2.50", "lan")
	tA.MAC = "02:00:00:00:01:50"
	tB := client("t-beta", "192.0.2.51", "lan")
	tB.MAC = "02:00:00:00:01:51"
	inTrust := Input{
		Snapshot: &unifi.Snapshot{
			Networks: []unifi.Network{network("lan")},
			Clients:  []unifi.Client{tA, tB},
		},
		Assets: map[string]classify.AssetProfile{
			tA.MAC: {Tier: classify.TierMedium},
			tB.MAC: {Tier: classify.TierMedium},
		},
		TargetSignals: []TargetSignal{
			{Asset: tB.IP, Proto: "tcp", Port: 8000, Product: "PopularApp", Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}},
		},
	}
	observed(&inTrust, tA, 8000, checks.GrantControl)
	observed(&inTrust, tB, 8000, checks.GrantControl)
	rTrust := Evaluate(inTrust)
	idxTA, idxTB := -1, -1
	for i, a := range rTrust.Actions {
		if strings.Contains(a.ID, tA.MAC) {
			idxTA = i
		}
		if strings.Contains(a.ID, tB.MAC) {
			idxTB = i
		}
	}
	if idxTA < 0 || idxTB < 0 || idxTA > idxTB {
		t.Fatalf("trusted-LAN-only tie-break must not reverse alpha/beta (idxTA=%d, idxTB=%d): %+v", idxTA, idxTB, rTrust.Actions)
	}

	// 9. IPv6-only high-profile signal on a dual-stack host must not promote a
	// forwarded IPv4 listener on the same port.
	ds := unifi.Client{ID: "ds", MAC: "02:00:00:00:01:60", Name: "dualstack", IP: "192.0.2.60", IPv6: []string{"2001:db8::60"}, NetworkID: "lan", NetworkName: "lan"}
	inDS := Input{
		Snapshot: &unifi.Snapshot{
			Networks: []unifi.Network{network("lan")},
			Clients:  []unifi.Client{ds},
			PortForwards: []unifi.PortForward{
				{ID: "pf-ds-v4", Name: "HTTPSv4", Enabled: true, Proto: "tcp", DstPort: "443", FwdIP: ds.IP, FwdPort: "443", Src: "any"},
			},
		},
		Assets: map[string]classify.AssetProfile{ds.MAC: {Tier: classify.TierMedium}},
		TargetSignals: []TargetSignal{
			{Asset: "2001:db8::60", Proto: "tcp", Port: 443, Product: "IPv6OnlyHP", Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}},
		},
	}
	rDS := Evaluate(inDS)
	dsExp := exposure(t, rDS, Internet, ds.MAC, "public access to tcp/443")
	if dsExp.Priority != P3 || dsExp.HighProfile {
		t.Fatalf("IPv6-only high-profile signal must not promote IPv4 forward (want P3, HighProfile=false), got %+v", dsExp)
	}

	// 10. Closing a port forward when UPnP leases are unknown must earn zero
	// credit even when the exposed service carries a high-profile signal.
	upnpHost := client("sshbox", "192.0.2.70", "lan")
	upnpHost.MAC = "02:00:00:00:01:70"
	inUPnP := Input{
		Snapshot: &unifi.Snapshot{
			Visibility:       &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true, SettingsAvailable: true},
			SecuritySettings: &unifi.SiteSecuritySettings{UPnPEnabled: true},
			Networks:         []unifi.Network{network("lan")},
			Clients:          []unifi.Client{upnpHost},
			PortForwards: []unifi.PortForward{
				{ID: "pf-22", Name: "SSH", Enabled: true, Proto: "tcp", DstPort: "22", FwdIP: upnpHost.IP, FwdPort: "22", Src: "any"},
			},
		},
		Assets: map[string]classify.AssetProfile{upnpHost.MAC: {Tier: classify.TierMedium}},
		CVEMatches: []cve.Match{
			{
				Confidence: cve.ConfidenceExact,
				Record:     cve.Record{ID: "CVE-2025-1111", Severity: checks.SeverityHigh, AttackVector: "N"},
				Product:    cve.Product{Label: "OpenSSH", HostIP: upnpHost.IP, HighConfidence: true, Ports: []cve.EndpointPort{{Transport: "tcp", Port: 22}}},
			},
		},
		TargetSignals: []TargetSignal{
			{Asset: upnpHost.IP, Proto: "tcp", Port: 22, Product: "OpenSSH", Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}},
		},
	}
	rUPnP := Evaluate(inUPnP)
	if pf := action(t, rUPnP, "act:wan-pf:pf-22"); pf.HighestTierReduced != "" {
		t.Fatalf("closing forward while UPnP leases are unknown must earn zero credit even with high-profile signal, got %+v", pf)
	}

	// 11. Exact KEV CVE must never rank below an exact non-KEV CVE on the same
	// high-profile product.
	kevBox := client("kevbox", "192.0.2.80", "lan")
	kevBox.MAC = "02:00:00:00:01:80"
	nonKevBox := client("nonkevbox", "192.0.2.81", "lan")
	nonKevBox.MAC = "02:00:00:00:01:81"
	inKEV := Input{
		Snapshot: &unifi.Snapshot{
			Networks: []unifi.Network{network("lan")},
			Clients:  []unifi.Client{kevBox, nonKevBox},
			PortForwards: []unifi.PortForward{
				{ID: "pf-kev", Name: "KEVWeb", Enabled: true, Proto: "tcp", DstPort: "443", FwdIP: kevBox.IP, FwdPort: "443", Src: "any"},
				{ID: "pf-nonkev", Name: "NonKEVWeb", Enabled: true, Proto: "tcp", DstPort: "443", FwdIP: nonKevBox.IP, FwdPort: "443", Src: "any"},
			},
		},
		Assets: map[string]classify.AssetProfile{
			kevBox.MAC:    {Tier: classify.TierMedium},
			nonKevBox.MAC: {Tier: classify.TierMedium},
		},
		CVEMatches: []cve.Match{
			{
				Confidence: cve.ConfidenceExact,
				Record:     cve.Record{ID: "CVE-2025-2001", Severity: checks.SeverityCritical, AttackVector: "N", KEV: true},
				Product:    cve.Product{Label: "WebEdge", HostIP: kevBox.IP, HighConfidence: true, Ports: []cve.EndpointPort{{Transport: "tcp", Port: 443}}},
			},
			{
				Confidence: cve.ConfidenceExact,
				Record:     cve.Record{ID: "CVE-2025-2002", Severity: checks.SeverityHigh, AttackVector: "N"},
				Product:    cve.Product{Label: "WebEdge", HostIP: nonKevBox.IP, HighConfidence: true, Ports: []cve.EndpointPort{{Transport: "tcp", Port: 443}}},
			},
		},
		TargetSignals: []TargetSignal{
			{Asset: kevBox.IP, Proto: "tcp", Port: 443, Product: "WebEdge", Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}},
			{Asset: nonKevBox.IP, Proto: "tcp", Port: 443, Product: "WebEdge", Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}},
		},
	}
	rKEV := Evaluate(inKEV)
	expKEV := exposure(t, rKEV, Internet, kevBox.MAC, "CVE-2025-2001")
	expNonKEV := exposure(t, rKEV, Internet, nonKevBox.MAC, "CVE-2025-2002")
	if expNonKEV.Priority < expKEV.Priority {
		t.Fatalf("non-KEV CVE must never outrank KEV CVE on same product: kev=%+v nonKev=%+v", expKEV, expNonKEV)
	}
}

// TestRelabellingInvariance verifies that renaming VLANs (including an isolated
// VLAN renamed between "Hall" and "IoT" through risk.Evaluate), SSIDs, and
// neutral client display labels does not change exposure priorities, cloud
// states, or action ranking.
func TestRelabellingInvariance(t *testing.T) {
	build := func(vlan1Name, vlan2Name, ssidName, camName, nasName string) Report {
		dev1 := unifi.Client{ID: "c1", MAC: "02:00:00:00:02:01", Name: camName, IP: "192.0.2.11", NetworkID: "n1", NetworkName: vlan1Name}
		dev2 := unifi.Client{ID: "c2", MAC: "02:00:00:00:02:02", Name: nasName, IP: "198.51.100.11", NetworkID: "n2", NetworkName: vlan2Name}
		snap := &unifi.Snapshot{
			Visibility: &unifi.SiteVisibility{GatewayPoliciesAvailable: true, PortForwardsAvailable: true, WLANsAvailable: true},
			Networks: []unifi.Network{
				{ID: "n1", Name: vlan1Name, ZoneName: "z1", VLAN: "10", Subnet: "192.0.2.1/24", IsolationEnabled: true},
				{ID: "n2", Name: vlan2Name, ZoneName: "z2", VLAN: "20", Subnet: "198.51.100.1/24"},
			},
			Clients: []unifi.Client{dev1, dev2},
			WLANs:   []unifi.WLANConfig{{Enabled: true, Name: ssidName, NetworkID: "n1", Security: "open"}},
			FirewallPolicies: []unifi.FirewallPolicy{
				allow("z1", "z2"),
				allow("z1", "External"),
			},
			PortForwards: []unifi.PortForward{
				{ID: "pf1", Name: "Web", Enabled: true, Proto: "tcp", DstPort: "8080", FwdIP: dev2.IP, FwdPort: "8080", Src: "any"},
			},
		}
		findings := []checks.Finding{
			{CheckID: "UB-TEST-AUTH", Client: dev2, Port: 8080, Transport: "tcp", ObservedIPs: []string{dev2.IP}},
		}
		riskRep := risk.Evaluate(snap, findings, config.NetworkConfig{})
		in := Input{
			Snapshot:    snap,
			Isolation:   riskRep.Isolation,
			SwitchPorts: riskRep.SwitchPorts,
			Assets: map[string]classify.AssetProfile{
				dev1.MAC: {Tier: classify.TierLow},
				dev2.MAC: {Tier: classify.TierHigh},
			},
			Checks: []*checks.Check{
				{ID: "UB-TEST-AUTH", Grants: []checks.GrantSpec{{Effect: checks.GrantControl, Basis: checks.BasisImplied}}},
			},
			Findings: findings,
		}
		return Evaluate(in)
	}

	r1 := build("IoT", "Trusted", "GuestWiFi", "Device-A", "Storage-A")
	r2 := build("Hall", "Segment-B", "Wireless-X", "Device-B", "Storage-B")

	if len(r1.Exposures) != len(r2.Exposures) {
		t.Fatalf("exposure count changed after relabelling: %d vs %d", len(r1.Exposures), len(r2.Exposures))
	}
	for i := range r1.Exposures {
		e1, e2 := r1.Exposures[i], r2.Exposures[i]
		if e1.Entry != e2.Entry || e1.Asset != e2.Asset || e1.Consequence != e2.Consequence || e1.State != e2.State || e1.Priority != e2.Priority || e1.Lane != e2.Lane {
			t.Fatalf("exposure %d changed after relabelling: %+v vs %+v", i, e1, e2)
		}
	}
	if len(r1.Cloud) != len(r2.Cloud) {
		t.Fatalf("cloud count changed after relabelling: %d vs %d", len(r1.Cloud), len(r2.Cloud))
	}
	for i := range r1.Cloud {
		if r1.Cloud[i].Asset != r2.Cloud[i].Asset || r1.Cloud[i].State != r2.Cloud[i].State {
			t.Fatalf("cloud %d changed after relabelling: %+v vs %+v", i, r1.Cloud[i], r2.Cloud[i])
		}
	}
	if len(r1.Actions) != len(r2.Actions) {
		t.Fatalf("action count changed after relabelling: %d vs %d", len(r1.Actions), len(r2.Actions))
	}
	for i := range r1.Actions {
		a1, a2 := r1.Actions[i], r2.Actions[i]
		if a1.ID != a2.ID || a1.Lane != a2.Lane || a1.HighestTierReduced != a2.HighestTierReduced || a1.PairsByTier != a2.PairsByTier {
			t.Fatalf("action %d changed after relabelling: %+v vs %+v", i, a1, a2)
		}
	}
}

// TestEvaluateAllInfraKeepsDuplicateNames verifies that multiple UniFi devices
// sharing a display label (such as two unnamed U6-Lite APs) each keep their own
// deterministic InfraReport keyed by canonical MAC.
func TestEvaluateAllInfraKeepsDuplicateNames(t *testing.T) {
	snap := &unifi.Snapshot{
		Devices: []unifi.Device{
			{MAC: "02:00:00:00:aa:01", Type: "udm", Name: "Gateway"},
			{MAC: "02:00:00:00:aa:03", Type: "uap", Model: "U6-Lite", UplinkMAC: "02:00:00:00:aa:01", UplinkPort: 1},
			{MAC: "02:00:00:00:aa:02", Type: "uap", Model: "U6-Lite", UplinkMAC: "02:00:00:00:aa:01", UplinkPort: 2},
		},
	}
	reps := EvaluateAllInfra(Input{Snapshot: snap})
	var aps []InfraReport
	for _, r := range reps {
		if r.Scope == "AP" {
			aps = append(aps, r)
		}
	}
	if len(aps) != 2 {
		t.Fatalf("expected 2 AP infra reports for duplicate-named APs, got %d: %+v", len(aps), aps)
	}
	if aps[0].TargetID != "02:00:00:00:aa:02" || aps[1].TargetID != "02:00:00:00:aa:03" {
		t.Fatalf("expected deterministic MAC tie-break ordering, got %+v", aps)
	}
}

// TestExpectedP2PAndVPNForwardsNotFlaggedAsUrgent verifies that intentionally
// public P2P peering ports (such as Ethereum DevP2P 30303) and VPN endpoints
// (such as WireGuard 51820) are not flagged as Fix now actions on their own,
// while a real unauthenticated grant or CVE on that port still surfaces.
func TestExpectedP2PAndVPNForwardsNotFlaggedAsUrgent(t *testing.T) {
	node := client("eth-node", "192.0.2.90", "lan")
	node.MAC = "02:00:00:00:01:90"
	snap := &unifi.Snapshot{
		Networks: []unifi.Network{network("lan")},
		Clients:  []unifi.Client{node},
		PortForwards: []unifi.PortForward{
			{ID: "pf-eth", Name: "Ethereum Execution DevP2P", Enabled: true, Proto: "tcp_udp", DstPort: "30303", FwdIP: node.IP, FwdPort: "30303", Src: "any"},
			{ID: "pf-consensus", Name: "Ethereum Consensus LibP2P", Enabled: true, Proto: "tcp_udp", DstPort: "9000", FwdIP: node.IP, FwdPort: "9000", Src: "any"},
			{ID: "pf-wg", Name: "WireGuard VPN", Enabled: true, Proto: "udp", DstPort: "51820", FwdIP: node.IP, FwdPort: "51820", Src: "any"},
		},
	}
	in := Input{
		Snapshot: snap,
		Assets:   map[string]classify.AssetProfile{node.MAC: {Tier: classify.TierHigh}},
	}
	clean := Evaluate(in)
	for _, a := range clean.Actions {
		if a.ID == "act:wan-pf:pf-eth" || a.ID == "act:wan-pf:pf-consensus" || a.ID == "act:wan-pf:pf-wg" {
			t.Fatalf("clean expected-p2p/vpn forward should not be flagged as an urgent action: %+v", a)
		}
	}

	// If an exact remote CVE affects that forwarded port, closing/patching must still surface.
	in.CVEMatches = []cve.Match{
		{
			Confidence: cve.ConfidenceExact,
			Record:     cve.Record{ID: "CVE-2025-30303", Severity: checks.SeverityCritical, AttackVector: "N", KEV: true},
			Product:    cve.Product{Label: "Geth", HostIP: node.IP, HighConfidence: true, Ports: []cve.EndpointPort{{Transport: "tcp", Port: 30303}}},
		},
	}
	vuln := Evaluate(in)
	exp := exposure(t, vuln, Internet, node.MAC, "CVE-2025-30303")
	if exp.Priority != P1 || exp.Lane != LaneFixNow {
		t.Fatalf("real CVE on forwarded P2P port must still surface as P1 Fix now, got %+v", exp)
	}
	patch := "act:patch:CVE-2025-30303:" + node.MAC
	if !slices.ContainsFunc(vuln.Simulation.Edges, func(e SimEdge) bool {
		return e.Tier == "wan" && e.To == node.MAC && slices.Contains(e.CutIDs, patch) && slices.Contains(e.CutIDs, "act:wan-pf:pf-eth")
	}) {
		t.Fatal("the vulnerable peering listener must be containable by patching it or closing its forward")
	}
}

// TestSimulationParallelCuts ensures each route carries only its own remedies.
// A second listener or publication must survive a cut to the first.
func TestSimulationParallelCuts(t *testing.T) {
	src := client("guest", "192.0.2.10", "guest")
	dst := client("storage", "198.51.100.10", "storage")
	in := Input{Snapshot: &unifi.Snapshot{
		Networks: []unifi.Network{network("guest"), network("storage")},
		Clients:  []unifi.Client{src, dst}, FirewallPolicies: []unifi.FirewallPolicy{allow("guest", "storage")},
		PortForwards:     []unifi.PortForward{{ID: "web", Enabled: true, FwdIP: dst.IP, DstPort: "9443", FwdPort: "443", Proto: "tcp"}},
		PublishedTunnels: []unifi.PublishedTunnel{{Provider: "relay", Hostname: "files.example", BackendIP: dst.IP, BackendPort: 443, AccessPolicy: "public"}},
	}, NetCfg: config.NetworkConfig{IsolationPolicy: config.IsolationIntent{GuestVLANs: []string{"guest"}}}}
	observed(&in, dst, 443, checks.GrantControl)
	observed(&in, dst, 8080, checks.GrantPivot)
	r := Evaluate(in)
	sim := r.Simulation
	if sim == nil || len(sim.Nodes) != 2 {
		t.Fatalf("missing inventory: %+v", sim)
	}
	if n := sim.Nodes[0]; n.ID != "storage" || n.EntityID != "host:ip/"+dst.IP || n.EntryExposure != "WAN TCP/9443" || n.InternetState == "" {
		t.Fatal(n)
	}
	want := map[string]string{
		"act:wan-pf:web": "act:wan-service:storage:tcp/443",
		"act:published-tunnel:relay:files.example": "act:wan-service:storage:tcp/443",
		"act:check:control-storage:storage:443":    "act:vlan-egress:guest->storage",
		"act:check:pivot-storage:storage:8080":     "act:vlan-egress:guest->storage",
	}
	for _, e := range sim.Edges {
		for _, id := range e.CutIDs {
			action(t, r, id)
		}
		if e.To != dst.ID {
			continue
		}
		for id, boundary := range want {
			if !slices.Contains(e.CutIDs, id) {
				continue
			}
			if len(e.CutIDs) != 2 || !slices.Contains(e.CutIDs, boundary) {
				t.Fatalf("wrong route remedies: %+v", e)
			}
			if strings.HasPrefix(id, "act:check:") {
				if e.Tier != "takeover" || e.From != src.ID {
					t.Fatal(e)
				}
			} else if e.Tier != "wan" || e.From != "internet" {
				t.Fatal(e)
			}
			delete(want, id)
		}
	}
	if len(want) > 0 {
		t.Fatalf("missing independently cuttable paths: %+v", want)
	}
	slices.Reverse(in.Snapshot.Clients)
	slices.Reverse(in.Findings)
	if !reflect.DeepEqual(sim, Evaluate(in).Simulation) {
		t.Fatal("inventory order changed the simulation")
	}
}

// TestSystemWireGuardGatewayRule distinguishes UniFi's VPN listener from a
// user rule with the same name and preserves confirmed findings on its port.
func TestSystemWireGuardGatewayRule(t *testing.T) {
	d := unifi.Device{MAC: "02:00:00:00:00:01", Name: "Router", Type: "udm", IP: "192.0.2.1"}
	p := allow("External", "Gateway")
	p.ID, p.Name, p.Origin, p.Protocol = "vpn", "Allow WireGuard VPN", "SYSTEM_DEFINED", "udp"
	p.Destination.AnyPort = false
	p.Destination.Ports = []int{51820}
	in := Input{Snapshot: &unifi.Snapshot{Devices: []unifi.Device{d}, FirewallPolicies: []unifi.FirewallPolicy{p}}}
	// A configuration review on this port is not proof of anonymous access.
	gw := risk.NewOracle(in.Snapshot, in.NetCfg).DeviceClient(d)
	gw.ID = "gateway"
	in.Findings = []checks.Finding{{CheckID: "config-review", Client: gw, Port: 51820, Transport: "udp", ObservedIPs: []string{d.IP}}}
	r := Evaluate(in)
	for _, a := range r.Actions {
		if a.ID == "act:gateway-local:vpn" {
			t.Fatal(a)
		}
	}
	for _, e := range r.Simulation.Edges {
		if e.Tier == "wan" {
			t.Fatal(e)
		}
	}
	user := p
	user.ID, user.Origin = "custom", "USER_DEFINED"
	in.Snapshot.FirewallPolicies = append(in.Snapshot.FirewallPolicies, user)
	action(t, Evaluate(in), "act:gateway-local:custom")
	in.Snapshot.FirewallPolicies = in.Snapshot.FirewallPolicies[:1]
	observed(&in, gw, 51820, checks.GrantControl)
	in.Findings[len(in.Findings)-1].Transport = "udp"
	r = Evaluate(in)
	if x := exposure(t, r, Internet, d.MAC, "control"); x.State != "exposed" {
		t.Fatal(x)
	}
	routeID := "act:gateway-local:vpn"
	action(t, r, routeID)
	if !slices.ContainsFunc(r.Simulation.Edges, func(e SimEdge) bool {
		return e.Tier == "wan" && e.To == d.MAC && slices.Contains(e.CutIDs, routeID) && slices.Contains(e.CutIDs, "act:check:control-gateway:"+d.MAC+":51820:udp")
	}) {
		t.Fatalf("missing confirmed WAN path: %+v", r.Simulation.Edges)
	}
}

// TestGatewayControlTraffic keeps built-in gateway services out of the action
// queue while preserving an independent user publication on the same gateway.
func TestGatewayControlTraffic(t *testing.T) {
	gw := unifi.Device{Type: "udm", MAC: "02:00:00:00:00:01", IP: "2001:db8::1"}
	s := &unifi.Snapshot{Devices: []unifi.Device{gw}}
	rule := func(name, origin, proto string, port int) unifi.FirewallPolicy {
		p := allow("External", "Gateway")
		p.ID, p.Name, p.Origin, p.IPVersion, p.Protocol = name, name, origin, "ipv6", proto
		if port != 0 {
			p.Destination.AnyPort, p.Destination.Ports = false, []int{port}
		}
		return p
	}
	s.FirewallPolicies = []unifi.FirewallPolicy{
		rule("Allow DHCPv6", "SYSTEM_DEFINED", "udp", 547),
		rule("Allow Neighbor Solicitations", "SYSTEM_DEFINED", "icmpv6", 0),
		rule("Allow Return Traffic", "SYSTEM_DEFINED", "all", 0),
		rule("Secure Shell", "USER_DEFINED", "all", 0),
	}
	in := Input{Snapshot: s, Assets: map[string]classify.AssetProfile{gw.MAC: {Tier: classify.TierCrown}}}
	r := Evaluate(in)
	for _, a := range r.Actions {
		if strings.HasPrefix(a.ID, "act:gateway-local:Allow ") {
			t.Errorf("system gateway control traffic produced an action: %+v", a)
		}
	}
	if a := action(t, r, "act:gateway-local:Secure Shell"); a.Lane != LaneFixNow || a.HighestTierReduced != P1 {
		t.Fatal(a)
	}
	in.CVEMatches = []cve.Match{{
		Confidence: cve.ConfidenceExact, Record: cve.Record{ID: "CVE-example", AttackVector: "N", KEV: true},
		Product: cve.Product{HostIP: gw.IP, Ports: []cve.EndpointPort{{Transport: "udp", Port: 547}}},
	}}
	r = Evaluate(in)
	if x := exposure(t, r, Internet, gw.MAC, "CVE-example"); x.State != "exposed" {
		t.Fatal(x)
	}
	if !slices.ContainsFunc(r.Simulation.Edges, func(e SimEdge) bool {
		return e.Tier == "wan" && e.To == gw.MAC && slices.Contains(e.CutIDs, "act:gateway-local:Allow DHCPv6") && slices.Contains(e.CutIDs, "act:patch:CVE-example:"+gw.MAC)
	}) {
		t.Fatalf("missing confirmed DHCPv6 finding: %+v", r.Simulation.Edges)
	}
}

// routedSimulation gives each listener a real inter-VLAN path and a ranked boundary action.
func routedSimulation() (Input, unifi.Client, unifi.Client) {
	src, dst := client("guest", "192.0.2.1", "guest"), client("service", "198.51.100.1", "lan")
	in := Input{Snapshot: &unifi.Snapshot{Networks: []unifi.Network{network("guest"), network("lan")},
		Clients: []unifi.Client{src, dst}, FirewallPolicies: []unifi.FirewallPolicy{allow("guest", "lan")}},
		NetCfg: config.NetworkConfig{IsolationPolicy: config.IsolationIntent{GuestVLANs: []string{"guest"}}}}
	return in, src, dst
}

// TestSimulationProtocolGrants keeps confirmed protocol access tied to its service remedy.
func TestSimulationProtocolGrants(t *testing.T) {
	in, src, dst := routedSimulation()
	in.Profiles = []probe.HostProfile{{Client: dst, ProbeIP: dst.IP, Services: []probe.Service{
		{Protocol: "modbus", Port: 502, State: probe.ServiceStateObservedProtocol},
		{Protocol: "upnp", Port: 1900, Transport: "udp", State: probe.ServiceStateObservedProtocol},
	}}}
	r := Evaluate(in)
	for label, id := range map[string]string{
		"Unauthenticated control - tcp/502":    "act:service:service:tcp/502",
		"Unauthenticated configure - udp/1900": "act:service:service:udp/1900",
	} {
		action(t, r, id)
		if !slices.ContainsFunc(r.Simulation.Edges, func(e SimEdge) bool {
			return e.From == src.ID && e.To == dst.ID && e.Tier == "takeover" && e.Label == label && slices.Contains(e.CutIDs, id)
		}) {
			t.Errorf("missing confirmed route for %s: %+v", id, r.Simulation.Edges)
		}
	}
}

// TestSimulationCVEImpact distinguishes availability findings, confirmed control, and
// vulnerabilities that still require credentials or interaction on the same socket.
func TestSimulationCVEImpact(t *testing.T) {
	in, src, dst := routedSimulation()
	for _, r := range []cve.Record{
		{ID: "CVE-dos", CVSSVector: "CVSS:3.1/AV:N/C:N/I:N/A:H"},
		{ID: "CVE-dos-trailing", CVSSVector: "CVSS:3.1/AV:N/A:H/C:N/I:N"},
		{ID: "CVE-dos-v4", CVSSVector: "CVSS:4.0/AV:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"},
		{ID: "CVE-control", CVSSVector: "CVSS:3.1/AV:N/C:N/I:H/A:H"},
		{ID: "CVE-admin", PrivilegesRequired: "H"}, {ID: "CVE-click", UserInteraction: "R"},
		{ID: "CVE-single-auth", CVSSVector: "(AV:N/AC:L/Au:S/C:C/I:C/A:C)", KEV: true},
		{ID: "CVE-multiple-auth", CVSSVector: "AV:N/AC:L/Au:M/C:P/I:P/A:P"},
		{ID: "CVE-no-auth", CVSSVector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"},
	} {
		r.Severity, r.AttackVector = checks.SeverityHigh, "N"
		in.CVEMatches = append(in.CVEMatches, cve.Match{Confidence: cve.ConfidenceExact, Record: r,
			Product: cve.Product{HostIP: dst.IP, Label: "Web service", Ports: []cve.EndpointPort{{Transport: "tcp", Port: 8000}}}})
	}
	want := map[string]string{"CVE-control": "takeover", "CVE-admin": "likely", "CVE-click": "likely",
		"CVE-single-auth": "likely", "CVE-multiple-auth": "likely", "CVE-no-auth": "takeover"}
	for _, e := range Evaluate(in).Simulation.Edges {
		if e.From != src.ID || e.To != dst.ID {
			continue
		}
		id := strings.TrimSuffix(e.Label, " - tcp/8000")
		if e.Tier != want[id] || !slices.Contains(e.CutIDs, "act:patch:"+id+":service") ||
			!slices.Contains(e.CutIDs, "act:patch-product:web-service:service") {
			t.Errorf("unexpected CVE path or missing patch: %+v", e)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatal("missing CVE paths", want)
	}
}

// TestSimulationConditionalGrants retains the boundary fix even when a read-only
// check cannot establish whether the listener will authorize a control request.
func TestSimulationConditionalGrants(t *testing.T) {
	in, src, dst := routedSimulation()
	catalog, err := checks.LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	in.Checks = catalog
	peer := client("peer", "198.51.100.2", "lan")
	dst.ESSID, dst.APMAC = "Home", "02:00:00:00:00:01"
	peer.ESSID, peer.APMAC = dst.ESSID, dst.APMAC
	in.Snapshot.Clients = []unifi.Client{src, dst, peer}
	in.Snapshot.WLANs = []unifi.WLANConfig{{Name: dst.ESSID, NetworkName: dst.NetworkName, Enabled: true}}
	in.Findings = []checks.Finding{
		{Client: dst, CheckID: "UB-2026-0039", Port: 56747},
		{Client: dst, CheckID: "UB-0019", Port: 623},
		{Client: dst, CheckID: "UB-2026-0001", Port: 443},
		{Client: dst, CheckID: "UB-0012", Port: 161},
		{Client: dst, CheckID: "UB-0015", Port: 1900},
		{Client: dst, CheckID: "UB-2026-0022", Port: 51826},
		{Client: dst, CheckID: "UB-2026-0063", Title: "Unauthenticated Roku External Control Protocol (ECP)", Port: 8060},
	}
	want := map[string]bool{
		"Conditional control (Zehnder ComfoConnect) - tcp/56747": true,
		"Conditional control (IPMI) - udp/623":                   true,
		"Conditional control (MegaRAC) - tcp/443":                true,
		"Conditional control (Roku ECP) - tcp/8060":              true,
	}
	r := Evaluate(in)
	if !slices.ContainsFunc(r.Simulation.Edges, func(e SimEdge) bool {
		return e.From == peer.ID && e.To == dst.ID && e.Tier == "likely" && e.Label == "Conditional control (HomeKit) - tcp/51826"
	}) {
		t.Error("missing same-network HomeKit pairing route")
	}
	boundary := "act:vlan-egress:guest->lan"
	action(t, r, boundary)
	for _, e := range r.Simulation.Edges {
		if e.From != src.ID || e.To != dst.ID || e.Tier == "pivot" {
			continue
		}
		if e.Tier != "likely" || !want[e.Label] || !slices.Equal(e.CutIDs, []string{boundary}) {
			t.Errorf("unexpected conditional path: %+v", e)
		}
		delete(want, e.Label)
	}
	if len(want) != 0 {
		t.Fatal("missing conditional paths", want)
	}
}

// TestRankedHomeKitProximity checks that only a local peer can earn pairing exposure.
func TestRankedHomeKitProximity(t *testing.T) {
	in, src, dst := routedSimulation()
	catalog, err := checks.LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	in.Checks = catalog
	in.Assets = map[string]classify.AssetProfile{dst.ID: {Tier: classify.TierHigh}}
	boundary := "act:vlan-egress:guest->lan"
	before := action(t, Evaluate(in), boundary)
	in.Findings = []checks.Finding{{Client: dst, CheckID: "UB-2026-0022", Port: 51826}}
	r := Evaluate(in)
	for _, e := range r.Exposures {
		if e.Entry == AssumeBreach && e.Asset == dst.ID && (e.Consequence == "control" || e.Consequence == "configure") {
			t.Errorf("guest reached a local HomeKit grant: %+v", e)
		}
	}
	if after := action(t, r, boundary); after.PairsByTier != before.PairsByTier {
		t.Errorf("HomeKit changed guest boundary credit from %v to %v", before.PairsByTier, after.PairsByTier)
	}

	src.NetworkID, src.NetworkName = dst.NetworkID, dst.NetworkName
	src.ESSID, dst.ESSID = "Home", "Home"
	src.APMAC, dst.APMAC = "02:00:00:00:00:01", "02:00:00:00:00:01"
	in.Snapshot.Clients = []unifi.Client{src, dst}
	in.Snapshot.WLANs = []unifi.WLANConfig{{Name: dst.ESSID, NetworkName: dst.NetworkName, Enabled: true}}
	in.NetCfg.IsolationPolicy.GuestVLANs = []string{dst.NetworkName}
	in.Findings[0].Client = dst
	r = Evaluate(in)
	for _, effect := range []string{"control", "configure"} {
		if e := exposure(t, r, AssumeBreach, dst.ID, effect); e.State != "needs-verification" {
			t.Errorf("unexpected local pairing exposure: %+v", e)
		}
	}
}

// TestReflectedHomeKitProximity checks that only a direct answer puts pairing
// on the trusted LAN's verification list.
func TestReflectedHomeKitProximity(t *testing.T) {
	in, accessory, reflector := routedSimulation()
	catalog, err := checks.LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(catalog, func(c *checks.Check) bool { return c.ID == "UB-2026-0022" })
	if i < 0 {
		t.Fatal("missing HomeKit check")
	}
	in.Checks = []*checks.Check{catalog[i]}
	hp := probe.HostProfile{Client: accessory, MDNSServices: []probe.MDNSService{{
		Type: "_hap._tcp", TXT: []string{"sf=1"}, Port: 51826, Transport: "tcp",
		TargetIPs: []string{accessory.IP}, ResponderIP: reflector.IP, Reflected: true, TrustedReflector: true,
	}}}
	in.Profiles = []probe.HostProfile{hp}
	runner := checks.NewRunner(in.Checks, 1)
	in.Findings = runner.RunHost(t.Context(), in.Profiles[0])
	if len(in.Findings) != 1 || !slices.Equal(in.Findings[0].ObservedIPs, []string{accessory.IP}) {
		t.Fatalf("expected a reflected finding for the guest accessory, got %+v", in.Findings)
	}
	for _, e := range Evaluate(in).Exposures {
		if e.Entry == TrustedLAN && e.Asset == accessory.ID && (e.Consequence == "configure" || e.Consequence == "control") {
			t.Errorf("reflected advertisement granted local pairing access: %+v", e)
		}
	}
	md := &in.Profiles[0].MDNSServices[0]
	md.ResponderIP, md.Reflected, md.TrustedReflector = accessory.IP, false, false
	in.Findings = runner.RunHost(t.Context(), in.Profiles[0])
	r := Evaluate(in)
	for _, effect := range []string{"configure", "control"} {
		if e := exposure(t, r, TrustedLAN, accessory.ID, effect); e.State != "needs-verification" {
			t.Errorf("direct answer: want pairing verification, got %+v", e)
		}
	}
}

// TestSimulationPotentialCVEs binds each product once per reachable listener.
// Advertisements and configured forwards alone cannot make a quiet appliance reachable.
func TestSimulationPotentialCVEs(t *testing.T) {
	in, src, dst := routedSimulation()
	dst.Name = "HP LaserJet M453"
	in.Snapshot.Clients[1] = dst
	hp := probe.HostProfile{Client: dst, ProbeIP: dst.IP, Services: []probe.Service{
		{State: probe.ServiceStateAdvertisedService, Protocol: "http", Port: 80},
	}}
	in.Snapshot.PortForwards = []unifi.PortForward{{ID: "printer", Enabled: true, Proto: "tcp", FwdIP: dst.IP, FwdPort: "9100", DstPort: "9100"}}
	appliance := cve.Product{Label: "HP LaserJet M453", Source: "hostname", HostIP: dst.IP}
	for i := range 7 {
		in.CVEMatches = append(in.CVEMatches, cve.Match{Product: appliance, Confidence: cve.ConfidencePotential,
			Record: cve.Record{ID: "CVE-printer-" + strconv.Itoa(i), AttackVector: "N", Severity: checks.SeverityCritical}})
	}
	web := client("web", "198.51.100.2", "lan")
	in.Snapshot.Clients = append(in.Snapshot.Clients, web)
	bound := cve.Product{Label: "Nginx", HostIP: web.IP, Ports: []cve.EndpointPort{{Transport: "tcp", Port: 9443}}}
	in.CVEMatches = append(in.CVEMatches, cve.Match{Product: bound, Confidence: cve.ConfidencePotential,
		Record: cve.Record{ID: "CVE-web", KEV: true, Severity: checks.SeverityHigh}})
	for _, tc := range []struct {
		version    string
		port       int
		confidence cve.Confidence
	}{
		{"10.2p1", 22, cve.ConfidencePotential},
		{"7.4p1", 2222, cve.ConfidenceVersionAmbiguous},
	} {
		in.CVEMatches = append(in.CVEMatches, cve.Match{Confidence: tc.confidence,
			Product: cve.Product{Label: "OpenSSH", HostIP: web.IP, Version: tc.version, Ports: []cve.EndpointPort{{Port: tc.port}}},
			Record:  cve.Record{ID: "CVE-ssh", AttackVector: "N", Severity: checks.SeverityCritical}})
	}
	in.CVEMatches = append(in.CVEMatches, cve.Match{Confidence: cve.ConfidencePotential,
		Product: cve.Product{Label: "Ollama", Source: "hostname", HostIP: web.IP},
		Record:  cve.Record{ID: "CVE-ollama", AttackVector: "N", Severity: checks.SeverityCritical}})
	for _, r := range []cve.Record{
		{ID: "CVE-local", KEV: true, AttackVector: "L"},
		{ID: "CVE-high", Severity: checks.SeverityHigh, AttackVector: "N"},
		{ID: "CVE-dos", KEV: true, AttackVector: "N", CVSSVector: "CVSS:3.1/AV:N/C:N/I:N/A:H"},
		{ID: "CVE-unspecified", Severity: checks.SeverityCritical},
	} {
		product := bound
		product.Label = r.ID
		in.CVEMatches = append(in.CVEMatches, cve.Match{Product: product, Confidence: cve.ConfidencePotential, Record: r})
	}
	for _, tc := range []struct {
		name       string
		open, want []int
	}{
		{"preferred", []int{9100, 443, 631, 2222}, []int{443, 631, 9100}},
		{"unrelated listeners", []int{22, 2222, 9999}, nil},
		{"no observation", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hp.OpenPorts = tc.open
			in.Profiles = []probe.HostProfile{hp}
			want := []string{"Potential known-exploited CVEs (Nginx) - tcp/9443", "Potential critical CVEs (OpenSSH) - tcp/2222"}
			for _, port := range tc.want {
				want = append(want, "Potential critical CVEs (HP LaserJet M453) - tcp/"+strconv.Itoa(port))
			}
			slices.Sort(want)
			var got []string
			for _, e := range Evaluate(in).Simulation.Edges {
				if e.From == src.ID && e.Tier != "pivot" {
					if e.Tier != "likely" {
						t.Fatal(e)
					}
					got = append(got, e.Label)
				}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
	// A rule allowing only the web interface cannot expose the printer socket.
	policy := &in.Snapshot.FirewallPolicies[0]
	policy.Protocol, policy.Destination.AnyPort, policy.Destination.Ports = "tcp", false, []int{443}
	in.Profiles[0].OpenPorts = []int{443, 631}
	var paths []string
	for _, e := range Evaluate(in).Simulation.Edges {
		if e.From == src.ID && e.To == dst.ID && e.Tier == "likely" {
			paths = append(paths, e.Label)
		}
	}
	if !slices.Equal(paths, []string{"Potential critical CVEs (HP LaserJet M453) - tcp/443"}) {
		t.Fatal("unexpected permitted listeners", paths)
	}
}

// TestWorkstationHostnameCVE keeps a software name from claiming workstation listeners.
func TestWorkstationHostnameCVE(t *testing.T) {
	in, src, dst := routedSimulation()
	dst.Name = "thinkpad-homeassistant"
	in.Snapshot.Clients[1] = dst
	in.CVEMatches = []cve.Match{{Confidence: cve.ConfidencePotential,
		Product: cve.Product{Label: "Home Assistant", Source: "hostname", HostIP: dst.IP},
		Record:  cve.Record{ID: "CVE-example", AttackVector: "N", Severity: checks.SeverityCritical}}}
	for _, port := range []int{22, 443} {
		in.Profiles = []probe.HostProfile{{Client: dst, ProbeIP: dst.IP, OpenPorts: []int{port}}}
		if role := classify.ClientRoles(in.Snapshot, in.Profiles)[dst.ID]; role.Category != classify.CategoryPersonal {
			t.Fatalf("expected a personal workstation, got %+v", role)
		}
		for _, e := range Evaluate(in).Simulation.Edges {
			if e.From == src.ID && e.To == dst.ID && e.Tier == "likely" {
				t.Errorf("hostname fingerprint borrowed port %d: %+v", port, e)
			}
		}
	}
}

// TestSimulationIPv6Listeners lets policy reach one of two addresses on the
// same host so a service or CVE attributed to the wrong listener changes the map.
func TestSimulationIPv6Listeners(t *testing.T) {
	in, src, dst := routedSimulation()
	dst.Name = "HP LaserJet M453"
	first, second := "2001:db8:2::1", "2001:db8:2::2"
	src.IP, dst.IPv6 = "2001:db8:1::1", []string{first, second}
	in.Snapshot.Clients = []unifi.Client{src, dst}
	in.Profiles = []probe.HostProfile{{Client: dst, ProbeIP: first, OpenPorts: []int{443}, Services: []probe.Service{
		{Port: 502, Protocol: "http", AddressFamily: "ipv6"},
	}}}
	probe.ApplyPassiveFlows(in.Profiles, []probe.PassiveFlowRecord{
		{Direction: "hosted", LocalIP: second, Port: 502, Transport: "tcp", Protocol: "modbus"},
		{Direction: "hosted", LocalIP: second, Port: 631, Transport: "tcp", Protocol: "ipp"},
	})
	for _, p := range []cve.Product{
		{Label: "HP LaserJet M453", HostIP: first, Source: "hostname"},
		{Label: "Nginx", HostIP: second, Ports: []cve.EndpointPort{{Port: 9443}}},
	} {
		in.CVEMatches = append(in.CVEMatches, cve.Match{Product: p, Confidence: cve.ConfidencePotential,
			Record: cve.Record{ID: "CVE-example", AttackVector: "N", Severity: checks.SeverityCritical}})
	}
	for _, tc := range []struct {
		ip   string
		want []string
	}{
		{first, []string{"Potential critical CVEs (HP LaserJet M453) - tcp/443"}},
		{second, []string{"Potential critical CVEs (Nginx) - tcp/9443", "Unauthenticated control - tcp/502"}},
	} {
		allow := &in.Snapshot.FirewallPolicies[0]
		allow.IPVersion, allow.Destination.AnyTarget, allow.Destination.IPs = "ipv6", false, []string{tc.ip}
		var got []string
		for _, e := range Evaluate(in).Simulation.Edges {
			if e.From == src.ID && e.To == dst.ID && (e.Tier == "likely" || e.Tier == "takeover") {
				got = append(got, e.Label)
			}
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("allow %s: got %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestSimulationWeakAuth keeps relay and SSH authentication risks on their observed sockets.
// Unrelated SSH hygiene has its own remedy and cannot create a control path.
func TestSimulationWeakAuth(t *testing.T) {
	in, src, dst := routedSimulation()
	in.Findings = []checks.Finding{
		{Client: dst, CheckID: "NERVA-SMB-SIGNING-NOT-REQUIRED", Port: 445, BaseSeverity: checks.SeverityMedium},
		{Client: dst, CheckID: "NERVA-SSH-WEAK-KEX", Port: 2222, BaseSeverity: checks.SeverityMedium},
		{Client: dst, CheckID: "NERVA-SMB-V1-ENABLED", Port: 445, BaseSeverity: checks.SeverityMedium},
		{Client: dst, CheckID: "NERVA-SSH-WEAK-CIPHER", Port: 2222, BaseSeverity: checks.SeverityMedium},
		{Client: dst, CheckID: "NERVA-SSH-WEAK-MAC", Port: 2222, BaseSeverity: checks.SeverityLow},
	}
	for _, tc := range []struct {
		methods []string
		none    bool
		label   string
	}{
		{[]string{"password"}, false, "SSH password auth"},
		{[]string{"keyboard-interactive"}, false, "SSH interactive auth"},
		{[]string{"keyboard-interactive", "password"}, false, "SSH password auth"},
		{[]string{"publickey"}, false, ""}, {[]string{"password"}, true, ""},
	} {
		in.Profiles = []probe.HostProfile{{Client: dst, ProbeIP: dst.IP, SSH: &probe.SSHInfo{
			Port: 2222, AuthMethods: tc.methods, NoneAuthAccepted: tc.none}}}
		want := map[string][]string{
			"Unsigned SMB (relay risk) - tcp/445": {"act:check:NERVA-SMB-SIGNING-NOT-REQUIRED:service:tcp/445", "act:vlan-egress:guest->lan"},
			"Weak SSH key exchange - tcp/2222":    {"act:check:NERVA-SSH-WEAK-KEX:service:tcp/2222", "act:vlan-egress:guest->lan"},
			"Legacy SMBv1 enabled - tcp/445":      {"act:check:NERVA-SMB-V1-ENABLED:service:tcp/445", "act:vlan-egress:guest->lan"},
			"Weak SSH cipher - tcp/2222":          {"act:check:NERVA-SSH-WEAK-CIPHER:service:tcp/2222", "act:vlan-egress:guest->lan"},
		}
		if tc.label != "" {
			want[tc.label+" - tcp/2222"] = []string{"act:vlan-egress:guest->lan"}
		}
		for _, e := range Evaluate(in).Simulation.Edges {
			if e.From != src.ID || e.To != dst.ID || e.Tier == "pivot" {
				continue
			}
			if cuts, ok := want[e.Label]; e.Tier != "likely" || !ok || !slices.Equal(cuts, e.CutIDs) {
				t.Errorf("auth %v: unexpected path %+v", tc, e)
			}
			delete(want, e.Label)
		}
		if len(want) > 0 {
			t.Errorf("auth %v: missing paths %v", tc, want)
		}
	}
}

// TestParseSimulationMode verifies the shared API and dashboard vocabulary.
func TestParseSimulationMode(t *testing.T) {
	for raw, want := range map[string]SimulationMode{
		"": ModeRealistic, "pRoVeN": ModeProven, "REALISTIC": ModeRealistic, "worst": ModeWorstCase,
	} {
		if got, err := ParseSimulationMode(raw); err != nil || got != want {
			t.Errorf("ParseSimulationMode(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"strict", "worst-case", "typo"} {
		if _, err := ParseSimulationMode(raw); err == nil {
			t.Errorf("accepted unknown mode %q", raw)
		}
	}
}

// TestSimulateHost exercises competing witnesses, equal-length paths, cycles
// and terminal exposure before and after applying hypothetical controls.
func TestSimulateHost(t *testing.T) {
	s := Simulation{Nodes: []SimNode{
		{ID: "root", Name: "Proxy", EgressCutIDs: []string{"egress"}},
		{ID: "b", Name: "BMC", Tier: "high"}, {ID: "a"}, {ID: "server", Tier: "crown"},
		{ID: "admin"}, {ID: "local", Tier: "high"}, {ID: "unseen"}, {ID: "conditional"}, {ID: "uncertain"},
	}}
	edge := func(from, to, tier string, cuts ...string) {
		s.Edges = append(s.Edges, SimEdge{From: from, To: to, Tier: tier, CutIDs: cuts})
	}
	edge("internet", "root", "wan", "wan")
	edge("internet", "b", "wan", "other-wan")
	edge("root", "a", "likely", "auth")
	edge("root", "b", "likely", "auth")
	edge("root", "b", "takeover", "patch")
	edge("root", "server", "l2", "isolate")
	edge("a", "server", "takeover", "second")
	s.Edges = append(s.Edges, SimEdge{From: "b", To: "server", Tier: "takeover",
		Label: "Manages server", Via: "Management relationship", CutIDs: []string{"managed"}})
	edge("b", "root", "takeover")
	edge("server", "admin", "pivot", "admin-login")
	edge("admin", "local", "l2", "isolate")
	edge("local", "unseen", "takeover", "out-of-scope")
	edge("local", "unseen", "unknown-takeover", "also-out-of-scope")
	edge("root", "b", "unknown-takeover")
	edge("b", "unseen", "unknown-takeover", "verify")
	edge("a", "conditional", "unknown-likely", "conditional-rule")
	edge("admin", "uncertain", "unknown", "unknown-rule")

	for _, tc := range []struct {
		mode                            SimulationMode
		cuts                            []string
		direct, cascade, l2             int
		paths, critical, unknown, fixes []string
	}{
		{ModeProven, nil, 1, 1, 0, []string{"b", "server"}, []string{"b", "server"}, []string{"unseen"},
			[]string{"egress", "managed", "patch", "verify", "wan"}},
		{ModeRealistic, nil, 2, 1, 0, []string{"b", "a", "server"}, []string{"b", "server"}, []string{"unseen", "conditional"},
			[]string{"auth", "conditional-rule", "egress", "managed", "patch", "second", "verify", "wan"}},
		{ModeWorstCase, nil, 2, 2, 1, []string{"b", "a", "server", "admin", "local"}, []string{"b", "server", "local"}, []string{"unseen", "conditional", "uncertain"},
			[]string{"admin-login", "auth", "conditional-rule", "egress", "isolate", "managed", "patch", "second", "unknown-rule", "verify", "wan"}},
		{ModeRealistic, []string{"patch", "verify"}, 2, 1, 0, []string{"b", "a", "server"}, []string{"b", "server"}, []string{"conditional"},
			[]string{"auth", "conditional-rule", "egress", "managed", "patch", "second", "verify", "wan"}},
		{ModeRealistic, []string{"patch", "auth", "patch"}, 0, 0, 0, nil, nil, []string{"b"},
			[]string{"auth", "conditional-rule", "egress", "managed", "patch", "second", "verify", "wan"}},
	} {
		t.Run(string(tc.mode)+"/"+strings.Join(tc.cuts, "+"), func(t *testing.T) {
			before := slices.Clone(tc.cuts)
			got, ok := s.SimulateHost("root", tc.mode, tc.cuts)
			if !ok || got.Host.ID != "root" || got.Mode != tc.mode || got.PeerCount != len(s.Nodes)-1 ||
				got.DirectReach != tc.direct || got.CascadedReach != tc.cascade || got.L2Exposed != tc.l2 || got.TotalReach != len(tc.paths) {
				t.Fatalf("unexpected reach: %+v", got)
			}
			if !slices.Equal(tc.cuts, before) || !slices.Equal(got.AppliedFixes, slices.Compact(slices.Sorted(slices.Values(before)))) {
				t.Fatalf("applied fixes %v for input %v", got.AppliedFixes, tc.cuts)
			}
			var paths, critical, unknown []string
			for _, p := range got.Paths {
				paths = append(paths, p.Target.ID)
				switch p.Target.ID {
				case "b":
					wantTier := "takeover"
					if slices.Contains(tc.cuts, "patch") {
						wantTier = "likely"
					}
					if p.Tier != wantTier || p.Hop != 1 {
						t.Errorf("parallel route = %+v", p)
					}
				case "server":
					if p.From != "b" || p.FromName != "BMC" || p.Hop != 2 || p.Tier != "takeover" || p.TerminalL2 ||
						p.Label != "Manages server" || p.Via != "Management relationship" || !slices.Equal(p.CutIDs, []string{"managed"}) {
						t.Errorf("management path = %+v", p)
					}
				case "local":
					if !p.TerminalL2 || p.Tier != "l2" || p.From != "admin" || p.Hop != 4 {
						t.Errorf("terminal path = %+v", p)
					}
				}
			}
			for _, n := range got.CriticalThreatened {
				critical = append(critical, n.ID)
			}
			for _, n := range got.UnknownTargets {
				unknown = append(unknown, n.ID)
			}
			if !slices.Equal(paths, tc.paths) || !slices.Equal(critical, tc.critical) ||
				!slices.Equal(unknown, tc.unknown) || !slices.Equal(got.RelevantFixes, tc.fixes) {
				t.Errorf("paths %v, critical %v, unknown %v, relevant fixes %v", paths, critical, unknown, got.RelevantFixes)
			}
		})
	}
	empty, ok := s.SimulateHost("unseen", ModeWorstCase, nil)
	if !ok || empty.Paths == nil || empty.UnknownTargets == nil || empty.CriticalThreatened == nil || empty.RelevantFixes == nil {
		t.Errorf("isolated host: %+v", empty)
	}
	if _, ok := s.SimulateHost("absent", ModeRealistic, nil); ok {
		t.Error("simulated absent host")
	}
	t.Run("equal-tier witnesses", func(t *testing.T) {
		s := s
		s.Edges = append(slices.Clone(s.Edges), SimEdge{From: "b", To: "server", Tier: "takeover", Label: "Second witness"})
		for _, tc := range []struct {
			cuts []string
			want string
		}{{nil, "Manages server"}, {[]string{"managed"}, "Second witness"}} {
			got, _ := s.SimulateHost("b", ModeProven, tc.cuts)
			if !slices.ContainsFunc(got.Paths, func(p HostBlastPath) bool {
				return p.Target.ID == "server" && p.From == "b" && p.Label == tc.want
			}) {
				t.Errorf("fixes %v: missing witness %q in %+v", tc.cuts, tc.want, got.Paths)
			}
		}
	})
	t.Run("entry and egress", func(t *testing.T) {
		s := Simulation{
			Nodes: []SimNode{{ID: "proxy", Tier: "high", EntryExposure: "WAN TCP/443", LocalExposure: "Local LAN",
				InternetState: cloudCapable, EgressCutIDs: []string{"lan", "wifi"}}, {ID: "peer"}, {ID: "uncertain"}},
			Edges: []SimEdge{
				{From: "internet", To: "proxy", Tier: "wan", Label: "WAN TCP/22 (restricted)", CutIDs: []string{"ssh"}},
				{From: "internet", To: "proxy", Tier: "wan", Label: "WAN TCP/443", CutIDs: []string{"https"}},
				{From: "peer", To: "proxy", Tier: "takeover"},
				{From: "uncertain", To: "proxy", Tier: "unknown-takeover"},
			},
		}
		for _, tc := range []struct {
			cuts          []string
			entry, egress string
		}{
			{[]string{"https", "lan"}, "WAN TCP/22 (restricted)", cloudCapable},
			{[]string{"https", "ssh", "lan", "wifi"}, "Local LAN", localOnly},
			{nil, "WAN TCP/443", cloudCapable},
		} {
			got, _ := s.SimulateHost("proxy", ModeRealistic, tc.cuts)
			peer, _ := s.SimulateHost("peer", ModeRealistic, tc.cuts)
			uncertain, _ := s.SimulateHost("uncertain", ModeRealistic, tc.cuts)
			if len(peer.Paths) != 1 || len(peer.CriticalThreatened) != 1 || len(uncertain.UnknownTargets) != 1 {
				t.Fatal("expected proxy as a reached, critical, and unknown target")
			}
			for _, n := range []SimNode{got.Host, peer.Paths[0].Target, peer.CriticalThreatened[0], uncertain.UnknownTargets[0]} {
				if n.ID != "proxy" || n.EntryExposure != tc.entry || n.InternetState != tc.egress {
					t.Errorf("fixes %v: %s has entry %q and egress %q, want %q and %q", tc.cuts, n.ID, n.EntryExposure, n.InternetState, tc.entry, tc.egress)
				}
			}
		}
	})
}

// TestSimulationManagementControl checks that hardware ownership survives network isolation.
func TestSimulationManagementControl(t *testing.T) {
	bmc, host, vm := client("bmc", "192.0.2.1", "management"), client("server", "198.51.100.1", "servers"), client("vm", "203.0.113.1", "guests")
	in := Input{Snapshot: &unifi.Snapshot{Clients: []unifi.Client{bmc, host, vm}},
		Assets: map[string]classify.AssetProfile{"bmc": {Manages: []string{host.ID}}, "server": {Hosts: []string{vm.ID}}}}
	want := map[string]string{bmc.ID: host.ID, host.ID: vm.ID}
	for _, e := range Evaluate(in).Simulation.Edges {
		if e.Tier == "takeover" {
			if want[e.From] != e.To || len(e.CutIDs) != 0 {
				t.Error(e)
			}
			delete(want, e.From)
		}
	}
	if len(want) != 0 {
		t.Fatal("missing hardware control", want)
	}
}

// TestInventoryGrants checks that discovery can leave a conditional question
// without turning an ordinary time reply into a read-access consequence.
func TestInventoryGrants(t *testing.T) {
	catalog, err := checks.LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		t.Fatal(err)
	}
	cl := client("server", "192.0.2.2", "lan")
	r := Evaluate(Input{Snapshot: &unifi.Snapshot{Clients: []unifi.Client{cl}}, Checks: catalog, Findings: []checks.Finding{
		{Client: cl, CheckID: "UB-0011", ClaimKind: checks.ClaimServiceObserved, BaseSeverity: checks.SeverityInfo, Category: "service-inventory", Transport: "udp", Port: 123},
		{Client: cl, CheckID: "UB-0014", Transport: "udp", Port: 5351},
	}})
	for _, a := range r.Actions {
		if strings.Contains(a.ID, "UB-0011") || (strings.Contains(a.ID, "UB-0014") && a.Lane != LaneVerify) {
			t.Fatal(a)
		}
	}
	for _, x := range r.Exposures {
		if x.Asset == cl.ID && x.Consequence == "read" {
			t.Fatal(x)
		}
	}
	action(t, r, "act:verify:UB-0014:server:udp/5351")
}

// TestSimulationInfrastructurePaths distinguishes control of adopted equipment
// from the VLANs and client attachments each device actually serves.
func TestSimulationInfrastructurePaths(t *testing.T) {
	const gw, sw, ap, leaf = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03", "02:00:00:00:00:04"
	camera := client("camera", "192.0.2.2", "cameras")
	camera.IsWired, camera.SwitchMAC = true, leaf
	phone := client("phone", "198.51.100.2", "staff")
	phone.APMAC = ap
	s := &unifi.Snapshot{
		Devices:  []unifi.Device{{MAC: gw, Type: "udm"}, {MAC: sw, Type: "usw", UplinkMAC: gw}, {MAC: ap, Type: "uap", UplinkMAC: sw}, {MAC: leaf, Type: "usw", UplinkMAC: sw}},
		Networks: []unifi.Network{{ID: "cameras", Name: "Cameras", VLAN: "3", IsolationEnabled: true}, {ID: "staff", Name: "Staff", RouterDeviceMAC: sw}},
		Clients:  []unifi.Client{camera, phone},
	}
	edges := Evaluate(Input{Snapshot: s}).Simulation.Edges
	for _, want := range []SimEdge{
		{From: gw, To: sw, Tier: "takeover", Label: "Managed UniFi gear", Via: "Controller owns device config"},
		{From: gw, To: ap, Tier: "takeover", Label: "Managed UniFi gear", Via: "Controller owns device config"},
		{From: gw, To: camera.ID, Tier: "pivot", Label: "Routed VLAN gateway", Via: "Routes Cameras"},
		{From: sw, To: phone.ID, Tier: "pivot", Label: "Routed VLAN gateway", Via: "Routes Staff"},
		{From: sw, To: ap, Tier: "pivot", Label: "Downstream UniFi gear", Via: "Switch uplink"},
		{From: sw, To: leaf, Tier: "pivot", Label: "Downstream UniFi gear", Via: "Switch uplink"},
		{From: leaf, To: camera.ID, Tier: "pivot", Label: "Wired client", Via: "Direct switch port"},
		{From: ap, To: phone.ID, Tier: "pivot", Label: "Wireless client", Via: "Associated with AP"},
	} {
		if !slices.ContainsFunc(edges, func(e SimEdge) bool { return reflect.DeepEqual(e, want) }) {
			t.Errorf("missing infrastructure path: %+v", want)
		}
	}
	for _, e := range edges {
		if (e.From == gw && e.To == phone.ID) || (e.From == sw && e.To == camera.ID) {
			t.Errorf("indirect route reported as a direct attachment: %+v", e)
		}
	}
	const cloudKey = "02:00:00:00:00:05"
	s.Devices[0].Type = "uxg"
	s.Devices = append(s.Devices, unifi.Device{MAC: cloudKey, Type: "uck"})
	edges = Evaluate(Input{Snapshot: s}).Simulation.Edges
	if !slices.ContainsFunc(edges, func(e SimEdge) bool { return e.From == cloudKey && e.To == gw && e.Tier == "takeover" }) ||
		slices.ContainsFunc(edges, func(e SimEdge) bool { return e.From == gw && e.Tier == "takeover" }) {
		t.Error("a standalone gateway must be managed by its Cloud Key")
	}
}

// TestPublicListenerPosture checks WAN priority and simulator entry against listener evidence.
func TestPublicListenerPosture(t *testing.T) {
	cl := client("server", "192.0.2.20", "lan")
	for _, tc := range []struct {
		name             string
		port             int
		methods          []string
		open, vulnerable bool
		lane             Lane
		tier             Priority
	}{
		{"HTTP", 80, nil, false, false, LaneReduceExposure, P3}, {"HTTPS", 443, nil, false, false, LaneReduceExposure, P3},
		{"vulnerable HTTPS", 443, nil, false, true, LaneFixNow, P1}, {"SSH key", 22, []string{"publickey"}, false, false, LaneReduceExposure, P3},
		{"SSH password", 22, []string{"publickey", "password"}, false, false, LaneFixNow, P1}, {"SSH interactive", 22, []string{"keyboard-interactive"}, false, false, LaneFixNow, P1},
		{"SSH advertised none", 22, []string{"none"}, false, false, LaneReduceExposure, P3}, {"SSH none", 22, nil, true, false, LaneFixNow, P1}, {"SSH unknown", 22, nil, false, false, LaneReduceExposure, P3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := strconv.Itoa(tc.port)
			pf := unifi.PortForward{ID: "forward", Enabled: true, Proto: "tcp", DstPort: port, FwdIP: cl.IP, FwdPort: port}
			in := Input{Snapshot: &unifi.Snapshot{Networks: []unifi.Network{network("lan")}, Clients: []unifi.Client{cl}, PortForwards: []unifi.PortForward{pf}, Visibility: &unifi.SiteVisibility{PortForwardsAvailable: true, GatewayPoliciesAvailable: true}},
				Assets: map[string]classify.AssetProfile{cl.ID: {Tier: classify.TierHigh}}, TargetSignals: []TargetSignal{{Asset: cl.ID, Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}}},
				Profiles: []probe.HostProfile{{Client: cl, ProbeIP: cl.IP, SSH: &probe.SSHInfo{Port: 22, AuthMethods: tc.methods, NoneAuthAccepted: tc.open}}}}
			if tc.vulnerable {
				observed(&in, cl, tc.port, checks.GrantControl)
			}
			r := Evaluate(in)
			if a := action(t, r, "act:wan-pf:forward"); a.Lane != tc.lane || a.HighestTierReduced != tc.tier {
				t.Fatal(a)
			}
			if !slices.ContainsFunc(r.Simulation.Edges, func(e SimEdge) bool { return e.To == cl.ID && e.Tier == "wan" }) {
				t.Fatal("lost WAN entry")
			}
			verify := slices.ContainsFunc(r.Actions, func(a Action) bool { return a.Lane == LaneVerify && strings.HasPrefix(a.ID, "act:verify:ssh-auth:") })
			if verify != (tc.name == "SSH unknown" || tc.name == "SSH key" || tc.name == "SSH advertised none") {
				t.Fatal("unexpected SSH verification status", verify)
			}
		})
	}
}

// TestGatewaySSHScope separates a confirmed TCP/22 rule from broad gateway access.
func TestGatewaySSHScope(t *testing.T) {
	gw := unifi.Device{MAC: "02:00:00:00:00:01", IP: "192.0.2.1", Type: "udm"}
	policy := allow("External", "Gateway")
	policy.Protocol = "tcp"
	policy.Destination.AnyPort, policy.Destination.Ports = false, []int{22}
	snap := &unifi.Snapshot{Devices: []unifi.Device{gw}, FirewallPolicies: []unifi.FirewallPolicy{policy}}
	in := Input{Snapshot: snap, Assets: map[string]classify.AssetProfile{gw.MAC: {Tier: classify.TierCrown}}}
	for _, tc := range []struct {
		settings *unifi.SiteSecuritySettings
		want     Priority
	}{
		{nil, P3}, {&unifi.SiteSecuritySettings{SSHEnabled: true, SSHPasswordAuthKnown: true}, P3},
		{&unifi.SiteSecuritySettings{SSHPasswordAuth: true}, P1},
	} {
		snap.SecuritySettings = tc.settings
		r := Evaluate(in)
		verify := slices.ContainsFunc(r.Actions, func(a Action) bool {
			return strings.HasPrefix(a.ID, "act:verify:ssh-auth:") && strings.Contains(a.Reason, "unknown")
		})
		if verify != (tc.want == P3) {
			t.Fatal("console SSH verification", tc.settings, verify)
		}
		if a := action(t, r, "act:gateway-local:"+policy.ID); a.HighestTierReduced != tc.want {
			t.Fatal(a)
		}
	}
}

// TestApplianceOnSharedNetworks preserves internet access for ordinary and guest devices.
func TestApplianceOnSharedNetworks(t *testing.T) {
	for _, zone := range []string{"Internal", "Hotspot"} {
		cl := client("printer", "192.0.2.31", "shared")
		cl.MAC = "02:00:00:00:00:31"
		n := network("shared")
		n.Name, n.ZoneName = "Default", zone
		if zone == "Hotspot" {
			n.Name = "Guest"
			n.IsolationEnabled = true
		}
		in := Input{Snapshot: &unifi.Snapshot{Networks: []unifi.Network{n}, Clients: []unifi.Client{cl}, FirewallPolicies: []unifi.FirewallPolicy{allow(zone, "External")}}, Profiles: []probe.HostProfile{{Client: cl, OpenPorts: []int{631}}}}
		r := Evaluate(in)
		if a := action(t, r, "act:move-iot:shared"); a.Lane != LaneReduceExposure || a.HighestTierReduced == "" {
			t.Fatal(a)
		}
		if exposure(t, r, AssumeBreach, cl.MAC, "shared network placement on "+n.Name).Lane != LaneReduceExposure ||
			slices.ContainsFunc(r.Exposures, func(x Exposure) bool { return x.Entry == CloudEgress && x.Consequence == "internet access" }) ||
			len(r.Simulation.Nodes[0].EgressCutIDs) > 0 {
			t.Fatal(r.Exposures)
		}
		if slices.ContainsFunc(r.Actions, func(a Action) bool { return a.ID == "act:vlan-egress:shared->internet" }) {
			t.Fatal(zone, "blanket egress cut")
		}
	}
}

// TestServiceRemedyBundles checks credit for controls that remove every parallel witness.
func TestServiceRemedyBundles(t *testing.T) {
	cl := client("compute", "192.0.2.9", "lan")
	in := Input{Snapshot: &unifi.Snapshot{Clients: []unifi.Client{cl}, Networks: []unifi.Network{network("lan")}},
		Checks: []*checks.Check{{ID: "UB-0002", Title: "Passwordless VNC", Grants: []checks.GrantSpec{{Effect: checks.GrantControl, Basis: checks.BasisProven}}}}}
	for _, p := range []int{5900, 5901} {
		in.Findings = append(in.Findings, checks.Finding{CheckID: "UB-0002", Client: cl, Port: p, BaseSeverity: checks.SeverityCritical})
	}
	product := cve.Product{HostIP: cl.IP, Label: "Web Server", Ports: []cve.EndpointPort{{Transport: "tcp", Port: 443}}}
	for _, id := range []string{"CVE-2022-1000", "CVE-2023-1000"} {
		m := cve.Match{Product: product, Record: cve.Record{ID: id, Severity: checks.SeverityCritical, AttackVector: "N"}, Confidence: cve.ConfidenceExact}
		in.CVEMatches = append(in.CVEMatches, m)
		proxy := m
		proxy.Product.Label = "Proxy"
		proxy.Record.ID = strings.Replace(id, "1000", "2000", 1)
		in.CVEMatches = append(in.CVEMatches, proxy)
		m.Product = cve.Product{HostIP: cl.IP, Label: "Printer OS"}
		m.Confidence = cve.ConfidencePotential
		in.CVEMatches = append(in.CVEMatches, m)
	}
	for _, tc := range []struct{ label, version, vector string }{
		{"Packaged OS", "3.2", "N"}, {"Local Printer", "", "L"}, {"Local Package", "4.1", "L"},
	} {
		in.CVEMatches = append(in.CVEMatches, cve.Match{Product: cve.Product{Label: tc.label, HostIP: cl.IP, Version: tc.version}, Record: cve.Record{KEV: true, AttackVector: tc.vector}, Confidence: cve.ConfidencePotential})
	}
	r := Evaluate(in)
	for _, id := range []string{"act:check-host:UB-0002:compute", "act:patch-product:web-server:compute", "act:patch-product:proxy:compute"} {
		if a := action(t, r, id); a.HighestTierReduced == "" || a.Lane != LaneFixNow {
			t.Fatal(a)
		}
	}
	if a := action(t, r, "act:verify:potential:compute:packaged-os"); a.Lane != LaneVerify || !strings.Contains(a.Reason, "version was reported") {
		t.Fatal(a)
	}
	for _, a := range r.Actions {
		if strings.HasPrefix(a.ID, "act:verify:") && (strings.Contains(a.ID, ":local-") || a.ID == "act:verify:unversioned:compute:packaged-os") {
			t.Fatal(a)
		}
	}
	notices := 0
	for _, a := range r.Actions {
		if a.ID == "act:verify:unversioned:compute:printer-os" && a.Lane == LaneVerify {
			notices++
		}
	}
	if notices != 1 {
		t.Fatal("unversioned verification count", notices)
	}
}

// TestSwitchOutdoorBundle confirms that two exposed sockets require a shared remedy.
func TestSwitchOutdoorBundle(t *testing.T) {
	cl := client("recorder", "192.0.2.10", "storage")
	sw := risk.SwitchDeviceView{MAC: "02:00:00:00:00:09", Name: "Garden"}
	for _, p := range []int{1, 2} {
		sw.Ports = append(sw.Ports, risk.SwitchPortView{PortIdx: p, Enabled: true, Zone: "external", NativeVLAN: "cameras"})
	}
	in := Input{SwitchPorts: []risk.SwitchDeviceView{sw}, Snapshot: &unifi.Snapshot{Clients: []unifi.Client{cl}, Networks: []unifi.Network{network("cameras"), network("storage")}, FirewallPolicies: []unifi.FirewallPolicy{allow("cameras", "storage")}}}
	observed(&in, cl, 5900, checks.GrantControl)
	if a := action(t, Evaluate(in), "act:port-ext-switch:"+sw.MAC); a.HighestTierReduced == "" || a.Lane != LaneReduceExposure {
		t.Fatal(a)
	}
}

// TestLocalServiceHygiene keeps low-priority maintenance and LAN-only SNMP out of Fix now.
func TestLocalServiceHygiene(t *testing.T) {
	cl := client("storage", "192.0.2.7", "servers")
	in := Input{Snapshot: &unifi.Snapshot{Clients: []unifi.Client{cl}, Networks: []unifi.Network{network("servers")}},
		Assets: map[string]classify.AssetProfile{cl.ID: {Tier: classify.TierHigh}},
		Findings: []checks.Finding{{CheckID: "NERVA-SSH-WEAK-MAC", Port: 22, Client: cl, BaseSeverity: checks.SeverityLow},
			{CheckID: "UB-0012", Port: 161, Client: cl, BaseSeverity: checks.SeverityMedium}},
		Checks: []*checks.Check{{ID: "UB-0012", Grants: []checks.GrantSpec{{Effect: checks.GrantRead, Basis: checks.BasisProven}}}}}
	r := Evaluate(in)
	if a := action(t, r, "act:check:NERVA-SSH-WEAK-MAC:storage:tcp/22"); a.HighestTierReduced != P4 {
		t.Fatal(a)
	}
	if a := action(t, r, "act:check:UB-0012:storage:161:udp"); a.Lane != LaneReduceExposure {
		t.Fatal(a)
	}
}

// TestDNSListenerScope distinguishes private LAN service traits from public or unresolved sockets.
func TestDNSListenerScope(t *testing.T) {
	cl := client("resolver", "10.0.0.53", "lan")
	for _, proto := range []string{"tcp", "udp"} {
		hp := probe.HostProfile{Client: cl, Services: []probe.Service{{Protocol: "dns", Port: 53, Transport: proto}}}
		s := &unifi.Snapshot{Clients: []unifi.Client{cl}, Networks: []unifi.Network{network("lan")}, Visibility: &unifi.SiteVisibility{PortForwardsAvailable: true, GatewayPoliciesAvailable: true}}
		in := Input{Snapshot: s, Profiles: []probe.HostProfile{hp}}
		has := func() bool {
			return slices.ContainsFunc(Evaluate(in).Actions, func(a Action) bool { return a.ID == "act:service:resolver:"+proto+"/53" })
		}
		if has() {
			t.Fatal(proto, "local DNS trait")
		}
		s.DynamicMappings = []unifi.DynamicPortMapping{{InternalIP: cl.IP, Transport: proto, IntPort: 53, ExtPort: 5353}}
		if !has() {
			t.Fatal(proto, "missing mapped DNS trait")
		}
		s.DynamicMappings = nil
		s.Visibility.GatewayPoliciesAvailable = false
		if !has() {
			t.Fatal(proto, "unknown visibility suppressed DNS")
		}
	}
}

// TestDNSOnlyTransit keeps generic transit separate from a system DNS exception.
func TestDNSOnlyTransit(t *testing.T) {
	src, dst := network("guest"), network("lan")
	src.ZoneName, dst.ZoneName = "Hotspot", "Internal"
	dns := allow("Hotspot", "Internal")
	dns.ID, dns.Name, dns.Origin, dns.Protocol = "dns", "Allow Public DNS", "SYSTEM_DEFINED", "tcp_udp"
	dns.Destination.AnyPort, dns.Destination.Ports = false, []int{53}
	extra := dns
	extra.ID, extra.Index, extra.Destination.Ports = "web", 10, []int{443}
	for _, tc := range []struct {
		name   string
		rules  []unifi.FirewallPolicy
		ranked bool
	}{
		{"built-in", []unifi.FirewallPolicy{dns}, false},
		{"independent opening", []unifi.FirewallPolicy{dns, extra}, true},
	} {
		s := &unifi.Snapshot{Networks: []unifi.Network{src, dst}, Clients: []unifi.Client{client("guest", "198.51.100.2", "guest"), client("lan", "192.0.2.2", "lan")}, FirewallPolicies: tc.rules}
		got := slices.ContainsFunc(Evaluate(Input{Snapshot: s}).Actions, func(a Action) bool { return a.ID == "act:vlan-egress:guest->lan" && a.HighestTierReduced != "" })
		if got != tc.ranked {
			t.Errorf("%s: ranked = %t", tc.name, got)
		}
	}
}

// TestDualStackWANListeners exercises actual IPv6 firewall rules alongside IPv4 forwards.
func TestDualStackWANListeners(t *testing.T) {
	cl := client("dual", "192.0.2.2", "lan")
	cl.IPv6 = []string{"2001:db8::2"}
	rule := allow("External", "lan")
	rule.Protocol, rule.IPVersion = "tcp", "ipv6"
	rule.Destination.AnyPort, rule.Destination.Ports = false, []int{22}
	in := Input{Snapshot: &unifi.Snapshot{Clients: []unifi.Client{cl}, Networks: []unifi.Network{network("lan")}, FirewallPolicies: []unifi.FirewallPolicy{rule}},
		Assets:   map[string]classify.AssetProfile{cl.ID: {Tier: classify.TierCrown}},
		Profiles: []probe.HostProfile{{Client: cl, ProbeIP: cl.IP, SSH: &probe.SSHInfo{Port: 22, AuthMethods: []string{"keyboard-interactive"}}}}}
	id := "act:gateway-routed:" + rule.ID
	r := Evaluate(in)
	if a := action(t, r, id); a.Lane != LaneFixNow || a.HighestTierReduced != P1 {
		t.Fatal(a)
	}
	in.Profiles[0].SSH.AuthMethods = []string{"publickey"}
	if a := action(t, Evaluate(in), "act:verify:ssh-auth:dual:"+cl.IPv6[0]); !strings.Contains(a.Reason, "unknown") {
		t.Fatal(a)
	}
	in.Profiles[0].SSH.NoneAuthAccepted = true
	in.Profiles = append(in.Profiles, probe.HostProfile{Client: cl, ProbeIP: cl.IPv6[0], SSH: &probe.SSHInfo{Port: 22, AuthMethods: []string{"publickey"}}})
	r = Evaluate(in)
	if a := action(t, r, id); a.Lane != LaneReduceExposure {
		t.Fatal(a)
	}
	if a := action(t, r, "act:verify:ssh-auth:dual:"+cl.IPv6[0]); !strings.Contains(a.Reason, "only public-key") {
		t.Fatal(a)
	}
	in.Snapshot.FirewallPolicies[0].Destination.Ports = []int{80, 443}
	in.Snapshot.PortForwards = []unifi.PortForward{{ID: "web", Enabled: true, Proto: "tcp", FwdIP: cl.IP, DstPort: "80,443"}}
	r = Evaluate(in)
	for _, id := range []string{"act:wan-pf:web", id, "act:wan-service:dual:tcp/443"} {
		if a := action(t, r, id); a.Lane != LaneReduceExposure || (a.HighestTierReduced != "" && a.HighestTierReduced != P3) {
			t.Fatal(a)
		}
	}
	in.Snapshot.PortForwards[0].DstPort = "80-89"
	if a := action(t, Evaluate(in), "act:wan-pf:web"); a.Lane != LaneFixNow {
		t.Fatal(a)
	}
	in.Snapshot.PortForwards[0].Name, in.Snapshot.PortForwards[0].DstPort = "NAS admin", "443"
	in.Snapshot.FirewallPolicies[0].Name, in.Snapshot.FirewallPolicies[0].Destination.Ports = "NAS admin", []int{443}
	r = Evaluate(in)
	for _, route := range []string{"act:wan-pf:web", id} {
		if a := action(t, r, route); a.Lane != LaneFixNow {
			t.Fatal(a)
		}
	}
}

// TestStrictSSHRemedy binds confirmed unauthenticated login to its observed listener.
func TestStrictSSHRemedy(t *testing.T) {
	src, dst := client("source", "192.0.2.2", "lan"), client("server", "198.51.100.2", "lab")
	hp := probe.HostProfile{Client: dst, ProbeIP: dst.IP, SSH: &probe.SSHInfo{Port: 22, NoneAuthAccepted: true}}
	in := Input{Snapshot: &unifi.Snapshot{Clients: []unifi.Client{src, dst}, Networks: []unifi.Network{network("lan"), network("lab")}, FirewallPolicies: []unifi.FirewallPolicy{allow("lan", "lab")}}, Profiles: []probe.HostProfile{hp}}
	in.Findings = checks.FindingsFromProfiles(in.Profiles, nil)
	r := Evaluate(in)
	id := "act:check:UB-SSH-NONE-AUTH:server:22"
	if !slices.ContainsFunc(r.Simulation.Edges, func(e SimEdge) bool {
		return e.From == src.ID && e.To == dst.ID && e.Tier == "takeover" && slices.Contains(e.CutIDs, id)
	}) {
		t.Fatal(r.Simulation.Edges)
	}
}

// TestGatewayManagementBundle preserves approved DNS for all sources of a gateway cut.
func TestGatewayManagementBundle(t *testing.T) {
	gw := unifi.Device{MAC: "02:00:00:00:00:01", IP: "192.0.2.1", Type: "udm"}
	lan, iot := network("Default"), network("IoT")
	lan.ZoneName = "Internal"
	s := &unifi.Snapshot{Devices: []unifi.Device{gw}, Networks: []unifi.Network{lan, iot}, WLANs: []unifi.WLANConfig{{Enabled: true, Security: "open", NetworkID: lan.ID, Name: "wifi"}}, FirewallPolicies: []unifi.FirewallPolicy{allow("Internal", "Gateway"), allow("IoT", "Gateway")}}
	in := Input{Snapshot: s, NetCfg: config.NetworkConfig{IsolationPolicy: config.IsolationIntent{IoTVLANs: []string{"IoT"}, ApprovedPaths: []config.ApprovedPath{
		{Name: "DNS", DestZone: "Gateway", Transport: "udp", Port: 53}, {Name: "Admin", DestZone: "Gateway", Transport: "tcp", Port: 443},
	}}}}
	vlan := network("user-vlan")
	vlan.Name = "Gateway"
	s.Networks = append(s.Networks, vlan)
	s.Clients = append(s.Clients, client("storage", "198.51.100.2", vlan.ID))
	s.FirewallPolicies = append(s.FirewallPolicies, allow("Internal", vlan.ZoneName), allow("IoT", vlan.ZoneName))
	r := Evaluate(in)
	for _, id := range []string{"act:vlan-egress:Default->" + risk.GatewayNetworkID, "act:vlan-ingress:" + risk.GatewayNetworkID} {
		a := action(t, r, id)
		if !strings.Contains(a.Title, "Gateway management") || !slices.Equal(a.BreaksApproved, []string{"Admin"}) {
			t.Fatal(a)
		}
	}
	for _, id := range []string{"act:vlan-egress:Default->" + vlan.ID, "act:vlan-ingress:" + vlan.ID} {
		if a := action(t, r, id); strings.Contains(a.Title, "Gateway management") || len(a.BreaksApproved) > 0 {
			t.Fatal(a)
		}
	}
}

// TestBundleCutsHighProfileEvidence leaves the ordinary parallel path reachable.
func TestBundleCutsHighProfileEvidence(t *testing.T) {
	g := graph{ids: map[fact]int{}, highProfileSources: map[int][]highProfileEdge{}}
	s := socket{host: "web", ip: "192.0.2.1", proto: "tcp", port: 443}.fact()
	cf := fact{consequence, "web", "control"}
	g.link(s, cf, trivial, 1, 0)
	g.markHighProfile(s, s)
	g.edges[g.ids[s]][0].bundle = 2
	g.link(s, cf, trivial, 3, 0)
	dist := []uint8{trivial, trivial}
	if !g.isHighProfileIn(g.ids[cf], cf, dist, nil, nil) || g.isHighProfileIn(g.ids[cf], cf, dist, nil, []bool{false, false, true, false}) {
		t.Fatal("bundle did not remove high-profile evidence")
	}
}

// TestSwitchRoutingLabel identifies the inter-VLAN hop for a reachable management service.
func TestSwitchRoutingLabel(t *testing.T) {
	const sw = "02:00:00:00:00:02"
	a, b := network("a"), network("b")
	a.RouterDeviceMAC, b.RouterDeviceMAC = sw, sw
	src, dst := client("source", "192.0.2.2", "a"), client("target", "198.51.100.2", "b")
	in := Input{Snapshot: &unifi.Snapshot{Clients: []unifi.Client{src, dst}, Networks: []unifi.Network{a, b}, Devices: []unifi.Device{{MAC: sw, Type: "usw"}}, SwitchACLCoverage: &unifi.SwitchACLCoverage{Status: "complete"}, Visibility: &unifi.SiteVisibility{SwitchACLsAvailable: true}}, Profiles: []probe.HostProfile{{Client: dst, ProbeIP: dst.IP, OpenPorts: []int{22}}}}
	r := Evaluate(in)
	if !slices.ContainsFunc(r.Simulation.Edges, func(e SimEdge) bool {
		return e.From == src.ID && e.To == dst.ID && e.Via == "Switch routing from a to b"
	}) {
		t.Fatal(r.Simulation.Edges)
	}
}

// TestKeyOnlyHygiene caps the remaining benefit of a public SSH restriction on a high-profile host.
func TestKeyOnlyHygiene(t *testing.T) {
	cl := client("storage", "192.0.2.7", "lan")
	in := Input{Snapshot: &unifi.Snapshot{Visibility: &unifi.SiteVisibility{PortForwardsAvailable: true, GatewayPoliciesAvailable: true}, Clients: []unifi.Client{cl}, Networks: []unifi.Network{network("lan")}, PortForwards: []unifi.PortForward{{ID: "ssh", Enabled: true, FwdIP: cl.IP, Proto: "tcp", DstPort: "22"}}},
		Assets:        map[string]classify.AssetProfile{cl.ID: {Tier: classify.TierCrown}},
		TargetSignals: []TargetSignal{{Asset: cl.ID, Velocity: cve.TargetVelocity{Class: cve.VelocityHighProfile}}},
		Profiles:      []probe.HostProfile{{Client: cl, ProbeIP: cl.IP, SSH: &probe.SSHInfo{Port: 22, AuthMethods: []string{"publickey"}}}},
		Findings:      []checks.Finding{{CheckID: "NERVA-SSH-WEAK-MAC", Port: 22, Client: cl, BaseSeverity: checks.SeverityLow}}}
	r := Evaluate(in)
	if x := exposure(t, r, Internet, cl.ID, "service setting: NERVA-SSH-WEAK-MAC"); x.Priority != P3 {
		t.Fatal(x)
	}
	if a := action(t, r, "act:wan-pf:ssh"); a.HighestTierReduced != P3 || a.Lane != LaneReduceExposure {
		t.Fatal(a)
	}
	for _, method := range []string{"password", "none"} {
		in.Snapshot.PortForwards[0].Src = "198.51.100.1"
		in.Profiles[0].SSH.AuthMethods = []string{method}
		in.Profiles[0].SSH.NoneAuthAccepted = method == "none"
		if a := action(t, Evaluate(in), "act:wan-pf:ssh"); a.Lane != LaneReduceExposure {
			t.Fatal(a)
		}
	}
}
