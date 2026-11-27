// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import (
	"cmp"
	"slices"
	"strings"

	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// SimNode describes one selectable inventory asset.
type SimNode struct {
	// ID identifies the asset across scans and network attachments.
	ID string `json:"id"`
	// EntityID opens the matching dashboard drawer.
	EntityID string `json:"entity_id"`
	// Name is the inventory display name.
	Name string `json:"name"`
	// IP is the displayed attachment's address.
	IP string `json:"ip,omitempty"`
	// VLAN identifies the displayed network.
	VLAN string `json:"vlan"`
	// Zone identifies the firewall zone of that network.
	Zone string `json:"zone,omitempty"`
	// Role is a short classification for the node badge.
	Role string `json:"role"`
	// Tier is the asset's impact classification.
	Tier string `json:"tier"`
	// EntryExposure describes the strongest baseline entry.
	EntryExposure string `json:"entry_exposure"`
	// LocalExposure describes entry after all public routes are closed.
	LocalExposure string `json:"local_exposure"`
	// InternetState summarizes observed cloud use or outbound policy.
	InternetState string `json:"internet_state"`
	// EgressCutIDs lists the VLAN controls needed to close every allowed internet path.
	EgressCutIDs []string `json:"egress_cut_ids,omitempty"`
	// IsDevice identifies adopted infrastructure.
	IsDevice bool `json:"is_device,omitempty"`
}

// SimEdge describes a potential route between assets.
type SimEdge struct {
	// From identifies the source asset or the internet.
	From string `json:"from"`
	// To identifies the destination asset.
	To string `json:"to"`
	// Tier distinguishes WAN entry, takeover, admin pivot, L2 peer reach and unknown reachability.
	Tier string `json:"tier"`
	// Label describes the service or permission on this route.
	Label string `json:"label"`
	// Via identifies the governing policy or network path.
	Via string `json:"via,omitempty"`
	// CutIDs are alternative actions that each sever this particular route.
	CutIDs []string `json:"cut_ids,omitempty"`
}

// Simulation contains the policy graph shared by the live and offline dashboards.
type Simulation struct {
	// PolicyCount counts the policies, ACLs and forwards in the snapshot.
	PolicyCount int `json:"policy_count"`
	// InventoryCount includes assets outside the interactive map's size limit.
	InventoryCount int `json:"inventory_count"`
	// Nodes lists the selectable inventory assets.
	Nodes []SimNode `json:"nodes"`
	// Edges preserves parallel routes with independent remedies.
	Edges []SimEdge `json:"edges"`
}

// listenerRemedies selects exact remote CVEs and evidenced anonymous grants.
// Conditional observations and generic configuration reviews cannot turn an
// intentional VPN or peering listener into a public vulnerability.
func (b *builder) listenerRemedies(s socket) []edge {
	i, ok := b.ids[s.fact()]
	if !ok {
		return nil
	}
	var out []edge
	for _, e := range b.edges[i] {
		if e.cut == 0 || b.facts[e.to].kind != consequence {
			continue
		}
		id := b.actions[e.cut].ID
		if strings.HasPrefix(id, "act:patch:") || (strings.HasPrefix(id, "act:check:") && e.level < moderate && !strings.HasPrefix(b.facts[e.to].detail, "service setting: ")) {
			out = append(out, e)
		}
	}
	return out
}

// simListeners indexes takeover evidence by socket so a patch never closes an
// unrelated service. Known management listeners remain possible credential
// pivots in worst-case mode after their unauthenticated path has been fixed.
func (b *builder) simListeners() map[string]map[socket][]SimEdge {
	out := make(map[string]map[socket][]SimEdge)
	// Availability-only CVEs still need patches, but they cannot establish a foothold.
	disruptionOnly := make(map[string]bool)
	for _, m := range b.CVEMatches {
		metrics := strings.Split(strings.Trim(m.Record.CVSSVector, "()"), "/")
		if (slices.Contains(metrics, "C:N") && slices.Contains(metrics, "I:N")) ||
			(slices.Contains(metrics, "VC:N") && slices.Contains(metrics, "VI:N") && slices.Contains(metrics, "SC:N") && slices.Contains(metrics, "SI:N")) {
			disruptionOnly[m.Record.ID] = true
		}
	}
	add := func(s socket, tier, label string, cuts ...string) {
		if s.ip == "" {
			return
		}
		if out[s.host] == nil {
			out[s.host] = make(map[socket][]SimEdge)
		}
		e := SimEdge{To: s.host, Tier: tier, Label: label + " · " + serviceName(s.proto, s.port)}
		e.CutIDs = cuts
		out[s.host][s] = append(out[s.host][s], e)
	}
	for s := range b.sockets {
		idx, ok := b.ids[s.fact()]
		if !ok {
			continue
		}
		for _, e := range b.edges[idx] {
			if e.cut == 0 || b.facts[e.to].kind != consequence {
				continue
			}
			detail := b.facts[e.to].detail
			tier := "takeover"
			switch {
			case strings.HasPrefix(b.actions[e.cut].ID, "act:patch:"):
				if disruptionOnly[detail] {
					continue
				}
				if e.level >= moderate {
					tier = "pivot"
				}
			case e.level < moderate && (detail == "control" || detail == "configure" || detail == "pivot"):
				detail = "Unauthenticated " + detail
			default:
				continue // Read-only and disruption findings do not grant control.
			}
			cuts := []string{b.actions[e.cut].ID}
			if e.bundle != 0 {
				cuts = append(cuts, b.actions[e.bundle].ID)
			}
			add(s, tier, detail, cuts...)
		}
	}
	addAdmin := func(host, ip, proto string, port int) {
		switch port {
		case 22, 80, 443, 445, 623, 3389, 5900, 8006, 8443:
			add(socket{host, address(ip), cmp.Or(proto, "tcp"), port}, "pivot", "Management service")
		}
	}
	for _, p := range b.Profiles {
		for _, port := range p.OpenPorts {
			addAdmin(hostKey(p.Client), p.EffectiveProbeIP(), "tcp", port)
		}
		for _, svc := range p.Services {
			if svc.State != "" && svc.State != probe.ServiceStateObservedProtocol && svc.State != probe.ServiceStateTLSUnknownApp {
				continue
			}
			for _, ip := range serviceIPs(p, svc.AddressFamily) {
				addAdmin(hostKey(p.Client), ip, svc.Transport, svc.Port)
			}
		}
	}
	for _, d := range b.Snapshot.Devices {
		if b.Oracle.DeviceClient(d).NetworkID == risk.GatewayNetworkID {
			for _, port := range []int{22, 443} {
				addAdmin(canonicalMAC(d.MAC), d.IP, "tcp", port)
			}
		}
	}
	return out
}

// compareWANLabels prefers unrestricted entry when several routes publish a host.
func compareWANLabels(a, b string) int {
	limited := func(s string) bool { return strings.Contains(s, "(") }
	if limited(a) != limited(b) {
		if limited(a) {
			return 1
		}
		return -1
	}
	if strings.HasPrefix(a, "WAN ") != strings.HasPrefix(b, "WAN ") {
		if strings.HasPrefix(a, "WAN ") {
			return -1
		}
		return 1
	}
	return cmp.Compare(a, b)
}

// simNodes considers inventory devices only, so each selectable node has a
// drawer. Additional attachments still participate in all reachability queries.
func (b *builder) simNodes() []SimNode {
	egress := map[string]string{}
	for _, row := range b.cloud {
		egress[row.Asset] = row.State
	}
	wan := map[string]string{}
	for _, e := range b.wanEdges {
		if wan[e.To] == "" || compareWANLabels(e.Label, wan[e.To]) < 0 {
			wan[e.To] = e.Label
		}
	}
	outdoor := map[string]map[int]bool{}
	for _, sw := range b.SwitchPorts {
		ports := map[int]bool{}
		for _, p := range sw.Ports {
			ports[p.PortIdx] = (p.Zone == "external" || p.Zone == "external_uplink") && p.State != "disabled"
		}
		outdoor[canonicalMAC(sw.MAC)] = ports
	}
	nodes := map[string]SimNode{}
	add := func(cl unifi.Client, device *unifi.Device) {
		id := hostKey(cl)
		if id == "" {
			return
		}
		n := b.network(cl.NetworkID, cl.NetworkName)
		if n.Name == "" {
			n = b.Oracle.NetworkForAddress(cl.PrimaryIP())
		}
		vlan := cmp.Or(n.Name, cl.NetworkName, "Unknown network")
		if n.VLAN != "" {
			vlan += " (VLAN " + n.VLAN + ")"
		}
		info := b.roles[id]
		role := string(info.Category)
		if info.Category == classify.CategoryNetService {
			role = "service"
		}
		if info.Category == classify.CategoryServer && strings.HasPrefix(info.Role, "NAS") {
			role = "nas"
		}
		if role == "" || role == "unknown" {
			role = "host"
		}
		isAppliance := appliance(info.Category) || namesNetwork(b.NetCfg.IsolationPolicy.IoTVLANs, n) || namesNetwork(b.NetCfg.IsolationPolicy.CameraVLANs, n)
		local := "Local LAN"
		switch {
		case outdoor[canonicalMAC(cl.SwitchMAC)][cl.SwitchPort]:
			local = "Outdoor cable"
		case strings.EqualFold(n.Purpose, "guest") || namesNetwork(b.NetCfg.IsolationPolicy.GuestVLANs, n):
			local = "Guest network"
		case isAppliance:
			local = "IoT / appliance"
		}
		for _, w := range b.Snapshot.WLANs {
			if w.Enabled && w.Name != "" && w.Name == cl.ESSID && (w.IsGuest || strings.EqualFold(w.Security, "open")) {
				local = "Open / guest Wi-Fi"
			}
		}
		mac := strings.ToLower(strings.TrimSpace(cl.MAC))
		entity := "host:" + mac
		if mac == "" {
			entity = "host:ip/" + strings.TrimSpace(cl.IP)
		}
		name := cl.DisplayName()
		if device != nil {
			entity, name = "dev:"+mac, deviceLabel(*device)
			role = strings.ToLower(cmp.Or(infraRole(*device), "device"))
			if cl.NetworkID == risk.GatewayNetworkID {
				vlan, role = "Gateway & Mgmt", "gateway"
			}
			local = "Management plane"
		}
		st := egress[id]
		if st == "" {
			row, _, _ := b.assessEgress(attachment{id, cl}, nil, isAppliance)
			st = row.State
		}
		node := SimNode{
			ID: id, EntityID: entity, Name: cmp.Or(name, id), IP: cl.PrimaryIP(),
			VLAN: vlan, Zone: n.ZoneName, Role: role, Tier: string(b.assets[id].profile.Tier),
			EntryExposure: cmp.Or(wan[id], local), LocalExposure: local, InternetState: st, IsDevice: device != nil,
		}
		if prev, ok := nodes[id]; !ok || node.IsDevice || cmp.Or(cmp.Compare(node.VLAN, prev.VLAN), cmp.Compare(node.IP, prev.IP), cmp.Compare(node.Name, prev.Name)) < 0 {
			nodes[id] = node
		}
	}
	for _, cl := range b.Snapshot.Clients {
		add(cl, nil)
	}
	for _, d := range b.Snapshot.Devices {
		if d.MAC != "" {
			add(b.Oracle.DeviceClient(d), &d)
		}
	}
	out := make([]SimNode, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n)
	}
	slices.SortFunc(out, func(a, b SimNode) int {
		if (wan[a.ID] != "") != (wan[b.ID] != "") {
			if wan[a.ID] != "" {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(tiers[classify.AssetTier(a.Tier)], tiers[classify.AssetTier(b.Tier)]), cmp.Compare(a.VLAN, b.VLAN), cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	return out
}

// simInfraEdges records the paths available to a compromised controller, router,
// switch or AP through its own configuration and physical attachments.
func (b *builder) simInfraEdges(kept map[string]bool) []SimEdge {
	var edges []SimEdge
	add := func(from, to, tier, label, via string) {
		if from != to && kept[from] && kept[to] {
			edges = append(edges, SimEdge{From: from, To: to, Tier: tier, Label: label, Via: via})
		}
	}
	controller := canonicalMAC(controllerHost(b.Input).MAC)
	roles := make(map[string]string)
	routers := make(map[string][]string)
	for _, d := range b.Snapshot.Devices {
		id := canonicalMAC(d.MAC)
		if !kept[id] {
			continue
		}
		role := infraRole(d)
		roles[id] = role
		switch role {
		case "Gateway", "Switch", "AP":
			add(controller, id, "takeover", "Managed UniFi gear", "Controller owns device config")
		}
		if role == "Gateway" {
			routers[""] = append(routers[""], id)
		}
		if role == "Gateway" || role == "Switch" {
			routers[id] = []string{id}
		}
	}
	for _, d := range b.Snapshot.Devices {
		id, parent := canonicalMAC(d.MAC), canonicalMAC(d.UplinkMAC)
		if (roles[id] == "Switch" || roles[id] == "AP") && roles[parent] == "Switch" {
			add(parent, id, "pivot", "Downstream UniFi gear", "Switch uplink")
		}
	}
	for _, cl := range b.Snapshot.Clients {
		id := hostKey(cl)
		if !kept[id] {
			continue
		}
		if _, device := roles[id]; device {
			continue // Adopted equipment uses its reported infrastructure uplink.
		}
		if sw := canonicalMAC(cl.SwitchMAC); cl.IsWired && roles[sw] == "Switch" {
			add(sw, id, "pivot", "Wired client", "Direct switch port")
		}
		if ap := canonicalMAC(cl.APMAC); !cl.IsWired && roles[ap] == "AP" {
			add(ap, id, "pivot", "Wireless client", "Associated with AP")
		}
		n := b.network(cl.NetworkID, cl.NetworkName)
		if networkKey(n) == "" {
			n = b.Oracle.NetworkForAddress(cl.PrimaryIP())
		}
		if router, ok := vlanRouter(n); ok {
			for _, from := range routers[router] {
				add(from, id, "pivot", "Routed VLAN gateway", "Routes "+cmp.Or(n.Name, n.ID))
			}
		}
	}
	return edges
}

// buildSimulation evaluates each retained attachment against actual listeners
// and L2 policy. Parallel witnesses stay separate until the browser applies cuts.
func (b *builder) buildSimulation(report Report) *Simulation {
	nodes := b.simNodes()
	if len(nodes) == 0 {
		return nil
	}
	sim := &Simulation{InventoryCount: len(nodes), Nodes: nodes[:min(60, len(nodes))], PolicyCount: len(b.Snapshot.FirewallPolicies) + len(b.Snapshot.SwitchACLs) + len(b.Snapshot.PortForwards)}
	valid := map[string]bool{}
	for _, a := range report.Actions {
		valid[a.ID] = true
	}
	kept := map[string]bool{}
	for _, n := range sim.Nodes {
		kept[n.ID] = true
	}
	sim.Edges = b.simInfraEdges(kept)
	for _, e := range b.wanEdges {
		if kept[e.To] {
			sim.Edges = append(sim.Edges, e)
		}
	}
	listeners := b.simListeners()
	attachments := make([]attachment, 0, len(kept))
	egressCuts := map[string][]string{}
	unknownEgress := map[string]bool{}
	for _, a := range b.clients {
		if kept[a.host] {
			attachments = append(attachments, a)
			_, allowed, missing := b.assessEgress(a, nil, false)
			unknownEgress[a.host] = unknownEgress[a.host] || missing
			if !allowed {
				continue
			}
			id := "act:vlan-egress:" + networkKey(b.network(a.client.NetworkID, a.client.NetworkName)) + "->internet"
			if !slices.Contains(egressCuts[a.host], id) {
				egressCuts[a.host] = append(egressCuts[a.host], id)
			}
		}
	}
	// Marking a host local-only requires known egress on every attachment and a control for every allowed path.
	for i, n := range sim.Nodes {
		ids := egressCuts[n.ID]
		if !unknownEgress[n.ID] && !slices.ContainsFunc(ids, func(id string) bool { return !valid[id] }) {
			slices.Sort(ids)
			sim.Nodes[i].EgressCutIDs = ids
		}
	}
	add := func(src attachment, pos risk.Position, dstID string, cell risk.IsolationCell, e SimEdge) {
		if cell.Effective == "unknown" {
			tier := "unknown"
			if e.Tier == "takeover" {
				tier = "unknown-takeover"
			}
			sim.Edges = append(sim.Edges, SimEdge{From: src.host, To: e.To, Tier: tier, Label: "Reachability unverified", Via: cell.MissingInput, CutIDs: slices.Clone(e.CutIDs)})
			return
		}
		if cell.Effective != "allow" {
			return
		}
		cut, from, dst, to := b.boundaryID(pos, dstID, cell)
		e.From, e.Via = src.host, cmp.Or(cell.DecisiveRuleName, cell.PathKind+" via "+from+" -> "+to)
		if e.Via == "Switch L2/L3 Default" {
			switch cell.PathKind {
			case "wired-same-vlan", "mixed-same-vlan", "cross-ap-wifi", "same-ap-wifi":
				e.Via = "Same network (no client isolation)"
			case "switch-routed":
				e.Via = "Switch routing from " + from + " to " + to
			}
		}
		e.CutIDs = slices.Clone(e.CutIDs)
		if valid[cut] {
			e.CutIDs = append(e.CutIDs, cut)
			if bundle := "act:vlan-ingress:" + dst; dst != "" && valid[bundle] {
				e.CutIDs = append(e.CutIDs, bundle)
			}
		}
		sim.Edges = append(sim.Edges, e)
	}
	for _, src := range attachments {
		for _, dst := range attachments {
			if src.host == dst.host {
				continue
			}
			srcNet := networkKey(b.network(src.client.NetworkID, src.client.NetworkName))
			sameNet := srcNet != "" && srcNet == networkKey(b.network(dst.client.NetworkID, dst.client.NetworkName))
			for _, ip := range src.client.AllIPs() {
				pos := risk.PositionForClient(src.client)
				pos.IP = ip
				fam := family(ip)
				if hasRoutableInFamily(dst.client, fam) {
					cell := b.Oracle.AnyPort(pos, dst.client, fam)
					// A routed allow needs a listener to pivot, but missing policy also matters on a quiet peer.
					if sameNet || cell.Effective == "unknown" {
						add(src, pos, dst.client.NetworkID, cell, SimEdge{To: dst.host, Tier: "l2", Label: "Same-VLAN peer"})
					}
				}
				for s, services := range listeners[dst.host] {
					if family(s.ip) != fam || !owns(dst.client, s.ip) {
						continue
					}
					cell := b.Oracle.Service(pos, pin(dst.client, s.ip), s.proto, s.port, fam)
					for _, service := range services {
						add(src, pos, dst.client.NetworkID, cell, service)
					}
				}
			}
		}
	}
	for _, n := range sim.Nodes {
		p := b.assets[n.ID].profile
		for _, to := range append(slices.Clone(p.Manages), p.Hosts...) {
			if kept[to] && to != n.ID {
				sim.Edges = append(sim.Edges, SimEdge{From: n.ID, To: to, Tier: "pivot", Label: "Management control", Via: "Declared management relationship"})
			}
		}
	}
	compare := func(a, b SimEdge) int {
		label := cmp.Compare(a.Label, b.Label)
		if a.Tier == "wan" && b.Tier == "wan" {
			label = compareWANLabels(a.Label, b.Label)
		}
		return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To), cmp.Compare(a.Tier, b.Tier),
			label, slices.Compare(a.CutIDs, b.CutIDs), cmp.Compare(a.Via, b.Via))
	}
	slices.SortFunc(sim.Edges, compare)
	sim.Edges = slices.CompactFunc(sim.Edges, func(a, b SimEdge) bool { return compare(a, b) == 0 })
	return sim
}
