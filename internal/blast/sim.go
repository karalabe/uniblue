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

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/cve"
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
	// Tier distinguishes WAN entry, takeover, likely risk, admin pivot and terminal L2 exposure.
	// Unknown reachability retains the evidence tier for mode-specific coverage.
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

// simListenerIndex keeps each route bound to the socket the Oracle must evaluate.
type simListenerIndex map[string]map[socket][]simListener

// simListener retains the grant's network prerequisite until the source is known.
type simListener struct {
	edge        SimEdge
	sameNetwork bool
}

// add preserves parallel remedies until the operator applies a hypothetical fix.
func (listeners simListenerIndex) add(s socket, tier, label string, sameNetwork bool, cuts ...string) {
	if s.host == "" || s.ip == "" || s.port <= 0 || s.port > 65535 {
		return
	}
	if listeners[s.host] == nil {
		listeners[s.host] = make(map[socket][]simListener)
	}
	listeners[s.host][s] = append(listeners[s.host][s], simListener{
		edge:        SimEdge{To: s.host, Tier: tier, Label: label + " - " + serviceName(s.proto, s.port), CutIDs: cuts},
		sameNetwork: sameNetwork,
	})
}

// conditionalLabel names the observed interface without claiming its access prerequisites were met.
func conditionalLabel(f checks.Finding, effect string) string {
	name := strings.TrimPrefix(strings.TrimPrefix(f.Title, "Unauthenticated "), "Unencrypted ")
	switch f.CheckID {
	case "UB-2026-0039":
		name = "Zehnder ComfoConnect"
	case "UB-2026-0063":
		name = "Roku ECP"
	case "UB-2026-0022":
		name = "HomeKit"
	case "UB-0019":
		name = "IPMI"
	case "UB-2026-0001":
		name = "MegaRAC"
	}
	label := "Conditional " + effect
	if name != "" {
		label += " (" + name + ")"
	}
	return label
}

// simGrant classifies a listener's consequence independently of whether it has a direct fix.
func (b *builder) simGrant(e edge, disruptionOnly map[string]bool) (tier, label string) {
	detail := b.facts[e.to].detail
	id := b.actions[e.cut].ID
	switch {
	case strings.HasPrefix(id, "act:patch:") && !disruptionOnly[detail]:
		if e.level >= moderate {
			return "likely", detail
		}
		return "takeover", detail
	case detail == "control" || detail == "configure" || detail == "pivot":
		if e.finding != 0 && e.level == moderate && detail != "configure" {
			return "likely", conditionalLabel(b.Findings[e.finding-1], detail)
		}
		if e.level < moderate && (strings.HasPrefix(id, "act:check:") || strings.HasPrefix(id, "act:service:")) {
			return "takeover", "Unauthenticated " + detail
		}
	case detail == "service setting: NERVA-SMB-SIGNING-NOT-REQUIRED":
		return "likely", "Unsigned SMB (relay risk)"
	case detail == "service setting: NERVA-SMB-V1-ENABLED":
		return "likely", "Legacy SMBv1 enabled"
	case detail == "service setting: NERVA-SSH-WEAK-KEX":
		return "likely", "Weak SSH key exchange"
	case detail == "service setting: NERVA-SSH-WEAK-CIPHER":
		return "likely", "Weak SSH cipher"
	}
	return "", ""
}

// simCVEs binds uncertain remote vulnerabilities to product endpoints. For an appliance
// identified from inventory, only observed web and device ports can witness reachability.
// The returned IDs also exclude availability-only CVEs from exact patch edges.
func (b *builder) simCVEs(listeners simListenerIndex, observed map[socket]bool) map[string]bool {
	appliancePorts := map[string][]socket{}
	for s := range observed {
		hosts := b.byIP[s.ip]
		if s.proto != "tcp" || len(hosts) != 1 || hosts[0] != s.host {
			continue
		}
		switch s.port {
		case 443, 80, 631, 8080, 8443, 9100:
			appliancePorts[s.ip] = append(appliancePorts[s.ip], s)
		}
	}
	type witness struct {
		socket  socket
		product string
	}
	critical := map[witness]bool{}
	disruptionOnly := map[string]bool{}
	for _, m := range b.CVEMatches {
		r := m.Record
		metrics := strings.Split(strings.Trim(r.CVSSVector, "()"), "/")
		if (slices.Contains(metrics, "C:N") && slices.Contains(metrics, "I:N")) ||
			(slices.Contains(metrics, "VC:N") && slices.Contains(metrics, "VI:N") && slices.Contains(metrics, "SC:N") && slices.Contains(metrics, "SI:N")) {
			disruptionOnly[r.ID] = true
			continue
		}
		// An unbounded advisory is insufficient evidence against a reported version.
		if m.Confidence != cve.ConfidenceVersionAmbiguous &&
			(m.Confidence != cve.ConfidencePotential || strings.TrimSpace(m.Product.Version) != "") {
			continue
		}
		if (!r.KEV && r.Severity < checks.SeverityCritical) || (r.AttackVector != "N" && !(r.AttackVector == "" && r.KEV)) {
			continue
		}
		ip := address(m.Product.HostIP)
		hosts := b.byIP[ip]
		if len(hosts) != 1 {
			continue
		}
		host := hosts[0]
		var sockets []socket
		if len(m.Product.Ports) == 0 {
			// A software name alone cannot tie a workstation or an unrelated listener to a device CVE.
			category := b.roles[host].Category
			if (appliance(category) || category == classify.CategoryBMC) &&
				(m.Product.Source != "hostname" || m.MatchedCPE.Part == "h" || classify.IsApplianceProduct(m.Product.Label)) {
				sockets = appliancePorts[ip]
			}
		} else {
			sockets = make([]socket, 0, len(m.Product.Ports))
			for _, ep := range m.Product.Ports {
				sockets = append(sockets, socket{host, ip, strings.ToLower(cmp.Or(ep.Transport, "tcp")), ep.Port})
			}
		}
		for _, s := range sockets {
			key := witness{s, m.Product.Label}
			critical[key] = critical[key] || r.Severity >= checks.SeverityCritical
		}
	}
	for key, isCritical := range critical {
		label := "Potential critical CVEs"
		if !isCritical {
			label = "Potential known-exploited CVEs"
		}
		if key.product != "" {
			label += " (" + key.product + ")"
		}
		listeners.add(key.socket, "likely", label, false)
	}
	return disruptionOnly
}

// simListeners keeps observed attack paths separate from management services that
// require assumed credential reuse. Fixing one path leaves independent routes intact.
func (b *builder) simListeners() simListenerIndex {
	out := simListenerIndex{}
	observed := map[socket]bool{}
	observe := func(host, ip, proto string, port int) {
		s := socket{host, address(ip), strings.ToLower(cmp.Or(proto, "tcp")), port}
		if s.host != "" && s.ip != "" && port > 0 && port <= 65535 {
			observed[s] = true
		}
	}
	for _, p := range b.Profiles {
		host, ip := hostKey(p.Client), p.EffectiveProbeIP()
		for _, port := range p.OpenPorts {
			observe(host, ip, "tcp", port)
		}
		for _, port := range p.ConnectOnlyPorts {
			observe(host, ip, "tcp", port)
		}
		for port := range p.HTTP {
			observe(host, ip, "tcp", port)
		}
		if p.SMB != nil {
			observe(host, ip, "tcp", 445)
		}
		if ssh := p.SSH; ssh != nil {
			observe(host, ip, "tcp", ssh.Port)
			if !ssh.NoneAuthAccepted {
				s := socket{host, address(ip), "tcp", ssh.Port}
				switch {
				case slices.Contains(ssh.AuthMethods, "password"):
					out.add(s, "likely", "SSH password auth", false)
				case slices.Contains(ssh.AuthMethods, "keyboard-interactive"):
					out.add(s, "likely", "SSH interactive auth", false)
				}
			}
		}
		for _, svc := range p.Services {
			if svc.State != "" && svc.State != probe.ServiceStateObservedProtocol && svc.State != probe.ServiceStateTLSUnknownApp {
				continue
			}
			observe(host, p.ServiceIP(svc), svc.Transport, svc.Port)
		}
	}
	for _, f := range b.Findings {
		if f.ClaimKind == checks.ClaimAssetIdentity || f.ClaimKind == checks.ClaimServiceAdvertised {
			continue
		}
		for _, ip := range f.EndpointIPs() {
			observe(hostKey(f.Client), ip, f.EffectiveTransport(), f.Port)
		}
	}
	// A port-bound product fingerprint establishes a listener even when the
	// matching probe profile is absent from the simulation input.
	for _, m := range b.CVEMatches {
		ip := address(m.Product.HostIP)
		if hosts := b.byIP[ip]; len(hosts) == 1 {
			for _, ep := range m.Product.Ports {
				observe(hosts[0], ip, ep.Transport, ep.Port)
			}
		}
	}
	disruptionOnly := b.simCVEs(out, observed)
	for s := range b.sockets {
		f := s.fact()
		for _, kind := range []factKind{endpoint, localEndpoint} {
			f.kind = kind
			idx, ok := b.ids[f]
			if !ok {
				continue
			}
			for _, e := range b.edges[idx] {
				if b.facts[e.to].kind != consequence {
					continue
				}
				tier, label := b.simGrant(e, disruptionOnly)
				if tier == "" {
					continue
				}
				var cuts []string
				if e.cut != 0 {
					cuts = append(cuts, b.actions[e.cut].ID)
				}
				if e.bundle != 0 {
					cuts = append(cuts, b.actions[e.bundle].ID)
				}
				out.add(s, tier, label, e.sameNetwork, cuts...)
			}
		}
	}
	for s := range observed {
		switch s.port {
		case 22, 80, 443, 445, 623, 3389, 5900, 8006, 8443:
			out.add(s, "pivot", "Management service", false)
		}
	}
	for _, d := range b.Snapshot.Devices {
		if b.Oracle.DeviceClient(d).NetworkID == risk.GatewayNetworkID {
			for _, port := range []int{22, 443} {
				out.add(socket{canonicalMAC(d.MAC), address(d.IP), "tcp", port}, "pivot", "Management service", false)
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
			if e.Tier == "takeover" || e.Tier == "likely" {
				tier = "unknown-" + e.Tier
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
						if !service.sameNetwork || sameNet {
							add(src, pos, dst.client.NetworkID, cell, service.edge)
						}
					}
				}
			}
		}
	}
	// Hardware and hypervisor ownership grants control independently of VLAN reachability.
	addControl := func(from string, targets []string, label string) {
		for _, to := range targets {
			if kept[to] && to != from {
				sim.Edges = append(sim.Edges, SimEdge{From: from, To: to, Tier: "takeover", Label: label, Via: "Management relationship"})
			}
		}
	}
	for _, n := range sim.Nodes {
		p := b.assets[n.ID].profile
		addControl(n.ID, p.Manages, "Manages server")
		addControl(n.ID, p.Hosts, "Hosts virtual machine")
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
