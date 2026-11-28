// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import (
	"cmp"
	"fmt"
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
	// EntryExposure is the display label for the highest-exposure entry path
	// (for example, "WAN TCP/443", "Outdoor cable", or "Local LAN").
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
	// Tier classifies the edge evidence: "wan", "takeover", "likely", "pivot",
	// "l2", "unknown", "unknown-takeover", or "unknown-likely". Unknown variants
	// preserve the underlying evidence tier for mode-specific traversal.
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

// SimulationMode sets the evidence threshold for traversing the inventory.
type SimulationMode string

const (
	// ModeProven follows only confirmed takeover paths.
	ModeProven SimulationMode = "proven"
	// ModeRealistic also follows paths supported by conditional evidence.
	ModeRealistic SimulationMode = "realistic"
	// ModeWorstCase also assumes credential reuse and includes terminal L2 peers.
	ModeWorstCase SimulationMode = "worst"
)

// ParseSimulationMode reads a dashboard or API mode, defaulting to Realistic.
func ParseSimulationMode(raw string) (SimulationMode, error) {
	switch mode := SimulationMode(strings.ToLower(strings.TrimSpace(raw))); mode {
	case "":
		return ModeRealistic, nil
	case ModeProven, ModeRealistic, ModeWorstCase:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown simulation mode %q (expected proven, realistic, or worst)", raw)
	}
}

// HostBlastPath describes the last edge of a shortest path from Patient Zero.
type HostBlastPath struct {
	// Target is the peer reached by this edge.
	Target SimNode `json:"target"`
	// From identifies the predecessor on the path.
	From string `json:"from"`
	// FromName is the predecessor's inventory name.
	FromName string `json:"from_name"`
	// Hop counts edges from Patient Zero to the target.
	Hop int `json:"hop"`
	// Tier identifies the strength of the surviving evidence.
	Tier string `json:"tier"`
	// Label describes the service or permission on the edge.
	Label string `json:"label"`
	// Via names the policy or relationship that permits the edge.
	Via string `json:"via,omitempty"`
	// TerminalL2 marks a same-VLAN peer that cannot propagate compromise.
	TerminalL2 bool `json:"terminal_l2,omitempty"`
	// CutIDs lists actions that sever this particular edge.
	CutIDs []string `json:"cut_ids,omitempty"`
}

// HostSimulation summarizes the modeled reach of one compromised inventory asset.
type HostSimulation struct {
	// Host is the selected Patient Zero.
	Host SimNode `json:"host"`
	// Mode is the evidence threshold used for traversal.
	Mode SimulationMode `json:"mode"`
	// AppliedFixes lists the hypothetical cuts used in this run.
	AppliedFixes []string `json:"applied_fixes"`
	// PeerCount counts all other nodes in the simulation.
	PeerCount int `json:"peer_count"`
	// DirectReach counts peers reached by one cascading edge.
	DirectReach int `json:"direct_reach"`
	// CascadedReach counts peers reached by two or more cascading edges.
	CascadedReach int `json:"cascaded_reach"`
	// L2Exposed counts additional peers exposed only at layer two.
	L2Exposed int `json:"l2_exposed"`
	// TotalReach counts distinct reached peers, including terminal L2 exposure.
	TotalReach int `json:"total_reach"`
	// CriticalThreatened lists reached peers with crown or high asset value.
	CriticalThreatened []SimNode `json:"critical_threatened"`
	// Paths lists cascading paths in breadth-first order, then terminal L2 paths.
	Paths []HostBlastPath `json:"paths"`
	// UnknownTargets lists unreached peers whose reachability needs verification.
	UnknownTargets []SimNode `json:"unknown_targets"`
	// RelevantFixes lists controls on the host's baseline entry, egress and reachable routes.
	RelevantFixes []string `json:"relevant_fixes"`
}

// permits keeps uncertain paths at the same evidence threshold as their verified counterparts.
func (m SimulationMode) permits(tier string) bool {
	switch tier {
	case "takeover", "unknown-takeover":
		return true
	case "likely", "unknown-likely":
		return m == ModeRealistic || m == ModeWorstCase
	case "pivot", "l2", "unknown":
		return m == ModeWorstCase
	}
	return false
}

// A hostRoute retains an unverified alternative independently of its best reachable edge.
type hostRoute struct {
	edge    *SimEdge
	unknown bool
}

// hostGraph indexes the bounded map by inventory position so equally short paths
// have the same predecessor in the API and the dashboard.
func (s *Simulation) hostGraph(indices map[string]int, mode SimulationMode, cuts map[string]bool) [][]hostRoute {
	rows := make([][]hostRoute, len(s.Nodes))
	for i := range rows {
		rows[i] = make([]hostRoute, len(s.Nodes))
	}
	rank := map[string]int{"takeover": 0, "likely": 1, "pivot": 2, "l2": 3}
	isCut := func(id string) bool { return cuts[id] }
	for i := range s.Edges {
		e := &s.Edges[i]
		from, srcOK := indices[e.From]
		to, dstOK := indices[e.To]
		if !srcOK || !dstOK || !mode.permits(e.Tier) || slices.ContainsFunc(e.CutIDs, isCut) {
			continue
		}
		route := &rows[from][to]
		if strings.HasPrefix(e.Tier, "unknown") {
			route.unknown = true
		} else if route.edge == nil || rank[e.Tier] < rank[route.edge.Tier] {
			route.edge = e
		}
	}
	return rows
}

// cascadingPeers walks only routes that can expose further peers. The first
// incoming edge records a shortest path and prevents cycles from expanding again.
func cascadingPeers(rows [][]hostRoute, root int) (queue []int, via []*SimEdge) {
	queue, via = []int{root}, make([]*SimEdge, len(rows))
	for head := 0; head < len(queue); head++ {
		for to, route := range rows[queue[head]] {
			if to != root && via[to] == nil && route.edge != nil && route.edge.Tier != "l2" {
				via[to] = route.edge
				queue = append(queue, to)
			}
		}
	}
	return queue, via
}

// SimulateHost models a compromise and its hypothetical fixes without modifying the snapshot.
// It returns false when the host or mode is unavailable.
func (s *Simulation) SimulateHost(hostID string, mode SimulationMode, appliedCuts []string) (HostSimulation, bool) {
	if s == nil || (mode != ModeProven && mode != ModeRealistic && mode != ModeWorstCase) {
		return HostSimulation{}, false
	}
	indices := make(map[string]int, len(s.Nodes))
	for i, n := range s.Nodes {
		indices[n.ID] = i
	}
	root, ok := indices[hostID]
	if !ok {
		return HostSimulation{}, false
	}
	cuts := make(map[string]bool, len(appliedCuts))
	for _, id := range appliedCuts {
		cuts[id] = true
	}
	result := HostSimulation{
		Mode: mode, PeerCount: len(s.Nodes) - 1,
		AppliedFixes: append([]string{}, sortedKeys(cuts)...),
		Paths:        []HostBlastPath{}, CriticalThreatened: []SimNode{}, UnknownTargets: []SimNode{},
	}
	rows := s.hostGraph(indices, mode, cuts)
	queue, via := cascadingPeers(rows, root)
	order := slices.Clone(queue[1:])
	unknown := make([]bool, len(rows))
	// Only cascading peers expose neighbors. Finish their traversal before assigning
	// L2 edges, since a longer takeover path takes precedence over local proximity.
	for _, from := range queue {
		for to, route := range rows[from] {
			unknown[to] = unknown[to] || route.unknown
			if to != root && via[to] == nil && route.edge != nil && route.edge.Tier == "l2" {
				via[to] = route.edge
				order = append(order, to)
			}
		}
	}
	// Keep baseline controls available to undo even when a cut removed the last route.
	if len(cuts) > 0 {
		queue, _ = cascadingPeers(s.hostGraph(indices, mode, nil), root)
	}
	sources := make(map[string]bool, len(queue))
	for _, i := range queue {
		sources[s.Nodes[i].ID] = true
	}
	relevant := make(map[string]bool)
	for _, id := range s.Nodes[root].EgressCutIDs {
		relevant[id] = true
	}
	wan := make(map[string]string)
	isCut := func(id string) bool { return cuts[id] }
	for _, e := range s.Edges {
		if e.Tier == "wan" && !slices.ContainsFunc(e.CutIDs, isCut) && (wan[e.To] == "" || compareWANLabels(e.Label, wan[e.To]) < 0) {
			wan[e.To] = e.Label
		}
		if e.Tier == "wan" && e.To == hostID || sources[e.From] && mode.permits(e.Tier) {
			for _, id := range e.CutIDs {
				relevant[id] = true
			}
		}
	}
	result.RelevantFixes = append([]string{}, sortedKeys(relevant)...)

	// Project the same surviving entry and egress onto every copy of a host.
	effectiveNode := func(idx int) SimNode {
		n := s.Nodes[idx]
		n.EntryExposure = cmp.Or(wan[n.ID], n.LocalExposure, n.EntryExposure)
		for _, id := range n.EgressCutIDs {
			if !cuts[id] {
				return n
			}
		}
		if len(n.EgressCutIDs) > 0 {
			n.InternetState = localOnly
		}
		return n
	}
	result.Host = effectiveNode(root)
	hops := make([]int, len(rows))
	for _, to := range order {
		n, e := effectiveNode(to), via[to]
		from := indices[e.From]
		hops[to] = hops[from] + 1
		path := HostBlastPath{Target: n, From: e.From, FromName: s.Nodes[from].Name, Hop: hops[to],
			Tier: e.Tier, Label: e.Label, Via: e.Via, TerminalL2: e.Tier == "l2", CutIDs: e.CutIDs}
		result.Paths = append(result.Paths, path)
		if n.Tier == "high" || n.Tier == "crown" {
			result.CriticalThreatened = append(result.CriticalThreatened, n)
		}
		if path.TerminalL2 {
			result.L2Exposed++
		} else if from == root {
			result.DirectReach++
		} else {
			result.CascadedReach++
		}
	}
	result.TotalReach = len(order)
	for i, uncertain := range unknown {
		if uncertain && i != root && via[i] == nil {
			result.UnknownTargets = append(result.UnknownTargets, effectiveNode(i))
		}
	}
	return result, true
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

// conditionalLabel names the observed interface without claiming its access
// prerequisites were met. The five explicit check overrides replace verbose
// finding titles with compact protocol or product names suited for graph edges.
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
		// Exclude "configure" from conditional "likely" edges because changing
		// settings without host control or pivot does not establish a lateral takeover.
		if e.finding != 0 && e.level == moderate && detail != "configure" {
			return "likely", conditionalLabel(b.Findings[e.finding-1], detail)
		}
		if e.level < moderate && (strings.HasPrefix(id, "act:check:") || strings.HasPrefix(id, "act:service:")) {
			return "takeover", "Unauthenticated " + detail
		}
	// These four SMB/SSH hardening findings expose lateral movement paths
	// (relay, SMBv1 exploitation, or weak SSH crypto) and map to "likely" edges.
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
		if m.ClientOnly {
			continue
		}
		r := m.Record
		// Filter out availability/DoS-only CVEs using CVSS v3 (C:N and I:N) and
		// CVSS v4 (VC:N, VI:N, SC:N, SI:N) vector metrics.
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
	// Common remote-management and file-sharing ports become "pivot" edges that
	// are traversed only in ModeWorstCase (assuming credential reuse).
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

// simNodes builds selectable simulation nodes restricted to real UniFi clients
// and adopted devices. Additional attachments still participate in reachability
// queries.
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
			entity = "host:ip/" + strings.TrimSpace(cl.PrimaryIP())
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
		// When a MAC appears as both a UniFi device and a client, prefer the device entry.
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
	edges := []SimEdge{}
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
	// Cap the interactive simulation graph at 60 nodes; simNodes sorts
	// WAN-exposed hosts ahead of asset tier before truncating to the top 60.
	sim := &Simulation{
		InventoryCount: len(nodes), Nodes: nodes[:min(60, len(nodes))],
		PolicyCount: len(b.Snapshot.FirewallPolicies) + len(b.Snapshot.SwitchACLs) + len(b.Snapshot.PortForwards),
	}
	actions := make(map[string]*Action, len(report.Actions))
	for i := range report.Actions {
		a := &report.Actions[i]
		actions[a.ID] = a
	}
	kept := map[string]bool{}
	for _, n := range sim.Nodes {
		kept[n.ID] = true
	}
	sim.Edges = b.simInfraEdges(kept)
	if len(nodes) == 0 {
		return sim
	}
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
		id := "act:vlan-egress:" + networkKey(b.network(a.client.NetworkID, a.client.NetworkName)) + "->internet"
		// Hosts outside the 60-node map still run assessEgress when an egress
		// action exists for their VLAN so targetAssets stays complete for host lookup.
		if kept[a.host] {
			attachments = append(attachments, a)
		} else if actions[id] == nil {
			continue
		}
		_, allowed, missing := b.assessEgress(a, nil, false)
		unknownEgress[a.host] = unknownEgress[a.host] || missing
		if !allowed {
			continue
		}
		if action := actions[id]; action != nil {
			action.addTarget(a.host)
		}
		if !slices.Contains(egressCuts[a.host], id) {
			egressCuts[a.host] = append(egressCuts[a.host], id)
		}
	}
	// Marking a host local-only requires known egress on every attachment and a control for every allowed path.
	for i, n := range sim.Nodes {
		ids := egressCuts[n.ID]
		if !unknownEgress[n.ID] && !slices.ContainsFunc(ids, func(id string) bool { return actions[id] == nil }) {
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
		if actions[cut] != nil {
			e.CutIDs = append(e.CutIDs, cut)
			if bundle := "act:vlan-ingress:" + dst; dst != "" && actions[bundle] != nil {
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
	// A compromised peer can reach additional targets outside the ranked entry paths.
	for _, e := range sim.Edges {
		for _, id := range e.CutIDs {
			if a := actions[id]; a != nil {
				a.addTarget(e.To)
			}
		}
	}
	return sim
}
