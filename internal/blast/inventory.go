// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// socket identifies one observed or configured service listener on a specific IP.
// Retaining the address ensures an IPv4 observation never grants capabilities to
// a separate listener that only exists on IPv6.
type socket struct {
	host, ip, proto string
	port            int
}

func (s socket) fact() fact { return fact{endpoint, s.host, s.ip + "/" + serviceName(s.proto, s.port)} }

type attachment struct {
	host   string
	client unifi.Client
}

type builder struct {
	Input
	*graph
	clients         []attachment               // populated in inventory: all unique (host, position) attachments
	byIP            map[string][]string        // populated in inventory: IP -> owning host keys
	roles           map[string]classify.Result // populated in inventory: hostKey -> device role classification
	nets            map[string]unifi.Network   // populated in inventory: network ID and lowercase name -> Network
	sockets         map[socket]bool            // populated in services/publications/routes: all known service listeners
	positions       map[risk.Position]fact     // populated in entries/services: interned Oracle query positions
	cloud           []ClientEgress             // populated in entries: worst-case per-host cloud egress summaries
	wanEdges        []SimEdge                  // populated in routes/internet: WAN simulation edges
	unknownPhysical bool                       // populated in entries/outdoor: true if any outdoor port VLAN config or isolation is unknown
}

func canonicalMAC(s string) string { return config.CanonicalMAC(s) }

func address(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

func networkKey(n unifi.Network) string { return cmp.Or(n.ID, n.Name) }

func (b *builder) network(id, name string) unifi.Network {
	if id == risk.GatewayNetworkID {
		return unifi.Network{ID: id, Name: "Gateway", ZoneName: "Gateway"}
	}
	if n, ok := b.nets[id]; ok {
		return n
	}
	return b.nets[strings.ToLower(name)]
}

// inventory indexes every device attachment independently while preserving all
// hosts that claim the same IP so duplicate-IP ambiguity stays visible.
func (b *builder) inventory() {
	b.nets = map[string]unifi.Network{}
	b.byIP = map[string][]string{}
	b.positions = map[risk.Position]fact{}
	b.sockets = map[socket]bool{}
	b.roles = classify.ClientRoles(b.Snapshot, b.Profiles)
	// Findings can reveal an out-of-band BMC (for example via an IPMI or iKVM
	// check) even when passive classification did not tag it as CategoryBMC.
	for _, cl := range b.Oracle.ManagementControllers(b.Findings) {
		h := hostKey(cl)
		role := b.roles[h]
		role.Category = classify.CategoryBMC
		b.roles[h] = role
	}
	for _, n := range b.Snapshot.Networks {
		if n.ID != "" {
			b.nets[n.ID] = n
		}
		b.nets[strings.ToLower(n.Name)] = n
	}
	seen := map[struct {
		host string
		pos  risk.Position
	}]bool{}
	add := func(cl unifi.Client) {
		key := hostKey(cl)
		if key == "" {
			return
		}
		if cl.NetworkID == "" && cl.NetworkName == "" {
			n := b.Oracle.NetworkForAddress(cl.PrimaryIP())
			cl.NetworkID, cl.NetworkName = n.ID, n.Name
		}
		p := struct {
			host string
			pos  risk.Position
		}{key, risk.PositionForClient(cl)}
		if seen[p] {
			return
		}
		seen[p] = true
		b.clients = append(b.clients, attachment{key, cl})
		if _, ok := b.assets[key]; !ok {
			b.addAsset(key, cl.DisplayName(), b.Assets[key])
		}
		for _, raw := range cl.AllIPs() {
			ip := address(raw)
			if ip == "" {
				continue
			}
			if !slices.Contains(b.byIP[ip], key) {
				b.byIP[ip] = append(b.byIP[ip], key)
			}
		}
	}
	// Index Snapshot.Clients first so live client records with full VLAN, AP, and
	// switch metadata take precedence over fallback entries from devices, profiles,
	// or findings.
	for _, cl := range b.Snapshot.Clients {
		add(cl)
	}
	for _, d := range b.Snapshot.Devices {
		cl := b.Oracle.DeviceClient(d)
		if _, found := b.assets[hostKey(cl)]; !found {
			add(cl)
		}
	}
	for _, hp := range b.Profiles {
		if _, ok := b.assets[hostKey(hp.Client)]; !ok {
			add(hp.Client)
		}
	}
	for _, f := range b.Findings {
		if f.Port > 0 {
			if _, ok := b.assets[hostKey(f.Client)]; !ok {
				add(f.Client)
			}
		}
	}
	// Keep offline port-forward, mapping, proxy, and tunnel targets in inventory
	// so configured public routes are still evaluated.
	addBackend := func(raw string) {
		if ip := address(raw); ip != "" && len(b.byIP[ip]) == 0 {
			add(unifi.Client{IP: ip})
		}
	}
	for _, f := range b.Snapshot.PortForwards {
		if f.Enabled {
			addBackend(f.FwdIP)
		}
	}
	for _, m := range b.Snapshot.DynamicMappings {
		addBackend(m.InternalIP)
	}
	for _, r := range b.Snapshot.ProxyRoutes {
		if r.PublicExposed {
			addBackend(r.BackendIP)
		}
	}
	for _, t := range b.Snapshot.PublishedTunnels {
		addBackend(t.BackendIP)
	}
}

// indexTargetSignals records high-profile target velocity hints on matching
// assets, exact IP/transport/port listeners, or host-wide ports. Unknown or
// low-confidence velocity never discounts opaque IoT devices.
func (b *builder) indexTargetSignals() {
	for _, sig := range b.TargetSignals {
		if sig.Velocity.Class != cve.VelocityHighProfile {
			continue
		}
		key := canonicalMAC(sig.Asset)
		sigIP := ""
		if _, ok := b.assets[key]; !ok {
			if ip := address(sig.Asset); ip != "" && len(b.byIP[ip]) == 1 {
				key = b.byIP[ip][0]
				sigIP = ip
			} else if _, ok := b.assets[sig.Asset]; ok {
				key = sig.Asset
			}
		}
		if key == "" {
			continue
		}
		if sig.Port > 0 {
			proto := strings.ToLower(cmp.Or(sig.Proto, "tcp"))
			svc := serviceName(proto, sig.Port)
			// Also record highProfileFamily so broad all-ports gateway policies
			// (which have no socket port) still inherit high-profile velocity for
			// the matching host and address family in routes.
			if sigIP != "" {
				b.highProfileSockets[key+"|"+sigIP+"|"+svc] = true
				b.highProfileFamily[key+"|"+family(sigIP)] = true
			} else {
				b.highProfilePorts[key+"|"+svc] = true
				b.highProfileFamily[key+"|ipv4"] = true
				b.highProfileFamily[key+"|ipv6"] = true
			}
		} else {
			b.highProfileHost[key] = true
		}
	}
}

// isHighProfileSocket reports whether listener s matches a port-scoped or
// exact-IP high-profile target signal.
func (b *builder) isHighProfileSocket(s socket) bool {
	svc := serviceName(s.proto, s.port)
	return b.highProfileSockets[s.host+"|"+s.ip+"|"+svc] || b.highProfilePorts[s.host+"|"+svc]
}

// resolvePublishedIP returns the unique host owning raw. When multiple inventory
// entries share raw, it records an explicit verification item and marks every
// candidate unknown from Internet so none falsely reports "contained".
func (b *builder) resolvePublishedIP(raw string) (string, bool) {
	ip := address(raw)
	if ip == "" {
		return "", false
	}
	hosts := b.byIP[ip]
	if len(hosts) == 1 {
		return hosts[0], true
	}
	if len(hosts) > 1 {
		b.verify(root(Internet), "duplicate-ip", ip, "Check duplicate IP address "+ip, "More than one device in the inventory reports this IP address, so UniBlue cannot tell which device receives forwarded traffic.", hosts...)
		for _, h := range hosts {
			b.link(root(Internet), fact{permission, h, "network access"}, unknown, 0, 0)
		}
	}
	return "", false
}

// socket records a listener for a specific host, IP address, transport, and port.
func (b *builder) socket(host, ip, proto string, port int) (socket, bool) {
	s := socket{host, address(ip), strings.ToLower(cmp.Or(proto, "tcp")), port}
	if host == "" || s.ip == "" || port <= 0 || port > 65535 {
		return s, false
	}
	b.sockets[s] = true
	return s, true
}

// grantLevel maps a check grant to its graph edge difficulty: assumed,
// conditional, or prerequisite-gated grants are moderate; direct control,
// pivot, and configure effects are trivial; all other direct effects are low.
func grantLevel(g checks.GrantSpec) uint8 {
	if g.Basis == checks.BasisAssumed || g.Basis == checks.BasisConditional || g.Requires != "" {
		return moderate
	}
	switch g.Effect {
	case checks.GrantControl, checks.GrantPivot, checks.GrantConfigure:
		return trivial
	default:
		return low
	}
}

// grant attaches a service consequence to its specific listener and remedy so
// independent findings supporting the same consequence survive a single cut.
func (b *builder) grant(s socket, from fact, g checks.GrantSpec, id int) *edge {
	cf := fact{consequence, s.host, string(g.Effect)}
	e := b.link(from, cf, grantLevel(g), id, 0)
	e.sameNetwork = g.SameNetwork
	if b.isHighProfileSocket(s) {
		b.markHighProfile(from, from)
	}
	return e
}

type serviceBundleKey struct{ host, label string }
type serviceMember struct{ node, edge, port int }

// serviceBundles indexes confirmed remedy edges by host and product or check.
type serviceBundles map[serviceBundleKey][]serviceMember

// record stores the slice index of the edge just linked from `from` so bundle
// assignment survives slice growth. Callers must invoke it immediately after
// link or grant.
func (groups serviceBundles) record(b *builder, from fact, port int, label string) {
	n := b.ids[from]
	k := serviceBundleKey{from.asset, label}
	groups[k] = append(groups[k], serviceMember{n, len(b.edges[n]) - 1, port})
}

// bundleServices assigns a single bundle remedy across multiple distinct
// remedies on the same host, preserving each narrower remedy alongside it. When
// checksByID is non-nil it bundles check findings spanning at least two ports;
// when checksByID is nil it bundles version-matched CVEs by product label.
func (b *builder) bundleServices(groups serviceBundles, checksByID map[string]*checks.Check) {
	for key, members := range groups {
		ports := map[int]bool{}
		ids := map[int]bool{}
		for _, m := range members {
			ports[m.port] = true
			ids[b.edges[m.node][m.edge].cut] = true
		}
		if len(ids) < 2 {
			continue
		}
		name := b.assets[key.host].name
		var bundle int
		if checksByID != nil {
			if len(ports) < 2 {
				continue
			}
			var list []string
			for _, p := range slices.Sorted(maps.Keys(ports)) {
				list = append(list, strconv.Itoa(p))
			}
			title := cmp.Or(checksByID[key.label].Title, key.label)
			bundle = b.action("act:check-host:"+key.label+":"+key.host, "Require sign-in or disable "+name+" ("+title+", ports "+strings.Join(list, ", ")+")", "Apply the same access restriction on every affected port.", LaneFixNow, 1)
		} else {
			bundle = b.action("act:patch-product:"+ProductSlug(key.label)+":"+key.host, "Update "+key.label+" on "+name+" ("+strconv.Itoa(len(ids))+" CVEs)", "One product update can address these version-matched vulnerabilities.", LaneFixNow, 2)
		}
		for _, m := range members {
			b.edges[m.node][m.edge].bundle = bundle
		}
	}
}

// ProductSlug gives product-wide actions a stable, readable identifier.
func ProductSlug(label string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(label), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }), "-")
}

// services wires check grants, protocol traits, CVEs, management ownership, and
// declared publications into the graph before network reachability is added.
func (b *builder) services() {
	checkBundles, productBundles := serviceBundles{}, serviceBundles{}
	byID := map[string]*checks.Check{}
	for _, c := range b.Checks {
		byID[c.ID] = c
	}
	onLink := map[socket]bool{}
	for _, hp := range b.Profiles {
		for _, md := range hp.MDNSServices {
			if !md.Reflected && !md.Withdrawn {
				onLink[socket{hostKey(hp.Client), address(md.ResponderIP), strings.ToLower(cmp.Or(md.Transport, "tcp")), md.Port}] = true
			}
		}
	}
	for i, f := range b.Findings {
		c := byID[f.CheckID]
		if f.Port == 0 {
			continue
		}
		grants := slices.Clone(f.Grants)
		if c != nil {
			grants = append(grants, checks.EffectiveGrants(c, f.Observation)...)
		}
		inventoryOnly := f.IsInventoryOnly() || (c != nil && c.IsInventoryOnly())
		if inventoryOnly {
			// A discovery response identifies a listener. Only a separate
			// prerequisite in its grant gives the operator something to verify.
			grants = slices.DeleteFunc(grants, func(g checks.GrantSpec) bool { return grantLevel(g) != moderate })
		}
		host := hostKey(f.Client)
		ips := f.EndpointIPs()
		if len(ips) == 0 && (!inventoryOnly || len(grants) != 0) {
			b.verify(root(TrustedLAN), "service-address", host+":"+serviceName(f.EffectiveTransport(), f.Port), "Check which IP serves "+b.assets[host].name, "This finding does not include an IP address, so it cannot be tied to a specific network path.", host)
		}
		for _, ip := range ips {
			s, ok := b.socket(host, ip, f.EffectiveTransport(), f.Port)
			if !ok {
				continue
			}
			b.link(root(TrustedLAN), s.fact(), trivial, 0, 0)
			// UB-0010 checks open DNS recursion; suppress it on private LAN-only port
			// 53 resolvers that are expected to serve local clients and are not exposed to WAN.
			if f.CheckID == "UB-0010" && s.port == 53 && b.Oracle.PrivateLANListener(f.Client, ip, s.proto, s.port) {
				continue
			}
			// Non-inventory findings that declare no capability grants still represent
			// hardening issues and are modeled as "service setting: <CheckID>" consequences.
			if !inventoryOnly && len(grants) == 0 && (c == nil || len(c.Grants) == 0) {
				title := fmt.Sprintf("Review %s on port %d", b.assets[host].name, s.port)
				a := b.action("act:check:"+f.CheckID+":"+host+":"+serviceName(s.proto, s.port), title, cmp.Or(f.Title, "A service check found a setting that needs attention."), LaneReduceExposure, 1)
				cf := fact{consequence, host, "service setting: " + f.CheckID}
				node := b.node(cf)
				b.settingSeverity[node] = max(b.settingSeverity[node], f.BaseSeverity)
				level := low
				if f.BaseSeverity <= checks.SeverityLow {
					level = moderate
				}
				b.link(s.fact(), cf, level, a, 0)
				if b.isHighProfileSocket(s) {
					b.markHighProfile(s.fact(), s.fact())
				}
			}
			for _, g := range grants {
				from := s.fact()
				if g.SameNetwork {
					from.kind = localEndpoint
					// Only a direct mDNS answer places this listener on the observer's link.
					if onLink[s] {
						b.link(root(TrustedLAN), from, trivial, 0, 0)
						delete(onLink, s)
					}
				}
				name := b.assets[host].name
				id := "act:check:" + f.CheckID + ":" + host + ":" + strconv.Itoa(f.Port)
				if s.proto != "tcp" {
					id += ":" + s.proto
				}
				if grantLevel(g) == moderate {
					title := fmt.Sprintf("Check access to %s on port %d", name, f.Port)
					reason := cmp.Or(strings.TrimSpace(g.Note), "Confirm whether sign-in, pairing, or another safeguard is required on this service.")
					if req := strings.TrimRight(strings.TrimSpace(g.Requires), "."); req != "" {
						reason = "Check whether this applies: " + req + "."
					}
					b.verify(from, f.CheckID, host+":"+serviceName(s.proto, s.port), title, reason)
					b.grant(s, from, g, 0).finding = uint32(i + 1)
				} else {
					title := fmt.Sprintf("Require sign-in or disable %s on port %d", name, f.Port)
					reason := cmp.Or(strings.TrimSpace(g.Note), strings.TrimSpace(f.Title), "Anyone who can reach this service can use it without signing in.")
					lane := LaneFixNow
					// UB-0012 checks SNMP public community read access; when WAN access has
					// not been confirmed, route it to LaneReduceExposure instead of FixNow.
					if f.CheckID == "UB-0012" && b.Oracle.ListenerWAN(f.Client, s.ip, s.proto, s.port) != "allow" {
						lane = LaneReduceExposure
						title = "Restrict SNMP read access on " + name
					}
					a := b.action(id, title, reason, lane, 1)
					b.grant(s, from, g, a)
					if lane == LaneFixNow && c != nil {
						checkBundles.record(b, from, s.port, f.CheckID)
					}
				}
			}
		}
	}
	for _, hp := range b.Profiles {
		host := hostKey(hp.Client)
		for _, p := range hp.OpenPorts {
			b.socket(host, hp.EffectiveProbeIP(), "tcp", p)
		}
		for _, svc := range hp.Services {
			ip := hp.ServiceIP(svc)
			s, ok := b.socket(host, ip, svc.Transport, svc.Port)
			if !ok {
				continue
			}
			trait, ok := classify.LookupProtocol(svc.Protocol)
			if !ok || (svc.State != "" && svc.State != probe.ServiceStateObservedProtocol) {
				continue
			}
			b.link(root(TrustedLAN), s.fact(), trivial, 0, 0)
			// Suppress built-in DNS recursion traits on private LAN-only resolvers
			// just as UB-0010 findings are suppressed above.
			if svc.Protocol == "dns" && s.port == 53 && b.Oracle.PrivateLANListener(hp.Client, ip, s.proto, s.port) {
				continue
			}
			for _, effect := range trait.AnonGrants {
				basis := checks.BasisConditional
				if trait.AuthModel == classify.AuthNone || svc.AnonymousAccess {
					basis = checks.BasisImplied
				}
				a := b.action("act:service:"+host+":"+serviceName(s.proto, s.port), fmt.Sprintf("Limit who can use %s on %s", svc.Protocol, b.assets[host].name), "Restricting this service to devices that need it limits who can use its built-in access.", LaneReduceExposure, 1)
				b.grant(s, s.fact(), checks.GrantSpec{Effect: effect, Basis: basis}, a)
			}
		}
		// Controlling a bridge, hub, or recorder implicitly grants control over its
		// attached child devices.
		for _, child := range hp.Children {
			if child.ID == "" {
				continue
			}
			key := "child:" + host + ":" + child.ID
			b.addAsset(key, cmp.Or(child.Name, child.ID), classify.AssetProfile{Tier: classify.TierMedium})
			b.link(fact{consequence, host, "control"}, fact{consequence, key, "control"}, trivial, 0, 0)
		}
	}
	for _, m := range b.CVEMatches {
		b.cve(m, productBundles)
	}
	b.bundleServices(checkBundles, byID)
	b.bundleServices(productBundles, nil)
	for key, p := range b.Assets {
		if _, ok := b.assets[key]; !ok {
			b.addAsset(key, key, p)
		}
	}
	for _, host := range sortedKeys(b.assets) {
		p := b.assets[host].profile
		targets := append(slices.Clone(p.Manages), p.Hosts...)
		// A BMC without explicit Manages targets still controls an underlying
		// server, so synthesize a crown-tier placeholder to preserve that blast radius.
		if b.roles[host].Category == classify.CategoryBMC && len(p.Manages) == 0 {
			key := "managed:" + host
			b.addAsset(key, "Unidentified server managed by "+b.assets[host].name, classify.AssetProfile{Tier: classify.TierCrown})
			targets = append(targets, key)
		}
		for _, to := range targets {
			if _, ok := b.assets[to]; !ok {
				b.addAsset(to, to, b.Assets[to])
			}
			b.link(fact{consequence, host, "control"}, fact{consequence, to, "control"}, trivial, 0, 0)
		}
	}
	// A pivot consequence turns the compromised host into a network origin on
	// every attachment it owns, enabling lateral traversal from its position.
	for _, cl := range b.clients {
		pivot := fact{consequence, cl.host, "pivot"}
		if _, ok := b.ids[pivot]; ok {
			b.link(pivot, b.position(risk.PositionForClient(cl.client)), trivial, 0, 0)
		}
	}
	b.publications()
}

func family(ip string) string {
	if strings.Contains(ip, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// cve binds network-reachable CVEs to observed endpoints. Distribution-backport
// ambiguity stays in Verify even for KEV entries; local-only CVEs are ignored.
func (b *builder) cve(m cve.Match, bundles serviceBundles) {
	ip := address(m.Product.HostIP)
	hosts := b.byIP[ip]
	r := m.Record
	// Ignore local, adjacent, and physical CVEs; keep KEV entries that have no
	// published CVSS vector yet so known-exploited advisories are not dropped.
	if r.AttackVector != "N" && !(r.AttackVector == "" && r.KEV) {
		return
	}
	if m.Confidence == cve.ConfidencePotential && (r.KEV || r.Severity >= checks.SeverityCritical) && len(hosts) == 1 {
		host := hosts[0]
		label := m.Product.Label
		target := host + ":" + ProductSlug(label)
		code, reason := "unversioned", "No installed version was reported. Check the build and patch status against the vendor advisory."
		if strings.TrimSpace(m.Product.Version) != "" {
			code, reason = "potential", "A version was reported, but the advisory could apply to a different build or platform. Check the affected versions and platform with the vendor."
		}
		if _, ok := b.actionIDs["act:verify:"+code+":"+target]; !ok {
			b.verify(root(TrustedLAN), code, target, "Verify "+label+" patches on "+b.assets[host].name, reason, host)
		}
		return
	}
	if !r.KEV && r.Severity < checks.SeverityHigh {
		return
	}
	if len(hosts) > 1 {
		b.verify(root(TrustedLAN), "duplicate-ip", ip, "Check duplicate IP address "+ip, "More than one device in the inventory reports this IP address, so UniBlue cannot confirm which device has "+r.ID+".", hosts...)
		return
	}
	if len(hosts) != 1 {
		return
	}
	host := hosts[0]
	for _, ep := range m.Product.Ports {
		s, ok := b.socket(host, ip, ep.Transport, ep.Port)
		if !ok {
			continue
		}
		b.link(root(TrustedLAN), s.fact(), trivial, 0, 0)
		if m.Confidence == cve.ConfidenceVersionAmbiguous {
			b.verify(s.fact(), r.ID, host+":"+serviceName(s.proto, s.port), "Check whether "+r.ID+" is patched on "+b.assets[host].name, "The version string matches, but the OS vendor may have already backported the security fix.")
			b.link(s.fact(), fact{consequence, host, r.ID}, moderate, 0, 0)
			continue
		}
		if m.Confidence != cve.ConfidenceExact {
			continue
		}
		d := low
		if r.KEV {
			d = trivial
		}
		// CVSS v2 records authentication in the vector itself.
		metrics := strings.Split(strings.Trim(r.CVSSVector, "()"), "/")
		if (r.PrivilegesRequired != "" && r.PrivilegesRequired != "N") || (r.UserInteraction != "" && r.UserInteraction != "N") ||
			slices.Contains(metrics, "Au:S") || slices.Contains(metrics, "Au:M") {
			d = moderate
		}
		a := b.action("act:patch:"+r.ID+":"+host, "Update "+b.assets[host].name+" to fix "+r.ID, "The running service version matches a known remote vulnerability.", LaneFixNow, 2)
		cf := fact{consequence, host, r.ID}
		edge := b.link(s.fact(), cf, d, a, 0)
		if b.isHighProfileSocket(s) {
			b.markHighProfile(s.fact(), s.fact())
		}
		// One CVE can affect several products on the same host. Clear the product
		// label on disagreement so pairIndexes does not attribute the shared CVE
		// consequence to one arbitrary product.
		label := m.Product.Label
		if previous, ok := b.patchProducts[edge.to]; ok && previous != label {
			label = ""
		}
		b.patchProducts[edge.to] = label
		if m.Product.Label != "" {
			bundles.record(b, s.fact(), s.port, m.Product.Label)
		}
	}
}

// publications registers configured public listeners even when active probing
// is disabled. One representative per port range suffices to expose the forward,
// while observed services inside that range keep their exact port checks.
func (b *builder) publications() {
	for _, p := range b.Snapshot.PortForwards {
		if !p.Enabled {
			continue
		}
		host, ok := b.resolvePublishedIP(p.FwdIP)
		if !ok {
			continue
		}
		for _, part := range strings.Split(cmp.Or(p.FwdPort, p.DstPort), ",") {
			lo, _, _ := strings.Cut(strings.TrimSpace(part), "-")
			port, _ := strconv.Atoi(lo)
			for _, proto := range []string{"tcp", "udp"} {
				if p.MatchesTransport(proto) {
					b.socket(host, p.FwdIP, proto, port)
				}
			}
		}
	}
	for _, m := range b.Snapshot.DynamicMappings {
		if host, ok := b.resolvePublishedIP(m.InternalIP); ok {
			b.socket(host, m.InternalIP, m.Transport, m.IntPort)
		}
	}
	for _, r := range b.Snapshot.ProxyRoutes {
		if r.PublicExposed {
			if host, ok := b.resolvePublishedIP(r.BackendIP); ok {
				b.socket(host, r.BackendIP, "tcp", r.BackendPort)
			}
		}
	}
	for _, t := range b.Snapshot.PublishedTunnels {
		if host, ok := b.resolvePublishedIP(t.BackendIP); ok {
			b.socket(host, t.BackendIP, "tcp", t.BackendPort)
		}
	}
}
