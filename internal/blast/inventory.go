// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

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
	clients         []attachment
	byIP            map[string][]string
	roles           map[string]classify.Result
	nets            map[string]unifi.Network
	sockets         map[socket]bool
	positions       map[risk.Position]fact
	cloud           []ClientEgress
	unknownPhysical bool
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
		b.verify(root(Internet), "duplicate-ip", ip, "Check duplicate IP address "+ip, "More than one device in the inventory reports this IP address, so UniBlue cannot tell which device receives forwarded traffic.")
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
func (b *builder) grant(s socket, g checks.GrantSpec, id int) {
	b.link(s.fact(), fact{consequence, s.host, string(g.Effect)}, grantLevel(g), id, 0)
}

// services wires check grants, protocol traits, CVEs, management ownership, and
// declared publications into the graph before network reachability is added.
func (b *builder) services() {
	byID := map[string]*checks.Check{}
	for _, c := range b.Checks {
		byID[c.ID] = c
	}
	for _, f := range b.Findings {
		c := byID[f.CheckID]
		if f.Port == 0 || (c == nil && f.IsInventoryOnly()) {
			continue
		}
		host := hostKey(f.Client)
		ips := f.EndpointIPs()
		if len(ips) == 0 {
			b.verify(root(TrustedLAN), "service-address", host+":"+serviceName(f.EffectiveTransport(), f.Port), "Check which IP serves "+b.assets[host].name, "This finding does not include an IP address, so it cannot be tied to a specific network path.")
		}
		for _, ip := range ips {
			s, ok := b.socket(host, ip, f.EffectiveTransport(), f.Port)
			if !ok {
				continue
			}
			b.link(root(TrustedLAN), s.fact(), trivial, 0, 0)
			var grants []checks.GrantSpec
			if c != nil {
				grants = checks.EffectiveGrants(c, f.Observation)
			}
			if len(grants) == 0 && !f.IsInventoryOnly() && (c == nil || len(c.Grants) == 0) {
				title := fmt.Sprintf("Review %s on port %d", b.assets[host].name, s.port)
				a := b.action("act:check:"+f.CheckID+":"+host+":"+serviceName(s.proto, s.port), title, cmp.Or(f.Title, "A service check found a setting that needs attention."), LaneReduceExposure, 1)
				b.link(s.fact(), fact{consequence, host, "service setting: " + f.CheckID}, low, a, 0)
			}
			for _, g := range grants {
				name := b.assets[host].name
				id := "act:check:" + c.ID + ":" + host + ":" + strconv.Itoa(f.Port)
				if s.proto != "tcp" {
					id += ":" + s.proto
				}
				if grantLevel(g) == moderate {
					title := fmt.Sprintf("Check access to %s on port %d", name, f.Port)
					reason := cmp.Or(strings.TrimSpace(g.Note), "Confirm whether sign-in, pairing, or another safeguard is required on this service.")
					if req := strings.TrimRight(strings.TrimSpace(g.Requires), "."); req != "" {
						reason = "Check whether this applies: " + req + "."
					}
					b.verify(s.fact(), c.ID, host+":"+serviceName(s.proto, s.port), title, reason)
					b.grant(s, g, 0)
				} else {
					title := fmt.Sprintf("Require sign-in or disable %s on port %d", name, f.Port)
					reason := cmp.Or(strings.TrimSpace(g.Note), strings.TrimSpace(f.Title), "Anyone who can reach this service can use it without signing in.")
					a := b.action(id, title, reason, LaneFixNow, 1)
					b.grant(s, g, a)
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
			ips := serviceIPs(hp, svc.AddressFamily)
			for _, ip := range ips {
				s, ok := b.socket(host, ip, svc.Transport, svc.Port)
				if !ok {
					continue
				}
				trait, ok := classify.LookupProtocol(svc.Protocol)
				if !ok || (svc.State != "" && svc.State != probe.ServiceStateObservedProtocol) {
					continue
				}
				b.link(root(TrustedLAN), s.fact(), trivial, 0, 0)
				for _, effect := range trait.AnonGrants {
					basis := checks.BasisConditional
					if trait.AuthModel == classify.AuthNone || svc.AnonymousAccess {
						basis = checks.BasisImplied
					}
					a := b.action("act:service:"+host+":"+serviceName(s.proto, s.port), fmt.Sprintf("Limit who can use %s on %s", svc.Protocol, b.assets[host].name), "Restricting this service to devices that need it limits who can use its built-in access.", LaneReduceExposure, 1)
					b.grant(s, checks.GrantSpec{Effect: effect, Basis: basis}, a)
				}
			}
		}
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
		b.cve(m)
	}
	for key, p := range b.Assets {
		if _, ok := b.assets[key]; !ok {
			b.addAsset(key, key, p)
		}
	}
	for _, host := range sortedKeys(b.assets) {
		p := b.assets[host].profile
		targets := append(slices.Clone(p.Manages), p.Hosts...)
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
	for _, cl := range b.clients {
		pivot := fact{consequence, cl.host, "pivot"}
		if _, ok := b.ids[pivot]; ok {
			b.link(pivot, b.position(risk.PositionForClient(cl.client)), trivial, 0, 0)
		}
	}
	b.publications()
}

// serviceIPs prefers the probed IP. Passive family observations without a single
// concrete IP cannot pin a service to a specific listener.
func serviceIPs(hp probe.HostProfile, fam string) []string {
	ip := hp.EffectiveProbeIP()
	if ip != "" && (fam == "" || family(ip) == fam) {
		return []string{ip}
	}
	var ips []string
	for _, raw := range hp.Client.AllIPs() {
		if fam == "" || family(raw) == fam {
			ips = append(ips, raw)
		}
	}
	if len(ips) == 1 {
		return ips
	}
	return nil
}

func family(ip string) string {
	if strings.Contains(ip, ":") {
		return "ipv6"
	}
	return "ipv4"
}

// cve binds network-reachable CVEs to observed endpoints. Distribution-backport
// ambiguity stays in Verify even for KEV entries; local-only CVEs are ignored.
func (b *builder) cve(m cve.Match) {
	ip := address(m.Product.HostIP)
	hosts := b.byIP[ip]
	r := m.Record
	if (!r.KEV && r.Severity < checks.SeverityHigh) || (r.AttackVector != "N" && !(r.AttackVector == "" && r.KEV)) {
		return
	}
	if len(hosts) > 1 {
		b.verify(root(TrustedLAN), "duplicate-ip", ip, "Check duplicate IP address "+ip, "More than one device in the inventory reports this IP address, so UniBlue cannot confirm which device has "+r.ID+".")
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
		if (r.PrivilegesRequired != "" && r.PrivilegesRequired != "N") || (r.UserInteraction != "" && r.UserInteraction != "N") {
			d = moderate
		}
		a := b.action("act:patch:"+r.ID+":"+host, "Update "+b.assets[host].name+" to fix "+r.ID, "The running service version matches a known remote vulnerability.", LaneFixNow, 2)
		b.link(s.fact(), fact{consequence, host, r.ID}, d, a, 0)
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
