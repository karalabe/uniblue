// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blast

import (
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
	builtinrules "github.com/karalabe/uniblue/rules"
)

var gatewayManagementPorts = []int{22, 80, 443, 8443}

var (
	wanClassifierOnce sync.Once
	wanClassifier     *risk.ExposureClassifier
)

func exposureClassifier() *risk.ExposureClassifier {
	wanClassifierOnce.Do(func() {
		wanClassifier, _ = risk.LoadExposureClassifier(builtinrules.BuiltinFS)
	})
	return wanClassifier
}

// gatewayControlTraffic identifies built-in rules for IPv6 configuration and
// established flows. These rules do not publish application listeners.
func gatewayControlTraffic(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "allow neighbor solicitations", "allow neighbor advertisements", "allow router advertisements",
		"allow router solicitations", "allow dhcpv6", "allow icmpv6", "allow return traffic":
		return true
	}
	return false
}

// isExpectedGatewayRule recognizes UniFi's own control traffic and VPN listeners.
// A user-defined policy with the same name still needs its own assessment.
func (b *builder) isExpectedGatewayRule(c risk.IsolationCell) bool {
	if c.PathKind != "gateway-local" {
		return false
	}
	var name string
	for _, p := range b.Snapshot.FirewallPolicies {
		if !p.Enabled {
			continue
		}
		if c.DecisiveRuleID != "" && c.DecisiveRuleID != p.ID ||
			c.DecisiveRuleID == "" && (c.DecisiveRuleName == "" || c.DecisiveRuleName != p.Name) {
			continue
		}
		// When only the name is known, every matching rule must be system-defined.
		if !strings.EqualFold(p.Origin, "SYSTEM_DEFINED") {
			return false
		}
		name = strings.ToLower(p.Name)
		if c.DecisiveRuleID != "" {
			break
		}
	}
	return gatewayControlTraffic(name) || strings.Contains(name, "wireguard") || strings.Contains(name, "openvpn") ||
		strings.Contains(name, "teleport") || strings.Contains(name, "l2tp") || strings.Contains(name, "vpn server") || strings.Contains(name, "ipsec")
}

// portForward resolves the exact publication so its public port and intended
// service class come from the same rule that authorized this socket.
func (b *builder) portForward(c risk.IsolationCell, s socket) (unifi.PortForward, bool) {
	for _, pf := range b.Snapshot.PortForwards {
		pf.FwdPort = cmp.Or(pf.FwdPort, pf.DstPort)
		if address(pf.FwdIP) != s.ip || !pf.ExposesEndpoint(s.port, s.proto) {
			continue
		}
		if (c.DecisiveRuleID != "" && pf.ID != c.DecisiveRuleID) ||
			(c.DecisiveRuleID == "" && pf.Name != c.DecisiveRuleName) {
			continue
		}
		return pf, true
	}
	return unifi.PortForward{}, false
}

// classifyForward applies the exposure rules to the listener reached by this forward.
func classifyForward(pf unifi.PortForward, s socket, cl unifi.Client) string {
	pf.FwdPort, pf.Proto = strconv.Itoa(s.port), s.proto
	return exposureClassifier().Classify(pf, cl).Class
}

// tcpOnlyPolicy checks the configured scope because a broad rule can also
// produce a TCP/22 witness when the oracle evaluates individual listeners.
func (b *builder) tcpOnlyPolicy(c risk.IsolationCell, ports ...int) bool {
	found := false
	for _, p := range b.Snapshot.FirewallPolicies {
		if !p.Enabled || p.ID != c.DecisiveRuleID || p.Name != c.DecisiveRuleName {
			continue
		}
		if p.ProtocolNegated || !strings.EqualFold(p.Protocol, "tcp") || !p.Destination.OnlyPort(ports...) {
			return false
		}
		found = true
	}
	return found
}

// sshAccess keeps adopted-device key settings separate from console authentication.
func (b *builder) sshAccess(s socket, cl unifi.Client) string {
	if cl.NetworkID == risk.GatewayNetworkID {
		if settings := b.Snapshot.SecuritySettings; settings != nil && settings.SSHPasswordAuth {
			return "password"
		}
		return ""
	}
	return risk.ObservedSSHAccess(b.Profiles, cl, s.ip, s.port)
}

type egressLink struct {
	from, to fact
	cut      int
	srcName  string
	dstKey   string
	dstName  string
}

type ruleScopeIndex struct {
	allScoped bool
	macs      map[string]bool
	prefixes  []netip.Prefix
}

func (r ruleScopeIndex) matchesClient(cl unifi.Client) bool {
	if r.allScoped {
		return true
	}
	m := canonicalMAC(cl.MAC)
	if len(r.macs) > 0 && (m == "" || r.macs[m]) {
		return true
	}
	for _, raw := range cl.AllIPs() {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		for _, pfx := range r.prefixes {
			if pfx.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func (r ruleScopeIndex) matchesPosition(pos risk.Position) bool {
	if r.allScoped {
		return true
	}
	m := canonicalMAC(pos.MAC)
	if len(r.macs) > 0 && (m == "" || r.macs[m]) {
		return true
	}
	if len(r.prefixes) > 0 && pos.IP == "" {
		return true
	}
	if pos.IP != "" {
		addr, err := netip.ParseAddr(strings.TrimSpace(pos.IP))
		if err != nil {
			return true
		}
		addr = addr.Unmap()
		for _, pfx := range r.prefixes {
			if pfx.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func parseSelectorPrefix(raw string) (netip.Prefix, bool) {
	s := strings.TrimSpace(raw)
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Masked(), true
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}

// matchesIPSelector checks whether addr matches a single IP, CIDR prefix, or
// inclusive "start-end" range in the same address family.
func matchesIPSelector(addr netip.Addr, raw string) bool {
	if pfx, ok := parseSelectorPrefix(raw); ok {
		return pfx.Contains(addr)
	}
	loStr, hiStr, ok := strings.Cut(strings.TrimSpace(raw), "-")
	if !ok {
		return false
	}
	lo, errLo := netip.ParseAddr(strings.TrimSpace(loStr))
	hi, errHi := netip.ParseAddr(strings.TrimSpace(hiStr))
	if errLo != nil || errHi != nil {
		return false
	}
	lo, hi = lo.Unmap(), hi.Unmap()
	return lo.BitLen() == addr.BitLen() && hi.BitLen() == addr.BitLen() && addr.Compare(lo) >= 0 && addr.Compare(hi) <= 0
}

// buildRuleScopeIndex records every IP, CIDR, and MAC referenced by any enabled
// firewall policy or switch ACL so unreferenced endpoints can safely share
// identical cross-VLAN Oracle decisions.
func (b *builder) buildRuleScopeIndex() ruleScopeIndex {
	idx := ruleScopeIndex{macs: map[string]bool{}}
	addEndpoint := func(ips, macs []string) {
		for _, m := range macs {
			if cm := canonicalMAC(m); cm != "" {
				idx.macs[cm] = true
			} else if strings.TrimSpace(m) != "" {
				idx.allScoped = true
			}
		}
		for _, raw := range ips {
			if pfx, ok := parseSelectorPrefix(raw); ok {
				idx.prefixes = append(idx.prefixes, pfx)
			} else if strings.TrimSpace(raw) != "" {
				idx.allScoped = true
			}
		}
	}
	for _, p := range b.Snapshot.FirewallPolicies {
		if !p.Enabled {
			continue
		}
		addEndpoint(p.Source.IPs, p.Source.MACs)
		addEndpoint(p.Destination.IPs, p.Destination.MACs)
	}
	for _, a := range b.Snapshot.SwitchACLs {
		if !a.Enabled {
			continue
		}
		addEndpoint(a.Source.IPs, a.Source.MACs)
		addEndpoint(a.Destination.IPs, a.Destination.MACs)
	}
	return idx
}

func isAutoPortForwardPolicy(p unifi.FirewallPolicy) bool {
	return strings.EqualFold(p.Origin, "SYSTEM_DEFINED") && strings.HasPrefix(strings.ToLower(strings.TrimSpace(p.Name)), "allow port forward")
}

// isAutoPortForwardCell reports whether c was decided by UniFi's auto-generated
// "Allow Port Forward" policy. When a rule ID is present, matching strictly by
// ID avoids mistaking a user-defined rule that shares the same name.
func (b *builder) isAutoPortForwardCell(c risk.IsolationCell) bool {
	for _, p := range b.Snapshot.FirewallPolicies {
		if c.DecisiveRuleID != "" {
			if p.ID == c.DecisiveRuleID {
				return isAutoPortForwardPolicy(p)
			}
			continue
		}
		if c.DecisiveRuleName != "" && p.Name == c.DecisiveRuleName && isAutoPortForwardPolicy(p) {
			return true
		}
	}
	return false
}

func (b *builder) hasEnabledPortForwardFor(rawIP string) bool {
	ip := address(rawIP)
	if ip == "" {
		return false
	}
	for _, pf := range b.Snapshot.PortForwards {
		if pf.Enabled && address(pf.FwdIP) == ip {
			return true
		}
	}
	return false
}

func policyTransports(proto string) []string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "", "all", "tcp_udp":
		return []string{"tcp", "udp"}
	case "tcp":
		return []string{"tcp"}
	case "udp":
		return []string{"udp"}
	default:
		return nil
	}
}

func policyMatchesFamily(ipVersion, ip string) bool {
	v := strings.ToLower(strings.TrimSpace(ipVersion))
	if v == "" || v == "both" {
		return true
	}
	return v == family(ip)
}

// addPolicySockets records ports explicitly opened by External-sourced allow
// policies, strictly scoped to the hosts and transports those policies target.
func (b *builder) addPolicySockets(a attachment) {
	dstNet := b.network(a.client.NetworkID, a.client.NetworkName)
	dstMAC := canonicalMAC(a.client.MAC)
	for _, p := range b.Snapshot.FirewallPolicies {
		if !p.Enabled || !strings.EqualFold(p.Action, "allow") || isAutoPortForwardPolicy(p) {
			continue
		}
		if p.Source.ZoneName != "" && !strings.EqualFold(p.Source.ZoneName, "External") {
			continue
		}
		ports := slices.Clone(p.Destination.Ports)
		for _, r := range p.Destination.PortRanges {
			ports = append(ports, r.Start)
		}
		if len(ports) == 0 {
			continue
		}
		if p.Destination.ZoneName != "" && !strings.EqualFold(p.Destination.ZoneName, dstNet.ZoneName) {
			continue
		}
		if len(p.Destination.NetworkIDs) > 0 {
			inNets := slices.Contains(p.Destination.NetworkIDs, dstNet.ID)
			if p.Destination.NegateTarget {
				inNets = !inNets
			}
			if !inNets {
				continue
			}
		}
		if !p.Destination.AnyTarget && len(p.Destination.MACs) > 0 {
			inMACs := dstMAC != "" && slices.ContainsFunc(p.Destination.MACs, func(m string) bool { return canonicalMAC(m) == dstMAC })
			if p.Destination.NegateTarget {
				inMACs = !inMACs
			}
			if !inMACs {
				continue
			}
		}
		protos := policyTransports(p.Protocol)
		if len(protos) == 0 {
			continue
		}
		for _, rawIP := range a.client.AllIPs() {
			ip := address(rawIP)
			if ip == "" || !policyMatchesFamily(p.IPVersion, ip) {
				continue
			}
			if !p.Destination.AnyTarget && len(p.Destination.IPs) > 0 {
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					continue
				}
				matched := false
				for _, sel := range p.Destination.IPs {
					if matchesIPSelector(addr, sel) {
						matched = true
						break
					}
				}
				if p.Destination.NegateTarget {
					matched = !matched
				}
				if !matched {
					continue
				}
			}
			for _, port := range ports {
				for _, proto := range protos {
					b.socket(a.host, ip, proto, port)
				}
			}
		}
	}
}

func isRoutableAddr(raw, fam string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if (fam == "ipv6") != addr.Is6() {
		return false
	}
	return !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && !addr.IsLinkLocalMulticast() && !addr.IsUnspecified()
}

func hasRoutableInFamily(cl unifi.Client, fam string) bool {
	for _, raw := range cl.AllIPs() {
		if isRoutableAddr(raw, fam) {
			return true
		}
	}
	return false
}

func isGatewayPolicyKind(kind string) bool {
	return kind == "gateway-routed" || kind == "gateway-local"
}

// allGatewayAllows peels away each winning gateway firewall policy so later
// rules that independently permit the same traffic become parallel graph edges.
func (b *builder) allGatewayAllows(query func(*risk.Oracle) []risk.IsolationCell, skipAutoPF func(risk.IsolationCell) bool) []risk.IsolationCell {
	var out []risk.IsolationCell
	excluded := map[string]bool{}
	seen := map[string]bool{}
	for step := 0; step <= len(b.Snapshot.FirewallPolicies); step++ {
		cells := query(b.Oracle.WithoutPolicies(excluded))
		progressed := false
		for _, c := range cells {
			if !isGatewayPolicyKind(c.PathKind) {
				continue
			}
			if c.Effective != "allow" {
				key := "unk|" + cmp.Or(c.DecisiveRuleID, c.DecisiveRuleName, c.MissingInput) + "|" + c.DestIP + "|" + c.SourceNetwork
				if !seen[key] {
					seen[key] = true
					out = append(out, c)
				}
				continue
			}
			if skipAutoPF != nil && skipAutoPF(c) {
				if c.DecisiveRuleID != "" && !excluded[c.DecisiveRuleID] {
					excluded[c.DecisiveRuleID] = true
					progressed = true
				}
				continue
			}
			key := cmp.Or(c.DecisiveRuleID, c.DecisiveRuleName) + "|" + c.DestIP + "|" + c.SourceNetwork
			if !seen[key] {
				seen[key] = true
				out = append(out, c)
			}
			if c.DecisiveRuleID != "" && !excluded[c.DecisiveRuleID] {
				excluded[c.DecisiveRuleID] = true
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

// routes queries the Oracle for WAN ingress and lateral reachability and builds
// the static edge graph consumed by counterfactual ranking.
func (b *builder) routes() {
	visibility := b.Snapshot.Visibility
	if visibility != nil && !visibility.WLANsAvailable {
		b.verify(root(WiFi), "wireless", "site", "Check wireless network settings", "The controller did not supply current Wi-Fi security and client-isolation settings.")
	}
	upnpUnknown := b.Snapshot.SecuritySettings != nil && b.Snapshot.SecuritySettings.UPnPEnabled && len(b.Snapshot.DynamicMappings) == 0
	if upnpUnknown {
		b.verify(root(Internet), "upnp-leases", "site", "Check automatic UPnP and NAT-PMP port mappings", "UPnP or NAT-PMP is turned on at the gateway, but active port mappings are unavailable, so UniBlue cannot confirm that LAN devices are unreachable from the internet.")
	}
	for _, a := range b.clients {
		cl := a.client
		b.addPolicySockets(a)
		if visibility != nil && !visibility.PortForwardsAvailable {
			b.missing(root(Internet), risk.IsolationCell{MissingInput: "port-forward telemetry unavailable"})
			b.link(root(Internet), fact{permission, a.host, "network access"}, unknown, 0, 0)
		}
		if upnpUnknown {
			b.link(root(Internet), fact{permission, a.host, "network access"}, unknown, 0, 0)
		}
		if b.unknownPhysical {
			n := b.network(cl.NetworkID, cl.NetworkName)
			if !strings.EqualFold(n.ZoneName, "External") && !strings.HasPrefix(strings.ToLower(n.Purpose), "wan") {
				b.link(root(Physical), fact{permission, a.host, "network access"}, unknown, 0, 0)
			}
		}
		for _, fam := range b.Oracle.Families(cl) {
			skipAuto := func(c risk.IsolationCell) bool {
				return b.isAutoPortForwardCell(c) && (visibility == nil || visibility.PortForwardsAvailable) && b.hasEnabledPortForwardFor(c.DestIP)
			}
			for _, c := range b.allGatewayAllows(func(o *risk.Oracle) []risk.IsolationCell {
				return o.InternetPolicy(cl, fam)
			}, skipAuto) {
				if c.Effective == "unknown" {
					b.missing(root(Internet), c)
					b.link(root(Internet), fact{permission, a.host, "network access"}, unknown, 0, 0)
				}
				if c.Effective == "allow" {
					if b.isExpectedGatewayRule(c) {
						continue
					}
					if _, ok := b.socket(a.host, c.DestIP, c.Transport, c.Port); !ok {
						entry, _ := b.scope(socket{}, c)
						lane := LaneFixNow
						if entry == InternetSource {
							lane = LaneReduceExposure
						}
						cut := b.action("act:"+cmp.Or(c.PathKind, "gateway-routed")+":"+cmp.Or(c.DecisiveRuleID, c.DecisiveRuleName), "Limit inbound internet rule "+cmp.Or(c.DecisiveRuleName, "on the gateway"), "This firewall rule allows inbound connections from the internet to reach inside the network.", lane, 1)
						pf := fact{permission, a.host, "network access"}
						b.link(root(entry), pf, trivial, cut, 0)
						if b.highProfileFamily[a.host+"|"+fam] {
							b.markHighProfile(root(entry), root(entry))
						}
						label := "WAN inbound rule"
						if entry == InternetSource {
							label += " (restricted)"
						}
						b.wanEdges = append(b.wanEdges, SimEdge{From: "internet", To: a.host, Tier: "wan", Label: label, Via: c.DecisiveRuleName, CutIDs: []string{b.actions[cut].ID}})
					}
				}
			}
		}
	}
	byHost := map[string][]socket{}
	for s := range b.sockets {
		byHost[s.host] = append(byHost[s.host], s)
	}
	groups := map[fact][]publication{}
	for _, a := range b.clients {
		b.internet(a, byHost[a.host], groups, upnpUnknown)
	}
	b.linkPublications(groups)

	scopeIdx := b.buildRuleScopeIndex()
	type crossKey struct {
		srcNet, srcZone     string
		srcHasIP, srcHasMAC bool
		dstNet              string
		dstHasIP, dstHasMAC bool
		fam                 string
	}
	type wifiKey struct {
		net, ap, ssid, fam string
	}
	crossCache := map[crossKey]risk.IsolationCell{}
	wifiCache := map[wifiKey]risk.IsolationCell{}

	hasApproved := len(b.NetCfg.IsolationPolicy.ApprovedPaths) > 0
	var deferredEgress []egressLink

	type posMeta struct {
		pos      risk.Position
		from     fact
		netKey   string
		mac      string
		scoped   bool
		families []string
		routable map[string]bool
	}
	positions := make([]posMeta, 0, len(b.positions))
	for pos, from := range b.positions {
		fams := b.Oracle.Families(unifi.Client{NetworkID: pos.NetworkID, NetworkName: pos.NetworkName, IP: pos.IP})
		rm := make(map[string]bool, len(fams))
		for _, fam := range fams {
			rm[fam] = pos.IP == "" || isRoutableAddr(pos.IP, fam)
		}
		positions = append(positions, posMeta{
			pos:      pos,
			from:     from,
			netKey:   networkKey(b.network(pos.NetworkID, pos.NetworkName)),
			mac:      canonicalMAC(pos.MAC),
			scoped:   scopeIdx.matchesPosition(pos),
			families: fams,
			routable: rm,
		})
	}
	slices.SortFunc(positions, func(a, b posMeta) int {
		return cmp.Compare(a.from.detail, b.from.detail)
	})

	for _, a := range b.clients {
		dstNet := b.network(a.client.NetworkID, a.client.NetworkName)
		dstNetKey := networkKey(dstNet)
		dstMAC := canonicalMAC(a.client.MAC)
		dstScoped := scopeIdx.matchesClient(a.client)
		dstFamilies := b.Oracle.Families(a.client)
		dstRoutable := make(map[string]bool, 2)
		for _, fam := range []string{"ipv4", "ipv6"} {
			dstRoutable[fam] = hasRoutableInFamily(a.client, fam)
		}
		for _, pm := range positions {
			pos, from := pm.pos, pm.from
			if (pm.mac != "" && pm.mac == dstMAC) || (pos.IP != "" && owns(a.client, pos.IP)) {
				continue
			}
			sameNet := pm.netKey != "" && pm.netKey == dstNetKey
			families := dstFamilies
			if len(pm.families) > len(families) {
				families = pm.families
			}
			for _, fam := range families {
				if a.client.NetworkID == risk.GatewayNetworkID {
					// DNS and DHCP on the gateway do not grant administrative access.
					for _, port := range gatewayManagementPorts {
						b.boundaryFact(pos, from, a.host, a.client.NetworkID, "network management", b.Oracle.Service(pos, a.client, "tcp", port, fam), &deferredEgress)
					}
				} else {
					var cell risk.IsolationCell
					switch {
					case !sameNet && pm.netKey != "" && dstNetKey != "" && !pm.scoped && !dstScoped && pm.routable[fam] && dstRoutable[fam]:
						k := crossKey{pm.netKey, pos.Zone, pos.IP != "", pm.mac != "", dstNetKey, true, dstMAC != "", fam}
						var ok bool
						if cell, ok = crossCache[k]; !ok {
							cell = b.Oracle.Transit(pos, a.client, fam)
							crossCache[k] = cell
						}
					case sameNet && !pos.IsWired && !a.client.IsWired && pos.APMAC != "" && strings.EqualFold(pos.APMAC, a.client.APMAC) && pos.SSID != "" && pos.SSID == a.client.ESSID:
						k := wifiKey{pm.netKey, strings.ToLower(pos.APMAC), pos.SSID, fam}
						var ok bool
						if cell, ok = wifiCache[k]; !ok {
							cell = b.Oracle.Transit(pos, a.client, fam)
							wifiCache[k] = cell
						}
					default:
						cell = b.Oracle.Transit(pos, a.client, fam)
					}
					if cell.Verdict != risk.IsolationApproved {
						b.boundaryFact(pos, from, a.host, a.client.NetworkID, "network access", cell, &deferredEgress)
					}
				}
				if hasApproved {
					for _, ap := range b.Oracle.ApprovedServices(pos, a.client, b.Findings, fam) {
						var cell risk.IsolationCell
						if ap.Port == 0 {
							cell = b.Oracle.AnyPort(pos, a.client, fam)
						} else {
							cell = b.Oracle.Service(pos, a.client, cmp.Or(ap.Transport, "tcp"), ap.Port, fam)
						}
						if cell.Effective == "allow" {
							if a.client.NetworkID != risk.GatewayNetworkID || ((ap.Transport == "" || strings.EqualFold(ap.Transport, "tcp")) && (ap.Port == 0 || slices.Contains(gatewayManagementPorts, ap.Port))) {
								cut, _, _, _ := b.boundary(pos, a.client.NetworkID, cell)
								b.approved(cut, ap.Name)
							}
							// Securing or untagging an outdoor port also interrupts approved traffic from that socket.
							for _, e := range b.edges[b.ids[root(Physical)]] {
								if e.to == b.ids[from] {
									b.approved(e.cut, ap.Name)
									b.approved(e.bundle, ap.Name)
									b.approved(e.tagCut, ap.Name)
								}
							}
						}
					}
				}
			}
			for _, s := range byHost[a.host] {
				if _, observed := b.ids[s.fact()]; !observed || !owns(a.client, s.ip) {
					continue
				}
				dst := pin(a.client, s.ip)
				c := b.Oracle.Service(pos, dst, s.proto, s.port, family(s.ip))
				b.lateral(pos, from, s.fact(), a.client.NetworkID, c, &deferredEgress)
			}
		}
	}
	b.linkEgressBundles(deferredEgress)
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return "multiple networks"
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	default:
		return strings.Join(names[:len(names)-1], ", ") + ", and " + names[len(names)-1]
	}
}

// linkEgressBundles attaches a combined destination-ingress action whenever two
// or more distinct source VLANs can reach the same destination VLAN, naming the
// exact source networks so the recommendation stays concrete and honest.
func (b *builder) linkEgressBundles(links []egressLink) {
	cutsByDst := map[string]map[int]bool{}
	srcsByDst := map[string]map[string]bool{}
	nameByDst := map[string]string{}
	for _, l := range links {
		if cutsByDst[l.dstKey] == nil {
			cutsByDst[l.dstKey] = map[int]bool{}
			srcsByDst[l.dstKey] = map[string]bool{}
		}
		cutsByDst[l.dstKey][l.cut] = true
		if l.srcName != "" {
			srcsByDst[l.dstKey][l.srcName] = true
		}
		nameByDst[l.dstKey] = l.dstName
	}
	bundles := map[string]int{}
	for _, dstKey := range sortedKeys(cutsByDst) {
		cuts := cutsByDst[dstKey]
		if len(cuts) < 2 {
			continue
		}
		dstName := nameByDst[dstKey]
		srcs := sortedKeys(srcsByDst[dstKey])
		srcList := joinNames(srcs)
		bundle := b.routedAction("act:vlan-ingress:"+dstKey, dstKey, srcs, "Block traffic from "+srcList+" to "+dstName,
			srcList+" can reach "+dstName+". Blocking only one still leaves it reachable from the rest.", 3)
		for cut := range cuts {
			for _, name := range b.actions[cut].BreaksApproved {
				b.approved(bundle, name)
			}
		}
		bundles[dstKey] = bundle
	}
	for _, l := range links {
		b.link(l.from, l.to, trivial, l.cut, bundles[l.dstKey])
	}
}

// boundaryFact records explicit deny evidence without allowing permissions to propagate.
func (b *builder) boundaryFact(pos risk.Position, from fact, host, dstID, label string, c risk.IsolationCell, deferred *[]egressLink) {
	if c.Effective == "deny" {
		b.link(from, fact{blocked, host, label}, trivial, 0, 0)
		return
	}
	b.lateral(pos, from, fact{permission, host, label}, dstID, c, deferred)
}

// pin locks an Oracle service query to the single address that supplied the evidence.
func pin(cl unifi.Client, ip string) unifi.Client {
	cl.IP = ip
	cl.IPv6 = nil
	return cl
}

func owns(cl unifi.Client, ip string) bool {
	return slices.ContainsFunc(cl.AllIPs(), func(s string) bool { return address(s) == ip })
}

// boundary returns the action controlling a permitted lateral path. For routed
// inter-VLAN rules it also returns the source display name and destination key/name.
func (b *builder) boundary(pos risk.Position, dstID string, c risk.IsolationCell) (cut int, srcName, dstKey, dstName string) {
	id, from, dk, to := b.boundaryID(pos, dstID, c)
	switch c.PathKind {
	case "same-ap-wifi":
		return b.action(id, "Turn on client isolation for "+pos.SSID, "This prevents wireless devices on the same access point from talking directly to each other.", LaneReduceExposure, 1), "", "", ""
	case "wired-same-vlan", "mixed-same-vlan", "cross-ap-wifi":
		return b.action(id, "Isolate devices on "+from, "Turn on port or client isolation so devices on "+from+" cannot reach each other directly.", LaneReduceExposure, 2), "", "", ""
	}
	return b.routedAction(id, dk, []string{from}, "Block unnecessary traffic from "+from+" to "+to, "Adding a firewall rule between these networks limits what a compromised device on "+from+" can reach.", 2), from, dk, to
}

// routedAction narrows gateway management advice so trusted clients can keep using DNS and DHCP.
func (b *builder) routedAction(id, dst string, sources []string, title, reason string, effort int) int {
	if dst == risk.GatewayNetworkID {
		title = "Restrict Gateway management access (SSH/HTTPS) from " + joinNames(sources)
		reason = "Allowing only admin devices to reach gateway SSH and HTTPS keeps normal DNS/DHCP working while limiting router takeover paths."
	}
	return b.action(id, title, reason, LaneReduceExposure, effort)
}

// boundaryID identifies the same control in the ranked report and in hypothetical client paths.
func (b *builder) boundaryID(pos risk.Position, dstID string, c risk.IsolationCell) (id, from, dk, to string) {
	src, dst := b.network(pos.NetworkID, cmp.Or(c.SourceNetwork, pos.NetworkName)), b.network(dstID, c.DestNetwork)
	from, to = cmp.Or(src.Name, c.SourceNetwork, "the source network"), cmp.Or(dst.Name, c.DestNetwork, "the destination network")
	key := cmp.Or(networkKey(src), from)
	switch c.PathKind {
	case "same-ap-wifi":
		return "act:l2-peers:" + key + ":wifi:" + pos.SSID, from, "", to
	case "wired-same-vlan", "mixed-same-vlan", "cross-ap-wifi":
		return "act:l2-peers:" + key, from, "", to
	}
	dk = cmp.Or(networkKey(dst), to)
	return "act:vlan-egress:" + key + "->" + dk, from, dk, to
}

func (b *builder) approved(id int, name string) {
	if id == 0 || name == "" || slices.Contains(b.actions[id].BreaksApproved, name) {
		return
	}
	b.actions[id].BreaksApproved = append(b.actions[id].BreaksApproved, name)
}

// missing records a verification item for incomplete controller telemetry.
func (b *builder) missing(from fact, c risk.IsolationCell) {
	label := cmp.Or(c.DestNetwork, c.SourceNetwork, "site")
	n := b.network("", cmp.Or(c.DestNetwork, c.SourceNetwork))
	key := cmp.Or(networkKey(n), label)
	why := strings.ToLower(c.MissingInput)
	code, title, reason := "route", "Check how traffic reaches "+label, "The controller did not provide enough information to verify this path."
	switch {
	case strings.Contains(why, "switch acl"):
		code = "switch-acls"
		title = "Check switch ACL rules for " + label
		reason = "Switch ACL data is missing, so UniBlue cannot verify which traffic this switch blocks."
	case strings.Contains(why, "polic") || strings.Contains(why, "firewall"):
		code = "firewall"
		key = "site"
		title = "Check gateway firewall rules"
		reason = "Firewall policy data is missing, so UniBlue cannot confirm which connections the gateway blocks."
	case strings.Contains(why, "router") || strings.Contains(why, "routing owner"):
		code = "router"
		title = "Identify which device routes " + label
	case strings.Contains(why, "port-forward"):
		code = "wan-forwards"
		key = "site"
		title = "Check internet port forwards"
		reason = "The controller did not supply the port-forward list, so UniBlue cannot confirm which services are exposed."
	}
	b.verify(from, code, key, title, reason)
}

func (b *builder) lateral(pos risk.Position, from, to fact, dstID string, c risk.IsolationCell, deferred *[]egressLink) {
	switch c.Effective {
	case "deny":
		return
	case "allow":
		cut, srcName, dstKey, dstName := b.boundary(pos, dstID, c)
		if dstKey != "" && deferred != nil {
			*deferred = append(*deferred, egressLink{from: from, to: to, cut: cut, srcName: srcName, dstKey: dstKey, dstName: dstName})
			return
		}
		b.link(from, to, trivial, cut, 0)
	default:
		b.missing(from, c)
		b.link(from, to, unknown, 0, 0)
	}
}

type publication struct {
	label        string
	s            socket
	entry        Entry
	level        uint8
	action       int
	expected     bool
	outcomeLevel uint8
}

// internet adds every independent WAN route for a host's sockets, peeling away
// shadowing gateway-routed policies and deduplicating UniFi's auto-generated
// "Allow Port Forward" companion policy only when the port forward is active.
func (b *builder) internet(a attachment, sockets []socket, groups map[fact][]publication, upnpUnknown bool) {
	anyIngress := false
	for _, s := range sockets {
		if !owns(a.client, s.ip) {
			continue
		}
		if upnpUnknown {
			b.link(root(Internet), s.fact(), unknown, 0, 0)
			b.link(root(Internet), fact{consequence, a.host, "public access to " + serviceName(s.proto, s.port)}, unknown, 0, 0)
		}
		if len(b.byIP[s.ip]) > 1 {
			b.verify(root(Internet), "duplicate-ip", s.ip, "Check duplicate IP address "+s.ip, "More than one device in the inventory reports this IP address, so UniBlue cannot tell which device receives forwarded traffic.")
			b.link(root(Internet), s.fact(), unknown, 0, 0)
			b.link(root(Internet), fact{consequence, a.host, "public access to " + serviceName(s.proto, s.port)}, unknown, 0, 0)
			b.link(root(Internet), fact{permission, a.host, "network access"}, unknown, 0, 0)
			continue
		}
		dst := pin(a.client, s.ip)
		fam := family(s.ip)
		rawCells := b.Oracle.Internet(dst, s.proto, s.port, fam)
		hasPortForward := slices.ContainsFunc(rawCells, func(c risk.IsolationCell) bool {
			return c.PathKind == "port-forward" && c.Effective == "allow" && (c.DestIP == "" || address(c.DestIP) == s.ip)
		})
		var cells []risk.IsolationCell
		for _, c := range rawCells {
			if !isGatewayPolicyKind(c.PathKind) {
				cells = append(cells, c)
			}
		}
		var skipAuto func(risk.IsolationCell) bool
		if hasPortForward {
			skipAuto = b.isAutoPortForwardCell
		}
		cells = append(cells, b.allGatewayAllows(func(o *risk.Oracle) []risk.IsolationCell {
			return o.Internet(dst, s.proto, s.port, fam)
		}, skipAuto)...)

		for _, c := range cells {
			if c.DestIP != "" && address(c.DestIP) != s.ip {
				continue
			}
			expected := b.isExpectedGatewayRule(c)
			if c.Effective == "allow" && expected && gatewayControlTraffic(c.DecisiveRuleName) && len(b.listenerRemedies(s)) == 0 {
				continue
			}
			anyIngress = true
			entry, level := b.scope(s, c)
			if level == unknown && c.Effective == "allow" {
				b.verify(root(entry), "public-login", cmp.Or(c.DecisiveRuleName, s.host), "Check login protection on "+cmp.Or(c.DecisiveRuleName, b.assets[s.host].name), "This service is published online, but the inventory does not say whether visitors must sign in.")
			}
			if c.Effective != "allow" {
				b.missing(root(entry), c)
				b.link(root(entry), s.fact(), unknown, 0, 0)
				b.link(root(entry), fact{consequence, a.host, "public access to " + serviceName(s.proto, s.port)}, unknown, 0, 0)
				b.link(root(entry), fact{permission, a.host, "network access"}, unknown, 0, 0)
				continue
			}
			id := cmp.Or(c.DecisiveRuleID, c.DecisiveRuleName)
			kind := c.PathKind
			entryLabel := "WAN " + strings.ToUpper(serviceName(s.proto, s.port))
			label := b.assets[s.host].name
			title := "Limit inbound internet rule " + cmp.Or(c.DecisiveRuleName, "for "+label)
			why := "This rule lets connections from the internet reach a service inside your network."
			sshOnly := s.port == 22 && s.proto == "tcp" && isGatewayPolicyKind(kind) && b.tcpOnlyPolicy(c, 22)
			webOnly := (s.port == 80 || s.port == 443) && s.proto == "tcp" && isGatewayPolicyKind(kind) && b.tcpOnlyPolicy(c, 80, 443)
			if webOnly {
				webOnly = classifyForward(unifi.PortForward{Enabled: true, Name: c.DecisiveRuleName}, s, a.client) == "web-entrypoint"
			}
			switch kind {
			case "port-forward":
				kind = "wan-pf"
				if pf, ok := b.portForward(c, s); ok {
					class := classifyForward(pf, s, a.client)
					webOnly = class == "web-entrypoint" && strings.EqualFold(pf.Proto, "tcp") && pf.OnlyPorts(80, 443)
					expected = class == "expected-p2p" || class == "vpn-entrypoint"
					sshOnly = s.port == 22 && strings.EqualFold(pf.Proto, "tcp") && pf.OnlyBackendPort(22)
					if pf.DstPort != "" {
						entryLabel = "WAN " + strings.ToUpper(s.proto) + "/" + pf.DstPort
					}
				}
				title = "Close port forward " + cmp.Or(c.DecisiveRuleName, "to "+label)
				why = "This port forward exposes a local service directly to the internet."
			case "proxy-route", "published-tunnel":
				entryLabel = "Public proxy"
				if kind == "published-tunnel" {
					entryLabel = "Published tunnel"
				}
				title = "Restrict public access through " + cmp.Or(c.DecisiveRuleName, label)
				why = "This public route forwards internet traffic to an internal service."
				id = c.Enforcer + ":" + id
			case "dynamic-mapping":
				entryLabel = "WAN automatic mapping"
				title = "Remove automatic port mapping to " + label
				why = "An automatic UPnP or NAT-PMP lease exposes this port to the internet."
			}
			id = cmp.Or(id, s.ip+":"+serviceName(s.proto, s.port))
			lane := LaneFixNow
			if entry == InternetSource || level >= moderate {
				lane = LaneReduceExposure
			}
			clean := len(b.listenerRemedies(s)) == 0
			outcomeLevel := trivial
			if clean && webOnly {
				lane, outcomeLevel = LaneReduceExposure, moderate
				title = "Review public web entrypoint " + cmp.Or(c.DecisiveRuleName, label)
				why = "Public HTTP/HTTPS entrypoint. Keep the reverse proxy patched and confirm no internal admin panels are exposed."
			}
			if sshOnly {
				switch auth := b.sshAccess(s, a.client); auth {
				case "none":
					why = "WAN SSH accepts connections without authentication."
				case "password":
					why = "Password or keyboard-interactive authentication is enabled on WAN SSH."
				default:
					if clean {
						lane, outcomeLevel = LaneReduceExposure, moderate
						title = "Restrict SSH source IPs or use VPN"
						why = "Limit which internet clients can reach SSH on " + label + "."
					}
					reason := "The authentication methods offered by this public SSH listener are unknown."
					if auth == "publickey" {
						reason = "The probed account offered only public-key login. SSH Match User rules can allow passwords for other accounts."
					}
					b.verify(root(entry), "ssh-auth", s.host+":"+s.ip, "Confirm password login is disabled on "+label, reason)
				}
			}
			if expected && clean {
				continue
			}
			act := b.action("act:"+kind+":"+id, title, why, lane, 1)
			for _, ap := range b.Oracle.ApprovedServices(risk.Position{Zone: "External"}, dst, b.Findings, fam) {
				if (ap.Port == 0 || ap.Port == s.port) && (ap.Transport == "" || strings.EqualFold(ap.Transport, s.proto)) {
					b.approved(act, ap.Name)
				}
			}
			k := fact{consequence, a.host, "public access to " + serviceName(s.proto, s.port)}
			groups[k] = append(groups[k], publication{label: entryLabel, s: s, entry: entry, level: level, action: act, expected: expected, outcomeLevel: outcomeLevel})
		}
	}
	if !anyIngress && !upnpUnknown && len(sockets) > 0 && b.Snapshot.Visibility != nil && b.Snapshot.Visibility.GatewayPoliciesAvailable && b.Snapshot.Visibility.PortForwardsAvailable {
		b.link(root(Internet), fact{blocked, a.host, "network access"}, trivial, 0, 0)
	}
}

// linkPublications adds a service-wide bundle cut whenever multiple distinct
// routes publish the same service (for example across both IPv4 and IPv6).
func (b *builder) linkPublications(groups map[fact][]publication) {
	for outcome, routes := range groups {
		host := outcome.asset
		service := serviceName(routes[0].s.proto, routes[0].s.port)
		bundle := 0
		if slices.ContainsFunc(routes, func(r publication) bool { return r.action != routes[0].action }) {
			lane, verb := LaneReduceExposure, "Review"
			if slices.ContainsFunc(routes, func(r publication) bool { return b.actions[r.action].Lane == LaneFixNow }) {
				lane, verb = LaneFixNow, "Close"
			}
			bundle = b.action("act:wan-service:"+host+":"+service, verb+" all public routes to "+b.assets[host].name+" on "+service, "Multiple routes publish this same service. Closing only one leaves it reachable through the others.", lane, 2)
			for _, r := range routes {
				for _, name := range b.actions[r.action].BreaksApproved {
					b.approved(bundle, name)
				}
			}
		}
		for _, r := range routes {
			label := r.label
			if r.entry == InternetSource {
				label += " (restricted)"
			} else if r.level == moderate {
				label += " (authenticated)"
			} else if r.level == unknown {
				label += " (login unverified)"
			}
			wan := SimEdge{From: "internet", To: host, Tier: "wan", Label: label, Via: b.actions[r.action].Title}
			wan.CutIDs = []string{b.actions[r.action].ID}
			if bundle != 0 {
				wan.CutIDs = append(wan.CutIDs, b.actions[bundle].ID)
			}
			if r.expected {
				// An intentional listener becomes a risky entry only while a finding on it survives.
				for _, e := range b.listenerRemedies(r.s) {
					route := wan
					route.CutIDs = append(slices.Clone(wan.CutIDs), b.actions[e.cut].ID)
					if e.bundle != 0 {
						route.CutIDs = append(route.CutIDs, b.actions[e.bundle].ID)
					}
					b.wanEdges = append(b.wanEdges, route)
				}
			} else {
				b.wanEdges = append(b.wanEdges, wan)
			}
			b.link(root(r.entry), r.s.fact(), r.level, r.action, bundle)
			if !r.expected {
				b.link(root(r.entry), outcome, r.outcomeLevel, r.action, bundle)
				if r.outcomeLevel == trivial && (b.isHighProfileSocket(r.s) || b.highProfileHost[r.s.host]) {
					b.markHighProfile(root(r.entry), r.s.fact())
				}
			}
		}
	}
}

// scope classifies an Oracle WAN decision by audience and authentication gating.
func (b *builder) scope(s socket, c risk.IsolationCell) (Entry, uint8) {
	if c.PathKind == "proxy-route" {
		for _, r := range b.Snapshot.ProxyRoutes {
			if r.Hostname == c.DecisiveRuleName && r.ProxyIP == c.Enforcer && address(r.BackendIP) == s.ip && r.BackendPort == s.port {
				if r.FrontendAuth == nil {
					return Internet, unknown
				}
				if *r.FrontendAuth || (r.BackendAuth != nil && *r.BackendAuth) {
					return Internet, moderate
				}
				break
			}
		}
	}
	if c.PathKind == "published-tunnel" {
		for _, t := range b.Snapshot.PublishedTunnels {
			if t.Hostname == c.DecisiveRuleName && address(t.BackendIP) == s.ip && t.BackendPort == s.port {
				switch strings.ToLower(t.AccessPolicy) {
				case "public", "none":
					return Internet, trivial
				case "authenticated":
					return Internet, moderate
				default:
					return Internet, unknown
				}
			}
		}
	}
	if (c.PathKind == "port-forward" || c.PathKind == "dynamic-mapping") && c.SourceNetwork != "" && c.SourceNetwork != "Internet" && c.SourceNetwork != "any" {
		return InternetSource, trivial
	}
	if isGatewayPolicyKind(c.PathKind) {
		for _, p := range b.Snapshot.FirewallPolicies {
			if p.ID == c.DecisiveRuleID && p.Name == c.DecisiveRuleName && !p.Source.AnyTarget && (len(p.Source.IPs) > 0 || len(p.Source.MACs) > 0) {
				return InternetSource, trivial
			}
		}
	}
	return Internet, trivial
}
