// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package risk

import (
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/unifi"
)

// Oracle evaluates configured L2, L3, and WAN reachability against a read-only
// UniFi snapshot. Queries do not mutate Oracle state and are safe to run
// concurrently as long as the caller does not mutate the borrowed snapshot.
type Oracle struct {
	compromised         map[string]bool
	snap                *unifi.Snapshot
	intent              config.IsolationIntent
	gwName, gwMAC, gwIP string
	gwPoliciesAvailable bool
	gwMissingReason     string
	switchACLStatus     string
	switchACLReason     string
	sortedPolicies      []unifi.FirewallPolicy
	sortedACLs          []unifi.SwitchACL
	serviceSourcePorts  []int
	netByID, netByName  map[string]unifi.Network
	clientsByMAC        map[string]unifi.Client
	clientsByIP         map[string][]unifi.Client
	ports               map[checks.SwitchPortRef]unifi.SwitchPort
	infrastructure      map[checks.SwitchPortRef]bool
	aps                 map[string]peerAttachment
	apUplinks           []peerAttachment
}

// NewOracle builds a reachability evaluator over an immutable snapshot and
// site configuration, pre-indexing networks, clients, switch ports, and AP
// uplinks once for repeated queries.
func NewOracle(snap *unifi.Snapshot, netCfg config.NetworkConfig) *Oracle {
	o := newPolicyOracle(snap)
	snap = o.snap
	o.intent = netCfg.IsolationPolicy
	o.netByID = make(map[string]unifi.Network, len(snap.Networks))
	o.netByName = make(map[string]unifi.Network, len(snap.Networks))
	o.clientsByMAC = make(map[string]unifi.Client, len(snap.Clients))
	o.clientsByIP = make(map[string][]unifi.Client, len(snap.Clients))
	o.ports = make(map[checks.SwitchPortRef]unifi.SwitchPort)
	o.infrastructure = make(map[checks.SwitchPortRef]bool)
	o.aps = make(map[string]peerAttachment)
	o.serviceSourcePorts = serviceSourcePorts(snap)
	for _, n := range snap.Networks {
		if n.Name != "" {
			o.netByName[strings.ToLower(n.Name)] = n
		}
		if n.ID != "" {
			o.netByID[n.ID] = n
		}
	}
	for _, cl := range snap.Clients {
		if mac := strings.ToLower(strings.TrimSpace(cl.MAC)); mac != "" {
			o.clientsByMAC[mac] = cl
		}
		seenIP := make(map[string]bool, 1+len(cl.IPv6))
		addIP := func(raw string) {
			if ip := canonicalIsolationIP(raw); ip != "" && !seenIP[ip] {
				seenIP[ip] = true
				o.clientsByIP[ip] = append(o.clientsByIP[ip], cl)
			}
		}
		addIP(cl.IP)
		for _, ip6 := range cl.IPv6 {
			addIP(ip6)
		}
	}
	for _, d := range snap.Devices {
		for _, p := range d.Ports {
			ref := portRef(d.MAC, p.PortIdx)
			o.ports[ref] = p
			if p.IsUplink {
				o.infrastructure[ref] = true
			}
		}
		ref := portRef(d.UplinkMAC, d.UplinkPort)
		if ref.SwitchMAC != "" && ref.PortIdx > 0 {
			o.infrastructure[ref] = true
		}
		if strings.EqualFold(d.Type, "uap") {
			ap := peerAttachment{label: firstNonEmptyStr(d.Name, d.MAC), ref: ref}
			o.aps[strings.ToLower(strings.TrimSpace(d.MAC))] = ap
			o.apUplinks = append(o.apUplinks, ap)
		}
	}
	return o
}

// newPolicyOracle prepares the routing evidence shared with VLAN classification.
// A zone-only evaluation borrows its snapshot and needs no attachment indexes.
func newPolicyOracle(snap *unifi.Snapshot) *Oracle {
	if snap == nil {
		snap = &unifi.Snapshot{}
	}
	o := &Oracle{snap: snap, sortedACLs: orderedSwitchACLs(snap.SwitchACLs)}
	o.gwName, o.gwMAC, o.gwIP = findGatewayIdentity(snap)
	o.sortedPolicies = orderedFirewallPolicies(snap.FirewallPolicies)
	// Missing policy telemetry cannot establish a default deny.
	o.gwPoliciesAvailable = true
	if snap.Visibility != nil {
		o.gwPoliciesAvailable = snap.Visibility.GatewayPoliciesAvailable
		if !o.gwPoliciesAvailable {
			o.gwMissingReason = "gateway firewall policies were unavailable from the controller"
			for _, f := range snap.Visibility.MissingFeeds {
				if strings.Contains(strings.ToLower(f), "firewall") {
					o.gwMissingReason = f
					break
				}
			}
		}
	} else if len(snap.FirewallPolicies) == 0 {
		o.gwPoliciesAvailable = false
		o.gwMissingReason = "snapshot omits firewall policies and their collection status"
	}

	o.switchACLStatus = "unavailable"
	o.switchACLReason = "controller snapshot omits switch ACLs"
	if snap.SwitchACLCoverage != nil && snap.SwitchACLCoverage.Status != "" {
		o.switchACLStatus = strings.ToLower(snap.SwitchACLCoverage.Status)
		if snap.SwitchACLCoverage.Reason != "" {
			o.switchACLReason = snap.SwitchACLCoverage.Reason
		}
	} else if len(snap.SwitchACLs) > 0 {
		o.switchACLStatus = "complete"
		o.switchACLReason = ""
	}
	if snap.Visibility != nil && !snap.Visibility.SwitchACLsAvailable && o.switchACLStatus == "complete" {
		o.switchACLStatus = "unavailable"
		o.switchACLReason = "switch ACL feed unavailable from the controller"
	}

	return o
}

// Position identifies the source of a reachability query.
type Position struct {
	// NetworkID identifies the source VLAN in the controller inventory.
	NetworkID string
	// NetworkName identifies the source VLAN when its ID is unavailable.
	NetworkName string
	// Zone supplies the source firewall zone when known.
	Zone string
	// IP pins the source address for its address family.
	IP string
	// MAC identifies the client for ACL and inventory lookups.
	MAC string
	// SwitchMAC identifies the switch serving a wired source.
	SwitchMAC string
	// SwitchPort identifies its physical access port.
	SwitchPort int
	// APMAC identifies the access point serving a wireless source.
	APMAC string
	// SSID identifies the wireless network on the access point.
	SSID string
	// IsWired reports an Ethernet attachment.
	IsWired bool
}

// PositionForClient captures the network and attachment observed for cl.
func PositionForClient(cl unifi.Client) Position {
	return Position{NetworkID: cl.NetworkID, NetworkName: cl.NetworkName, IP: cl.PrimaryIP(), MAC: cl.MAC,
		SwitchMAC: cl.SwitchMAC, SwitchPort: cl.SwitchPort, APMAC: cl.APMAC, SSID: cl.ESSID, IsWired: cl.IsWired}
}

// Service evaluates a new connection from src to a single destination service.
// Effective reports configured policy reachability, while Verdict evaluates it
// against a deny expectation.
func (o *Oracle) Service(src Position, dst unifi.Client, proto string, port int, fam string) IsolationCell {
	return o.reach(src, dst, strings.ToLower(strings.TrimSpace(proto)), port, strings.ToLower(fam), nil)
}

// AnyPort searches for any permitted new connection across all protocols and
// ports, recording a concrete witness port when a service-scoped rule matches.
func (o *Oracle) AnyPort(src Position, dst unifi.Client, fam string) IsolationCell {
	return o.reach(src, dst, "", 0, strings.ToLower(fam), nil)
}

// Transit searches for a general network opening, accepting the built-in DNS
// exception while still evaluating every independent packet class.
func (o *Oracle) Transit(src Position, dst unifi.Client, fam string) IsolationCell {
	return o.reach(src, dst, "", 0, strings.ToLower(fam), o.builtinDNS)
}

// InternetEgress searches public destinations for a permitted connection from
// this particular client. The boundary solver pins the source while searching
// destination addresses and ports on both sides of every policy selector.
func (o *Oracle) InternetEgress(cl unifi.Client, fam string) IsolationCell {
	cl = o.hydrateClient(cl, fam)
	n := o.network(cl.NetworkID, cl.NetworkName)
	external := unifi.Network{Name: "Internet", ZoneName: "External", Subnet: "0.0.0.0/0", IPv6Subnet: "2000::/3"}
	peers := peerEndpoints{src: cl}
	if n.InternetAccessEnabled != nil && !*n.InternetAccessEnabled && !o.compromised[config.CanonicalMAC(o.gwMAC)] {
		return o.endpointPath(n, external, n.ZoneName, "External", peers, "", 0, fam, nil)
	}
	if len(peerAddresses(cl, fam)) == 0 {
		return IsolationCell{Effective: "unknown", Verdict: IsolationUnknown, MissingInput: "The client address is missing"}
	}
	if _, local := routableClient(cl, fam); local {
		return o.nonRoutableCell(n, external, n.ZoneName, "External", cl, "", 0, fam)
	}
	// Keep L3 switch routing intact when switch ACLs are present or during
	// infrastructure-compromise evaluation so switch egress blocks remain
	// monotonic before and after gateway compromise. Preserve RouterUnresolved
	// in all cases so unresolved routing owners never report allow then unknown.
	if len(o.snap.SwitchACLs) == 0 && len(o.compromised) == 0 {
		n.RouterDeviceMAC = ""
	}
	scoped := *o
	scoped.sortedPolicies = o.policiesWithExternalDefault(n)
	return scoped.evaluateBoundary(nil, config.IsolationIntent{}, n, external, n.ZoneName, "External", fam, "deny", &peers)
}

// Families returns the address families modeled for this client and network.
func (o *Oracle) Families(cl unifi.Client) []string {
	n := o.network(cl.NetworkID, cl.NetworkName)
	if siteHasIPv6Context(o.snap, n, n, cl) || strings.Contains(cl.IP, ":") {
		return []string{"ipv4", "ipv6"}
	}
	return []string{"ipv4"}
}

// NetworkForAddress resolves inventory without network IDs through the most
// specific configured LAN prefix, including an infrastructure management IP.
func (o *Oracle) NetworkForAddress(ip string) unifi.Network {
	n, _ := lookupNetworkByIP(o.snap, ip)
	return n
}

// DeviceClient builds a query destination for UniFi infrastructure devices that
// do not appear in the client inventory. Gateways use GatewayNetworkID so rules
// targeting the Gateway zone apply even when the management IP lies in a LAN subnet.
func (o *Oracle) DeviceClient(d unifi.Device) unifi.Client {
	cl := unifi.Client{ID: d.ID, MAC: d.MAC, IP: d.IP, Name: d.Name, IsWired: true, SwitchMAC: d.UplinkMAC, SwitchPort: d.UplinkPort}
	n := o.NetworkForAddress(d.IP)
	cl.NetworkID, cl.NetworkName = n.ID, n.Name
	switch strings.ToLower(d.Type) {
	case "udm", "udr", "udw", "ucg", "uxg", "ugw", "usg", "gateway", "router":
		cl.NetworkID, cl.NetworkName = GatewayNetworkID, "Gateway"
	}
	return cl
}

// GatewayNetworkID is the synthetic network ID assigned to UniFi gateways so
// they stay distinct from any user-named VLAN called "Gateway".
const GatewayNetworkID = "uniblue:gateway"

// ApprovedServices resolves the owner's intended workflows for a concrete
// source network and destination using the same role matching as isolation.
func (o *Oracle) ApprovedServices(src Position, dst unifi.Client, findings []checks.Finding, fam string) []config.ApprovedPath {
	n, d := o.network(src.NetworkID, src.NetworkName), o.network(dst.NetworkID, dst.NetworkName)
	var paths []config.ApprovedPath
	for _, ap := range o.intent.ApprovedPaths {
		if ap.DestRole != "" && !clientMatchesApprovedRole(dst, findings, ap.DestRole, ap.Function) {
			continue
		}
		if hasApprovedPath([]config.ApprovedPath{ap}, firstNonEmptyStr(src.Zone, n.ZoneName), n.Name, dst, d.ZoneName, "", firstNonEmptyStr(ap.Transport, "tcp"), ap.Port, fam) {
			paths = append(paths, ap)
		}
	}
	return paths
}

// Internet returns configured or unresolved WAN ingress paths reaching dst's
// service in address family fam. Missing port-forward, firewall policy, or
// zone telemetry produces explicit unknown cells rather than an empty result.
func (o *Oracle) Internet(dst unifi.Client, proto string, port int, fam string) []IsolationCell {
	proto, fam = strings.ToLower(strings.TrimSpace(proto)), strings.ToLower(fam)
	dst = o.hydrateClient(dst, fam)
	net := o.network(dst.NetworkID, dst.NetworkName)
	ips := peerAddresses(dst, fam)
	var routableIPs []string
	for _, ip := range ips {
		if !isNonRoutableIP(ip) {
			routableIPs = append(routableIPs, ip)
		}
	}
	var cells []IsolationCell
	ingress := func(ip, kind, enforcer string) IsolationCell {
		return IsolationCell{SourceZone: "External", SourceNetwork: "Internet", DestNetwork: net.Name, DestZone: net.ZoneName,
			DestHost: dst.DisplayName(), DestIP: canonicalIsolationIP(ip), DestFunction: "service", Transport: proto, Port: port,
			IPFamily: fam, PathKind: kind, Enforcer: enforcer, Expected: "deny", Effective: "allow", Verdict: IsolationViolation}
	}
	if o.snap.Visibility != nil && !o.snap.Visibility.PortForwardsAvailable {
		ip := ""
		if len(ips) > 0 {
			ip = ips[0]
		}
		c := ingress(ip, "port-forward", o.gwName)
		c.EnforcerMACs = enforcerMACs(o.gwMAC)
		c.Effective, c.Verdict = "unknown", IsolationUnknown
		c.MissingInput = "WAN port-forward telemetry unavailable from controller"
		cells = append(cells, c)
	}
	for _, f := range o.snap.PortForwards {
		f.FwdPort = firstNonEmptyStr(f.FwdPort, f.DstPort)
		if !slices.Contains(routableIPs, canonicalIsolationIP(f.FwdIP)) || !matchesIPFamily(f.IPVersion, fam) || !f.ExposesEndpoint(port, proto) {
			continue
		}
		c := ingress(f.FwdIP, "port-forward", o.gwName)
		c.EnforcerMACs, c.DecisiveRuleID, c.DecisiveRuleName = enforcerMACs(o.gwMAC), f.ID, f.Name
		c.DecisiveReason = "WAN port forward from any source"
		if f.SourceUnknown {
			c.Effective, c.Verdict, c.DecisiveReason = "unknown", IsolationUnknown, ""
			c.MissingInput = "WAN port forward source filter is unresolved"
		} else if f.IsSourceRestricted() {
			c.SourceNetwork = f.Src
			c.DecisiveReason = "WAN port forward restricted to " + f.Src
		}
		cells = append(cells, c)
	}
	for _, m := range o.snap.DynamicMappings {
		if m.ExpiresAt != nil && !o.snap.CollectedAt.IsZero() && !m.ExpiresAt.After(o.snap.CollectedAt) {
			continue
		}
		if m.IntPort != port || !strings.EqualFold(m.Transport, proto) || !slices.Contains(routableIPs, canonicalIsolationIP(m.InternalIP)) {
			continue
		}
		c := ingress(m.InternalIP, "dynamic-mapping", o.gwName)
		c.EnforcerMACs, c.DecisiveRuleName = enforcerMACs(o.gwMAC), m.Protocol
		c.DecisiveRuleID = fmt.Sprintf("%s:%s:%d:%s:%d:%s", strings.ToLower(m.Protocol), proto, m.ExtPort, c.DestIP, port, m.Source)
		c.DecisiveReason = fmt.Sprintf("%s maps WAN port %d to this service", m.Protocol, m.ExtPort)
		if m.Source != "" {
			c.SourceNetwork = m.Source
		}
		cells = append(cells, c)
	}
	// Owner-declared web frontends describe TCP backends independently of gateway NAT.
	if proto == "tcp" {
		for _, t := range o.snap.PublishedTunnels {
			if t.BackendPort == port && slices.Contains(ips, canonicalIsolationIP(t.BackendIP)) {
				c := ingress(t.BackendIP, "published-tunnel", t.Provider)
				c.DecisiveRuleName = t.Hostname
				c.DecisiveReason = "Published tunnel with access policy " + firstNonEmptyStr(t.AccessPolicy, "unknown")
				cells = append(cells, c)
			}
		}
		for _, r := range o.snap.ProxyRoutes {
			if r.PublicExposed && r.BackendPort == port && slices.Contains(ips, canonicalIsolationIP(r.BackendIP)) {
				c := ingress(r.BackendIP, "proxy-route", r.ProxyIP)
				if cands := o.clientsByIP[canonicalIsolationIP(r.ProxyIP)]; len(cands) == 1 {
					c.EnforcerMACs = enforcerMACs(cands[0].MAC)
				}
				c.DecisiveRuleName, c.DecisiveReason = r.Hostname, "Public reverse proxy route to this backend"
				cells = append(cells, c)
			}
		}
	}
	if len(ips) > 0 || fam != "ipv6" || siteHasIPv6Context(o.snap, net, net, dst) {
		cells = append(cells, o.firewallIngress(net, dst, proto, port, fam)...)
	}
	return cells
}

// ListenerWAN reports allow, deny or unknown for the exact observed socket.
// A missing lease inventory cannot rule out an automatic port mapping.
func (o *Oracle) ListenerWAN(cl unifi.Client, ip, proto string, port int) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "unknown"
	}
	addr = addr.Unmap()
	fam := "ipv4"
	if addr.Is6() {
		fam = "ipv6"
	}
	cl.IP, cl.IPv6 = addr.String(), nil
	state := "deny"
	if o.snap.Visibility == nil && o.snap.PortForwards == nil {
		state = "unknown"
	}
	if o.snap.SecuritySettings != nil && o.snap.SecuritySettings.UPnPEnabled && len(o.snap.DynamicMappings) == 0 {
		state = "unknown"
	}
	for _, cell := range o.Internet(cl, proto, port, fam) {
		if cell.Effective == "allow" {
			return "allow"
		}
		if cell.Effective == "unknown" {
			state = "unknown"
		}
	}
	return state
}

// PrivateLANListener identifies private listeners with no permitted or unresolved WAN path.
func (o *Oracle) PrivateLANListener(cl unifi.Client, ip, proto string, port int) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	return err == nil && addr.Unmap().IsPrivate() && o.ListenerWAN(cl, ip, proto, port) == "deny"
}

// WithCompromised returns an independent scenario that bypasses only the named enforcers.
func (o *Oracle) WithCompromised(enforcerMACs ...string) *Oracle {
	cp := *o
	cp.compromised = make(map[string]bool, len(o.compromised)+len(enforcerMACs))
	maps.Copy(cp.compromised, o.compromised)
	for _, raw := range enforcerMACs {
		if mac, ok := config.ParseCanonicalMAC(raw); ok {
			cp.compromised[mac] = true
		}
	}
	return &cp
}

const compromiseReason = "Enforcer compromised in what-if scenario"

// bypass marks a decision at one compromised hop so the other hops can still enforce their rules.
func (o *Oracle) bypass(cell *IsolationCell, mac string) bool {
	if len(o.compromised) == 0 || !o.compromised[config.CanonicalMAC(mac)] {
		return false
	}
	applyDecisionToCell(cell, policyDecision{action: "allow", reason: compromiseReason})
	return true
}

// WithoutPolicies returns a shallow copy of the Oracle with the specified
// firewall policy IDs removed so callers can test whether a later rule still
// allows traffic after removing the winning rule.
func (o *Oracle) WithoutPolicies(excludeIDs map[string]bool) *Oracle {
	if len(excludeIDs) == 0 {
		return o
	}
	cp := *o
	filtered := make([]unifi.FirewallPolicy, 0, len(o.sortedPolicies))
	for _, p := range o.sortedPolicies {
		if !excludeIDs[p.ID] {
			filtered = append(filtered, p)
		}
	}
	cp.sortedPolicies = filtered
	return &cp
}

// InternetPolicy finds an inbound policy witness even when a host has no
// observed services. Internet can then resolve all publications for that socket.
func (o *Oracle) InternetPolicy(dst unifi.Client, fam string) []IsolationCell {
	dst = o.hydrateClient(dst, fam)
	return o.firewallIngress(o.network(dst.NetworkID, dst.NetworkName), dst, "", 0, fam)
}

// isNonRoutableIP reports addresses that cannot cross an L3 router or WAN gateway.
func isNonRoutableIP(raw string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified()
}

// nonRoutableExternalCIDRs returns exact CIDR boundaries matching isNonRoutableIP
// so External source-interval partitioning isolates non-routable ranges cleanly.
func nonRoutableExternalCIDRs(fam string) []string {
	if fam == "ipv6" {
		return []string{"::/128", "::1/128", "fe80::/10", "ff02::/16"}
	}
	return []string{"0.0.0.0/32", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/24"}
}

// isWANNetwork reports whether n represents an External/WAN uplink.
func isWANNetwork(n unifi.Network) bool {
	return strings.EqualFold(n.ZoneName, "External") || strings.EqualFold(n.Purpose, "wan") || strings.EqualFold(n.Purpose, "wan2")
}

// routableClient removes loopback, unspecified, and link-local addresses in fam
// from cl and reports whether cl had addresses in fam that were all non-routable.
func routableClient(cl unifi.Client, fam string) (unifi.Client, bool) {
	if len(peerAddresses(cl, fam)) == 0 {
		return cl, false
	}
	if cl.IP != "" && isNonRoutableIP(cl.IP) {
		if addr, err := netip.ParseAddr(strings.TrimSpace(cl.IP)); err == nil && (fam == "ipv6") == addr.Unmap().Is6() {
			cl.IP = ""
		}
	}
	if fam == "ipv6" && len(cl.IPv6) > 0 {
		var keep []string
		for _, raw := range cl.IPv6 {
			if !isNonRoutableIP(raw) {
				keep = append(keep, raw)
			}
		}
		cl.IPv6 = keep
	}
	return cl, len(peerAddresses(cl, fam)) == 0
}

// firewallIngress evaluates External-to-LAN firewall policies at the gateway,
// including VLANs whose internal east-west routing belongs to an L3 switch.
func (o *Oracle) firewallIngress(net unifi.Network, dst unifi.Client, proto string, port int, fam string) []IsolationCell {
	var nonRoutable bool
	if dst, nonRoutable = routableClient(dst, fam); nonRoutable {
		return nil
	}
	if !o.compromised[config.CanonicalMAC(o.gwMAC)] && o.gwPoliciesAvailable && net.ZoneName != "" && !slices.ContainsFunc(o.sortedPolicies, func(p unifi.FirewallPolicy) bool {
		return p.Enabled && (p.Source.ZoneName == "" || strings.EqualFold(p.Source.ZoneName, "External")) &&
			(p.Destination.ZoneName == "" || strings.EqualFold(p.Destination.ZoneName, net.ZoneName))
	}) {
		return nil
	}
	var wans []unifi.Network
	for _, n := range o.snap.Networks {
		if strings.EqualFold(n.ZoneName, "External") || strings.EqualFold(n.Purpose, "wan") || strings.EqualFold(n.Purpose, "wan2") {
			wans = append(wans, unifi.Network{ID: n.ID, Name: n.Name})
		}
	}
	if len(wans) == 0 {
		// Leave ID and Name empty when WAN network inventory is absent so
		// WAN-scoped network selectors resolve to unknown instead of mismatching.
		wans = []unifi.Network{{}}
	}
	net.RouterDeviceMAC, net.RouterUnresolved = "", false
	wanScopedRule := make(map[string]bool, len(o.sortedPolicies))
	for _, p := range o.sortedPolicies {
		if p.ID != "" && len(p.Source.NetworkIDs) > 0 {
			wanScopedRule[p.ID] = true
		}
	}
	type ingressKey struct{ ip, ruleID, ruleName, missing string }
	byKey := make(map[ingressKey][]IsolationCell)
	var order []ingressKey
	for _, wan := range wans {
		wan.Subnet, wan.IPv6Subnet = "0.0.0.0/0", "2000::/3"
		seenWAN := make(map[ingressKey]bool)
		paths := o.servicePaths(wan, net, "External", net.ZoneName, peerEndpoints{dst: dst}, proto, port, fam)
		if port == 0 {
			paths = func(yield func(IsolationCell) bool) {
				yield(o.evaluateBoundary(nil, config.IsolationIntent{}, wan, net, "External", net.ZoneName, fam, "deny", &peerEndpoints{dst: dst, concrete: true}))
			}
		}
		for c := range paths {
			if c.Effective == "deny" {
				continue
			}
			k := ingressKey{c.DestIP, c.DecisiveRuleID, c.DecisiveRuleName, c.MissingInput}
			if seenWAN[k] {
				continue
			}
			seenWAN[k] = true
			if _, ok := byKey[k]; !ok {
				order = append(order, k)
			}
			byKey[k] = append(byKey[k], c)
		}
	}
	var cells []IsolationCell
	for _, k := range order {
		group := byKey[k]
		// Collapse an unscoped rule to "Internet" only when every WAN interface
		// resolves to it. When an earlier WAN-scoped block prevents one uplink
		// from reaching the rule, keep the permitting WAN interface name.
		if len(group) == len(wans) && !wanScopedRule[k.ruleID] {
			c := group[0]
			c.SourceNetwork = "Internet"
			cells = append(cells, c)
			continue
		}
		for _, c := range group {
			if c.SourceNetwork == "" {
				c.SourceNetwork = "Internet"
			}
			cells = append(cells, c)
		}
	}
	return cells
}

// hydrateClient fills missing network, address, and L2 attachment metadata on cl
// from the snapshot client inventory so finding-derived clients resolve cleanly.
func (o *Oracle) hydrateClient(cl unifi.Client, fam string) unifi.Client {
	observed := o.inventoryClient(cl)
	if cl.Name == "" {
		cl.Name = observed.DisplayName()
	}
	if len(peerAddresses(cl, fam)) == 0 {
		if fam == "ipv4" {
			if addr, err := netip.ParseAddr(strings.TrimSpace(cl.IP)); err == nil && addr.Unmap().Is6() {
				// Allocate a fresh slice so concurrent queries never write into the caller's backing array.
				cl.IPv6 = append(slices.Clone(cl.IPv6), cl.IP)
			}
			if observed.IP != "" {
				cl.IP = observed.IP
			}
		} else if addrs := peerAddresses(observed, "ipv6"); len(addrs) > 0 {
			cl.IPv6 = addrs
		}
	}
	if cl.NetworkID == "" && cl.NetworkName == "" {
		cl.NetworkID, cl.NetworkName = observed.NetworkID, observed.NetworkName
	}
	switch {
	case cl.IsWired || ((cl.SwitchMAC != "" || cl.SwitchPort > 0) && cl.APMAC == "" && cl.ESSID == "" && (observed.IsWired || (observed.APMAC == "" && observed.ESSID == ""))):
		cl.IsWired = true
		// Hydrate switch attachment when omitted or when one side matches inventory.
		if observed.IsWired {
			if cl.SwitchMAC == "" && cl.SwitchPort == 0 {
				cl.SwitchMAC, cl.SwitchPort = observed.SwitchMAC, observed.SwitchPort
			} else if cl.SwitchPort == 0 && strings.EqualFold(cl.SwitchMAC, observed.SwitchMAC) {
				cl.SwitchPort = observed.SwitchPort
			} else if cl.SwitchMAC == "" && cl.SwitchPort == observed.SwitchPort {
				cl.SwitchMAC = observed.SwitchMAC
			}
		}
	case cl.SwitchMAC == "" && cl.SwitchPort == 0 && cl.APMAC == "" && cl.ESSID == "":
		cl.IsWired, cl.SwitchMAC, cl.SwitchPort = observed.IsWired, observed.SwitchMAC, observed.SwitchPort
		cl.APMAC, cl.ESSID = observed.APMAC, observed.ESSID
	case !observed.IsWired:
		if cl.APMAC == "" {
			cl.APMAC = observed.APMAC
		}
		if cl.ESSID == "" {
			cl.ESSID = observed.ESSID
		}
	}
	if cl.MAC == "" {
		cl.MAC = observed.MAC
	}
	return cl
}

// reach hydrates source and destination identities from inventory before
// dispatching to either the same-VLAN L2 peer solver or the routed solver.
func (o *Oracle) reach(src Position, dst unifi.Client, proto string, port int, fam string, approve func(IsolationCell) bool) IsolationCell {
	a := o.hydrateClient(unifi.Client{
		NetworkID: src.NetworkID, NetworkName: src.NetworkName, MAC: src.MAC, IP: src.IP,
		SwitchMAC: src.SwitchMAC, SwitchPort: src.SwitchPort, IsWired: src.IsWired, APMAC: src.APMAC, ESSID: src.SSID,
	}, fam)
	dst = o.hydrateClient(dst, fam)
	srcNet, dstNet := o.network(a.NetworkID, a.NetworkName), o.network(dst.NetworkID, dst.NetworkName)
	srcNet.ID, dstNet.ID = firstNonEmptyStr(srcNet.ID, a.NetworkID), firstNonEmptyStr(dstNet.ID, dst.NetworkID)
	peers := peerEndpoints{src: a, dst: dst, concrete: true}
	same := srcNet.Name != "" && strings.EqualFold(srcNet.Name, dstNet.Name)
	if srcNet.ID != "" && dstNet.ID != "" {
		same = srcNet.ID == dstNet.ID
	}
	if !same {
		srcZone := firstNonEmptyStr(src.Zone, srcNet.ZoneName)
		if isWANNetwork(srcNet) {
			srcZone = firstNonEmptyStr(srcZone, "External")
			srcNet.Subnet, srcNet.IPv6Subnet = "0.0.0.0/0", "2000::/3"
		}
		var nonRoutable bool
		if peers.src, nonRoutable = routableClient(peers.src, fam); nonRoutable {
			return o.nonRoutableCell(srcNet, dstNet, srcZone, dstNet.ZoneName, dst, proto, port, fam)
		}
		if peers.dst, nonRoutable = routableClient(peers.dst, fam); nonRoutable {
			return o.nonRoutableCell(srcNet, dstNet, srcZone, dstNet.ZoneName, dst, proto, port, fam)
		}
		cell := o.endpointPath(srcNet, dstNet, srcZone, dstNet.ZoneName, peers, proto, port, fam, approve)
		cell.DestHost = dst.DisplayName()
		if proto == "" {
			cell.DestFunction = "any-port"
		}
		return cell
	}
	cell := o.peerPath(srcNet, peers, proto, port, fam)
	cell.SourceNetwork, cell.DestNetwork = srcNet.Name, dstNet.Name
	cell.SourceZone = firstNonEmptyStr(src.Zone, srcNet.ZoneName, srcNet.Name)
	cell.DestZone = firstNonEmptyStr(dstNet.ZoneName, dstNet.Name)
	cell.DestHost = dst.DisplayName()
	if ips := peerAddresses(dst, fam); cell.DestIP == "" && len(ips) > 0 {
		cell.DestIP = ips[0]
	}
	cell.Expected, cell.IPFamily = "deny", fam
	if proto != "" {
		cell.Transport, cell.Port = proto, port
	}
	return cell
}

// nonRoutableCell returns a deny cell when a cross-VLAN or External query only
// carries loopback, unspecified, or link-local addresses in fam.
func (o *Oracle) nonRoutableCell(srcNet, dstNet unifi.Network, srcZone, dstZone string, dst unifi.Client, proto string, port int, fam string) IsolationCell {
	destFn := "service"
	if proto == "" {
		destFn = "any-port"
	}
	c := IsolationCell{
		SourceZone:    firstNonEmptyStr(srcZone, srcNet.Name),
		SourceNetwork: srcNet.Name,
		DestZone:      firstNonEmptyStr(dstZone, dstNet.Name),
		DestNetwork:   dstNet.Name,
		DestHost:      dst.DisplayName(),
		DestFunction:  destFn,
		Transport:     firstNonEmptyStr(proto, "all"),
		Port:          port,
		IPFamily:      fam,
		PathKind:      "gateway-routed",
		Enforcer:      o.gwName,
		EnforcerMACs:  enforcerMACs(o.gwMAC),
		Expected:      "deny",
	}
	if ips := peerAddresses(dst, fam); len(ips) > 0 {
		c.DestIP = ips[0]
	}
	applyDecisionToCell(&c, policyDecision{
		action: "deny",
		reason: "Non-routable loopback or link-local address cannot cross an L3 boundary",
	})
	return c
}

// endpointPath uses the same first-match policy solver for concrete services
// and the same full-domain boundary search for routed and switched clients.
func (o *Oracle) endpointPath(srcNet, dstNet unifi.Network, srcZone, dstZone string, peers peerEndpoints, proto string, port int, fam string, approve func(IsolationCell) bool) IsolationCell {
	eval := o
	if strings.EqualFold(dstZone, "External") {
		if srcNet.InternetAccessEnabled != nil && !*srcNet.InternetAccessEnabled && !o.compromised[config.CanonicalMAC(o.gwMAC)] {
			c := IsolationCell{
				SourceZone:    firstNonEmptyStr(srcZone, srcNet.Name),
				SourceNetwork: srcNet.Name,
				DestZone:      "External",
				DestNetwork:   firstNonEmptyStr(dstNet.Name, "Internet"),
				DestHost:      peers.dst.DisplayName(),
				DestFunction:  "service",
				Transport:     firstNonEmptyStr(proto, "all"),
				Port:          port,
				IPFamily:      fam,
				PathKind:      "gateway-routed",
				Enforcer:      o.gwName,
				EnforcerMACs:  enforcerMACs(o.gwMAC),
				Expected:      "deny",
			}
			if ips := peerAddresses(peers.dst, fam); len(ips) > 0 {
				c.DestIP = ips[0]
			}
			applyDecisionToCell(&c, policyDecision{
				action: "deny",
				reason: "Allow Internet Access is disabled on the network",
			})
			return c
		}
		// External egress always traverses the gateway and falls back to the
		// network's Allow Internet Access toggle when no explicit rule matches.
		srcNet.RouterDeviceMAC, srcNet.RouterUnresolved = "", false
		scoped := *o
		scoped.sortedPolicies = o.policiesWithExternalDefault(srcNet)
		eval = &scoped
	}
	if proto == "" {
		return eval.boundaryWithApproval(nil, config.IsolationIntent{}, srcNet, dstNet, srcZone, dstZone, fam, "deny", &peers, approve)
	}
	return eval.firstServicePath(srcNet, dstNet, srcZone, dstZone, peers, proto, port, fam)
}

// firstServicePath returns the first permitting cell for one service, or the
// highest-precedence unknown/deny cell if no packet class is allowed.
func (o *Oracle) firstServicePath(srcNet, dstNet unifi.Network, srcZone, dstZone string, peers peerEndpoints, proto string, port int, fam string) IsolationCell {
	var best IsolationCell
	for cell := range o.servicePaths(srcNet, dstNet, srcZone, dstZone, peers, proto, port, fam) {
		if cell.Effective == "allow" {
			return cell
		}
		if best.Effective == "" || (best.Effective == "deny" && cell.Effective == "unknown") {
			best = cell
		}
	}
	return best
}

// policiesWithExternalDefault appends a trailing External fallback rule so
// unmatched internet egress honors the network's Allow Internet Access toggle
// (or resolves unknown when the controller omitted it).
func (o *Oracle) policiesWithExternalDefault(n unifi.Network) []unifi.FirewallPolicy {
	anyEP := unifi.PolicyEndpoint{AnyTarget: true, AnyPort: true}
	fallback := unifi.FirewallPolicy{
		Enabled:     true,
		Index:       1 << 30,
		Name:        "External default",
		Protocol:    "all",
		Source:      anyEP,
		Destination: anyEP,
		Action:      "ALLOW",
	}
	fallback.Destination.ZoneName = "External"
	if n.InternetAccessEnabled == nil {
		fallback.UnsupportedReason = "controller omitted the External default"
	}
	return append(append([]unifi.FirewallPolicy(nil), o.sortedPolicies...), fallback)
}

// serviceSourcePorts partitions the unspecified TCP or UDP source port at rule
// boundaries. A single representative covers sites without source-port filters.
func serviceSourcePorts(s *unifi.Snapshot) []int {
	var ports []int
	var ranges []unifi.PortRange
	add := func(ep unifi.PolicyEndpoint) {
		if !ep.AnyPort {
			ports = append(ports, ep.Ports...)
			ranges = append(ranges, ep.PortRanges...)
		}
	}
	for _, p := range s.FirewallPolicies {
		if p.Enabled {
			add(p.Source)
		}
	}
	for _, a := range s.SwitchACLs {
		if a.Enabled {
			add(a.Source)
		}
	}
	var reps []int
	for _, iv := range partitionPortIntervals(ports, ranges) {
		reps = append(reps, representativePortInInterval(iv))
	}
	return reps
}

// servicePaths yields the distinct packet equivalence classes for a service so
// single-path queries can stop at the first allow while Internet collects every
// deciding rule across uplinks.
func (o *Oracle) servicePaths(srcNet, dstNet unifi.Network, srcZone, dstZone string, peers peerEndpoints, proto string, port int, fam string) iter.Seq[IsolationCell] {
	return func(yield func(IsolationCell) bool) {
		q := pathQuery{srcZone: srcZone, srcNetID: srcNet.ID, srcNetName: srcNet.Name,
			dstZone: dstZone, dstNetID: dstNet.ID, dstNetName: dstNet.Name, dstMAC: peers.dst.MAC,
			proto: proto, port: port, ipFamily: fam, state: "new"}
		srcIPs, srcMACs := peerAddresses(peers.src, fam), []string{peers.src.MAC}
		if len(srcIPs) == 0 {
			srcIPs = []string{""}
			if peers.src.IP == "" && peers.src.MAC == "" {
				srcIPs, srcMACs = o.sourceRepresentatives(srcNet, dstNet, q, sampleNetworkIPForFamily(srcNet, o.snap, fam))
			}
		}
		dstIPs := peerAddresses(peers.dst, fam)
		if len(dstIPs) == 0 {
			dstIPs = []string{""}
		}
		sports := o.serviceSourcePorts
		if proto != "tcp" && proto != "udp" {
			sports = []int{0}
		}
		count := 0
		for _, sip := range srcIPs {
			for _, mac := range srcMACs {
				for _, dip := range dstIPs {
					for _, sport := range sports {
						q.srcIP, q.srcMAC, q.dstIP, q.srcPort = sip, mac, dip, sport
						cell := o.routedCell(srcNet, dstNet, q, peers.dst.DisplayName(), "service", "deny")
						if count == maxExactBoundaryEvals {
							applyDecisionToCell(&cell, policyDecision{action: "unknown", missingInput: "Service query exceeded the exact verification limit"})
							yield(cell)
							return
						}
						count++
						if !yield(cell) {
							return
						}
					}
				}
			}
		}
	}
}

// attachment resolves a wireless client's AP uplink or a wired client's socket.
func (o *Oracle) attachment(cl unifi.Client) peerAttachment {
	ref := portRef(cl.SwitchMAC, cl.SwitchPort)
	if !cl.IsWired {
		ref = o.aps[strings.ToLower(strings.TrimSpace(cl.APMAC))].ref
	}
	return peerAttachment{label: cl.DisplayName(), ref: ref, client: cl}
}

// peerPath evaluates a directional pair of clients on the same VLAN, handling
// same-AP Wi-Fi isolation directly and forwarding cross-port or cross-AP pairs
// through switch port isolation and switch ACL evaluation.
func (o *Oracle) peerPath(n unifi.Network, peers peerEndpoints, proto string, port int, fam string) IsolationCell {
	a, b := peers.src, peers.dst
	if (!a.IsWired && a.APMAC == "") || (!b.IsWired && b.APMAC == "") {
		return IsolationCell{PathKind: "peer-attachment", Transport: "all", Verdict: IsolationUnknown, Effective: "unknown",
			MissingInput: "Controller did not resolve all peer attachments on " + n.Name}
	}
	if !a.IsWired && !b.IsWired && a.APMAC != "" && strings.EqualFold(a.APMAC, b.APMAC) {
		cell := IsolationCell{PathKind: "same-ap-wifi", DestFunction: "same-vlan-wifi-peers", EnforcerMACs: enforcerMACs(a.APMAC), Transport: "all"}
		if o.bypass(&cell, a.APMAC) {
			return cell
		}
		for _, w := range o.snap.WLANs {
			if w.Enabled && strings.EqualFold(w.NetworkName, n.Name) && a.ESSID != "" && a.ESSID == b.ESSID && w.Name == a.ESSID {
				cell := o.sameAP(w)
				cell.EnforcerMACs = enforcerMACs(a.APMAC)
				return cell
			}
		}
		return IsolationCell{PathKind: "same-ap-wifi", DestFunction: "same-vlan-wifi-peers", EnforcerMACs: enforcerMACs(a.APMAC),
			Effective: "unknown", Verdict: IsolationUnknown, MissingInput: "Shared WLAN isolation settings unavailable", Transport: "all"}
	}
	kind, function := "wired-same-vlan", "same-vlan-wired-peers"
	switch {
	case a.IsWired != b.IsWired:
		kind, function = "mixed-same-vlan", "same-vlan-mixed-peers"
	case !a.IsWired:
		kind, function = "cross-ap-wifi", "cross-ap-wifi-peers"
	}
	from, to := o.attachment(a), o.attachment(b)
	path := o.peerLabel(from) + " and " + o.peerLabel(to)
	cell, _ := o.peerPorts(from.ref, to.ref, path, false)
	if cell.Effective == "" {
		cell = o.peerACL(n, peers, from.ref.SwitchMAC, fam, proto, port)
		unknownPeerPorts(&cell, o.peerPortSettingsKnown(from.ref, to.ref), path)
	}
	cell.PathKind, cell.DestFunction = kind, function
	return cell
}

// orderedFirewallPolicies preserves controller order within each priority group.
func orderedFirewallPolicies(policies []unifi.FirewallPolicy) []unifi.FirewallPolicy {
	sorted := slices.Clone(policies)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Index < sorted[j].Index })
	return sorted
}

// inventoryClient resolves the full client record from snapshot inventory by
// MAC or canonical IPv4/IPv6 address, scoping IP matches by VLAN when multiple
// clients share a link-local or overlapping address across networks.
func (o *Oracle) inventoryClient(cl unifi.Client) unifi.Client {
	if full, ok := o.clientsByMAC[strings.ToLower(strings.TrimSpace(cl.MAC))]; ok {
		return full
	}
	matchByIP := func(raw string) (unifi.Client, bool) {
		ip := canonicalIsolationIP(raw)
		cands := o.clientsByIP[ip]
		if len(cands) == 0 {
			return unifi.Client{}, false
		}
		if cl.NetworkID != "" || cl.NetworkName != "" {
			net := o.network(cl.NetworkID, cl.NetworkName)
			wantID := firstNonEmptyStr(cl.NetworkID, net.ID)
			wantName := firstNonEmptyStr(net.Name, cl.NetworkName)
			for _, cand := range cands {
				if wantID != "" && cand.NetworkID != "" {
					if cand.NetworkID == wantID {
						return cand, true
					}
					continue
				}
				if wantName != "" && strings.EqualFold(cand.NetworkName, wantName) {
					return cand, true
				}
			}
			return unifi.Client{}, false
		}
		if len(cands) == 1 {
			return cands[0], true
		}
		return unifi.Client{}, false
	}
	if full, ok := matchByIP(cl.IP); ok {
		return full
	}
	for _, ip6 := range cl.IPv6 {
		if full, ok := matchByIP(ip6); ok {
			return full
		}
	}
	return cl
}

// network prefers the controller ID when a client also supplies a display name.
func (o *Oracle) network(id, name string) unifi.Network {
	if id == GatewayNetworkID {
		return unifi.Network{ID: id, Name: "Gateway", ZoneName: "Gateway"}
	}
	if id != "" {
		if n, ok := o.netByID[id]; ok {
			return n
		}
	}
	if name != "" {
		if n, ok := o.netByName[strings.ToLower(name)]; ok {
			return n
		}
	}

	return unifi.Network{Name: name}
}

// peerAttachment identifies a switch socket. An AP uplink can represent all
// wireless clients behind it when containment evaluates a whole VLAN.
type peerAttachment struct {
	label  string
	ref    checks.SwitchPortRef
	client unifi.Client
}

// portRef canonicalizes a switch MAC and port index for lookup maps.
func portRef(mac string, idx int) checks.SwitchPortRef {
	return checks.SwitchPortRef{SwitchMAC: strings.ToLower(strings.TrimSpace(mac)), PortIdx: idx}
}

// peerLabel includes the attachment to distinguish clients with the same name.
func (o *Oracle) peerLabel(x peerAttachment) string {
	if x.ref.SwitchMAC != "" && x.ref.PortIdx > 0 {
		return fmt.Sprintf("%s (%s port %d)", peerLabel(x.label), peerLabel(deviceNameByMAC(o.snap, x.ref.SwitchMAC)), x.ref.PortIdx)
	}
	return peerLabel(x.label)
}

// sameAP evaluates the WLAN setting that governs two stations on the same AP.
func (o *Oracle) sameAP(wlan unifi.WLANConfig) IsolationCell {
	c := IsolationCell{
		PathKind:       "same-ap-wifi",
		DestFunction:   "same-vlan-wifi-peers",
		Transport:      "all",
		IPFamily:       "both",
		Enforcer:       wlan.Name,
		Effective:      "deny",
		Verdict:        IsolationBlockedOK,
		DecisiveReason: "Same-AP client isolation enabled on " + wlan.Name,
	}
	if !wlan.L2Isolation {
		c.Effective = "allow"
		c.Verdict = IsolationViolation
		c.DecisiveReason = "Same-AP client isolation is disabled on " + wlan.Name
		c.RecommendedFix = "Enable Client Device Isolation on " + wlan.Name
	}
	if o.snap.Visibility != nil && !o.snap.Visibility.WLANsAvailable && c.Verdict == IsolationBlockedOK {
		c.Verdict = IsolationUnknown
		c.Effective = "unknown"
		c.MissingInput = "Current WLAN isolation settings unavailable for " + wlan.Name
	}
	return c
}

// peerPorts checks whether switch port isolation blocks the path or whether
// physical attachment telemetry is incomplete; an undecided cell requires
// directional switch ACL evaluation.
func (o *Oracle) peerPorts(a, b checks.SwitchPortRef, path string, single bool) (IsolationCell, string) {
	pa, pb := o.ports[a], o.ports[b]
	sameSwitch := a.SwitchMAC != "" && a.SwitchMAC == b.SwitchMAC && a.PortIdx > 0 && b.PortIdx > 0
	c := IsolationCell{Enforcer: "Switch port isolation", Transport: "all", IPFamily: "both"}
	if sameSwitch && (single || a != b) {
		c.EnforcerMACs = enforcerMACs(a.SwitchMAC)
		if o.bypass(&c, a.SwitchMAC) {
			return c, ""
		}
	}
	if sameSwitch && (single || a != b) && !pa.IsolationUnknown && !pb.IsolationUnknown && pa.Isolation && pb.Isolation {
		c.Verdict, c.Effective = IsolationBlockedOK, "deny"
		c.DecisiveReason = "Isolated switch ports: " + path
		return c, ""
	}
	if !sameSwitch || (!single && a == b) || o.switchACLStatus != "complete" {
		c.Verdict, c.Effective = IsolationUnknown, "unknown"
		c.MissingInput = "Cannot verify the complete switched path for " + path
		if o.switchACLStatus != "complete" {
			c.MissingInput += ". Switch ACL unavailable: " + o.switchACLReason
			return c, "switch ACLs (" + peerLabel(o.switchACLReason) + ")"
		}
		return c, "complete switched paths"
	}
	return c, ""
}

// peerPortSettingsKnown reports whether both ends can forward a permitted ACL flow.
func (o *Oracle) peerPortSettingsKnown(a, b checks.SwitchPortRef) bool {
	pa, okA := o.ports[a]
	pb, okB := o.ports[b]
	return okA && okB && !pa.IsolationUnknown && !pb.IsolationUnknown
}

// unknownPeerPorts downgrades an ACL permit when port isolation could still block it.
func unknownPeerPorts(cell *IsolationCell, known bool, path string) bool {
	if known || cell.Verdict != IsolationViolation {
		return false
	}
	cell.Verdict, cell.Effective = IsolationUnknown, "unknown"
	cell.MissingInput = "Effective switch port settings unavailable for " + path
	return true
}

// peerACL evaluates the switch that carries a directional peer crossing.
func (o *Oracle) peerACL(n unifi.Network, peers peerEndpoints, sw, fam, proto string, port int) IsolationCell {
	// Same-VLAN L2 peer ACLs run on the resolved access switch even if the
	// VLAN's L3 router could not be resolved or its firewall zone is External.
	n.RouterDeviceMAC, n.RouterUnresolved = sw, false
	zone := firstNonEmptyStr(n.ZoneName, n.Name)
	if strings.EqualFold(zone, "External") || strings.EqualFold(zone, "Gateway") {
		zone = ""
	}
	// The switch fabric has its own ACLs. Gateway source selectors and the
	// gateway Internet-access toggle do not govern same-VLAN L2 switching.
	fabric := *o
	fabric.sortedPolicies = nil
	var cell IsolationCell
	if proto == "" {
		cell = fabric.evaluateBoundary(nil, config.IsolationIntent{}, n, n, zone, zone, fam, "deny", &peers)
	} else {
		cell = fabric.firstServicePath(n, n, zone, zone, peers, proto, port, fam)
	}
	cell.Enforcer = deviceNameByMAC(o.snap, sw) + " (switch ACL)"
	return cell
}

// enforcerMACs returns a single-element slice holding raw's canonical MAC when
// valid, omitting empty or synthetic hardware identifiers from serialized cells.
func enforcerMACs(raw string) []string {
	if mac, ok := config.ParseCanonicalMAC(raw); ok {
		return []string{mac}
	}
	return nil
}

// evaluateRoutedPath evaluates a routed service across the source addresses
// and MACs covered by the query.
func (o *Oracle) evaluateRoutedPath(
	srcNet, dstNet unifi.Network,
	q pathQuery,
	destHost, destFunction, expected string,
) IsolationCell {
	// When a network-wide query leaves srcIP/srcMAC unspecified (for example,
	// Untrusted -> BMC, Guest -> Printer, or Gateway DHCP/DNS), partition the
	// source network across all policy source selectors so subnet-scoped rules
	// (such as UniFi's "Isolated Networks" with source 10.3.0.0/16) resolve
	// cleanly while single-host rules still get exact multi-partition coverage.
	if strings.TrimSpace(q.srcIP) == "" && strings.TrimSpace(q.srcMAC) == "" {
		if sample := sampleNetworkIPForFamily(srcNet, o.snap, q.ipFamily); sample != "" {
			return o.evaluateRoutedPathAcrossSourceNetwork(
				srcNet, dstNet,
				q, destHost, destFunction, expected, sample,
			)
		}
	}

	return o.routedCell(srcNet, dstNet, q, destHost, destFunction, expected)
}

// routingPath lists the ordered policy enforcers along an L3 path. An empty
// MAC denotes the UniFi gateway (matching Network.RouterDeviceMAC), and a nil
// path signals that at least one routing owner is unresolved.
type routingPath []string

const gatewayOwner = ""

// routingOwners resolves the mandatory enforcers for a routed crossing.
// Same-switch VLANs stay on that switch, while mixed switch/gateway crossings
// require both the L3 switch ACL and the gateway zone firewall to permit traffic.
func routingOwners(src, dst unifi.Network, srcZone, dstZone string) routingPath {
	if strings.EqualFold(dstZone, "External") {
		if src.RouterUnresolved {
			return nil
		}
		if a := strings.TrimSpace(src.RouterDeviceMAC); a != "" {
			return routingPath{a, gatewayOwner}
		}
		return routingPath{gatewayOwner}
	}
	if strings.EqualFold(dstZone, "Gateway") || strings.EqualFold(srcZone, "External") {
		return routingPath{gatewayOwner}
	}
	if src.RouterUnresolved || dst.RouterUnresolved {
		return nil
	}
	a, b := strings.TrimSpace(src.RouterDeviceMAC), strings.TrimSpace(dst.RouterDeviceMAC)
	switch {
	case strings.EqualFold(a, b):
		return routingPath{a}
	case a == "":
		return routingPath{b, gatewayOwner}
	default:
		return routingPath{a, b}
	}
}

// includesACL reports whether a switch on the path is in the rule's device scope.
func (path routingPath) includesACL(deviceMACs []string) bool {
	for _, mac := range path {
		if mac != gatewayOwner && (len(deviceMACs) == 0 || containsFold(deviceMACs, mac)) {
			return true
		}
	}
	return false
}

// routedCell evaluates one packet class across every mandatory enforcer on the
// path: any verified deny settles the path immediately, while an allow requires
// every enforcer to permit the packet.
func (o *Oracle) routedCell(srcNet, dstNet unifi.Network, q pathQuery, destHost, destFunction, expected string) IsolationCell {
	cell := IsolationCell{
		SourceZone:    firstNonEmptyStr(q.srcZone, srcNet.Name),
		SourceNetwork: srcNet.Name,
		DestZone:      firstNonEmptyStr(q.dstZone, dstNet.Name),
		DestNetwork:   dstNet.Name,
		DestHost:      destHost,
		DestIP:        q.dstIP,
		DestFunction:  destFunction,
		Transport:     q.proto,
		Port:          q.port,
		IPFamily:      q.ipFamily,
		PathKind:      "gateway-routed",
		Expected:      expected,
	}
	path := routingOwners(srcNet, dstNet, q.srcZone, q.dstZone)
	if len(path) == 0 {
		applyDecisionToCell(&cell, policyDecision{action: "unknown", missingInput: "Switch routing owner could not be resolved"})
		return cell
	}
	var result IsolationCell
	var macs []string
	for _, owner := range path {
		hop := o.enforcerCell(cell, owner, q)
		if len(path) == 1 || hop.Effective == "deny" {
			return hop
		}
		macs = append(macs, hop.EnforcerMACs...)
		// An unresolved hop takes precedence. Among permits, keep evidence of a
		// bypass or a named rule in preference to a default forwarding decision.
		defaultPermit := result.DecisiveRuleID == "" && result.DecisiveReason != compromiseReason
		if result.Effective == "" || result.Effective == "allow" && (hop.Effective == "unknown" || hop.DecisiveReason == compromiseReason || defaultPermit) {
			result = hop
		}
	}
	if result.Effective == "unknown" {
		return result
	}
	if !slices.Contains(path, gatewayOwner) {
		// Distinct L3 switches cross a transit VLAN, and controller snapshots do
		// not include next-hop route tables showing whether the gateway enforces it.
		cell.PathKind, cell.Enforcer = "switch-routed", "Inter-VLAN routing network"
		applyDecisionToCell(&cell, policyDecision{action: "unknown", missingInput: "Inter-switch transit route is unavailable"})
		return cell
	}
	result.EnforcerMACs = macs
	return result
}

// enforcerCell attributes a packet decision and its evidence to one routing owner.
func (o *Oracle) enforcerCell(cell IsolationCell, owner string, q pathQuery) IsolationCell {
	if owner != "" {
		name := deviceNameByMAC(o.snap, owner)
		cell.PathKind, cell.Enforcer = "switch-routed", name+" (L3 Switch ACL)"
		cell.EnforcerMACs = enforcerMACs(owner)
		if o.bypass(&cell, owner) {
			return cell
		}
		if o.switchACLStatus != "complete" {
			applyDecisionToCell(&cell, policyDecision{action: "unknown", missingInput: fmt.Sprintf("Switch ACL unavailable for L3 switch %s (%s).", name, o.switchACLReason)})
			cell.RecommendedFix = fmt.Sprintf("Collect switch ACL configuration from %s to verify effective isolation.", name)
		} else {
			applyDecisionToCell(&cell, evaluateSwitchACLs(o.sortedACLs, owner, q))
		}
		return cell
	}
	cell.Enforcer, cell.EnforcerMACs = o.gwName+" (Zone Firewall)", enforcerMACs(o.gwMAC)
	if strings.EqualFold(q.dstZone, "Gateway") {
		cell.PathKind = "gateway-local"
	}
	if o.bypass(&cell, o.gwMAC) {
		return cell
	}
	switch {
	case !o.gwPoliciesAvailable:
		applyDecisionToCell(&cell, policyDecision{action: "unknown", missingInput: fmt.Sprintf(
			"Gateway firewall policy telemetry is unavailable (%s); isolation cannot be verified without controller firewall rules.",
			firstNonEmptyStr(o.gwMissingReason, "firewall policy feed missing"),
		)})
		cell.RecommendedFix = "Grant the configured account read access to the site firewall zones and policies to verify gateway isolation."
	case strings.TrimSpace(q.srcZone) == "" || strings.TrimSpace(q.dstZone) == "":
		applyDecisionToCell(&cell, policyDecision{action: "unknown", missingInput: fmt.Sprintf(
			"Unresolved firewall zone for %s -> %s; controller did not map one or both networks to a Zone-Based Firewall zone.",
			cell.SourceNetwork, cell.DestNetwork,
		)})
	default:
		applyDecisionToCell(&cell, evaluateGatewayPolicies(o.sortedPolicies, q))
	}
	return cell
}

// sourceRepresentatives partitions a source network wherever a rule can change
// its decision. The same classes apply to VLAN-wide probes and External ingress.
func (o *Oracle) sourceRepresentatives(srcNet, dstNet unifi.Network, q pathQuery, srcIPSample string) ([]string, []string) {
	var srcPosSelectors, srcNegSelectors []string
	srcMACSet := make(map[string]struct{})
	hasSrcMAC := false

	collectEndpoint := func(ep unifi.PolicyEndpoint) {
		if ep.ZoneName != "" && q.srcZone != "" && !strings.EqualFold(ep.ZoneName, q.srcZone) {
			return
		}
		if !endpointMatchesNetworkSelector(ep, srcNet) {
			return
		}
		if ep.AnyTarget {
			return
		}
		if ep.NegateTarget {
			srcNegSelectors = append(srcNegSelectors, ep.IPs...)
		} else {
			srcPosSelectors = append(srcPosSelectors, ep.IPs...)
		}
		for _, m := range ep.MACs {
			if ml := strings.ToLower(strings.TrimSpace(m)); ml != "" {
				hasSrcMAC = true
				srcMACSet[ml] = struct{}{}
			}
		}
	}

	path := routingOwners(srcNet, dstNet, q.srcZone, q.dstZone)
	if slices.Contains(path, gatewayOwner) && o.gwPoliciesAvailable {
		for _, pol := range o.sortedPolicies {
			if !pol.Enabled || !matchesIPFamily(pol.IPVersion, q.ipFamily) || !matchesConnState(pol.ConnectionStates, q.state) {
				continue
			}
			if pol.Destination.ZoneName != "" && q.dstZone != "" && !strings.EqualFold(pol.Destination.ZoneName, q.dstZone) {
				continue
			}
			collectEndpoint(pol.Source)
		}
	}
	for _, acl := range o.sortedACLs {
		if o.switchACLStatus == "complete" && acl.Enabled && matchesIPFamily(acl.IPVersion, q.ipFamily) && path.includesACL(acl.DeviceMACs) {
			collectEndpoint(acl.Source)
		}
	}

	srcNetPfx, hasSrcNetPfx := networkPrefixForFamily(srcNet, q.ipFamily)
	prefSrc, _ := netip.ParseAddr(strings.TrimSpace(srcIPSample))
	prefSrc = prefSrc.Unmap()

	if strings.EqualFold(q.srcZone, "External") {
		srcNegSelectors = append(srcNegSelectors, nonRoutableExternalCIDRs(q.ipFamily)...)
	}
	var srcIPs []string
	for _, iv := range partitionIPIntervals(srcNet, o.snap, q.ipFamily, srcPosSelectors, srcNegSelectors, nil) {
		if rep := representativeIPInInterval(iv, srcNetPfx, hasSrcNetPfx, prefSrc); rep != "" {
			if strings.EqualFold(q.srcZone, "External") && isNonRoutableIP(rep) {
				continue
			}
			srcIPs = append(srcIPs, rep)
		}
	}
	if len(srcIPs) == 0 {
		srcIPs = []string{srcIPSample}
	}

	var srcMACs []string
	if hasSrcMAC {
		for m := range srcMACSet {
			srcMACs = append(srcMACs, m)
		}
		sort.Strings(srcMACs)
		srcMACs = append(srcMACs, syntheticOtherMAC)
	} else {
		srcMACs = []string{""}
	}

	return srcIPs, srcMACs
}

// evaluateRoutedPathAcrossSourceNetwork evaluates a network-wide routed query
// across every distinct source IP/MAC equivalence class of srcNet so subnet-scoped
// rules resolve deterministically without ever masking partial-subnet leaks.
func (o *Oracle) evaluateRoutedPathAcrossSourceNetwork(
	srcNet, dstNet unifi.Network,
	q pathQuery,
	destHost, destFunction, expected, srcIPSample string,
) IsolationCell {
	srcIPs, srcMACs := o.sourceRepresentatives(srcNet, dstNet, q, srcIPSample)
	var firstCell IsolationCell
	var unknownCell *IsolationCell
	var brokenCell *IsolationCell
	first := true
	evals := 0
	for _, sip := range srcIPs {
		for _, smac := range srcMACs {
			evals++
			if evals > maxExactBoundaryEvals {
				firstCell.Effective = "unknown"
				firstCell.Verdict = IsolationUnknown
				firstCell.MissingInput = fmt.Sprintf("Policy evaluation exceeded %d exact source partitions for %s -> %s.", maxExactBoundaryEvals, srcNet.Name, dstNet.Name)
				return firstCell
			}
			sub := q
			sub.srcIP = sip
			sub.srcMAC = smac
			cell := o.routedCell(srcNet, dstNet, sub, destHost, destFunction, expected)
			if first {
				firstCell = cell
				first = false
			}
			if expected == "deny" {
				if cell.Verdict == IsolationViolation {
					return cell
				}
				if cell.Verdict == IsolationUnknown && unknownCell == nil {
					cp := cell
					unknownCell = &cp
				}
			} else {
				if cell.Verdict == IsolationBrokenDependency && brokenCell == nil {
					cp := cell
					brokenCell = &cp
				}
				if cell.Verdict == IsolationUnknown && unknownCell == nil {
					cp := cell
					unknownCell = &cp
				}
			}
		}
	}
	if brokenCell != nil {
		return *brokenCell
	}
	if unknownCell != nil {
		return *unknownCell
	}
	return firstCell
}
